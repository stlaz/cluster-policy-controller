package psalabelsyncer

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacv1informers "k8s.io/client-go/informers/rbac/v1"
	rbacv1listers "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	securityv1 "github.com/openshift/api/security/v1"
	securityv1informers "github.com/openshift/client-go/security/informers/externalversions/security/v1"
	securityv1listers "github.com/openshift/client-go/security/listers/security/v1"
)

const BySAIndexName = "ByServiceAccount"

type SAToSCCCache struct {
	roleLister                rbacv1listers.RoleLister
	clusterRoleLister         rbacv1listers.ClusterRoleLister
	roleBindingIndexer        cache.Indexer
	clusterRoleBindingIndexer cache.Indexer

	sccLister securityv1listers.SecurityContextConstraintsLister

	rolesSynced        cache.InformerSynced
	roleBindingsSynced cache.InformerSynced
}

// role and clusterrolebinding object for generic handling, assumes one and
// at most one of role/clusterrole is always non-nil
type roleBindingObj struct {
	roleBinding        *rbacv1.RoleBinding
	clusterRoleBinding *rbacv1.ClusterRoleBinding
}

func newRoleBindingObj(obj interface{}) (*roleBindingObj, error) {
	if o, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
		return &roleBindingObj{
			clusterRoleBinding: o,
		}, nil
	} else if o, ok := obj.(*rbacv1.RoleBinding); ok {
		return &roleBindingObj{
			roleBinding: o,
		}, nil
	}

	return nil, fmt.Errorf("the object is neither a RoleBinding, nor a ClusterRoleBinding: %v", obj)
}

func (r *roleBindingObj) RoleRef() rbacv1.RoleRef {
	if binding := r.clusterRoleBinding; binding != nil {
		return binding.RoleRef
	}
	return r.roleBinding.RoleRef
}

func (r *roleBindingObj) Subjects() []rbacv1.Subject {
	if binding := r.clusterRoleBinding; binding != nil {
		return binding.Subjects
	}
	return r.roleBinding.Subjects
}

func (r *roleBindingObj) AppliesToNS(ns string) bool {
	if r.clusterRoleBinding != nil {
		return true
	}
	return ns == r.roleBinding.Namespace
}

func BySAIndexKeys(obj interface{}) ([]string, error) {
	roleBinding, err := newRoleBindingObj(obj)
	if err != nil {
		return nil, err
	}

	serviceAccounts := []string{}
	for _, subject := range roleBinding.Subjects() {
		if subject.APIGroup == "" && subject.Kind == "ServiceAccount" {
			serviceAccounts = append(serviceAccounts, serviceaccount.MakeUsername(subject.Namespace, subject.Name))
		} else if subject.APIGroup == rbacv1.GroupName && subject.Kind == "Group" &&
			(subject.Name == serviceaccount.AllServiceAccountsGroup ||
				subject.Name == user.AllAuthenticated ||
				strings.HasPrefix(subject.Name, serviceaccount.ServiceAccountGroupPrefix)) {
			serviceAccounts = append(serviceAccounts, subject.Name)
		}
	}

	return serviceAccounts, nil
}

func NewSAToSCCCache(rbacInformers rbacv1informers.Interface, sccInfomer securityv1informers.SecurityContextConstraintsInformer) *SAToSCCCache {
	return &SAToSCCCache{
		roleLister:                rbacInformers.Roles().Lister(),
		clusterRoleLister:         rbacInformers.ClusterRoles().Lister(),
		roleBindingIndexer:        rbacInformers.RoleBindings().Informer().GetIndexer(),
		clusterRoleBindingIndexer: rbacInformers.ClusterRoleBindings().Informer().GetIndexer(),

		sccLister: sccInfomer.Lister(),

		// TODO: do I need these?
		rolesSynced:        rbacInformers.Roles().Informer().HasSynced,
		roleBindingsSynced: rbacInformers.RoleBindings().Informer().HasSynced,
	}
}

// SCCsFor returns a slice of all the SCCs that a given service account can use
// to run pods in its namespace
// It expects the serviceAccount name in the system:serviceaccount:<ns>:<name> form
func (c *SAToSCCCache) SCCsFor(serviceAccount *corev1.ServiceAccount) (sets.String, error) {
	saUserInfo := serviceaccount.UserInfo(
		serviceAccount.Namespace,
		serviceAccount.Name,
		string(serviceAccount.UID),
	)

	// realSAUserInfo adds the "system:authenticated" group to SA UserInfo groups
	realSAUserInfo := &user.DefaultInfo{
		Name:   saUserInfo.GetName(),
		Groups: append(saUserInfo.GetGroups(), user.AllAuthenticated),
		UID:    saUserInfo.GetUID(),
		Extra:  saUserInfo.GetExtra(),
	}

	objs, err := getIndexedRolebindings(c.roleBindingIndexer, realSAUserInfo)
	if err != nil {
		return nil, err
	}

	clusterObjs, err := getIndexedRolebindings(c.clusterRoleBindingIndexer, realSAUserInfo)
	if err != nil {
		return nil, err
	}
	objs = append(objs, clusterObjs...)

	sccs, err := c.sccLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	allowedSCCs := sets.NewString()
	for _, scc := range sccs {
		if sccAllowsSA(scc, realSAUserInfo) {
			allowedSCCs.Insert(scc.Name)
		}
	}

	// TODO: (idea): determine, ahead of time, which SCCs are allowed for all authenticated or for all SAs?
	for _, o := range objs {
		rb, err := newRoleBindingObj(o)
		if err != nil {
			// this would be rather weird
			return nil, err
		}

		// we particularly care only about Roles in the SA NS
		if roleRef := rb.RoleRef(); rb.AppliesToNS(serviceAccount.Namespace) && roleRef.APIGroup == rbacv1.GroupName {
			switch roleRef.Kind {
			case "Role":
				r, err := c.roleLister.Roles(serviceAccount.Namespace).Get(roleRef.Name)
				if err != nil {
					if errors.IsNotFound(err) {
						continue
					}
					// TODO: maybe just ignore and log?
					return nil, err
				}
				allowedSCCs.Insert(SCCsAllowedByPolicyRules(serviceAccount.Namespace, realSAUserInfo, sccs, r.Rules)...)

			case "ClusterRole":
				r, err := c.clusterRoleLister.Get(roleRef.Name)
				if err != nil {
					if errors.IsNotFound(err) {
						continue
					}
					// TODO: maybe just ignore and log?
					return nil, err
				}
				allowedSCCs.Insert(SCCsAllowedByPolicyRules(serviceAccount.Namespace, realSAUserInfo, sccs, r.Rules)...)

			default:
				// ignore invalid role references
				continue
			}
		}
	}

	return allowedSCCs, nil
}

func SCCsAllowedByPolicyRules(nsName string, saUserInfo user.Info, sccs []*securityv1.SecurityContextConstraints, rules []rbacv1.PolicyRule) []string {
	ar := authorizer.AttributesRecord{
		User:            saUserInfo,
		APIGroup:        securityv1.GroupName,
		Resource:        "securitycontextconstraints",
		Namespace:       nsName,
		Verb:            "use",
		ResourceRequest: true,
	}

	allowedSCCs := make([]string, 0, len(sccs))
	for _, scc := range sccs {
		ar.Name = scc.Name
		if rbac.RulesAllow(ar, rules...) {
			allowedSCCs = append(allowedSCCs, scc.Name)
		}
	}

	return allowedSCCs
}

func getIndexedRolebindings(indexer cache.Indexer, saUserInfo user.Info) ([]interface{}, error) {
	objs, err := indexer.ByIndex(BySAIndexName, saUserInfo.GetName())
	if err != nil {
		return nil, err
	}

	for _, g := range saUserInfo.GetGroups() {
		groupObjs, err := indexer.ByIndex(BySAIndexName, g)
		if err != nil {
			return nil, err
		}
		objs = append(objs, groupObjs...)
	}

	return objs, nil
}

func sccAllowsSA(scc *securityv1.SecurityContextConstraints, saUserInfo user.Info) bool {
	for _, u := range scc.Users {
		if u == saUserInfo.GetName() {
			return true
		}
	}

	saNSGroups := sets.NewString(saUserInfo.GetGroups()...)
	for _, g := range scc.Groups {
		if saNSGroups.Has(g) {
			return true
		}
	}

	return false
}
