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
	"k8s.io/klog/v2"
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

	usefulRoles sets.String
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

	return nil, fmt.Errorf("the object is neither a RoleBinding, nor a ClusterRoleBinding: %T", obj)
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

func (r *roleBindingObj) Namespace() string {
	if r.clusterRoleBinding != nil {
		return ""
	}
	return r.roleBinding.Namespace
}

// roleObj helps to handle roles and clusterroles in a generic manner
type roleObj struct {
	role        *rbacv1.Role
	clusterRole *rbacv1.ClusterRole
}

func newRoleObj(obj interface{}) (*roleObj, error) {
	switch r := obj.(type) {
	case *rbacv1.ClusterRole:
		return &roleObj{
			clusterRole: r,
		}, nil
	case *rbacv1.Role:
		return &roleObj{
			role: r,
		}, nil
	case *roleObj:
		return r, nil
	default:
		return nil, fmt.Errorf("the object is neither a Role, nor a ClusterRole: %T", obj)
	}
}

func (r *roleObj) Rules() []rbacv1.PolicyRule {
	if role := r.clusterRole; role != nil {
		return role.Rules
	}
	return r.role.Rules
}

func (r *roleObj) Name() string {
	if role := r.clusterRole; role != nil {
		return role.Name
	}
	return r.role.Name
}

func (r *roleObj) Namespace() string {
	if role := r.clusterRole; role != nil {
		return role.Namespace
	}
	return r.role.Namespace
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
			roleObj, err := c.GetRoleFromRoleRef(serviceAccount.Namespace, roleRef)
			if err != nil {
				if errors.IsNotFound(err) {
					continue
				}
				// TODO: maybe just ignore and log?
				return nil, err
			}
			allowedSCCs.Insert(SCCsAllowedByPolicyRules(serviceAccount.Namespace, realSAUserInfo, sccs, roleObj.Rules())...)
		}
	}

	return allowedSCCs, nil
}

func (c *SAToSCCCache) GetRoleFromRoleRef(ns string, roleRef rbacv1.RoleRef) (*roleObj, error) {
	var role interface{}
	var err error
	switch kind := roleRef.Kind; kind {
	case "Role":
		role, err = c.roleLister.Roles(ns).Get(roleRef.Name)
	case "ClusterRole":
		role, err = c.clusterRoleLister.Get(roleRef.Name)
	default:
		return nil, fmt.Errorf("unknown kind in roleRef: %s", kind)
	}
	if err != nil {
		return nil, err
	}

	return newRoleObj(role)
}

func (c *SAToSCCCache) IsRoleBindingRelevant(obj interface{}) bool {
	rb, err := newRoleBindingObj(obj)
	if err != nil {
		klog.Warningf("unexpected error, this may be a bug: %v", err)
		return false
	}

	role, err := c.GetRoleFromRoleRef(rb.Namespace(), rb.RoleRef())
	if err != nil {
		klog.Infof("failed to retrieve a role for a rolebinding ref: %v", err)
		return false
	}

	// TODO: actually cache the relevant rolebindings and relevant roles
	// or maybe only the roles and update cached roles on a role update?
	return c.IsRoleInvolvesSCCs(role, false)
}

func (c *SAToSCCCache) IsRoleInvolvesSCCs(obj interface{}, isRoleUpdate bool) bool {
	role, err := newRoleObj(obj)
	if err != nil {
		klog.Warningf("unexpected error, this may be a bug: %v", err)
		return false
	}

	sccs, err := c.sccLister.List(labels.Everything()) // TODO: this should probably requeue, right?
	if err != nil {
		klog.Warning("failed to list SCCs: %v", err)
		return false
	}

	if isRoleUpdate {
		c.SyncRoleCache(role.Namespace(), role.Name(), role.Rules(), sccs)
	}
	return c.usefulRoles.Has(fmt.Sprintf("%s/%s", role.Namespace(), role.Name()))
}

func (c *SAToSCCCache) InitializeRoleCache() error {
	roles, err := c.roleLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to initialize role cache: %w", err)
	}

	clusterRoles, err := c.clusterRoleLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to initialize role cache: %w", err)
	}

	sccs, err := c.sccLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to initialize role cache: %w", err)
	}

	for _, r := range roles {
		c.SyncRoleCache(r.Namespace, r.Name, r.Rules, sccs)
	}

	for _, r := range clusterRoles {
		c.SyncRoleCache(r.Namespace, r.Name, r.Rules, sccs)
	}

	return nil
}

func (c *SAToSCCCache) SyncRoleCache(roleNS, roleName string, rules []rbacv1.PolicyRule, sccs []*securityv1.SecurityContextConstraints) {
	dummyUserInfo := &user.DefaultInfo{
		Name: "dummyUser",
	}
	if len(SCCsAllowedByPolicyRules("", dummyUserInfo, sccs, rules)) > 0 {
		c.usefulRoles.Insert(fmt.Sprintf("%s/%s", roleNS, roleName))
	}

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
