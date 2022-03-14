package psalabelsyncer

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	rbacv1listers "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"

	securityv1 "github.com/openshift/api/security/v1"
	securityv1listers "github.com/openshift/client-go/security/listers/security/v1"
)

const (
	NS1     = "mambonumberfive"
	NS2     = "mumbonumbertwo"
	SA1Name = "one"
	SA2Name = "two"
)

var (
	NS1SA1 = corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SA1Name,
			Namespace: NS1,
		},
	}
	NS2SA1 = corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SA1Name,
			Namespace: NS2,
		},
	}
	NS2SA2 = corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SA2Name,
			Namespace: NS2,
		},
	}
	NSDontCareSA1 = corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SA1Name,
			Namespace: "randomns",
		},
	}
)

func TestSCCRoleCache_SCCsFor(t *testing.T) {
	basicSCCs := []string{"scc_authenticated", "scc_allsa"}
	allSCCs := append(basicSCCs, "scc_sa1", "scc_sa1group_sa2", "scc_none", "scc_none2")

	tests := []struct {
		name         string
		roles        []*rbacv1.Role
		clusterRoles []*rbacv1.ClusterRole

		roleBindings        []*rbacv1.RoleBinding
		clusterRoleBindings []*rbacv1.ClusterRoleBinding

		serviceAccount *corev1.ServiceAccount

		want    sets.String
		wantErr bool
	}{
		{
			name:           "only SCCs with authenticated/SAs groups match", // TODO: allow an SCC lister override so that no SCCs match
			serviceAccount: &NSDontCareSA1,
			want:           sets.NewString(basicSCCs...),
		},
		{
			name:           "SCC with specific SA username matches",
			serviceAccount: &NS2SA1,
			want:           sets.NewString(basicSCCs...).Insert("scc_sa1group_sa2"),
		},
		{
			name:           "SCC with specific SA user and NS group matches",
			serviceAccount: &NS1SA1,
			want:           sets.NewString(basicSCCs...).Insert("scc_sa1", "scc_sa1group_sa2"),
		},
		{
			name:           "all SCCs assigned via a broad cluster rolebinding",
			serviceAccount: &NS2SA1,
			clusterRoles: []*rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterrole",
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{"*"},
							Resources: []string{"*"},
							Verbs:     []string{"*"},
						},
					},
				},
			},
			clusterRoleBindings: []*rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterrolebinding",
					},
					RoleRef: rbacv1.RoleRef{
						APIGroup: rbacv1.GroupName,
						Kind:     "ClusterRole",
						Name:     "clusterrole",
					},
					Subjects: []rbacv1.Subject{
						{
							APIGroup:  corev1.GroupName,
							Kind:      "ServiceAccount",
							Name:      SA1Name,
							Namespace: NS2,
						},
					},
				},
			},
			want: sets.NewString(allSCCs...),
		},

		{
			name:           "single SCCs assigned via a cluster rolebinding",
			serviceAccount: &NS2SA2,
			clusterRoles: []*rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterrole",
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups:     []string{securityv1.GroupName},
							Resources:     []string{"securitycontextconstraints"},
							ResourceNames: []string{"scc_none"},
							Verbs:         []string{"use"},
						},
					},
				},
			},
			clusterRoleBindings: []*rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterrolebinding",
					},
					RoleRef: rbacv1.RoleRef{
						APIGroup: rbacv1.GroupName,
						Kind:     "ClusterRole",
						Name:     "clusterrole",
					},
					Subjects: []rbacv1.Subject{
						{
							APIGroup:  corev1.GroupName,
							Kind:      "ServiceAccount",
							Name:      SA2Name,
							Namespace: NS2,
						},
					},
				},
			},
			want: sets.NewString(basicSCCs...).Insert("scc_none"),
		},
		{
			name:           "all SCCs assigned via a rolebinding to a broad role",
			serviceAccount: &NS2SA1,
			roles: []*rbacv1.Role{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role",
						Namespace: NS2,
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{"*"},
							Resources: []string{"*"},
							Verbs:     []string{"*"},
						},
					},
				},
			},
			roleBindings: []*rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "rolebinding",
						Namespace: NS2,
					},
					RoleRef: rbacv1.RoleRef{
						APIGroup: rbacv1.GroupName,
						Kind:     "Role",
						Name:     "role",
					},
					Subjects: []rbacv1.Subject{
						{
							APIGroup:  corev1.GroupName,
							Kind:      "ServiceAccount",
							Name:      SA1Name,
							Namespace: NS2,
						},
					},
				},
			},
			want: sets.NewString(allSCCs...),
		},
		{
			name:           "specific SCC assigned via a rolebinding to a clusterrole",
			serviceAccount: &NS2SA2,
			clusterRoles: []*rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "role",
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups:     []string{securityv1.GroupName},
							Resources:     []string{"securitycontextconstraints"},
							ResourceNames: []string{"scc_none"},
							Verbs:         []string{"use"},
						},
					},
				},
			},
			roleBindings: []*rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "rolebinding",
						Namespace: NS2,
					},
					RoleRef: rbacv1.RoleRef{
						APIGroup: rbacv1.GroupName,
						Kind:     "ClusterRole",
						Name:     "role",
					},
					Subjects: []rbacv1.Subject{
						{
							APIGroup:  corev1.GroupName,
							Kind:      "ServiceAccount",
							Name:      SA2Name,
							Namespace: NS2,
						},
					},
				},
			},
			want: sets.NewString(basicSCCs...).Insert("scc_none"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roles := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, r := range tt.roles {
				require.NoError(t, roles.Add(r))
			}

			clusterRoles := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, cr := range tt.clusterRoles {
				require.NoError(t, clusterRoles.Add(cr))
			}

			roleBindings := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{BySAIndexName: BySAIndexKeys})
			for _, rb := range tt.roleBindings {
				require.NoError(t, roleBindings.Add(rb))
			}

			clusterRoleBindings := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{BySAIndexName: BySAIndexKeys})
			for _, crb := range tt.clusterRoleBindings {
				require.NoError(t, clusterRoleBindings.Add(crb))
			}

			roleLister := rbacv1listers.NewRoleLister(roles)
			clusterRoleLister := rbacv1listers.NewClusterRoleLister(clusterRoles)

			c := &SAToSCCCache{
				roleLister:                roleLister,
				clusterRoleLister:         clusterRoleLister,
				roleBindingIndexer:        roleBindings,
				clusterRoleBindingIndexer: clusterRoleBindings,
				sccLister:                 sccLister(t),
				rolesSynced:               func() bool { return true },
				roleBindingsSynced:        func() bool { return true },
			}
			got, err := c.SCCsFor(tt.serviceAccount)
			if (err != nil) != tt.wantErr {
				t.Errorf("SCCRoleCache.SCCsFor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.want.Equal(got) {
				t.Errorf("SCCRoleCache.SCCsFor() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func sccLister(t *testing.T) securityv1listers.SecurityContextConstraintsLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, scc := range []*securityv1.SecurityContextConstraints{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc_authenticated",
			},
			Groups: []string{"system:authenticated"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc_allsa",
			},
			Groups: []string{"system:serviceaccounts"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc_sa1",
			},
			Users: []string{"system:serviceaccount:" + NS1 + ":" + SA1Name},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc_sa1group_sa2",
			},
			Groups: []string{"system:serviceaccounts:" + NS1},
			Users:  []string{"system:serviceaccount:" + NS2 + ":" + SA1Name},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc_none",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scc_none2",
			},
		},
	} {
		require.NoError(t, indexer.Add(scc))
	}

	return securityv1listers.NewSecurityContextConstraintsLister(indexer)
}
