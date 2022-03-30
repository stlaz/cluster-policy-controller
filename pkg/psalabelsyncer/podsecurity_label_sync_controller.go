package psalabelsyncer

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	rbacv1informers "k8s.io/client-go/informers/rbac/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	rbacv1listers "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"
	psapi "k8s.io/pod-security-admission/api"

	securityv1 "github.com/openshift/api/security/v1"
	securityv1informers "github.com/openshift/client-go/security/informers/externalversions/security/v1"
	securityv1listers "github.com/openshift/client-go/security/listers/security/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	controllerName        = "pod-security-admission-label-synchronization-controller"
	labelSyncControlLabel = "security.openshift.io/scc.podSecurityLabelSync"
)

type PodSecurityAdmissionLabelSynchronizationController struct {
	namespaceClient corev1client.NamespaceInterface

	namespaceLister          corev1listers.NamespaceLister
	roleLister               rbacv1listers.RoleLister
	roleBindingLister        rbacv1listers.RoleBindingLister
	clusterRoleLister        rbacv1listers.ClusterRoleLister
	clusterRoleBindingLister rbacv1listers.ClusterRoleBindingLister
	serviceAccountLister     corev1listers.ServiceAccountLister
	sccLister                securityv1listers.SecurityContextConstraintsLister

	saToSCCsCache *SAToSCCCache
}

func NewPodSecurityAdmissionLabelSynchronizationController(
	namespaceClient corev1client.NamespaceInterface,
	namespaceInformer corev1informers.NamespaceInformer,
	rbacInformers rbacv1informers.Interface,
	serviceAccountInformer corev1informers.ServiceAccountInformer,
	sccInformer securityv1informers.SecurityContextConstraintsInformer,
	eventRecorder events.Recorder,
) (factory.Controller, error) {

	// add the indexers that are used in the SAToSCC cache
	if err := rbacInformers.RoleBindings().Informer().AddIndexers(
		cache.Indexers{BySAIndexName: BySAIndexKeys},
	); err != nil {
		return nil, err
	}

	if err := rbacInformers.ClusterRoleBindings().Informer().AddIndexers(
		cache.Indexers{BySAIndexName: BySAIndexKeys},
	); err != nil {
		return nil, err
	}

	c := &PodSecurityAdmissionLabelSynchronizationController{
		namespaceClient: namespaceClient,

		namespaceLister:          namespaceInformer.Lister(),
		roleLister:               rbacInformers.Roles().Lister(),
		roleBindingLister:        rbacInformers.RoleBindings().Lister(),
		clusterRoleLister:        rbacInformers.ClusterRoles().Lister(),
		clusterRoleBindingLister: rbacInformers.ClusterRoleBindings().Lister(),
		serviceAccountLister:     serviceAccountInformer.Lister(),
		sccLister:                sccInformer.Lister(),

		saToSCCsCache: NewSAToSCCCache(rbacInformers, sccInformer),
	}

	return factory.New().
		WithSync(c.sync).
		WithFilteredEventsInformers(
			func(obj interface{}) bool {
				return c.saToSCCsCache.IsRoleBindingRelevant(obj)
			},
			rbacInformers.RoleBindings().Informer(),
			rbacInformers.ClusterRoleBindings().Informer(),
		).
		WithFilteredEventsInformers(
			func(obj interface{}) bool {
				return c.saToSCCsCache.IsRoleInvolvesSCCs(obj, true)
			},
			rbacInformers.Roles().Informer(),
			rbacInformers.ClusterRoles().Informer(),
		).
		WithFilteredEventsInformers(
			func(obj interface{}) bool {
				// TODO: also probably don't react on NSes that are being deleted
				ns, ok := obj.(*corev1.Namespace)
				if !ok {
					return false
				}
				// the SCC mapping requires the annotation
				// FIXME: make the mapping not panic but error out instead
				if ns.Annotations == nil || len(ns.Annotations[securityv1.UIDRangeAnnotation]) == 0 {
					return false
				}
				return true
			},
			namespaceInformer.Informer(),
		).
		WithInformers(
			serviceAccountInformer.Informer(),
			sccInformer.Informer(), // FIXME: we need to resync the cache on an SCC update (in case one is added or removed)
		).
		ToController(
			controllerName,
			eventRecorder.WithComponentSuffix(controllerName),
		), nil
}

func (c *PodSecurityAdmissionLabelSynchronizationController) sync(ctx context.Context, controllerContext factory.SyncContext) error {
	labelRequirement, err := labels.NewRequirement(labelSyncControlLabel, selection.NotEquals, []string{"false"})
	if err != nil {
		return fmt.Errorf("failed to create a label requirement to list only opted-in namespaces: %w", err)
	}

	nsList, err := c.namespaceLister.List(labels.NewSelector().Add(*labelRequirement))
	if err != nil {
		return err
	}

	var errs []error
	for _, ns := range nsList {
		serviceAccounts, err := c.serviceAccountLister.ServiceAccounts(ns.Name).List(labels.Everything())
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list service accounts for %s: %w", ns.Name, err))
			continue
		}

		nsSCCs := sets.NewString()
		for _, sa := range serviceAccounts {
			allowedSCCs, err := c.saToSCCsCache.SCCsFor(sa)
			if err != nil {
				// TODO: log err and continue for the next NS
				return err
			}
			nsSCCs.Insert(allowedSCCs.UnsortedList()...)
		}

		var currentNSLevel uint8
		for _, sccName := range nsSCCs.UnsortedList() {
			scc, err := c.sccLister.Get(sccName)
			if err != nil {
				// TODO: the SCC was removed in the meantime and synced in the cache?
				return err
			}
			sccPSaLevel := convertSCCToPSALevel(ns, scc)

			if sccPSaLevel > currentNSLevel {
				currentNSLevel = sccPSaLevel
			}
			// can't go more privileged
			if currentNSLevel == privileged {
				break
			}
		}

		var nsCopy *corev1.Namespace
		psaLevel := internalRestrictivnessToPSaLevel(currentNSLevel)
		if ns.Labels[psapi.EnforceLevelLabel] != string(psaLevel) || ns.Labels[psapi.EnforceVersionLabel] != psapi.VersionLatest {
			nsCopy = ns.DeepCopy()
			if nsCopy.Labels == nil {
				nsCopy.Labels = map[string]string{}
			}

			nsCopy.Labels[psapi.EnforceLevelLabel] = string(psaLevel)
			nsCopy.Labels[psapi.EnforceVersionLabel] = psapi.VersionLatest

			_, err := c.namespaceClient.Update(ctx, nsCopy, metav1.UpdateOptions{})
			if err != nil {
				// TODO: better error handling, repeat update tries, go to next NS?
				return err
			}
		}
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}
	return nil
}
