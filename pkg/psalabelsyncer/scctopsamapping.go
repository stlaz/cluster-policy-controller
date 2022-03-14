package psalabelsyncer

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	psapi "k8s.io/pod-security-admission/api"

	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/library-go/pkg/security/uid"
)

const (
	restricted uint8 = iota
	baseline
	privileged
)

func internalRestrictivnessToPSaLevel(restr uint8) psapi.Level {
	switch restr {
	case restricted:
		return psapi.LevelRestricted
	case baseline:
		return psapi.LevelBaseline
	case privileged:
		return psapi.LevelPrivileged
	default:
		return ""
	}
}

func convertSCCToPSALevel(namespace *corev1.Namespace, scc *securityv1.SecurityContextConstraints) uint8 {
	sccRestrictivness := make([]uint8, 0, 10)
	sccRestrictivness = append(sccRestrictivness,
		convert_hostDir(scc.AllowHostDirVolumePlugin, scc.Volumes),
		convert_hostNamespace(scc.AllowHostIPC, scc.AllowHostNetwork, scc.AllowHostPID),
		convert_hostPorts(scc.AllowHostPorts),
		convert_allowPrivilegeEscalation(scc.AllowPrivilegeEscalation, scc.DefaultAllowPrivilegeEscalation),
		convert_allowPrivilegedContainer(scc.AllowPrivilegedContainer),
		convert_allowedCapabilities(scc.AllowedCapabilities, scc.RequiredDropCapabilities),
		convert_unsafeSysctls(scc.AllowedUnsafeSysctls),
		convert_runAsUserOrDie(namespace, &scc.RunAsUser),
		convert_volumes(scc.Volumes),
		convert_seLinuxOptions(&scc.SELinuxContext),
	)

	// scc.ForbiddenSysctls <-- only restricts the current allowed set, unused for conversion
	// scc.AllowedFlexVolumes <-- only restricts the current allowed set, unused for conversion

	// scc.DefaultAddCapabilities  <-- this is still restricted by the set of allowed capabilities

	// scc.FSGroup <-- seems to be ignored by PSa
	// scc.ReadOnlyRootFilesystem <-- seems to be ignored by PSa
	// scc.SupplementalGroups <-- seems to be ignored by PSa

	// scc.SeccompProfiles <-- FIXME: this matured to GA in kube but is not reflected to SCCs

	var restrictiveness = restricted
	for _, r := range sccRestrictivness {
		if r == privileged {
			return privileged
		}

		if r > restrictiveness {
			restrictiveness = r
		}
	}
	return restrictiveness
}

func convert_hostDir(allowHostDirVolumePlugin bool, volumes []securityv1.FSType) uint8 {
	// upstream: check_hostPathVolumes
	// baseline allows: undefined/null
	if allowHostDirVolumePlugin {
		return privileged
	}

	for _, v := range volumes {
		if v == securityv1.FSTypeHostPath || v == securityv1.FSTypeAll {
			return privileged
		}
	}
	return restricted
}

func convert_hostNamespace(allowHostIPC, allowHostNetwork, allowHostPorts bool) uint8 {
	// upstream: check_hostNamespaces
	// baseline allows: undefined, false
	if allowHostIPC || allowHostNetwork || allowHostPorts {
		return privileged
	}

	return restricted
}

func convert_hostPorts(allowHostPorts bool) uint8 {
	// upstream: check_hostPorts
	// baseline allows: undefined/0
	if allowHostPorts {
		return privileged
	}
	return restricted
}

func convert_allowPrivilegeEscalation(allowPrivilegeEscalation *bool, defaultAllowPrivilegeEscalation *bool) uint8 {
	// upstream: check_allowPrivilegeEscalation
	// restricted allows: false
	if allowPrivilegeEscalation == nil {
		if defaultAllowPrivilegeEscalation == nil || *defaultAllowPrivilegeEscalation {
			return baseline
		}
		// defaultAllowPrivilegeEscalation == false here
		return restricted
	} else if *allowPrivilegeEscalation {
		return baseline
	}

	return restricted
}

func convert_allowPrivilegedContainer(allowPrivilegedContainer bool) uint8 {
	// upstream: check_privileged
	// baseline allows: false, undefined/null
	if allowPrivilegedContainer {
		return privileged
	}

	return restricted
}

// FIXME: <needs a fix in OCP>
// this single conversion will make all SCCs be evaluated as `baseline` at best
// since we don't currently have a way to require dropping ALL caps in OCP
func convert_allowedCapabilities(sccAllowedCapabilities, requiredDropCapabilities []corev1.Capability) uint8 {
	// upstream: check_capabilities_{baseline,restricted}
	// baseline allows:  `baseline_capabilities_allowed_1_0`
	// restricted:
	//     allows: NET_BIND_SERVICE
	//     requires: drop ALL <-- ALL is missing in OpenShift
	baseline_capabilities_allowed_1_0 := sets.NewString(
		"AUDIT_WRITE",
		"CHOWN",
		"DAC_OVERRIDE",
		"FOWNER",
		"FSETID",
		"KILL",
		"MKNOD",
		"NET_BIND_SERVICE",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"SYS_CHROOT",
	)

	sccAllowed := sets.NewString()
	for _, cap := range sccAllowedCapabilities {
		sccAllowed.Insert(string(cap))
	}

	if !baseline_capabilities_allowed_1_0.IsSuperset(sccAllowed) {
		return privileged
	}

	// restricted conditions below
	if !sets.NewString("NET_BIND_SERVICE").IsSuperset(sccAllowed) {
		return baseline
	}

	var dropsAll bool
	for _, cap := range requiredDropCapabilities {
		if cap == "ALL" {
			dropsAll = true
			break
		}
	}
	if !dropsAll {
		return baseline
	}

	return restricted
}

func convert_unsafeSysctls(allowedUnsafeSysctls []string) uint8 {
	// upstream: check_sysctls
	// baseline allows: `sysctls_allowed_1_0`

	// ocp uses the k8s.io/kubernetes/pkg/security/podsecuritypolicy/sysctl.SafeSysctlWhitelist()
	// which matches these sysctls
	sysctls_allowed_1_0 := sets.NewString(
		"kernel.shm_rmid_forced",
		"net.ipv4.ip_local_port_range",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.ping_group_range",
		"net.ipv4.ip_unprivileged_port_start",
	)

	sccAllowedSysctls := sets.NewString(allowedUnsafeSysctls...)
	if !sysctls_allowed_1_0.IsSuperset(sccAllowedSysctls) {
		return privileged
	}

	return restricted
}

// INTERESTING: this function makes the whole conversion NS-dependant
func convert_runAsUserOrDie(
	namespace *corev1.Namespace,
	runAsUser *securityv1.RunAsUserStrategyOptions,
) uint8 {
	// upstream: check_runAsUser
	// restricted requires: non-zero, undefined
	switch runAsUser.Type {
	case securityv1.RunAsUserStrategyMustRunAsNonRoot:
		return restricted
	case securityv1.RunAsUserStrategyMustRunAs:
		// RunAsUserStrategyMustRunAs requires the UID to be set
		if runAsUser.UID != nil && *runAsUser.UID > 0 {
			return restricted
		}
		return baseline
	case securityv1.RunAsUserStrategyMustRunAsRange:
		if runAsUser.UIDRangeMin == nil || runAsUser.UIDRangeMax == nil {
			annotationVal, ok := namespace.Annotations[securityv1.UIDRangeAnnotation]
			if !ok || len(annotationVal) == 0 {
				panic(fmt.Errorf("the namespace %q has no valid %q label or the label's missing value, even though the SCC requires it", namespace, securityv1.UIDRangeAnnotation))
			}

			uidBlock, err := uid.ParseBlock(annotationVal)
			if err != nil {
				panic(fmt.Errorf("failed to parse uid block for the %q namespace: %v", namespace, err))
			}

			if uidBlock.Start > 0 { // we only care about the beginning of the block, no need to check for valid blocks here
				return restricted
			}

			return baseline
		}

		// we only care about the beginning of the block, no need to check for valid blocks here
		if *runAsUser.UIDRangeMin > 0 {
			return restricted
		}

		return baseline

	case securityv1.RunAsUserStrategyRunAsAny:
		return baseline
	default:
		panic(fmt.Errorf("unknown strategy: %s", runAsUser.Type))
	}

}

func convert_volumes(volumes []securityv1.FSType) uint8 {
	// upstream: check_restrictedVolumes
	// restricted:
	//   requires:
	//     none of the following to be set
	//       spec.volumes[*].hostPath
	//       spec.volumes[*].gcePersistentDisk
	//       spec.volumes[*].awsElasticBlockStore
	//       spec.volumes[*].gitRepo
	//       spec.volumes[*].nfs
	//       spec.volumes[*].iscsi
	//       spec.volumes[*].glusterfs
	//       spec.volumes[*].rbd
	//       spec.volumes[*].flexVolume
	//       spec.volumes[*].cinder
	//       spec.volumes[*].cephfs
	//       spec.volumes[*].flocker
	//       spec.volumes[*].fc
	//       spec.volumes[*].azureFile
	//       spec.volumes[*].vsphereVolume
	//       spec.volumes[*].quobyte
	//       spec.volumes[*].azureDisk
	//       spec.volumes[*].portworxVolume
	//       spec.volumes[*].photonPersistentDisk
	//       spec.volumes[*].scaleIO
	//       spec.volumes[*].storageos
	//   allows:
	//     configMap
	//     downwardAPI
	//     emptyDir
	//     projected
	//     secret
	//     csi
	//     persistentVolumeClaim
	//     ephemeral
	// ------------------------------------
	// upstream: check_hostPathVolumes
	// baseline allows: undefined/null

	for _, v := range volumes {
		switch v {
		case securityv1.FSTypeAll,
			securityv1.FSTypeHostPath:
			return privileged
		case securityv1.FSTypeConfigMap,
			securityv1.FSTypeDownwardAPI,
			securityv1.FSTypeEmptyDir,
			securityv1.FSProjected,
			securityv1.FSTypeSecret,
			securityv1.FSTypeCSI,
			securityv1.FSTypePersistentVolumeClaim,
			securityv1.FSTypeEphemeral,
			securityv1.FSTypeNone:
			return restricted
		case securityv1.FSTypeAzureFile,
			securityv1.FSTypeAzureDisk,
			securityv1.FSTypeFlocker,
			securityv1.FSTypeFlexVolume,
			securityv1.FSTypeGCEPersistentDisk,
			securityv1.FSTypeAWSElasticBlockStore,
			securityv1.FSTypeGitRepo,
			securityv1.FSTypeNFS,
			securityv1.FSTypeISCSI,
			securityv1.FSTypeGlusterfs,
			securityv1.FSTypeRBD,
			securityv1.FSTypeCinder,
			securityv1.FSTypeCephFS,
			securityv1.FSTypeFC,
			securityv1.FSTypeVsphereVolume,
			securityv1.FSTypeQuobyte,
			securityv1.FSTypePhotonPersistentDisk,
			securityv1.FSPortworxVolume,
			securityv1.FSScaleIO,
			securityv1.FSStorageOS:
			return baseline
		default:
			panic(fmt.Errorf("unknown volume type: %s", v))
		}
	}

	// likely no volumes were configured -> defaults to none allowed
	return restricted
}

func convert_seLinuxOptions(opts *securityv1.SELinuxContextStrategyOptions) uint8 {
	// upstream: check_seLinuxOptions
	// baseline:
	//   allows:
	//     type: `selinux_allowed_types_1_0`
	//   requires:
	//     user: empty
	//     role: empty
	selinux_allowed_types_1_0 := sets.NewString("", "container_t", "container_init_t", "container_kvm_t")

	if opts.Type != securityv1.SELinuxStrategyMustRunAs {
		return privileged
	}

	if opts.SELinuxOptions == nil {
		return restricted
	}

	if !selinux_allowed_types_1_0.Has(opts.SELinuxOptions.Type) {
		return privileged
	}

	if len(opts.SELinuxOptions.User) > 0 {
		return privileged
	}

	if len(opts.SELinuxOptions.Role) > 0 {
		return privileged
	}

	return restricted
}
