/*
 * Virtualization detection implementation.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "virtual.h"
#include "utils.h"
#include "logger.h"
#include "paths.h"

/* Read a file and return 1 if it contains the given keyword substring. */
static int check_file_contains(const char *path, const char *keyword) {
    char buf[4096];
    int n = utils_read_file_string(path, buf, sizeof(buf));
    if (n != 0) return 0;
    return (strstr(buf, keyword) != NULL) ? 1 : 0;
}

/* Return 1 if the given path exists on the filesystem. */
static int file_exists(const char *path) {
    return utils_file_exists(path);
}

/* Cached output of "systemd-detect-virt" so the command is executed only
 * once. Mirrors the Go reference (virtualization.go): any non-empty output
 * is reported verbatim as the virtualization string (kvm, lxc, docker,
 * vmware, microsoft, xen, podman, ...). */
static char g_virt_sd_output[256] = {0};
static int g_virt_sd_cached = 0;

/* Returns 1 when systemd-detect-virt produced a non-empty result; the
 * trimmed output is written into out. */
static int virt_systemd_output(char *out, size_t out_len) {
    if (!g_virt_sd_cached) {
        int exit_code = 0;
        utils_exec_command("systemd-detect-virt 2>/dev/null",
                           g_virt_sd_output, sizeof(g_virt_sd_output), &exit_code);
        g_virt_sd_cached = 1;
    }
    char *p = g_virt_sd_output;
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    if (*p == '\0') return 0;
    snprintf(out, out_len, "%s", p);
    /* Trim trailing whitespace. */
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r' ||
                       out[len - 1] == ' ' || out[len - 1] == '\t')) {
        out[--len] = '\0';
    }
    return len > 0;
}

/* Mapping for systemd vendor strings that differ from the C constant set
 * (mirrors the Go hypervisor vendor mapping where applicable). */
static const char *virt_map_systemd_output(const char *raw) {
    if (strcmp(raw, "microsoft") == 0) return VIRT_TYPE_HYPERV;
    if (strcmp(raw, "oracle") == 0) return VIRT_TYPE_VIRTUALBOX;
    return raw; /* kvm/qemu/vmware/xen/lxc/docker/podman/... pass through */
}

static const char *virt_detect_once(void) {
    /* Container heuristics first (mirrors the Go detectContainer, keeping
     * the C openvz probe as a superset). */
    if (file_exists(KOMARI_PATH_DOCKER_ENV)) {
        KOMARI_LOG_DEBUG("Virtualization detected: docker (/.dockerenv exists)");
        return VIRT_TYPE_DOCKER;
    }

    if (check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "docker") ||
        check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "kubepods") ||
        check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "cri-containerd")) {
        KOMARI_LOG_DEBUG("Virtualization detected: docker (cgroup)");
        return VIRT_TYPE_DOCKER;
    }

    if (check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "libpod") ||
        check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "podman")) {
        KOMARI_LOG_DEBUG("Virtualization detected: podman (cgroup)");
        return "podman";
    }

    if (check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "kubepods") ||
        check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "k8s")) {
        KOMARI_LOG_DEBUG("Virtualization detected: kubernetes (cgroup)");
        return "kubernetes";
    }

    if (file_exists(KOMARI_PATH_CONTAINER_ENV)) {
        KOMARI_LOG_DEBUG("Virtualization detected: container (/run/.containerenv)");
        return "container";
    }

    if (check_file_contains(KOMARI_PATH_PROC_SELF_CGROUP, "lxc") ||
        file_exists("/dev/.lxc-boot-id")) {
        KOMARI_LOG_DEBUG("Virtualization detected: lxc");
        return VIRT_TYPE_LXC;
    }

    if (file_exists(KOMARI_PATH_PROC_VZ_VEINFO)) {
        KOMARI_LOG_DEBUG("Virtualization detected: openvz (C superset of the Go chain)");
        return VIRT_TYPE_OPENVZ;
    }

    /* systemd-detect-virt: report the raw output verbatim (trimmed), with
     * a small mapping for vendor names that differ from the C constants. */
    {
        char raw[256];
        if (virt_systemd_output(raw, sizeof(raw))) {
            const char *mapped = virt_map_systemd_output(raw);
            KOMARI_LOG_DEBUG("Virtualization detected via systemd-detect-virt: %s", mapped);
            return mapped;
        }
    }

    if (check_file_contains(KOMARI_PATH_PROC_CPUINFO, "QEMU") ||
        check_file_contains(KOMARI_PATH_PROC_CPUINFO, "KVM")) {
        KOMARI_LOG_DEBUG("Virtualization detected: kvm/qemu (/proc/cpuinfo)");
        return check_file_contains(KOMARI_PATH_PROC_CPUINFO, "QEMU") ? VIRT_TYPE_QEMU : VIRT_TYPE_KVM;
    }

    if (file_exists(KOMARI_PATH_SYS_DMI_PRODUCT_NAME)) {
        if (check_file_contains(KOMARI_PATH_SYS_DMI_PRODUCT_NAME, "VMware")) {
            KOMARI_LOG_DEBUG("Virtualization detected: vmware (DMI)");
            return VIRT_TYPE_VMWARE;
        }
        if (check_file_contains(KOMARI_PATH_SYS_DMI_PRODUCT_NAME, "VirtualBox")) {
            KOMARI_LOG_DEBUG("Virtualization detected: virtualbox (DMI)");
            return VIRT_TYPE_VIRTUALBOX;
        }
        if (check_file_contains(KOMARI_PATH_SYS_DMI_PRODUCT_NAME, "KVM")) {
            KOMARI_LOG_DEBUG("Virtualization detected: kvm (DMI)");
            return VIRT_TYPE_KVM;
        }
        if (check_file_contains(KOMARI_PATH_SYS_DMI_PRODUCT_NAME, "Parallels")) {
            KOMARI_LOG_DEBUG("Virtualization detected: parallels (DMI)");
            return "parallels";
        }
        if (check_file_contains(KOMARI_PATH_SYS_DMI_PRODUCT_NAME, "bhyve")) {
            KOMARI_LOG_DEBUG("Virtualization detected: bhyve (DMI)");
            return "bhyve";
        }
        if (check_file_contains(KOMARI_PATH_SYS_DMI_PRODUCT_NAME, "acrn")) {
            KOMARI_LOG_DEBUG("Virtualization detected: acrn (DMI)");
            return "acrn";
        }
    }

    KOMARI_LOG_DEBUG("No virtualization detected");
    return VIRT_TYPE_NONE;
}

/* Cached detection result so repeated calls (including virt_is_container /
 * virt_is_vm) do not re-run the full probe each time. */
static const char *g_virt_type = NULL;

const char *virt_detect(void) {
    if (g_virt_type) return g_virt_type;
    g_virt_type = virt_detect_once();
    return g_virt_type;
}

bool virt_is_container(void) {
    const char *type = virt_detect();
    return (strcmp(type, VIRT_TYPE_DOCKER) == 0 ||
            strcmp(type, VIRT_TYPE_LXC) == 0 ||
            strcmp(type, VIRT_TYPE_OPENVZ) == 0);
}

bool virt_is_vm(void) {
    const char *type = virt_detect();
    return (strcmp(type, VIRT_TYPE_KVM) == 0 ||
            strcmp(type, VIRT_TYPE_QEMU) == 0 ||
            strcmp(type, VIRT_TYPE_VMWARE) == 0 ||
            strcmp(type, VIRT_TYPE_VIRTUALBOX) == 0 ||
            strcmp(type, VIRT_TYPE_HYPERV) == 0 ||
            strcmp(type, VIRT_TYPE_XEN) == 0);
}
