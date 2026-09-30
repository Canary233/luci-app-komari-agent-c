/*
 * System monitoring data collection implementation.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <fnmatch.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <ctype.h>
#include <netdb.h>
#include <inttypes.h>

#include "monitoring.h"
#include "utils.h"
#include "config.h"
#include "logger.h"
#include "paths.h"

/* Cross-call CPU sampling state. Previously monitoring_get_cpu_info blocked
 * for 100ms on every call to measure a CPU usage delta inside the function.
 * Since report_thread already invokes this once per second, we instead sample
 * /proc/stat once per call and compute the delta against the previous call's
 * snapshot. This removes the 100ms blocking and lets the thread respond to
 * shutdown signals promptly. */
static unsigned long long g_last_cpu_total = 0;
static unsigned long long g_last_cpu_used = 0;
static int g_cpu_sample_initialized = 0;

/* Cached invariant CPU fields. cpu_name, cpu_cores and cpu_arch only change
 * on reboot or CPU hotplug; re-reading /proc/cpuinfo every second is pure
 * waste. Populate once on the first call. */
static cpu_info_t g_cpu_invariants;
static int g_cpu_physical_cores = 0; /* 0 until probed; 1 when /proc/cpuinfo lacks physical id */
static int g_cpu_invariants_cached = 0;

/* Tiered sampling caches. disk/connections/process_count change slowly and
 * require scanning multiple /proc files or all of /proc; refresh them every
 * MONITORING_SLOW_TTL seconds instead of every report cycle. */
#define MONITORING_SLOW_TTL_SEC 5
static disk_info_t g_disk_cache;
static conn_info_t g_conn_cache;
static int g_process_count_cache = 0;
static time_t g_disk_cache_ts = 0;
static time_t g_conn_cache_ts = 0;
static time_t g_process_count_ts = 0;

/* NIC / mount point filters. Configured via config_load_* (include_nics,
 * exclude_nics, include_mountpoints) through monitoring_set_nic_filters /
 * monitoring_set_mountpoint_filter and applied by the collection functions,
 * which do not receive agent_config_t. */
static char g_include_nics[MAX_NICS_LEN] = "";
static char g_exclude_nics[MAX_NICS_LEN] = "";
static char g_include_mountpoints[MAX_MOUNTPOINTS_LEN] = "";

/* Check whether `name` appears in a comma-separated list, ignoring
 * surrounding whitespace around entries. Entries may contain shell-style
 * wildcards (*, ?, [...]) resolved with fnmatch, mirroring the Go
 * filepath.Match based filter (net.go shouldInclude). */
static int name_in_list(const char *list, const char *name) {
    if (!list || !*list || !name || !*name) return 0;
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        while (len > 0 && start[len - 1] == ' ') len--;
        char pattern[128];
        if (len >= sizeof(pattern)) len = sizeof(pattern) - 1;
        memcpy(pattern, start, len);
        pattern[len] = '\0';
        if (fnmatch(pattern, name, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Virtual-interface prefix blacklist, mirroring the Go reference
 * (net.go loopbackNames): br-, cni/docker/podman/flannel bridges, veth
 * pairs, libvirt/KVM virbr, Proxmox vmbr, tap and firewall chaining
 * interfaces. lo* matches via the "lo" prefix. */
static const char *const NIC_EXCLUDE_PREFIXES[] = {
    "br", "cni", "docker", "podman", "flannel", "lo",
    "veth", "virbr", "vmbr", "tap", "fwbr", "fwpr",
};
#define NIC_EXCLUDE_PREFIXES_COUNT \
    (int)(sizeof(NIC_EXCLUDE_PREFIXES) / sizeof(NIC_EXCLUDE_PREFIXES[0]))

/* Decide whether a NIC participates in traffic statistics, applying the
 * same precedence as the Go reference: blacklist first, then include
 * (which wins over exclude), then exclude, then "include empty = all". */
static int nic_should_include(const char *name) {
    if (!name || !*name) return 0;
    for (int i = 0; i < NIC_EXCLUDE_PREFIXES_COUNT; i++) {
        size_t plen = strlen(NIC_EXCLUDE_PREFIXES[i]);
        if (strncmp(name, NIC_EXCLUDE_PREFIXES[i], plen) == 0) {
            return 0;
        }
    }
    if (g_include_nics[0] != '\0') {
        return name_in_list(g_include_nics, name);
    }
    if (g_exclude_nics[0] != '\0' && name_in_list(g_exclude_nics, name)) {
        return 0;
    }
    return 1;
}

void monitoring_set_nic_filters(const char *include, const char *exclude) {
    utils_set_string(g_include_nics, sizeof(g_include_nics), include);
    utils_set_string(g_exclude_nics, sizeof(g_exclude_nics), exclude);
}

void monitoring_set_mountpoint_filter(const char *include) {
    utils_set_string(g_include_mountpoints, sizeof(g_include_mountpoints), include);
}

/* Optional host /proc mountpoint (HOST_PROC). Empty by default. */
static char g_host_proc[256] = "";

void monitoring_set_host_proc(const char *path) {
    utils_set_string(g_host_proc, sizeof(g_host_proc), path);
}

const char *monitoring_get_host_proc(void) {
    return g_host_proc;
}

int monitoring_list_interfaces(char ifaces[][32], int max) {
    if (!ifaces || max <= 0) return -1;

    FILE *fp = fopen(KOMARI_PATH_PROC_NET_DEV, "r");
    if (!fp) return -1;

    char line[512];
    int count = 0;

    if (!fgets(line, sizeof(line), fp) || !fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && count < max) {
        char iface[32];
        uint64_t rx_bytes, tx_bytes;
        if (sscanf(line, "%31[^:]: %" SCNu64 " %" SCNu64,
                   iface, &rx_bytes, &tx_bytes) >= 1) {
            char *p = iface;
            while (*p == ' ') p++;
            if (!nic_should_include(p)) continue;
            strncpy(ifaces[count], p, 31);
            ifaces[count][31] = '\0';
            count++;
        }
    }
    fclose(fp);
    return count;
}

void monitoring_net_speed_update(monitoring_net_state_t *state) {
    net_info_t info;
    monitoring_get_net_info(state, &info);
}

int monitoring_net_state_init(monitoring_net_state_t *state) {
    if (!state) return -1;
    memset(state, 0, sizeof(*state));
    if (pthread_mutex_init(&state->mutex, NULL) != 0) {
        return -1;
    }
    state->mutex_inited = true;
    state->has_prev_sample = false;
    return 0;
}

void monitoring_net_state_cleanup(monitoring_net_state_t *state) {
    if (!state) return;
    if (state->mutex_inited) {
        pthread_mutex_destroy(&state->mutex);
        state->mutex_inited = false;
    }
}

int monitoring_get_cpu_info(cpu_info_t *info) {
    if (!info) return -1;

    memset(info, 0, sizeof(cpu_info_t));

    /* Populate invariant fields (cpu_cores, cpu_arch, cpu_name) from cache
     * on subsequent calls; refresh from /proc/cpuinfo only on the first
     * call. These fields do not change at runtime. */
    if (!g_cpu_invariants_cached) {
        g_cpu_invariants.cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (g_cpu_invariants.cpu_cores <= 0) g_cpu_invariants.cpu_cores = 1;

        /* Count physical cores as unique (physical id, core id) pairs in
         * /proc/cpuinfo, mirroring gopsutil cpu.Counts(false). ARM SoCs and
         * older kernels may omit these fields; fall back to the logical
         * count (matching the Go behavior when the pairing is unknown). */
        {
            FILE *pf = fopen(KOMARI_PATH_PROC_CPUINFO, "r");
            if (pf) {
                char pline[256];
                int have_ids = 0;
                long phys = -1, core = -1;
                /* Small fixed-size registry: SMP systems rarely exceed this
                 * many unique pairs; a linear scan over the table keeps the
                 * code allocation-free. */
                enum { MAX_PHYS = 512 };
                static long seen[MAX_PHYS][2];
                int seen_n = 0;
                while (fgets(pline, sizeof(pline), pf)) {
                    if (strncmp(pline, "physical id", 11) == 0) {
                        const char *colon = strchr(pline, ':');
                        if (colon) phys = strtol(colon + 1, NULL, 10), have_ids |= 1;
                    } else if (strncmp(pline, "core id", 7) == 0) {
                        const char *colon = strchr(pline, ':');
                        if (colon) core = strtol(colon + 1, NULL, 10), have_ids |= 2;
                    } else if (strncmp(pline, "processor", 9) == 0) {
                        /* A new logical CPU starts: flush the pending pair. */
                        if (have_ids == 3 && seen_n < MAX_PHYS) {
                            int dup = 0;
                            for (int k = 0; k < seen_n; k++) {
                                if (seen[k][0] == phys && seen[k][1] == core) { dup = 1; break; }
                            }
                            if (!dup) { seen[seen_n][0] = phys; seen[seen_n][1] = core; seen_n++; }
                        }
                        have_ids = 0;
                        phys = -1;
                        core = -1;
                    }
                }
                /* Flush the final processor block (no trailing entry). */
                if (have_ids == 3 && seen_n < MAX_PHYS) {
                    int dup = 0;
                    for (int k = 0; k < seen_n; k++) {
                        if (seen[k][0] == phys && seen[k][1] == core) { dup = 1; break; }
                    }
                    if (!dup) { seen[seen_n][0] = phys; seen[seen_n][1] = core; seen_n++; }
                }
                fclose(pf);
                g_cpu_physical_cores = (seen_n > 0) ? seen_n : g_cpu_invariants.cpu_cores;
            } else {
                g_cpu_physical_cores = g_cpu_invariants.cpu_cores;
            }
        }

#if defined(__aarch64__)
        strcpy(g_cpu_invariants.cpu_arch, "arm64");
#elif defined(__arm__)
        strcpy(g_cpu_invariants.cpu_arch, "arm");
#elif defined(__x86_64__)
        strcpy(g_cpu_invariants.cpu_arch, "x86_64");
#elif defined(__i386__)
        strcpy(g_cpu_invariants.cpu_arch, "i386");
#else
        strcpy(g_cpu_invariants.cpu_arch, "unknown");
#endif

        FILE *fp = fopen(KOMARI_PATH_PROC_CPUINFO, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "model name", 10) == 0 ||
                    strncmp(line, "Model", 5) == 0 ||
                    strncmp(line, "cpu model", 9) == 0) {
                    char *colon = strchr(line, ':');
                    if (colon) {
                        colon++;
                        while (*colon == ' ') colon++;
                        char *nl = strchr(colon, '\n');
                        if (nl) *nl = '\0';
                        strncpy(g_cpu_invariants.cpu_name, colon, sizeof(g_cpu_invariants.cpu_name) - 1);
                        /* Explicit NUL termination in case source fills the buffer. */
                        g_cpu_invariants.cpu_name[sizeof(g_cpu_invariants.cpu_name) - 1] = '\0';
                    }
                    break;
                }
            }
            fclose(fp);
        }

        if (g_cpu_invariants.cpu_name[0] == '\0') {
            strcpy(g_cpu_invariants.cpu_name, "Unknown CPU");
        }
        g_cpu_invariants_cached = 1;
    }

    info->cpu_cores = g_cpu_invariants.cpu_cores;
    info->cpu_physical_cores = g_cpu_physical_cores;
    strncpy(info->cpu_arch, g_cpu_invariants.cpu_arch, sizeof(info->cpu_arch) - 1);
    info->cpu_arch[sizeof(info->cpu_arch) - 1] = '\0';
    strncpy(info->cpu_name, g_cpu_invariants.cpu_name, sizeof(info->cpu_name) - 1);
    info->cpu_name[sizeof(info->cpu_name) - 1] = '\0';

    /* Sample /proc/stat once and compute CPU usage against the previous
     * call's snapshot, instead of blocking for 100ms inside this function.
     * The first call has no baseline and reports 0.0% usage. */
    FILE *stat_fp = fopen(KOMARI_PATH_PROC_STAT, "r");
    if (stat_fp) {
        unsigned long long user, nice, system, idle, iowait, irq, softirq, steal = 0;
        if (fscanf(stat_fp, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &user, &nice, &system, &idle, &iowait, &irq, &softirq,
                   &steal) >= 7) {
            /* Include steal in the total: on virtualized hosts the
             * hypervisor's steal time is real elapsed CPU time that appears
             * in no guest-side column, and omitting it inflated the computed
             * usage. guest/guest_nice are already counted inside user/nice
             * by the kernel, so they stay out of the sum. On kernels that
             * only expose 7 columns, fscanf leaves steal at 0. */
            unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal;
            unsigned long long used = user + nice + system + irq + softirq;

            if (g_cpu_sample_initialized) {
                /* Guard against counter wraparound or reset to avoid a
                 * bogus spike when /proc/stat counters go backwards. */
                unsigned long long total_diff = (total >= g_last_cpu_total) ? (total - g_last_cpu_total) : 0;
                unsigned long long used_diff = (used >= g_last_cpu_used) ? (used - g_last_cpu_used) : 0;

                if (total_diff > 0) {
                    info->cpu_usage = (double)used_diff / (double)total_diff * 100.0;
                }
            }

            g_last_cpu_total = total;
            g_last_cpu_used = used;
            g_cpu_sample_initialized = 1;
        }
        fclose(stat_fp);
    }

    return 0;
}

int monitoring_get_mem_swap_info(bool memory_include_cache, mem_info_t *mem, mem_info_t *swap) {
    /* Parse /proc/meminfo once for both memory and swap fields. Previously
     * monitoring_get_mem_info and monitoring_get_swap_info each opened and
     * parsed the file independently, doubling the per-cycle
     * fopen/fgets/sscanf cost. Either output pointer may be NULL to skip
     * that portion. */
    if (!mem && !swap) return -1;

    if (mem) memset(mem, 0, sizeof(mem_info_t));
    if (swap) memset(swap, 0, sizeof(mem_info_t));

    FILE *fp = fopen(KOMARI_PATH_PROC_MEMINFO, "r");
    if (!fp) return -1;

    char line[256];
    /* Accumulate in 64-bit: on 32-bit targets `value * 1024` overflows for
     * memories >= 4 GiB (and the sums below can overflow too). */
    uint64_t mem_total = 0, mem_free = 0, mem_available = 0;
    uint64_t buffers = 0, cached = 0, shmem = 0, sreclaimable = 0;
    uint64_t swap_total = 0, swap_free = 0, swap_cached = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long value;
        char key[64];

        if (sscanf(line, "%63[^:]: %lu", key, &value) == 2) {
            if (strcmp(key, "MemTotal") == 0) {
                mem_total = (uint64_t)value * 1024;
            } else if (strcmp(key, "MemFree") == 0) {
                mem_free = (uint64_t)value * 1024;
            } else if (strcmp(key, "MemAvailable") == 0) {
                mem_available = (uint64_t)value * 1024;
            } else if (strcmp(key, "Buffers") == 0) {
                buffers = (uint64_t)value * 1024;
            } else if (strcmp(key, "Cached") == 0) {
                cached = (uint64_t)value * 1024;
            } else if (strcmp(key, "Shmem") == 0) {
                shmem = (uint64_t)value * 1024;
            } else if (strcmp(key, "SReclaimable") == 0) {
                sreclaimable = (uint64_t)value * 1024;
            } else if (strcmp(key, "SwapTotal") == 0) {
                swap_total = (uint64_t)value * 1024;
            } else if (strcmp(key, "SwapFree") == 0) {
                swap_free = (uint64_t)value * 1024;
            } else if (strcmp(key, "SwapCached") == 0) {
                swap_cached = (uint64_t)value * 1024;
            }
        }
    }
    fclose(fp);

    if (mem) {
        mem->total = mem_total;
        mem->free = mem_free;
        mem->available = mem_available;
        mem->buffers = buffers;
        mem->cached = cached + sreclaimable;

        if (memory_include_cache) {
            /* Go mem.go memory_include_cache mode: used = total - free,
             * counting buff/cache as used. */
            mem->used = mem_total - mem_free;
        } else {
            /* Default mode mirrors the Go htop-like calculation
             * (mem.go GetMemHtopLike): used = total - (free + cached +
             * sreclaimable + buffers) + shmem, with an underflow guard that
             * falls back to total - free. memory_report_raw_used selects
             * the same formula on Linux (the Go flag only forces the htop
             * path on non-Linux or when /proc is unreadable), so no extra
             * branch is needed here. */
            uint64_t used_diff = mem_free + cached + sreclaimable + buffers;
            uint64_t used = (mem_total >= used_diff)
                                     ? mem_total - used_diff
                                     : mem_total - mem_free;
            mem->used = used + shmem;
        }
    }

    if (swap) {
        swap->total = swap_total;
        swap->free = swap_free;
        /* Go mem.go Swap(): used = total - free - SwapCached with an
         * underflow guard falling back to total - free. */
        uint64_t deductions = swap_free + swap_cached;
        swap->used = (swap_total >= deductions) ? swap_total - deductions
                                                : swap_total - swap_free;
    }

    return 0;
}

int monitoring_get_mem_info(bool memory_include_cache, mem_info_t *info) {
    /* Thin wrapper for backward compatibility; delegates to the combined
     * parser so /proc/meminfo is read once per cycle when callers invoke
     * monitoring_get_mem_info and monitoring_get_swap_info back-to-back. */
    return monitoring_get_mem_swap_info(memory_include_cache, info, NULL);
}

int monitoring_get_swap_info(bool memory_include_cache, mem_info_t *info) {
    return monitoring_get_mem_swap_info(memory_include_cache, NULL, info);
}

/* Mount-point prefix blacklist, mirroring the Go reference
 * (disk.go isPhysicalDisk). Compared case-insensitively; entries match
 * exactly or as a directory prefix. */
static const char *const MOUNTPOINT_EXCLUDE_PREFIXES[] = {
    "/tmp", "/var/tmp", "/dev", "/run", "/var/lib/containers",
    "/var/lib/docker", "/proc", "/sys", "/sys/fs/cgroup",
    "/etc/resolv.conf", "/etc/hosts", "/etc/hostname", "/nix/store",
};
#define MOUNTPOINT_EXCLUDE_PREFIXES_COUNT \
    (int)(sizeof(MOUNTPOINT_EXCLUDE_PREFIXES) / sizeof(MOUNTPOINT_EXCLUDE_PREFIXES[0]))

/* Filesystem-type blacklist (disk.go). Compared case-insensitively, exact
 * match or prefix. overlay is included in the Go blacklist; the OpenWrt
 * root filesystem survives through the "/" always-include rule below. */
static const char *const FSTYPE_EXCLUDE_PREFIXES[] = {
    "tmpfs", "devtmpfs", "udev", "nfs", "cifs", "smb", "vboxsf", "9p",
    "fuse", "overlay", "proc", "devpts", "sysfs", "cgroup", "mqueue",
    "hugetlbfs", "debugfs", "binfmt_misc", "securityfs", "tracefs",
    "pstore", "squashfs",
};
#define FSTYPE_EXCLUDE_PREFIXES_COUNT \
    (int)(sizeof(FSTYPE_EXCLUDE_PREFIXES) / sizeof(FSTYPE_EXCLUDE_PREFIXES[0]))

static int str_in_blacklist(const char *value, const char *const *list, int count) {
    for (int i = 0; i < count; i++) {
        size_t plen = strlen(list[i]);
        if (strncasecmp(value, list[i], plen) == 0) {
            /* Prefix lists contain both plain names ("/tmp") and directory
             * names; require the value to match fully or continue with a
             * path separator so "/temporary" does not hit "/tmp". */
            if (value[plen] == '\0' || value[plen] == '/' ||
                list[i][plen - 1] == '/') {
                return 1;
            }
        }
    }
    return 0;
}

/* Check whether a mountpoint appears in the include filter list. Accepts
 * ';'-separated lists (Go include_mountpoints format) and ','-separated
 * lists (legacy C format); entries may carry wildcards via fnmatch. */
static int mountpoint_in_filter(const char *mountpoint) {
    const char *sep = strchr(g_include_mountpoints, ';');
    const char *list = g_include_mountpoints;
    char buf[MAX_MOUNTPOINTS_LEN];
    (void)sep;
    /* Normalize: treat both separators by scanning manually. */
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == ',' || *p == ';') p++;
        const char *start = p;
        while (*p && *p != ',' && *p != ';') p++;
        size_t len = (size_t)(p - start);
        while (len > 0 && start[len - 1] == ' ') len--;
        if (len == 0) continue;
        char pattern[256];
        if (len >= sizeof(pattern)) len = sizeof(pattern) - 1;
        memcpy(pattern, start, len);
        pattern[len] = '\0';
        if (fnmatch(pattern, mountpoint, 0) == 0 ||
            strncmp(pattern, mountpoint, len) == 0) {
            (void)buf;
            return 1;
        }
    }
    return 0;
}

/* Decide whether a /proc/mounts entry counts as a physical disk, mirroring
 * the Go isPhysicalDisk rules. */
static int is_physical_mount(const char *device, const char *mountpoint,
                             const char *fstype, const char *opts) {
    /* Rule 1: "/" is always included (keeps the OpenWrt overlay root). */
    if (strcmp(mountpoint, "/") == 0) return 1;

    /* Rule 2: mountpoint prefix blacklist. */
    if (str_in_blacklist(mountpoint, MOUNTPOINT_EXCLUDE_PREFIXES,
                         MOUNTPOINT_EXCLUDE_PREFIXES_COUNT)) {
        return 0;
    }

    /* Rule 3: autofs without a /dev/ device is excluded. */
    if (strcmp(fstype, "autofs") == 0 && strncmp(device, "/dev/", 5) != 0) {
        return 0;
    }

    /* Rule 4: fuseblk (ntfs-3g) is always kept. */
    if (strcmp(fstype, "fuseblk") == 0) return 1;

    /* Rule 5: fstype blacklist. */
    if (str_in_blacklist(fstype, FSTYPE_EXCLUDE_PREFIXES,
                         FSTYPE_EXCLUDE_PREFIXES_COUNT)) {
        return 0;
    }

    /* Rule 6: network mounts carry "remote"/"network" in opts (mainly
     * Windows; cheap to honour on Linux). */
    if (opts && (strcasestr(opts, "remote") != NULL ||
                 strcasestr(opts, "network") != NULL)) {
        return 0;
    }

    /* Rule 7: loop devices are excluded. */
    if (strncmp(device, "/dev/loop", 9) == 0) return 0;

    return 1;
}

int monitoring_get_disk_info(disk_info_t *info) {
    if (!info) return -1;

    /* Serve cached result if fresh, to avoid scanning /proc/mounts and
     * statvfs on every mount point every report cycle. */
    time_t now = time(NULL);
    if (g_disk_cache_ts != 0 && now - g_disk_cache_ts < MONITORING_SLOW_TTL_SEC) {
        *info = g_disk_cache;
        return 0;
    }

    memset(info, 0, sizeof(disk_info_t));

    FILE *fp = fopen(KOMARI_PATH_PROC_MOUNTS, "r");
    if (!fp) return -1;

    /* When an explicit mountpoint filter is configured, only those
     * mountpoints are measured (skipping physical-disk filtering and device
     * dedup entirely), mirroring disk.go. The list accepts ';' (Go format)
     * and ',' (legacy C format). */
    int filter_mode = (g_include_mountpoints[0] != '\0');

    /* Device dedup table: the same device mounted at multiple locations
     * (bind mounts, quota remounts) must be counted once, keeping the entry
     * with the larger total. ZFS devices are deduped by pool name (the part
     * before the first '/'). Mirrors disk.go. */
    enum { MAX_TRACKED = 256 };
    struct {
        char device[128];
        uint64_t total;
        uint64_t free;
    } seen[MAX_TRACKED];
    int seen_n = 0;

    char line[512];
    char device[256], mountpoint[256], fstype[64], opts[256];

    while (fgets(line, sizeof(line), fp)) {
        /* Clear opts each line: sscanf only fills it when the mount-options
         * field is present, and is_physical_mount() would otherwise read a
         * stale value (or uninitialized memory on the first short line). */
        opts[0] = '\0';
        if (sscanf(line, "%255s %255s %63s %255s", device, mountpoint,
                   fstype, opts) < 3) {
            continue;
        }

        /* Filter mode: measure only listed mountpoints. */
        if (filter_mode) {
            if (!mountpoint_in_filter(mountpoint)) continue;
        } else if (!is_physical_mount(device, mountpoint, fstype, opts)) {
            continue;
        }

        struct statvfs st;
        if (statvfs(mountpoint, &st) != 0) continue;

        /* Cast to uint64_t before multiplication to avoid 32-bit overflow
         * and clamp on uint64_t overflow (MIN-27/28). */
        uint64_t frsize = (uint64_t)st.f_frsize;
        uint64_t blocks = (uint64_t)st.f_blocks;
        uint64_t bfree  = (uint64_t)st.f_bfree;

        uint64_t total = (frsize != 0 && blocks > UINT64_MAX / frsize)
                         ? UINT64_MAX : blocks * frsize;
        uint64_t free_b = (frsize != 0 && bfree  > UINT64_MAX / frsize)
                          ? UINT64_MAX : bfree  * frsize;

        if (filter_mode) {
            /* No dedup in filter mode, matching the Go behavior. */
            if (total > UINT64_MAX - info->total) info->total = UINT64_MAX;
            else info->total += total;
            if (free_b > UINT64_MAX - info->free) info->free = UINT64_MAX;
            else info->free += free_b;
            continue;
        }

        /* Dedup key: ZFS pools dedupe by pool name, everything else by
         * device path. */
        char key[128];
        if (strcmp(fstype, "zfs") == 0) {
            const char *slash = strchr(device, '/');
            size_t klen = slash ? (size_t)(slash - device) : strlen(device);
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, device, klen);
            key[klen] = '\0';
        } else {
            snprintf(key, sizeof(key), "%s", device);
        }

        int idx = -1;
        for (int i = 0; i < seen_n; i++) {
            if (strcmp(seen[i].device, key) == 0) { idx = i; break; }
        }
        if (idx < 0 && seen_n < MAX_TRACKED) {
            snprintf(seen[seen_n].device, sizeof(seen[seen_n].device), "%s", key);
            seen[seen_n].total = total;
            seen[seen_n].free = free_b;
            seen_n++;
        } else if (idx >= 0 && total > seen[idx].total) {
            /* Same device mounted again: keep the larger total entry. */
            seen[idx].total = total;
            seen[idx].free = free_b;
        }
    }
    fclose(fp);

    if (!filter_mode) {
        for (int i = 0; i < seen_n; i++) {
            if (seen[i].total > UINT64_MAX - info->total) info->total = UINT64_MAX;
            else info->total += seen[i].total;
            if (seen[i].free > UINT64_MAX - info->free) info->free = UINT64_MAX;
            else info->free += seen[i].free;
        }
    }

    /* Guard against unsigned underflow: in abnormal filesystem states (e.g.
     * statvfs returning f_bfree > f_blocks, or aggregated mounts where free
     * exceeds total), info->free could be larger than info->total, which
     * would wrap to ~UINT64_MAX and report a nonsensical ~16 EB usage. */
    info->used = (info->free > info->total) ? 0 : (info->total - info->free);

    /* Update cache so subsequent calls within the TTL skip the scan. */
    g_disk_cache = *info;
    g_disk_cache_ts = now;

    return 0;
}

int monitoring_get_net_info(monitoring_net_state_t *state, net_info_t *info) {
    if (!info) return -1;

    memset(info, 0, sizeof(net_info_t));

    FILE *fp = fopen(KOMARI_PATH_PROC_NET_DEV, "r");
    if (!fp) return -1;

    char line[512];
    uint64_t total_rx = 0, total_tx = 0;
    uint64_t total_rx_packets = 0, total_tx_packets = 0;

    /* /proc/net/dev starts with two header lines. Check fgets return values
     * so an empty or unreadable file (e.g. /proc not mounted) is reported as
     * an error rather than silently returning zero statistics. */
    if (!fgets(line, sizeof(line), fp) || !fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        uint64_t rx_bytes, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast;
        uint64_t tx_bytes, tx_packets, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed;

        if (sscanf(line, "%31[^:]: %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                   " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                   " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                   " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                   iface, &rx_bytes, &rx_packets, &rx_errs, &rx_drop, &rx_fifo, &rx_frame,
                   &rx_compressed, &rx_multicast, &tx_bytes, &tx_packets, &tx_errs, &tx_drop,
                   &tx_fifo, &tx_colls, &tx_carrier, &tx_compressed) >= 10) {

            char *p = iface;
            while (*p == ' ') p++;

            /* Blacklist + include/exclude filters (see nic_should_include). */
            if (!nic_should_include(p)) continue;

            total_rx += rx_bytes;
            total_tx += tx_bytes;
            total_rx_packets += rx_packets;
            total_tx_packets += tx_packets;
        }
    }
    fclose(fp);

    info->rx_bytes = total_rx;
    info->tx_bytes = total_tx;
    info->rx_packets = total_rx_packets;
    info->tx_packets = total_tx_packets;

    /* Compute per-second speed from the delta against the previous sample.
     * When state is NULL the caller opts out of rate tracking (speed stays 0). */
    if (state) {
        pthread_mutex_lock(&state->mutex);
        uint64_t now = utils_get_current_timestamp();
        if (state->has_prev_sample) {
            uint64_t time_diff = now - state->last_time;
            if (time_diff > 0) {
                /* Guard against counter wraparound or reset to avoid underflow */
                uint64_t rx_diff = (total_rx >= state->last_rx) ? (total_rx - state->last_rx) : 0;
                uint64_t tx_diff = (total_tx >= state->last_tx) ? (total_tx - state->last_tx) : 0;
                /* Use floating-point division and round to nearest to avoid
                   integer truncation that systematically under-reports the
                   transfer rate (MIN-29/30). */
                info->rx_speed = (uint64_t)((double)rx_diff / (double)time_diff + 0.5);
                info->tx_speed = (uint64_t)((double)tx_diff / (double)time_diff + 0.5);
            }
        }

        state->last_rx = total_rx;
        state->last_tx = total_tx;
        state->last_time = now;
        state->has_prev_sample = true;
        pthread_mutex_unlock(&state->mutex);
    }

    return 0;
}

int monitoring_get_load_info(load_info_t *info) {
    if (!info) return -1;
    
    memset(info, 0, sizeof(load_info_t));
    
    FILE *fp = fopen(KOMARI_PATH_PROC_LOADAVG, "r");
    if (!fp) return -1;
    
    double load1, load5, load15;
    if (fscanf(fp, "%lf %lf %lf", &load1, &load5, &load15) == 3) {
        info->load1 = load1;
        info->load5 = load5;
        info->load15 = load15;
    }
    fclose(fp);
    
    return 0;
}

int monitoring_get_conn_info(conn_info_t *info) {
    if (!info) return -1;

    /* Serve cached result if fresh, to avoid opening 4 /proc/net/* files
     * and counting lines on every report cycle. */
    time_t now = time(NULL);
    if (g_conn_cache_ts != 0 && now - g_conn_cache_ts < MONITORING_SLOW_TTL_SEC) {
        *info = g_conn_cache;
        return 0;
    }

    memset(info, 0, sizeof(conn_info_t));

    FILE *fp = fopen(KOMARI_PATH_PROC_NET_TCP, "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            info->tcp_count++;
        }
        fclose(fp);
    }

    fp = fopen(KOMARI_PATH_PROC_NET_TCP6, "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            info->tcp_count++;
        }
        fclose(fp);
    }

    fp = fopen(KOMARI_PATH_PROC_NET_UDP, "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            info->udp_count++;
        }
        fclose(fp);
    }

    fp = fopen(KOMARI_PATH_PROC_NET_UDP6, "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            info->udp_count++;
        }
        fclose(fp);
    }

    /* Update cache. */
    g_conn_cache = *info;
    g_conn_cache_ts = now;

    return 0;
}

int monitoring_get_system_info(system_info_t *info) {
    if (!info) return -1;
    
    memset(info, 0, sizeof(system_info_t));
    
    /* OS name resolution order, mirroring the Go reference os_linux.go:
     * /etc/os-release PRETTY_NAME (generic Linux) first, then the OpenWrt
     * specific /etc/openwrt_release, then a bare "OpenWrt" fallback. */
    FILE *fp = fopen("/etc/os-release", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *eq = line + 12;
                while (*eq == '\'' || *eq == '"') eq++;
                char *end = eq + strlen(eq) - 1;
                while (end > eq && (*end == '\'' || *end == '"' || *end == '\n')) {
                    *end = '\0';
                    end--;
                }
                strncpy(info->os_name, eq, sizeof(info->os_name) - 1);
                info->os_name[sizeof(info->os_name) - 1] = '\0';
                break;
            }
        }
        fclose(fp);
    }

    if (info->os_name[0] == '\0') {
        fp = fopen("/etc/openwrt_release", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "DISTRIB_DESCRIPTION", 19) == 0) {
                    char *eq = strchr(line, '=');
                    if (eq) {
                        eq++;
                        while (*eq == '\'' || *eq == '"') eq++;
                        char *end = eq + strlen(eq) - 1;
                        while (end > eq && (*end == '\'' || *end == '"' || *end == '\n')) {
                            *end = '\0';
                            end--;
                        }
                        strncpy(info->os_name, eq, sizeof(info->os_name) - 1);
                        info->os_name[sizeof(info->os_name) - 1] = '\0';
                    }
                    break;
                }
            }
            fclose(fp);
        }
    }

    if (info->os_name[0] == '\0') {
        strcpy(info->os_name, "OpenWrt");
    }
    
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(info->kernel_version, uts.release, sizeof(info->kernel_version) - 1);
        /* Explicit NUL termination in case source fills the buffer. */
        info->kernel_version[sizeof(info->kernel_version) - 1] = '\0';
        strncpy(info->arch, uts.machine, sizeof(info->arch) - 1);
        info->arch[sizeof(info->arch) - 1] = '\0';
        strncpy(info->hostname, uts.nodename, sizeof(info->hostname) - 1);
        info->hostname[sizeof(info->hostname) - 1] = '\0';
    }
    
    info->uptime = monitoring_get_uptime();
    
    return 0;
}

uint64_t monitoring_get_uptime(void) {
    /* Delegate to utils_get_uptime_seconds to avoid duplicating the
     * /proc/uptime parsing logic. Both functions historically had identical
     * implementations; keeping a single source of truth makes future
     * changes (e.g. a fallback to /sys/class/rtc) apply everywhere. */
    return utils_get_uptime_seconds();
}

int monitoring_get_process_count(void) {
    /* Serve cached result if fresh, to avoid a full /proc readdir scan on
     * every report cycle. On busy systems /proc can have thousands of
     * entries. */
    time_t now = time(NULL);
    if (g_process_count_ts != 0 && now - g_process_count_ts < MONITORING_SLOW_TTL_SEC) {
        return g_process_count_cache;
    }

    /* Container environments may expose the host's /proc at a different
     * location (HOST_PROC env / host_proc config), mirroring the Go
     * gopsutil HostProc override. */
    const char *proc_root = KOMARI_PATH_PROC;
    {
        const char *host_proc = monitoring_get_host_proc();
        if (host_proc && host_proc[0] != '\0') {
            proc_root = host_proc;
        }
    }

    int count = 0;
    DIR *dir = opendir(proc_root);
    if (!dir) return g_process_count_cache;  /* fall back to last known value */

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            int is_pid = 1;
            for (int i = 0; entry->d_name[i]; i++) {
                if (!isdigit(entry->d_name[i])) {
                    is_pid = 0;
                    break;
                }
            }
            if (is_pid && entry->d_name[0] != '\0') {
                count++;
            }
        }
    }
    closedir(dir);

    g_process_count_cache = count;
    g_process_count_ts = now;

    return count;
}

int monitoring_get_ip_address(char *ipv4, size_t ipv4_len,
                               char *ipv6, size_t ipv6_len) {
    if (ipv4) ipv4[0] = '\0';
    if (ipv6) ipv6[0] = '\0';
    
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        if (strncmp(ifa->ifa_name, "docker", 6) == 0) continue;
        if (strncmp(ifa->ifa_name, "veth", 4) == 0) continue;
        if (strncmp(ifa->ifa_name, "br-", 3) == 0) continue;
        
        int family = ifa->ifa_addr->sa_family;
        
        if (family == AF_INET && ipv4 && ipv4_len > 0 && ipv4[0] == '\0') {
            char host[NI_MAXHOST];
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                           host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                strncpy(ipv4, host, ipv4_len - 1);
                /* Explicit NUL termination in case source fills the buffer. */
                ipv4[ipv4_len - 1] = '\0';
            }
        } else if (family == AF_INET6 && ipv6 && ipv6_len > 0 && ipv6[0] == '\0') {
            char host[NI_MAXHOST];
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            if (!IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                               host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                    strncpy(ipv6, host, ipv6_len - 1);
                    ipv6[ipv6_len - 1] = '\0';
                }
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return 0;
}
