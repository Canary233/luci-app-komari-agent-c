/*
 * Public IP address detection via external echo services, mirroring the Go
 * reference monitoring/unit/ip.go.
 *
 * Resolution order (GetIPAddress):
 *   1. NIC addresses when get_ip_addr_from_nic is set (first IPv4 and first
 *      global IPv6 from filtered interfaces).
 *   2. Configured custom_ipv4 / custom_ipv6 overrides.
 *   3. External detection APIs (IPv4 list then IPv6 list), each forced over
 *      its own address family with a 15-second timeout.
 *
 * Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
 * Licensed under MIT License
 */

#ifndef KOMARI_AGENT_C_IP_DETECT_H
#define KOMARI_AGENT_C_IP_DETECT_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Detect the public IPv4 and IPv6 addresses for this host.
 *
 * @param get_from_nic   Try the local interfaces first (true) or skip
 *                       straight to custom/WebAPI sources (false)
 * @param custom_ipv4    User-configured IPv4 override (may be NULL/empty)
 * @param custom_ipv6    User-configured IPv6 override (may be NULL/empty)
 * @param ipv4_out       Output buffer for the detected IPv4 ("" when unknown)
 * @param ipv4_len       Size of ipv4_out
 * @param ipv6_out       Output buffer for the detected IPv6 ("" when unknown)
 * @param ipv6_len       Size of ipv6_out
 */
void ip_detect_public(bool get_from_nic, const char *custom_ipv4,
                      const char *custom_ipv6,
                      char *ipv4_out, size_t ipv4_len,
                      char *ipv6_out, size_t ipv6_len);

/**
 * Detect only the IPv4 address (helper for tests/partial use).
 *
 * @return 0 when an address was found, -1 otherwise
 */
int ip_detect_ipv4_api(char *out, size_t out_len);

/**
 * Detect only the IPv6 address (helper for tests/partial use).
 *
 * @return 0 when an address was found, -1 otherwise
 */
int ip_detect_ipv6_api(char *out, size_t out_len);

#endif /* KOMARI_AGENT_C_IP_DETECT_H */
