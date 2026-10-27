/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.storage.ldap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Server-level allow-list of hosts that an LDAP user storage provider is permitted to connect to. It constrains the
 * LDAP {@code connectionUrl} and reduces the SSRF surface, preventing a realm administrator from pointing the Keycloak
 * LDAP client at an arbitrary (e.g. internal) host.
 *
 * <p>An instance is parsed once at startup from the {@code ldap-allowed-hosts} option (SPI key
 * {@code kc.spi-storage--ldap--allowed-hosts}) and is then used for pure, side-effect-free matching during
 * {@link LDAPStorageProviderFactory#validateConfiguration}.
 *
 * <p>Supported entry forms (comma-separated):
 * <ul>
 *     <li>exact hostname, e.g. {@code ldap.example.com} (matched case-insensitively)</li>
 *     <li>wildcard suffix, e.g. {@code *.example.com} &mdash; matches sub-domains such as {@code a.example.com} and
 *         {@code x.y.example.com}, but NOT the apex {@code example.com}. List {@code example.com} explicitly to allow
 *         the apex.</li>
 *     <li>literal IP address, e.g. {@code 192.0.2.1} or {@code fd00::1} (exact match)</li>
 *     <li>IP CIDR range, e.g. {@code 10.0.0.0/8} or {@code fd00::/8} (both IPv4 and IPv6)</li>
 *     <li>{@code *} &mdash; matches any host (equivalent to an empty allow-list)</li>
 * </ul>
 *
 * <p>Matching is strictly lexical: hostnames are NEVER resolved via DNS. A literal-IP host is matched only against
 * IP/CIDR entries; a hostname host is matched only against hostname entries. Consequently a hostname that happens to
 * resolve to an in-range IP is not matched by a CIDR entry &mdash; operators wanting IP-level control must use IP/CIDR
 * entries together with IP connection hosts.
 *
 * <p>When the allow-list is empty (option unset), {@link #isAllowed(String)} returns {@code true} for any host,
 * preserving the historical behaviour. When the allow-list is non-empty and the host cannot be determined
 * ({@code null}/blank), matching fails closed (returns {@code false}).
 */
public final class LdapHostAllowList {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    private static final LdapHostAllowList ALLOW_ALL = new LdapHostAllowList(false, Set.of(), List.of(), List.of());

    private final boolean matchAll;
    private final Set<String> exactHosts;         // lowercased hostnames
    private final List<String> wildcardSuffixes;  // lowercased, e.g. ".example.com"
    private final List<CidrRange> cidrs;

    private LdapHostAllowList(boolean matchAll, Set<String> exactHosts, List<String> wildcardSuffixes, List<CidrRange> cidrs) {
        this.matchAll = matchAll;
        this.exactHosts = exactHosts;
        this.wildcardSuffixes = wildcardSuffixes;
        this.cidrs = cidrs;
    }

    /**
     * Parses a comma-separated allow-list. A {@code null}/blank value, or one with no usable entries, yields an
     * allow-all instance. Invalid entries fail fast with {@link IllegalArgumentException} so that a misconfiguration
     * surfaces at startup rather than silently widening or narrowing access.
     *
     * @param csv the raw comma-separated option value, may be {@code null}
     * @return the parsed allow-list, never {@code null}
     */
    public static LdapHostAllowList parse(String csv) {
        if (csv == null || csv.isBlank()) {
            return ALLOW_ALL;
        }

        boolean matchAll = false;
        Set<String> exactHosts = new LinkedHashSet<>();
        List<String> wildcardSuffixes = new ArrayList<>();
        List<CidrRange> cidrs = new ArrayList<>();

        for (String raw : csv.split(",")) {
            String entry = raw.trim();
            if (entry.isEmpty()) {
                continue;
            }
            if ("*".equals(entry)) {
                matchAll = true;
                continue;
            }
            if (entry.indexOf('/') >= 0) {
                cidrs.add(parseCidr(entry));
                continue;
            }
            if (entry.startsWith("*.")) {
                // "*.example.com" -> ".example.com"; matched via endsWith on the lowercased host
                wildcardSuffixes.add(entry.substring(1).toLowerCase(Locale.ROOT));
                continue;
            }
            byte[] ip = tryParseIpLiteral(entry);
            if (ip != null) {
                // a bare literal IP is treated as a full-prefix CIDR (exact IP match)
                cidrs.add(new CidrRange(ip, ip.length * 8));
                continue;
            }
            if (looksLikeIpLiteral(entry)) {
                // e.g. "999.1.1.1" - shaped like an IP but not a valid one; fail fast instead of treating it as a host
                throw new IllegalArgumentException("Invalid LDAP allowed-hosts entry '" + entry + "': not a valid IP address or hostname");
            }
            exactHosts.add(entry.toLowerCase(Locale.ROOT));
        }

        if (!matchAll && exactHosts.isEmpty() && wildcardSuffixes.isEmpty() && cidrs.isEmpty()) {
            return ALLOW_ALL;
        }
        return new LdapHostAllowList(matchAll, exactHosts, wildcardSuffixes, cidrs);
    }

    /**
     * Returns {@code true} when the given host is permitted by this allow-list. See the class Javadoc for the matching
     * rules. This method never throws and never performs DNS resolution.
     *
     * @param host the host to check, typically {@link java.net.URI#getHost()} (may be {@code null})
     */
    public boolean isAllowed(String host) {
        if (matchAll) {
            return true;
        }
        if (exactHosts.isEmpty() && wildcardSuffixes.isEmpty() && cidrs.isEmpty()) {
            return true; // empty allow-list -> allow everything
        }
        if (host == null) {
            return false; // fail closed when a non-empty allow-list is active but the host is unknown
        }

        String normalized = normalizeHost(host);
        if (normalized.isEmpty()) {
            return false;
        }

        byte[] ip = tryParseIpLiteral(normalized);
        if (ip != null) {
            // literal IP hosts are matched only against IP/CIDR entries
            for (CidrRange range : cidrs) {
                if (range.matches(ip)) {
                    return true;
                }
            }
            return false;
        }

        // hostname hosts are matched only against hostname entries (no DNS resolution, no CIDR check)
        if (exactHosts.contains(normalized)) {
            return true;
        }
        for (String suffix : wildcardSuffixes) {
            if (normalized.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeHost(String host) {
        String h = host.trim();
        // URI.getHost() may return an IPv6 literal wrapped in brackets, e.g. "[fd00::1]"
        if (h.length() >= 2 && h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        return h.toLowerCase(Locale.ROOT);
    }

    private static CidrRange parseCidr(String entry) {
        int slash = entry.indexOf('/');
        String ipPart = entry.substring(0, slash).trim();
        String prefixPart = entry.substring(slash + 1).trim();

        if (ipPart.length() >= 2 && ipPart.startsWith("[") && ipPart.endsWith("]")) {
            ipPart = ipPart.substring(1, ipPart.length() - 1);
        }

        byte[] network = tryParseIpLiteral(ipPart);
        if (network == null) {
            throw new IllegalArgumentException("Invalid LDAP allowed-hosts CIDR entry '" + entry + "': '" + ipPart + "' is not a literal IP address");
        }

        int prefix;
        try {
            prefix = Integer.parseInt(prefixPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid LDAP allowed-hosts CIDR entry '" + entry + "': prefix length is not a number");
        }
        int maxPrefix = network.length * 8;
        if (prefix < 0 || prefix > maxPrefix) {
            throw new IllegalArgumentException("Invalid LDAP allowed-hosts CIDR entry '" + entry + "': prefix length must be between 0 and " + maxPrefix);
        }
        return new CidrRange(network, prefix);
    }

    /**
     * Parses a literal IPv4/IPv6 address into its network bytes WITHOUT performing any DNS resolution.
     *
     * @return the address bytes (4 for IPv4, 16 for IPv6), or {@code null} when {@code value} is not a valid literal
     *         IP address
     */
    private static byte[] tryParseIpLiteral(String value) {
        if (value == null || !looksLikeIpLiteral(value)) {
            return null;
        }
        return value.indexOf(':') >= 0 ? parseIpv6(value) : parseIpv4(value);
    }

    /**
     * Parses a dotted-decimal IPv4 literal into 4 bytes, or returns {@code null} when any octet is missing,
     * non-numeric, or out of the 0-255 range. Never performs DNS resolution.
     */
    private static byte[] parseIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                return null;
            }
            int octet = 0;
            for (int j = 0; j < part.length(); j++) {
                char c = part.charAt(j);
                if (c < '0' || c > '9') {
                    return null;
                }
                octet = octet * 10 + (c - '0');
            }
            if (octet > 255) {
                return null;
            }
            out[i] = (byte) octet;
        }
        return out;
    }

    /**
     * Parses an IPv6 literal into 16 bytes, supporting {@code ::} compression and a trailing embedded IPv4
     * (e.g. {@code ::ffff:192.0.2.1}). Returns {@code null} for anything malformed. Never performs DNS resolution.
     */
    private static byte[] parseIpv6(String value) {
        String s = value;
        int zone = s.indexOf('%');
        if (zone >= 0) {
            s = s.substring(0, zone); // drop any zone id
        }
        if (s.isEmpty() || s.indexOf(':') < 0) {
            return null;
        }

        // Expand a trailing embedded IPv4 (e.g. "...:192.0.2.1") into two 16-bit groups.
        int lastColon = s.lastIndexOf(':');
        String tail = s.substring(lastColon + 1);
        if (tail.indexOf('.') >= 0) {
            byte[] v4 = parseIpv4(tail);
            if (v4 == null) {
                return null;
            }
            int g1 = ((v4[0] & 0xFF) << 8) | (v4[1] & 0xFF);
            int g2 = ((v4[2] & 0xFF) << 8) | (v4[3] & 0xFF);
            s = s.substring(0, lastColon + 1) + Integer.toHexString(g1) + ":" + Integer.toHexString(g2);
        }

        String head;
        String rest;
        boolean compressed;
        int dc = s.indexOf("::");
        if (dc >= 0) {
            if (s.indexOf("::", dc + 1) >= 0) {
                return null; // at most one "::" is allowed
            }
            head = s.substring(0, dc);
            rest = s.substring(dc + 2);
            compressed = true;
        } else {
            head = s;
            rest = null;
            compressed = false;
        }

        List<Integer> headGroups = parseIpv6Groups(head);
        if (headGroups == null) {
            return null;
        }
        List<Integer> tailGroups = compressed ? parseIpv6Groups(rest) : null;
        if (compressed && tailGroups == null) {
            return null;
        }

        int total = headGroups.size() + (compressed ? tailGroups.size() : 0);
        if (compressed) {
            if (total > 7) {
                return null; // "::" must stand for at least one all-zero group
            }
        } else if (total != 8) {
            return null;
        }

        int[] groups = new int[8];
        int idx = 0;
        for (int g : headGroups) {
            groups[idx++] = g;
        }
        idx += 8 - total; // zero-filled gap represented by "::"
        if (compressed) {
            for (int g : tailGroups) {
                groups[idx++] = g;
            }
        }

        byte[] out = new byte[16];
        for (int g = 0; g < 8; g++) {
            out[g * 2] = (byte) ((groups[g] >> 8) & 0xFF);
            out[g * 2 + 1] = (byte) (groups[g] & 0xFF);
        }
        return out;
    }

    /**
     * Splits a colon-separated run of IPv6 groups (no {@code ::}) into 16-bit values. An empty string yields an empty
     * list (valid on either side of a {@code ::}). Returns {@code null} when any group is empty, longer than 4 hex
     * digits, or contains a non-hex character.
     */
    private static List<Integer> parseIpv6Groups(String s) {
        List<Integer> groups = new ArrayList<>();
        if (s.isEmpty()) {
            return groups;
        }
        for (String part : s.split(":", -1)) {
            if (part.isEmpty() || part.length() > 4) {
                return null;
            }
            int value = 0;
            for (int j = 0; j < part.length(); j++) {
                int digit = Character.digit(part.charAt(j), 16);
                if (digit < 0) {
                    return null;
                }
                value = (value << 4) | digit;
            }
            groups.add(value);
        }
        return groups;
    }

    /**
     * Cheap syntactic check for whether {@code value} is shaped like an IP literal. Only values passing this check are
     * handed to {@link #parseIpv4(String)}/{@link #parseIpv6(String)}, so hostnames are never mistaken for IP literals
     * and no DNS resolution is ever triggered.
     */
    private static boolean looksLikeIpLiteral(String value) {
        return value.indexOf(':') >= 0 || IPV4_PATTERN.matcher(value).matches();
    }

    /**
     * An IP CIDR range with pre-masked network bytes, supporting both IPv4 (4-byte) and IPv6 (16-byte) addresses.
     */
    private static final class CidrRange {

        private final byte[] network;
        private final int prefix;

        CidrRange(byte[] address, int prefix) {
            this.prefix = prefix;
            this.network = mask(address, prefix);
        }

        boolean matches(byte[] address) {
            if (address.length != network.length) {
                return false; // address-family mismatch (IPv4 vs IPv6)
            }
            return Arrays.equals(mask(address, prefix), network);
        }

        private static byte[] mask(byte[] address, int prefix) {
            byte[] result = address.clone();
            int fullBytes = prefix / 8;
            int remainingBits = prefix % 8;
            if (remainingBits != 0 && fullBytes < result.length) {
                result[fullBytes] = (byte) (result[fullBytes] & (0xFF << (8 - remainingBits)));
                fullBytes++;
            }
            for (int i = fullBytes; i < result.length; i++) {
                result[i] = 0;
            }
            return result;
        }
    }
}
