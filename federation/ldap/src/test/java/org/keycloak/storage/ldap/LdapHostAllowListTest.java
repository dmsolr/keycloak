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

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests the parsing and matching semantics of {@link LdapHostAllowList}, the server-level allow-list constraining the
 * LDAP {@code connectionUrl} host to reduce the SSRF surface. Matching is strictly lexical: no DNS resolution is ever
 * performed.
 */
public class LdapHostAllowListTest {

    // --- empty / allow-all -------------------------------------------------

    @Test
    public void testEmptyAllowListAllowsEverything() {
        for (String csv : new String[]{null, "", "   ", " , , "}) {
            LdapHostAllowList allowList = LdapHostAllowList.parse(csv);
            Assert.assertTrue("null host should be allowed when the list is empty", allowList.isAllowed(null));
            Assert.assertTrue(allowList.isAllowed(""));
            Assert.assertTrue(allowList.isAllowed("ldap.example.com"));
            Assert.assertTrue(allowList.isAllowed("10.1.2.3"));
            Assert.assertTrue(allowList.isAllowed("anything.at.all"));
        }
    }

    @Test
    public void testStarEntryAllowsEverything() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("*");
        Assert.assertTrue(allowList.isAllowed(null));
        Assert.assertTrue(allowList.isAllowed("ldap.example.com"));
        Assert.assertTrue(allowList.isAllowed("10.1.2.3"));

        // "*" mixed with other entries still allows everything
        LdapHostAllowList mixed = LdapHostAllowList.parse("ldap.example.com,*,10.0.0.0/8");
        Assert.assertTrue(mixed.isAllowed("other.example.org"));
    }

    // --- exact hostname ----------------------------------------------------

    @Test
    public void testExactHostname() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("ldap.example.com");
        Assert.assertTrue(allowList.isAllowed("ldap.example.com"));
        // case-insensitive on both the entry and the host
        Assert.assertTrue(LdapHostAllowList.parse("LDAP.Example.COM").isAllowed("ldap.example.com"));
        Assert.assertTrue(allowList.isAllowed("LDAP.EXAMPLE.COM"));

        Assert.assertFalse(allowList.isAllowed("other.example.com"));
        Assert.assertFalse(allowList.isAllowed("sub.ldap.example.com"));
        Assert.assertFalse(allowList.isAllowed("xldap.example.com"));

        // fail-closed on unknown host when the list is non-empty
        Assert.assertFalse(allowList.isAllowed(null));
        Assert.assertFalse(allowList.isAllowed(""));
        Assert.assertFalse(allowList.isAllowed("   "));
    }

    @Test
    public void testMultipleExactHostnames() {
        LdapHostAllowList allowList = LdapHostAllowList.parse(" a.example.com , b.example.com ");
        Assert.assertTrue(allowList.isAllowed("a.example.com"));
        Assert.assertTrue(allowList.isAllowed("b.example.com"));
        Assert.assertFalse(allowList.isAllowed("c.example.com"));
    }

    // --- wildcard suffix ---------------------------------------------------

    @Test
    public void testWildcardSuffix() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("*.example.com");
        Assert.assertTrue(allowList.isAllowed("a.example.com"));
        Assert.assertTrue(allowList.isAllowed("x.y.example.com"));
        Assert.assertTrue(allowList.isAllowed("A.EXAMPLE.COM"));
        // the apex is NOT matched by a wildcard suffix
        Assert.assertFalse(allowList.isAllowed("example.com"));
        // a look-alike domain must not match
        Assert.assertFalse(allowList.isAllowed("notexample.com"));
        Assert.assertFalse(allowList.isAllowed("example.com.evil.org"));
    }

    @Test
    public void testWildcardSuffixWithExplicitApex() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("*.example.com,example.com");
        Assert.assertTrue(allowList.isAllowed("example.com"));
        Assert.assertTrue(allowList.isAllowed("a.example.com"));
        Assert.assertFalse(allowList.isAllowed("notexample.com"));
    }

    // --- literal IPv4 ------------------------------------------------------

    @Test
    public void testLiteralIpv4() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("192.0.2.1");
        Assert.assertTrue(allowList.isAllowed("192.0.2.1"));
        Assert.assertFalse(allowList.isAllowed("192.0.2.2"));
        Assert.assertFalse(allowList.isAllowed("ldap.example.com"));
    }

    @Test
    public void testIpv4Cidr() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("10.0.0.0/8");
        Assert.assertTrue(allowList.isAllowed("10.1.2.3"));
        Assert.assertTrue(allowList.isAllowed("10.255.255.255"));
        Assert.assertTrue(allowList.isAllowed("10.0.0.0"));
        Assert.assertFalse(allowList.isAllowed("11.0.0.1"));
        Assert.assertFalse(allowList.isAllowed("9.255.255.255"));
    }

    @Test
    public void testIpv4CidrPartialByteMask() {
        // /12 covers 10.16.0.0 - 10.31.255.255
        LdapHostAllowList allowList = LdapHostAllowList.parse("10.16.0.0/12");
        Assert.assertTrue(allowList.isAllowed("10.16.0.1"));
        Assert.assertTrue(allowList.isAllowed("10.31.255.255"));
        Assert.assertFalse(allowList.isAllowed("10.15.255.255"));
        Assert.assertFalse(allowList.isAllowed("10.32.0.0"));
    }

    @Test
    public void testIpv4CidrZeroPrefixMatchesAnyIpv4() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("0.0.0.0/0");
        Assert.assertTrue(allowList.isAllowed("8.8.8.8"));
        Assert.assertTrue(allowList.isAllowed("10.0.0.1"));
        // a /0 IPv4 range still does not match IPv6 or hostnames (family isolation)
        Assert.assertFalse(allowList.isAllowed("fd00::1"));
        Assert.assertFalse(allowList.isAllowed("ldap.example.com"));
    }

    // --- IPv6 --------------------------------------------------------------

    @Test
    public void testIpv6Literal() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("fd00::1");
        Assert.assertTrue(allowList.isAllowed("fd00::1"));
        // URI.getHost() may hand back a bracketed IPv6 literal; it must be normalized
        Assert.assertTrue(allowList.isAllowed("[fd00::1]"));
        // equivalent compressed / expanded forms must match
        Assert.assertTrue(allowList.isAllowed("fd00:0:0:0:0:0:0:1"));
        Assert.assertFalse(allowList.isAllowed("fd00::2"));
    }

    @Test
    public void testIpv6Cidr() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("fd00::/8");
        Assert.assertTrue(allowList.isAllowed("fd12::34"));
        Assert.assertTrue(allowList.isAllowed("[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]"));
        Assert.assertFalse(allowList.isAllowed("fc00::1"));
        Assert.assertFalse(allowList.isAllowed("2001:db8::1"));
    }

    @Test
    public void testAddressFamilyIsolation() {
        // an IPv4 host must never match an IPv6 CIDR and vice-versa
        LdapHostAllowList v6 = LdapHostAllowList.parse("fd00::/8");
        Assert.assertFalse(v6.isAllowed("10.0.0.1"));

        LdapHostAllowList v4 = LdapHostAllowList.parse("10.0.0.0/8");
        Assert.assertFalse(v4.isAllowed("fd00::1"));
    }

    // --- no-DNS semantics --------------------------------------------------

    @Test
    public void testHostnameNotMatchedByCidrNoDns() {
        // a hostname host is matched only against hostname entries; it is never resolved to an IP for CIDR matching
        LdapHostAllowList allowList = LdapHostAllowList.parse("10.0.0.0/8");
        Assert.assertFalse(allowList.isAllowed("ldap.internal"));
        Assert.assertFalse(allowList.isAllowed("ldap.example.com"));
    }

    @Test
    public void testLiteralIpNotMatchedByHostnameEntry() {
        // a literal-IP host is matched only against IP/CIDR entries, not hostname entries
        LdapHostAllowList allowList = LdapHostAllowList.parse("ldap.example.com");
        Assert.assertFalse(allowList.isAllowed("10.0.0.1"));
    }

    // --- mixed entries -----------------------------------------------------

    @Test
    public void testMultipleMixedEntries() {
        LdapHostAllowList allowList = LdapHostAllowList.parse("ldap.example.com,*.corp.example.org,10.0.0.0/8,fd00::1");
        Assert.assertTrue(allowList.isAllowed("ldap.example.com"));
        Assert.assertTrue(allowList.isAllowed("a.corp.example.org"));
        Assert.assertTrue(allowList.isAllowed("10.9.8.7"));
        Assert.assertTrue(allowList.isAllowed("fd00::1"));
        Assert.assertFalse(allowList.isAllowed("evil.com"));
        Assert.assertFalse(allowList.isAllowed("11.0.0.1"));
    }

    // --- invalid entries fail fast ----------------------------------------

    @Test
    public void testInvalidCidrPrefixThrows() {
        assertParseFails("10.0.0.0/33");
        assertParseFails("fd00::/129");
        assertParseFails("10.0.0.0/-1");
        assertParseFails("10.0.0.0/abc");
    }

    @Test
    public void testInvalidCidrAddressThrows() {
        // a CIDR whose address part is not a literal IP is rejected (no DNS resolution to "fix" it)
        assertParseFails("foo/24");
        assertParseFails("ldap.example.com/24");
    }

    @Test
    public void testMalformedIpLiteralThrows() {
        // shaped like an IPv4 literal but out of range -> fail fast rather than silently treat as a hostname
        assertParseFails("999.1.1.1");
        assertParseFails("10.0.0.256");
    }

    @Test
    public void testInvalidEntryAmongValidOnesThrows() {
        // one bad entry poisons the whole parse (fail-fast, no silent partial allow-list)
        assertParseFails("ldap.example.com,10.0.0.0/33");
    }

    @Test
    public void testIsEnforced() {
        // unset / blank / "*" -> no restriction, callers may skip per-request URL checks
        Assert.assertFalse(LdapHostAllowList.parse(null).isEnforced());
        Assert.assertFalse(LdapHostAllowList.parse("  ").isEnforced());
        Assert.assertFalse(LdapHostAllowList.parse("*").isEnforced());
        Assert.assertFalse(LdapHostAllowList.parse("*,").isEnforced());
        // "*" wins over other entries: the list still allows any host
        Assert.assertFalse(LdapHostAllowList.parse("*,ldap.example.com").isEnforced());
        // any real entry activates enforcement
        Assert.assertTrue(LdapHostAllowList.parse("ldap.example.com").isEnforced());
        Assert.assertTrue(LdapHostAllowList.parse("*.example.com").isEnforced());
        Assert.assertTrue(LdapHostAllowList.parse("10.0.0.0/8").isEnforced());
    }

    private static void assertParseFails(String csv) {
        try {
            LdapHostAllowList.parse(csv);
            Assert.fail("Expected IllegalArgumentException for invalid entry: " + csv);
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }
}
