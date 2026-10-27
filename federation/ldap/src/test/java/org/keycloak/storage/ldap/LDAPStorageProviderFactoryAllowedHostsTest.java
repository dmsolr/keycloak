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

import org.keycloak.component.ComponentValidationException;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests {@link LDAPStorageProviderFactory#validateConnectionUrlHosts(String)}, the shared enforcement point of the
 * server-level LDAP host allow-list used both by {@code validateConfiguration} (component save) and by the admin
 * test-connection/test-authentication endpoints ({@code LDAPServerCapabilitiesManager.testLDAP}).
 */
public class LDAPStorageProviderFactoryAllowedHostsTest {

    private static LDAPStorageProviderFactory factoryWithAllowedHosts(String csv) {
        LDAPStorageProviderFactory factory = new LDAPStorageProviderFactory();
        factory.setAllowedHosts(LdapHostAllowList.parse(csv));
        return factory;
    }

    private static void assertAllowed(LDAPStorageProviderFactory factory, String connectionUrl) {
        factory.validateConnectionUrlHosts(connectionUrl);
    }

    private static void assertNotAllowed(LDAPStorageProviderFactory factory, String connectionUrl) {
        try {
            factory.validateConnectionUrlHosts(connectionUrl);
            Assert.fail("Expected ComponentValidationException for connection URL: " + connectionUrl);
        } catch (ComponentValidationException expected) {
            Assert.assertEquals("ldapErrorConnectionUrlHostNotAllowed", expected.getMessage());
        }
    }

    @Test
    public void testEmptyAllowListAllowsAnyHost() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts(null);
        assertAllowed(factory, "ldap://ldap.example.com:389");
        assertAllowed(factory, "ldaps://10.1.2.3:636");
    }

    @Test
    public void testExactHostname() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("ldap.example.com");
        assertAllowed(factory, "ldap://ldap.example.com:389");
        assertNotAllowed(factory, "ldap://evil.example.org:389");
    }

    @Test
    public void testWildcardAndCidrEntries() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("*.example.com,10.0.0.0/8");
        assertAllowed(factory, "ldaps://a.example.com:636");
        assertAllowed(factory, "ldap://10.1.2.3:389");
        assertNotAllowed(factory, "ldap://11.0.0.1:389");
        assertNotAllowed(factory, "ldap://example.com:389");
    }

    @Test
    public void testMultiUrlAllHostsMustBeAllowed() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("ldap1.example.com");
        assertAllowed(factory, "ldap://ldap1.example.com:389 ldaps://ldap1.example.com:636");
        // the second host is not on the allow-list
        assertNotAllowed(factory, "ldap://ldap1.example.com:389 ldap://ldap2.example.org:389");
    }

    @Test
    public void testIpv6LiteralHost() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("fd00::/8");
        assertAllowed(factory, "ldap://[fd00::1]:389");
        assertNotAllowed(factory, "ldap://[fe80::1]:389");
    }

    @Test
    public void testNullUrlIsAllowed() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("ldap.example.com");
        // a null connection URL yields no URLs to check
        assertAllowed(factory, null);
    }

    @Test
    public void testBlankUrlFailsClosedWhenAllowListActive() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("ldap.example.com");
        // a blank URL has no host; with a non-empty allow-list matching fails closed
        assertNotAllowed(factory, "");
        // with an allow-all list, any (even host-less) URL is permitted
        assertAllowed(factoryWithAllowedHosts(null), "");
    }

    @Test
    public void testMalformedUrl() {
        LDAPStorageProviderFactory factory = factoryWithAllowedHosts("ldap.example.com");
        try {
            // URI.create rejects the malformed percent-escape with IllegalArgumentException
            factory.validateConnectionUrlHosts("ldap://host%zz");
            Assert.fail("Expected ComponentValidationException for malformed URL");
        } catch (ComponentValidationException expected) {
            Assert.assertEquals("ldapErrorInvalidConnectionUrl", expected.getMessage());
        }
    }
}
