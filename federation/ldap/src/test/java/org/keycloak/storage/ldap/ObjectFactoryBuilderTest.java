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

import javax.naming.CommunicationException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

/**
 * Tests that {@link ObjectFactoryBuilder} constrains LDAP referral targets with the server-level host allow-list,
 * so an allowed LDAP server cannot redirect the client to a host outside the list (see {@code ldap-allowed-hosts}).
 */
public class ObjectFactoryBuilderTest {

    @After
    public void resetAllowList() {
        // the allow-list is JVM-global static state; restore allow-all for other tests
        ObjectFactoryBuilder.setAllowedHosts(LdapHostAllowList.parse(null));
    }

    private static Reference referral(String url) {
        return new Reference("javax.naming.ldap.LdapContext", new StringRefAddr("URL", url));
    }

    @Test
    public void testAllowAllAcceptsAnyReferral() throws Exception {
        ObjectFactoryBuilder builder = new ObjectFactoryBuilder();
        Assert.assertNotNull(builder.createObjectFactory(referral("ldap://any.internal.host:389"), null));
    }

    @Test
    public void testAllowedReferralHostAccepted() throws Exception {
        ObjectFactoryBuilder.setAllowedHosts(LdapHostAllowList.parse("ldap.example.com"));
        ObjectFactoryBuilder builder = new ObjectFactoryBuilder();
        Assert.assertNotNull(builder.createObjectFactory(referral("ldap://ldap.example.com:389"), null));
    }

    @Test
    public void testDisallowedReferralHostRejected() {
        ObjectFactoryBuilder.setAllowedHosts(LdapHostAllowList.parse("ldap.example.com"));
        ObjectFactoryBuilder builder = new ObjectFactoryBuilder();
        try {
            builder.createObjectFactory(referral("ldap://evil.internal.host:389"), null);
            Assert.fail("Expected CommunicationException for a referral host outside the allow-list");
        } catch (CommunicationException expected) {
            // expected
        } catch (Exception e) {
            Assert.fail("Unexpected exception: " + e);
        }
    }

    @Test
    public void testMultiUrlReferralAllHostsMustBeAllowed() {
        ObjectFactoryBuilder.setAllowedHosts(LdapHostAllowList.parse("ldap1.example.com"));
        ObjectFactoryBuilder builder = new ObjectFactoryBuilder();
        try {
            builder.createObjectFactory(referral("ldap://ldap1.example.com:389 ldap://ldap2.example.org:389"), null);
            Assert.fail("Expected CommunicationException when one referral host is outside the allow-list");
        } catch (CommunicationException expected) {
            // expected
        } catch (Exception e) {
            Assert.fail("Unexpected exception: " + e);
        }
    }

    @Test
    public void testMalformedReferralUrlRejectedWhenEnforced() {
        ObjectFactoryBuilder.setAllowedHosts(LdapHostAllowList.parse("ldap.example.com"));
        ObjectFactoryBuilder builder = new ObjectFactoryBuilder();
        try {
            builder.createObjectFactory(referral("ldap://host%zz"), null);
            Assert.fail("Expected CommunicationException for a malformed referral URL");
        } catch (CommunicationException expected) {
            // expected
        } catch (Exception e) {
            Assert.fail("Unexpected exception: " + e);
        }
    }
}
