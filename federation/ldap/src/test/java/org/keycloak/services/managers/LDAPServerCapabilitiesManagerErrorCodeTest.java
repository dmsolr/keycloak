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

package org.keycloak.services.managers;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests {@link LDAPServerCapabilitiesManager#getErrorCode(Throwable)} mapping, in particular that the custom
 * {@code NamingException} subtypes are not shadowed by the general {@code NamingError} code (the mapping uses a
 * cascade of {@code if} statements where the most specific check must come last).
 */
public class LDAPServerCapabilitiesManagerErrorCodeTest {

    @Test
    public void testHostNotAllowedWinsOverNamingError() {
        // HostNotAllowedException extends NamingException, so it must be checked after the NamingException branch
        Assert.assertEquals("HostNotAllowed",
                LDAPServerCapabilitiesManager.getErrorCode(
                        new LDAPServerCapabilitiesManager.HostNotAllowedException("not permitted")));
    }

    @Test
    public void testInvalidBindDNWinsOverNamingError() {
        Assert.assertEquals("InvalidBindDN",
                LDAPServerCapabilitiesManager.getErrorCode(
                        new LDAPServerCapabilitiesManager.InvalidBindDNException("bad dn")));
    }

    @Test
    public void testCredentialReentryRequired() {
        Assert.assertEquals("CredentialReentryRequired",
                LDAPServerCapabilitiesManager.getErrorCode(
                        new LDAPServerCapabilitiesManager.CredentialReentryRequiredException("re-enter")));
    }

    @Test
    public void testPlainNamingException() {
        Assert.assertEquals("NamingError",
                LDAPServerCapabilitiesManager.getErrorCode(new javax.naming.NamingException("generic")));
    }
}
