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

import java.util.Set;
import java.util.concurrent.TimeUnit;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests the {@code ldap-metrics-tags} parsing and the realm/ldap tag decoration of the
 * {@code keycloak.ldap.requests} timer in {@link LDAPStorageProviderFactory}.
 */
public class LDAPStorageProviderFactoryMetricsTagsTest {

    private static final String METER_NAME = "keycloak.ldap.requests";

    @Test
    public void testParseMetricsTags() {
        Assert.assertTrue(LDAPStorageProviderFactory.parseMetricsTags(null).isEmpty());
        Assert.assertTrue(LDAPStorageProviderFactory.parseMetricsTags("").isEmpty());

        Assert.assertEquals(Set.of(LDAPStorageProviderFactory.REALM_TAG),
                LDAPStorageProviderFactory.parseMetricsTags("realm"));
        Assert.assertEquals(Set.of(LDAPStorageProviderFactory.LDAP_TAG),
                LDAPStorageProviderFactory.parseMetricsTags("ldap"));
        Assert.assertEquals(Set.of(LDAPStorageProviderFactory.REALM_TAG, LDAPStorageProviderFactory.LDAP_TAG),
                LDAPStorageProviderFactory.parseMetricsTags("realm,ldap"));
        Assert.assertEquals(Set.of(LDAPStorageProviderFactory.REALM_TAG, LDAPStorageProviderFactory.LDAP_TAG),
                LDAPStorageProviderFactory.parseMetricsTags(" ldap , realm "));
    }

    @Test
    public void testParseMetricsTagsUnknownValue() {
        try {
            LDAPStorageProviderFactory.parseMetricsTags("bogus");
            Assert.fail("Expected IllegalArgumentException for unknown tag");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    @Test
    public void testWithExtraTagsAddsRealmAndLdapOnce() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        Meter.MeterProvider<Timer> provider = Timer.builder(METER_NAME).withRegistry(registry);

        Meter.MeterProvider<Timer> decorated = LDAPStorageProviderFactory.withExtraTags(
                provider, true, "myrealm", true, "myldap");
        decorated.withTags("operation", "search", "outcome", "success", "error", "")
                .record(1, TimeUnit.MILLISECONDS);

        Timer timer = registry.find(METER_NAME).timer();
        Assert.assertNotNull(timer);
        Assert.assertEquals("myrealm", tagValue(timer, LDAPStorageProviderFactory.REALM_TAG));
        Assert.assertEquals("myldap", tagValue(timer, LDAPStorageProviderFactory.LDAP_TAG));
        Assert.assertEquals(1, countTag(timer, LDAPStorageProviderFactory.REALM_TAG));
        Assert.assertEquals(1, countTag(timer, LDAPStorageProviderFactory.LDAP_TAG));
        // the original record-site tags must be preserved
        Assert.assertEquals("search", tagValue(timer, "operation"));
        Assert.assertEquals("success", tagValue(timer, "outcome"));
    }

    @Test
    public void testWithExtraTagsOnlyRealm() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        Meter.MeterProvider<Timer> provider = Timer.builder(METER_NAME).withRegistry(registry);

        Meter.MeterProvider<Timer> decorated = LDAPStorageProviderFactory.withExtraTags(
                provider, true, "myrealm", false, "myldap");
        decorated.withTags("operation", "search", "outcome", "success", "error", "")
                .record(1, TimeUnit.MILLISECONDS);

        Timer timer = registry.find(METER_NAME).timer();
        Assert.assertNotNull(timer);
        Assert.assertEquals("myrealm", tagValue(timer, LDAPStorageProviderFactory.REALM_TAG));
        Assert.assertEquals(0, countTag(timer, LDAPStorageProviderFactory.LDAP_TAG));
    }

    @Test
    public void testUndecoratedProviderHasNoRealmOrLdap() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        Meter.MeterProvider<Timer> provider = Timer.builder(METER_NAME).withRegistry(registry);

        provider.withTags("operation", "search", "outcome", "success", "error", "")
                .record(1, TimeUnit.MILLISECONDS);

        Timer timer = registry.find(METER_NAME).timer();
        Assert.assertNotNull(timer);
        Assert.assertEquals(0, countTag(timer, LDAPStorageProviderFactory.REALM_TAG));
        Assert.assertEquals(0, countTag(timer, LDAPStorageProviderFactory.LDAP_TAG));
    }

    @Test
    public void testNullNamesBecomeEmptyTagValues() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        Meter.MeterProvider<Timer> provider = Timer.builder(METER_NAME).withRegistry(registry);

        Meter.MeterProvider<Timer> decorated = LDAPStorageProviderFactory.withExtraTags(
                provider, true, null, true, null);
        decorated.withTags("operation", "search", "outcome", "success", "error", "")
                .record(1, TimeUnit.MILLISECONDS);

        Timer timer = registry.find(METER_NAME).timer();
        Assert.assertNotNull(timer);
        Assert.assertEquals("", tagValue(timer, LDAPStorageProviderFactory.REALM_TAG));
        Assert.assertEquals("", tagValue(timer, LDAPStorageProviderFactory.LDAP_TAG));
    }

    private static String tagValue(Timer timer, String key) {
        for (Tag tag : timer.getId().getTags()) {
            if (tag.getKey().equals(key)) {
                return tag.getValue();
            }
        }
        return null;
    }

    private static int countTag(Timer timer, String key) {
        int count = 0;
        for (Tag tag : timer.getId().getTags()) {
            if (tag.getKey().equals(key)) {
                count++;
            }
        }
        return count;
    }
}
