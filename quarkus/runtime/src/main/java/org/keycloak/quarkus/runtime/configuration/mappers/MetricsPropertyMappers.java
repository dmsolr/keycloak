package org.keycloak.quarkus.runtime.configuration.mappers;

import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.config.MetricsOptions;

import static org.keycloak.quarkus.runtime.configuration.Configuration.isTrue;
import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;


final class MetricsPropertyMappers implements PropertyMapperGrouping {

    public static final String METRICS_ENABLED_MSG = "metrics are enabled";

    @Override
    public List<PropertyMapper<?>> getPropertyMappers() {
        return List.of(
                fromOption(MetricsOptions.METRICS_ENABLED)
                        .to("quarkus.micrometer.enabled")
                        .build(),
                fromOption(MetricsOptions.LDAP_METRICS_HISTOGRAMS_ENABLED)
                        .to("kc.spi-storage--ldap--metrics-histograms-enabled")
                        .isEnabled(MetricsPropertyMappers::ldapMetricsEnabled,
                                METRICS_ENABLED_MSG + " and feature " + Profile.Feature.LDAP_METRICS.getKey() + " is enabled")
                        .build(),
                fromOption(MetricsOptions.LDAP_METRICS_SLOS)
                        .to("kc.spi-storage--ldap--metrics-slos")
                        .paramLabel("list of buckets")
                        .isEnabled(MetricsPropertyMappers::ldapMetricsEnabled,
                                METRICS_ENABLED_MSG + " and feature " + Profile.Feature.LDAP_METRICS.getKey() + " is enabled")
                        .build(),
                fromOption(MetricsOptions.LDAP_METRICS_TAGS)
                        .to("kc.spi-storage--ldap--metrics-tags")
                        .paramLabel("tags")
                        .isEnabled(MetricsPropertyMappers::ldapMetricsEnabled,
                                METRICS_ENABLED_MSG + " and feature " + Profile.Feature.LDAP_METRICS.getKey() + " is enabled")
                        .build()
        );
    }

    public static boolean metricsEnabled() {
        return isTrue(MetricsOptions.METRICS_ENABLED);
    }

    private static boolean ldapMetricsEnabled() {
        return metricsEnabled() && Profile.isFeatureEnabled(Profile.Feature.LDAP_METRICS);
    }
}
