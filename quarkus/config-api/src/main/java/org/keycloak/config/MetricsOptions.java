package org.keycloak.config;

import java.util.List;

public class MetricsOptions {

    public static final Option<Boolean> METRICS_ENABLED = new OptionBuilder<>("metrics-enabled", Boolean.class)
            .category(OptionCategory.METRICS)
            .description("If the server should expose metrics. If enabled, metrics are available at the '/metrics' endpoint.")
            .buildTime(true)
            .defaultValue(Boolean.FALSE)
            .build();

    public static final Option<Boolean> LDAP_METRICS_HISTOGRAMS_ENABLED = new OptionBuilder<>("ldap-metrics-histograms-enabled", Boolean.class)
            .category(OptionCategory.METRICS)
            .description("Enables a histogram with default buckets for the duration of LDAP requests.")
            .buildTime(false)
            .defaultValue(Boolean.FALSE)
            .build();

    public static final Option<String> LDAP_METRICS_SLOS = new OptionBuilder<>("ldap-metrics-slos", String.class)
            .category(OptionCategory.METRICS)
            .description("Service level objectives for LDAP request metrics. Use this instead of the default histogram, or use it in combination to add additional buckets. " +
                    "Specify a list of comma-separated values defined in milliseconds. Example with buckets from 5ms to 10s: 5,10,25,50,250,500,1000,2500,5000,10000")
            .buildTime(false)
            .build();

    public static final Option<List<String>> LDAP_METRICS_TAGS = OptionBuilder.listOptionBuilder("ldap-metrics-tags", String.class)
            .category(OptionCategory.METRICS)
            .description("Comma-separated list of tags to be collected for LDAP request metrics. Disabled by default to avoid a high metrics cardinality.")
            .buildTime(false)
            .expectedValues(List.of("realm", "ldap"))
            .build();

}
