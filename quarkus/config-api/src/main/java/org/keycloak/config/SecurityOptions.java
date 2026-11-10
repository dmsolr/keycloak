package org.keycloak.config;

import java.util.Arrays;
import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.common.crypto.FipsMode;

public class SecurityOptions {

    public static final Option<FipsMode> FIPS_MODE = new OptionBuilder<>("fips-mode", FipsMode.class)
            .category(OptionCategory.SECURITY)
            .expectedValues(getFipsModeValues())
            .buildTime(true)
            .description("Sets the FIPS mode. If '" + FipsMode.NON_STRICT + "' is set, FIPS is enabled but on non-approved mode. For full FIPS compliance, set '" + FipsMode.STRICT + "' to run on approved mode. "
                    + "This option defaults to '" + FipsMode.DISABLED + "' when '" + Profile.Feature.FIPS.getKey() + "' feature is disabled, which is by default. "
                    + "This option defaults to '" + FipsMode.NON_STRICT + "' when '" + Profile.Feature.FIPS.getKey() + "' feature is enabled.")
            .defaultValue(FipsMode.DISABLED)
            .build();

    public static final Option<List<String>> LDAP_ALLOWED_HOSTS = OptionBuilder.listOptionBuilder("ldap-allowed-hosts", String.class)
            .category(OptionCategory.SECURITY)
            .description("Comma-separated allow-list of hosts that an LDAP user storage provider is permitted to connect to, "
                    + "used to reduce the SSRF surface of the LDAP connection URL. Each entry may be an exact hostname "
                    + "(ldap.example.com), a wildcard suffix (*.example.com, matching sub-domains only), a literal IP address "
                    + "(192.0.2.1, fd00::1), or an IP CIDR range (10.0.0.0/8, fd00::/8). Hosts are matched literally and are "
                    + "never resolved via DNS, so a hostname is only matched by hostname entries and a literal IP only by "
                    + "IP/CIDR entries. The list is enforced both when an LDAP component is saved or tested and at runtime "
                    + "before a provider connects, and it also constrains LDAP referral targets (when secure-referral is enabled, "
                    + "which is the default). When unset or empty, any host is allowed.")
            .buildTime(false)
            .build();

    private static List<String> getFipsModeValues() {
        return Arrays.asList(FipsMode.NON_STRICT.toString(), FipsMode.STRICT.toString());
    }
}
