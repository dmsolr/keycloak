package org.keycloak.storage.ldap;

import java.net.URI;
import java.util.Hashtable;
import java.util.List;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.ldap.LdapContext;
import javax.naming.spi.NamingManager;
import javax.naming.spi.ObjectFactory;

import org.keycloak.storage.ldap.idm.store.ldap.SessionBoundInitialLdapContext;
import org.keycloak.utils.KeycloakSessionUtil;

import org.jboss.logging.Logger;

/**
 * <p>A {@link javax.naming.spi.ObjectFactoryBuilder} implementation to filter out referral references if they do not
 * point to an LDAP URL.
 *
 * <p>When the LDAP provider encounters a referral, it tries to create an {@link ObjectFactory} from this builder.
 * If the referral reference contains an LDAP URL, a {@link DirContextObjectFactory} is created to handle the referral.
 * Otherwise, a {@link CommunicationException} is thrown to indicate that the referral cannot be processed.
 *
 * <p>Referral URLs are additionally checked against the server-level LDAP host allow-list
 * ({@code ldap-allowed-hosts}), so an allowed LDAP server cannot redirect the client to a host outside the list.
 */
final class ObjectFactoryBuilder implements javax.naming.spi.ObjectFactoryBuilder, ObjectFactory {

    private static final Logger logger = Logger.getLogger(ObjectFactoryBuilder.class);
    private static final String IS_KC_OBJECT_FACTORY_BUILDER = "kc.jndi.object.factory.builder";

    // Shared with LDAPStorageProviderFactory (server-level option, parsed once at startup). Allow-all until configured.
    private static volatile LdapHostAllowList allowedHosts = LdapHostAllowList.parse(null);

    static void setAllowedHosts(LdapHostAllowList allowList) {
        allowedHosts = allowList;
    }

    static boolean isSet() {
        Hashtable<Object, Object> env = new Hashtable<>();

        env.put(ObjectFactoryBuilder.IS_KC_OBJECT_FACTORY_BUILDER, Boolean.TRUE);

        try {
            Object instance = NamingManager.getObjectInstance(null, null, null, env);

            if (instance != null && instance.getClass().getName().equals(ObjectFactoryBuilder.class.getName())) {
                return true;
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to determine if ObjectFactoryBuilder is set", e);
        }

        return false;
    }

    @Override
    public ObjectFactory createObjectFactory(Object obj, Hashtable<?, ?> environment) throws NamingException {
        if (logger.isTraceEnabled()) {
            logger.tracef("Creating ObjectFactory for object: %s", obj);
        }

        if (obj instanceof Reference ref) {
            String factoryClassName = ref.getFactoryClassName();

            if (factoryClassName != null) {
                logger.warnf("Referral refence contains an object factory %s but it will be ignored", factoryClassName);
            }

            String ldapUrl = getLdapUrl(ref);

            if (ldapUrl != null) {
                checkReferralHosts(ldapUrl);
                return new DirContextObjectFactory(ldapUrl);
            }
        } else {
            logger.debugf("Unsupported reference object of type %s: ", obj);
            return this;
        }

        throw new CommunicationException("Referral reference does not contain an LDAP URL: " + obj);
    }

    // Referral URLs must pass the same host allow-list as the configured connection URL; otherwise an allowed
    // LDAP server could redirect the client to an arbitrary (e.g. internal) host. Fails closed on unknown hosts.
    private static void checkReferralHosts(String ldapUrl) throws CommunicationException {
        LdapHostAllowList allowList = allowedHosts;
        if (!allowList.isEnforced()) {
            return;
        }
        for (String url : ldapUrl.split(" ")) {
            String host;
            try {
                host = URI.create(url).getHost();
            } catch (IllegalArgumentException e) {
                throw new CommunicationException("Malformed referral URL: " + url);
            }
            if (!allowList.isAllowed(host)) {
                logger.warnf("Referral URL host is not permitted by the LDAP allowed-hosts list. Rejecting referral: %s", url);
                throw new CommunicationException("Referral URL host is not permitted by the LDAP allowed-hosts list: " + url);
            }
        }
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> env) {
        if (env != null && env.containsKey(IS_KC_OBJECT_FACTORY_BUILDER)) {
            return this;
        }
        return obj;
    }

    private String getLdapUrl(Reference ref) {
        for (int i = 0; i < ref.size(); i++) {
            RefAddr addr = ref.get(i);
            String addrType = addr.getType();

            if ("URL".equalsIgnoreCase(addrType)) {
                Object content = addr.getContent();

                if (content == null) {
                    return null;
                }

                String rawUrl = content.toString();

                for (String url : List.of(rawUrl.split(" "))) {
                    if (!url.toLowerCase().startsWith("ldap")) {
                        logger.warnf("Unsupported scheme from reference URL %s. Ignoring reference.", url);
                        return null;
                    }
                }

                return rawUrl;
            } else {
                logger.warnf("Ignoring address of type '%s' from referral reference", addrType);
            }
        }

        return null;
    }

    private record DirContextObjectFactory(String ldapUrl) implements ObjectFactory {

        @Override
        public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> env) throws Exception {
            @SuppressWarnings("unchecked")
            Hashtable<Object, Object> newEnv = (Hashtable<Object, Object>) env.clone();
            newEnv.put(LdapContext.PROVIDER_URL, ldapUrl);
            return new SessionBoundInitialLdapContext(KeycloakSessionUtil.getKeycloakSession(), newEnv, null);
        }
    }
}
