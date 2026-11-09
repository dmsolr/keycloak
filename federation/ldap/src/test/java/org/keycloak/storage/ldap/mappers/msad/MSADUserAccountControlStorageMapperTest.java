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

package org.keycloak.storage.ldap.mappers.msad;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.requiredactions.UpdatePassword;
import org.keycloak.services.messages.Messages;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.mappers.msad.MSADUserAccountControlStorageMapper.AuthErrorAction;
import org.keycloak.storage.ldap.mappers.msad.MSADUserAccountControlStorageMapper.AuthErrorOutcome;

/**
 * 使用 MSAD 与 Samba AD DC 在 simple bind 失败时返回的诊断消息，
 * 验证 {@link MSADUserAccountControlStorageMapper#extractErrorCode(String)}，
 * 以及 {@link MSADUserAccountControlStorageMapper#resolveAuthErrorCode(String, UserStorageProvider.EditMode)}
 * 在不同 Edit mode 下的处理结果。
 */
public class MSADUserAccountControlStorageMapperTest {

    @Test
    public void testMsadPasswordExpired() {
        Assert.assertEquals("532", MSADUserAccountControlStorageMapper.extractErrorCode(
                "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 532, v4563\u0000]"));
    }

    @Test
    public void testMsadPasswordMustChange() {
        Assert.assertEquals("773", MSADUserAccountControlStorageMapper.extractErrorCode(
                "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 773, v4563\u0000]"));
    }

    @Test
    public void testMsadInvalidCredentials() {
        Assert.assertEquals("52e", MSADUserAccountControlStorageMapper.extractErrorCode(
                "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563\u0000]"));
    }

    @Test
    public void testSambaPasswordMustChange() {
        Assert.assertEquals("773", MSADUserAccountControlStorageMapper.extractErrorCode(
                "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 773, v1db1]"));
    }

    @Test
    public void testSambaPasswordExpired() {
        Assert.assertEquals("532", MSADUserAccountControlStorageMapper.extractErrorCode(
                "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 532, v1db1]"));
    }

    @Test
    public void testMessageWithLineBreak() {
        Assert.assertEquals("532", MSADUserAccountControlStorageMapper.extractErrorCode(
                "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09044E,\ncomment: AcceptSecurityContext error, data 532, v4563\n]"));
    }

    @Test
    public void testUnrelatedMessage() {
        Assert.assertNull(MSADUserAccountControlStorageMapper.extractErrorCode("[LDAP: error code 49 - Invalid Credentials]"));
    }

    @Test
    public void testNullMessage() {
        Assert.assertNull(MSADUserAccountControlStorageMapper.extractErrorCode(null));
    }

    private static void assertOutcome(String errorCode, UserStorageProvider.EditMode editMode, boolean allowed,
                                      AuthErrorAction action, String noteName, String messageKey) {
        AuthErrorOutcome outcome = MSADUserAccountControlStorageMapper.resolveAuthErrorCode(errorCode, editMode);
        Assert.assertEquals("allowed for " + errorCode + "/" + editMode, allowed, outcome.allowed);
        Assert.assertEquals("action for " + errorCode + "/" + editMode, action, outcome.action);
        Assert.assertEquals("note for " + errorCode + "/" + editMode, noteName, outcome.authNoteName);
        Assert.assertEquals("message for " + errorCode + "/" + editMode, messageKey, outcome.messageKey);
    }

    @Test
    public void testPasswordExpiredWritable() {
        for (String code : new String[]{"532", "773"}) {
            assertOutcome(code, UserStorageProvider.EditMode.WRITABLE, true, AuthErrorAction.UPDATE_PASSWORD,
                    UpdatePassword.UPDATE_PASSWORD_MESSAGE, Messages.PASSWORD_EXPIRED_UPDATE);
        }
    }

    @Test
    public void testPasswordExpiredNonWritable() {
        for (String code : new String[]{"532", "773"}) {
            for (UserStorageProvider.EditMode mode : new UserStorageProvider.EditMode[]{
                    UserStorageProvider.EditMode.READ_ONLY, UserStorageProvider.EditMode.UNSYNCED}) {
                assertOutcome(code, mode, false, AuthErrorAction.NONE,
                        AbstractUsernameFormAuthenticator.LOGIN_ERROR_MESSAGE, Messages.PASSWORD_EXPIRED_CONTACT_ADMIN);
            }
        }
    }

    @Test
    public void testAccountExpiredAllModes() {
        for (UserStorageProvider.EditMode mode : UserStorageProvider.EditMode.values()) {
            assertOutcome("701", mode, false, AuthErrorAction.NONE,
                    AbstractUsernameFormAuthenticator.LOGIN_ERROR_MESSAGE, Messages.ACCOUNT_EXPIRED);
        }
    }

    @Test
    public void testAccountDisabledWritable() {
        assertOutcome("533", UserStorageProvider.EditMode.WRITABLE, true, AuthErrorAction.DISABLE_USER, null, null);
    }

    @Test
    public void testAccountDisabledNonWritable() {
        for (UserStorageProvider.EditMode mode : new UserStorageProvider.EditMode[]{
                UserStorageProvider.EditMode.READ_ONLY, UserStorageProvider.EditMode.UNSYNCED}) {
            assertOutcome("533", mode, false, AuthErrorAction.NONE,
                    AbstractUsernameFormAuthenticator.LOGIN_ERROR_MESSAGE, Messages.ACCOUNT_DISABLED);
        }
    }

    @Test
    public void testAccountLockedAllModes() {
        for (UserStorageProvider.EditMode mode : UserStorageProvider.EditMode.values()) {
            assertOutcome("775", mode, false, AuthErrorAction.NONE,
                    AbstractUsernameFormAuthenticator.LOGIN_ERROR_MESSAGE, Messages.ACCOUNT_LOCKED);
        }
    }

    @Test
    public void testInvalidCredentialsAllModes() {
        for (UserStorageProvider.EditMode mode : UserStorageProvider.EditMode.values()) {
            assertOutcome("52e", mode, false, AuthErrorAction.NONE, null, null);
        }
    }
}
