/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.models.utils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;

import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit tests for {@link RepresentationToModel} credential conversion logic.
 */
public class RepresentationToModelTest {

    /**
     * Reflectively invokes the private {@code convertDeprecatedCredentialsFormat} method.
     */
    private void convertDeprecatedCredentialsFormat(UserRepresentation user) throws Exception {
        Method method = RepresentationToModel.class.getDeclaredMethod("convertDeprecatedCredentialsFormat", UserRepresentation.class);
        method.setAccessible(true);
        try {
            method.invoke(null, user);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new RuntimeException(cause);
        }
    }

    /**
     * Deserialises a {@code CredentialRepresentation} from a JSON string so that deprecated
     * fields (which have no public setters) can be populated for testing.
     */
    private CredentialRepresentation credFromJson(String json) throws Exception {
        return JsonSerialization.readValue(json, CredentialRepresentation.class);
    }

    /**
     * Regression test for https://github.com/keycloak/keycloak/issues/41640.
     * A deprecated password credential with {@code hashIterations} absent (null) must not throw NPE.
     */
    @Test
    public void testConvertDeprecatedPasswordCredential_nullHashIterations() throws Exception {
        CredentialRepresentation cred = credFromJson(
                "{\"type\":\"password\",\"hashedSaltedValue\":\"hashedValue\",\"salt\":\"saltValue\"}");

        UserRepresentation user = new UserRepresentation();
        user.setUsername("testuser");
        user.setCredentials(Collections.singletonList(cred));

        // Must not throw NullPointerException
        convertDeprecatedCredentialsFormat(user);

        Assert.assertNotNull("credentialData should be populated after conversion", cred.getCredentialData());
        Assert.assertNotNull("secretData should be populated after conversion", cred.getSecretData());
    }

    /**
     * A deprecated TOTP credential with {@code digits}, {@code counter}, and {@code period} absent (null)
     * must not throw NPE.
     */
    @Test
    public void testConvertDeprecatedTotpCredential_nullOtpFields() throws Exception {
        CredentialRepresentation cred = credFromJson(
                "{\"type\":\"totp\",\"hashedSaltedValue\":\"otpSecret\"}");

        UserRepresentation user = new UserRepresentation();
        user.setUsername("otpuser");
        user.setCredentials(Collections.singletonList(cred));

        // Must not throw NullPointerException
        convertDeprecatedCredentialsFormat(user);

        Assert.assertNotNull("credentialData should be populated after conversion", cred.getCredentialData());
        Assert.assertNotNull("secretData should be populated after conversion", cred.getSecretData());
        Assert.assertEquals("type should be normalised to otp", OTPCredentialModel.TYPE, cred.getType());
    }

    /**
     * A deprecated password credential with all fields populated (including hashIterations) should
     * still convert correctly after the null-safe fix.
     */
    @Test
    public void testConvertDeprecatedPasswordCredential_withHashIterations() throws Exception {
        CredentialRepresentation cred = credFromJson(
                "{\"type\":\"password\",\"hashedSaltedValue\":\"hashedValue\",\"salt\":\"saltValue\","
                + "\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\"}");

        UserRepresentation user = new UserRepresentation();
        user.setUsername("testuser2");
        user.setCredentials(Collections.singletonList(cred));

        convertDeprecatedCredentialsFormat(user);

        Assert.assertNotNull(cred.getCredentialData());
        Assert.assertTrue("credentialData should embed hashIterations",
                cred.getCredentialData().contains("27500"));
    }
}
