/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.apple.executor;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Unit tests for {@link AppleExecutor}.
 */
public class AppleExecutorTest {

    private AppleExecutor appleExecutor;
    private Map<String, String> authenticatorProperties;

    @BeforeClass
    public void setUp() {

        appleExecutor = new AppleExecutor();
        authenticatorProperties = new HashMap<>();
    }

    @Test
    public void testGetName() {

        assertEquals(appleExecutor.getName(), "AppleExecutor", "Executor name should match");
    }

    @Test
    public void testGetAuthorizationServerEndpointWithCustomValue() {

        authenticatorProperties.put(AppleAuthenticatorConstants.APPLE_AUTHZ_ENDPOINT,
                "https://custom-apple-auth.com/authorize");
        String endpoint = appleExecutor.getAuthorizationServerEndpoint(authenticatorProperties);
        assertEquals(endpoint, "https://custom-apple-auth.com/authorize",
                "Should return custom authorization endpoint when specified");
    }

    @Test
    public void testGetAuthorizationServerEndpointWithDefaultValue() {

        authenticatorProperties.remove(AppleAuthenticatorConstants.APPLE_AUTHZ_ENDPOINT);
        String endpoint = appleExecutor.getAuthorizationServerEndpoint(authenticatorProperties);
        assertEquals(endpoint, AppleAuthenticatorConstants.AUTHORIZATION_SERVER_ENDPOINT,
                "Should return default authorization endpoint when not specified");
    }

    @Test
    public void testGetTokenEndpointWithCustomValue() {

        authenticatorProperties.put(AppleAuthenticatorConstants.APPLE_TOKEN_ENDPOINT,
                "https://custom-apple-auth.com/token");
        String endpoint = appleExecutor.getTokenEndpoint(authenticatorProperties);
        assertEquals(endpoint, "https://custom-apple-auth.com/token",
                "Should return custom token endpoint when specified");
    }

    @Test
    public void testGetTokenEndpointWithDefaultValue() {

        authenticatorProperties.remove(AppleAuthenticatorConstants.APPLE_TOKEN_ENDPOINT);
        String endpoint = appleExecutor.getTokenEndpoint(authenticatorProperties);
        assertEquals(endpoint, AppleAuthenticatorConstants.TOKEN_ENDPOINT,
                "Should return default token endpoint when not specified");
    }

    @Test
    public void testGetUserInfoEndpoint() {

        String userInfoEndpoint = appleExecutor.getUserInfoEndpoint(authenticatorProperties);
        assertNull(userInfoEndpoint, "User info endpoint should be null for Apple");
    }

    @DataProvider(name = "jsonObjectProvider")
    public Object[][] getJsonObjects() {
        // Test case 1: JSON object with email
        Map<String, Object> jsonWithEmail = new HashMap<>();
        jsonWithEmail.put(OIDCAuthenticatorConstants.Claim.EMAIL, "user@example.com");
        jsonWithEmail.put(OIDCAuthenticatorConstants.Claim.SUB, "123456");

        // Test case 2: JSON object with only SUB
        Map<String, Object> jsonWithoutEmail = new HashMap<>();
        jsonWithoutEmail.put(OIDCAuthenticatorConstants.Claim.SUB, "123456");

        return new Object[][]{
                {jsonWithEmail, "user@example.com"},
                {jsonWithoutEmail, "123456"}
        };
    }

    @Test(dataProvider = "jsonObjectProvider")
    public void testGetAuthenticatedUserIdentifier(Map<String, Object> jsonObject, String expectedUser) {

        String authenticatedUser = appleExecutor.getAuthenticatedUserIdentifier(jsonObject);
        assertEquals(authenticatedUser, expectedUser, "Authenticated user should match expected value");
    }
}
