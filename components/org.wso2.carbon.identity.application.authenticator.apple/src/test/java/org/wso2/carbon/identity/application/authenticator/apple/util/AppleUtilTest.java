/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 *
 */

package org.wso2.carbon.identity.application.authenticator.apple.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.apple.AppleErrorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for the Apple authenticator util class.
 */
public class AppleUtilTest {

    private static Map<String, String> testAuthenticatorProperties;
    private MockedStatic<KeyFactory> keyFactory;

    private final long currentEpochTime = Instant.now().getEpochSecond();
    private final long newExpiryEpochTime = currentEpochTime + 7200;

    @AfterClass
    public void tearDown() {

        keyFactory.close();
    }

    @Test
    public void testGenerateClientSecret() throws AuthenticationFailedException, ParseException {

        initAuthenticatorProperties();
        String clientSecret = AppleUtil.generateClientSecret(testAuthenticatorProperties, currentEpochTime,
                newExpiryEpochTime);
        String[] clientSecretParts = clientSecret.split("\\.");

        // Assert for header.
        byte[] decodedHeader = Base64.decodeBase64(clientSecretParts[0].getBytes(StandardCharsets.UTF_8));
        Set<Map.Entry<String, Object>> headerAttributes = JSONObjectUtils.parseJSONObject(
                new String(decodedHeader, StandardCharsets.UTF_8)).entrySet();
        for (Map.Entry<String, Object> entry: headerAttributes) {
            switch (entry.getKey()) {
                case "kid":
                    assertEquals(entry.getValue(), testAuthenticatorProperties.get(
                            AppleAuthenticatorConstants.KEY_ID));
                    break;
                case "alg":
                    assertEquals(entry.getValue(), JWSAlgorithm.ES256.getName());
                    break;
                default:
                    break;
            }
        }

        // Assert for jwt attributes.
        byte[] decodedBody = Base64.decodeBase64(clientSecretParts[1].getBytes(StandardCharsets.UTF_8));
        Set<Map.Entry<String, Object>> jwtAttributeSet = JSONObjectUtils.parseJSONObject(
                new String(decodedBody, StandardCharsets.UTF_8)).entrySet();
        for (Map.Entry<String, Object> entry: jwtAttributeSet) {
            switch (entry.getKey()) {
                case OAuth2Util.ISS:
                    assertEquals(entry.getValue(), testAuthenticatorProperties.get(
                            AppleAuthenticatorConstants.TEAM_ID));
                    break;
                case OAuth2Util.IAT:
                    assertEquals(entry.getValue(), currentEpochTime);
                    break;
                case OAuth2Util.EXP:
                    assertEquals(entry.getValue(), newExpiryEpochTime);
                    break;
                case OAuth2Util.AUD:
                    assertEquals(entry.getValue(), AppleAuthenticatorConstants.CLIENT_SECRET_JWT_AUDIENCE);
                    break;
                case OAuth2Util.SUB:
                    assertEquals(entry.getValue(), testAuthenticatorProperties.get(
                            OIDCAuthenticatorConstants.CLIENT_ID));
                    break;
                default:
                    break;
            }
        }
    }

    @DataProvider(name = "generateClientSecretDataProvider")
    public Object[][] generateClientSecretDataProvider() {

        keyFactory = mockStatic(KeyFactory.class);

        // Expected exception.
        return new Object[][] {
                {NoSuchAlgorithmException.class},
                {InvalidKeySpecException.class}
        };
    }

    @Test(dataProvider = "generateClientSecretDataProvider")
    public void testGenerateClientSecretWithError(Class<Exception> expectedException)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        initAuthenticatorProperties();
        KeyFactory keyFactoryMock;

        if (expectedException.equals(NoSuchAlgorithmException.class)) {
            when(KeyFactory.getInstance("EC")).thenThrow(NoSuchAlgorithmException.class);
        } else if (expectedException.equals(InvalidKeySpecException.class)) {
            keyFactoryMock = mock(KeyFactory.class);
            when(KeyFactory.getInstance(any())).thenReturn(keyFactoryMock);
            when(keyFactoryMock.generatePrivate(any())).thenThrow(InvalidKeySpecException.class);
        }

        try {
            AppleUtil.generateClientSecret(testAuthenticatorProperties, currentEpochTime, newExpiryEpochTime);
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_PRIVATE_KEY
                    .getCode());
        }
    }

    private void initAuthenticatorProperties() {

        testAuthenticatorProperties = new HashMap<>();
        testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "testClientId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.TEAM_ID, "testTeamId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.KEY_ID, "testKeyId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.PRIVATE_KEY, "-----BEGIN PRIVATE KEY-----\n" +
                "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgzFs/tGqHIchtAQyxZNNo\n" +
                "Ml/8lB/FhBlUvIdAfLBF5/2hRANCAATV2pzqzrpi6PvE0u08cSEKtwv8jqTdEx1S\n" +
                "rlf5IBbG+Y4Roo1zQ4s1ztL4j9kQmea6+TvYsRXDn2599Ea5dki/\n" +
                "-----END PRIVATE KEY-----\n");
    }
}
