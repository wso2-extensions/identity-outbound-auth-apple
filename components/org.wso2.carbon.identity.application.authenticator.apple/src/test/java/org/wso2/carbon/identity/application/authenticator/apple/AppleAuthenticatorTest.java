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

package org.wso2.carbon.identity.application.authenticator.apple;

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the Apple authenticator class.
 */
public class AppleAuthenticatorTest {

    private AppleAuthenticator appleAuthenticator;
    private static Map<String, String> testAuthenticatorProperties;
    private static AuthenticatorConfig authenticatorConfig;

    @Mock
    private OAuthClientResponse oAuthClientResponseMock;

    private AuthenticationContext authenticationContextMock;
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilderMock;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder;

    private static final String TEST_EMAIL = "user@test.com";
    private static final String TEST_SUB = "testSub";

    @BeforeClass
    public void setup() {

        appleAuthenticator = new AppleAuthenticator();

        testAuthenticatorProperties = new HashMap<>();
        testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "testClientId");
        testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.CLIENT_SECRET_VALIDITY_PERIOD, "7200");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.TEAM_ID, "testTeamId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.KEY_ID, "testKeyId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.PRIVATE_KEY, "testPrivateKey");
        testAuthenticatorProperties.put(IdentityApplicationConstants.OAuth2.CALLBACK_URL,
                "https://localhost:9443/commonauth");
        testAuthenticatorProperties.put(IdentityApplicationConstants.Authenticator.OIDC.SCOPES, "name email");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.ADDITIONAL_QUERY_PARAMETERS, "");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET, "false");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA, "0");

        authenticatorConfig = new AuthenticatorConfig();

        // Initialize mocks.
        fileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        fileBasedConfigurationBuilderMock = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilderMock);
        when(fileBasedConfigurationBuilderMock.getAuthenticatorBean(AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME))
                .thenReturn(authenticatorConfig);
        authenticationContextMock = mock(AuthenticationContext.class);
        when(authenticationContextMock.getAuthenticatorProperties()).thenReturn(testAuthenticatorProperties);
    }

    @AfterClass
    public void tearDown() {

        fileBasedConfigurationBuilder.close();
    }

    @Test
    public void testInitiateAuthenticationRequest() {

        String expectedUrl = "https://appleid.apple.com/auth/authorize?response_type=code&client_id=testClientId&redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fcommonauth&scope=name%20email&state=af0ifjsldkj";

        // TODO.
    }

//    @Test
//    public void testProcessAuthenticationResponse() {
//
//        // TODO.
//    }

    @Test
    public void testGetName() {

        String name = appleAuthenticator.getName();
        Assert.assertEquals(name, AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME);
    }

    @Test
    public void testGetFriendlyName() {

        String friendlyName = appleAuthenticator.getFriendlyName();
        Assert.assertEquals(friendlyName, AppleAuthenticatorConstants.APPLE_CONNECTOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetSubjectAttributes() {

        Map<ClaimMapping, String> subjectAttributes = appleAuthenticator.getSubjectAttributes(oAuthClientResponseMock,
                testAuthenticatorProperties);
        Assert.assertEquals(subjectAttributes.size(), 0);
    }

    @DataProvider(name = "getClaimDialectURIDataProvider")
    public Object[][] getClaimDialectURIDataProvider() {

        String oidcDialectUri = "http://wso2.org/oidc/claim";
        String customDialectUri = "http://custom/dialect";

        Map<String, String> parameterMap1 = new HashMap<>();

        Map<String, String> parameterMap2 = new HashMap<>();
        parameterMap2.put(AppleAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER, customDialectUri);

        return new Object[][]{
                {parameterMap1, oidcDialectUri},
                {parameterMap2, customDialectUri}
        };
    }

    @Test(dataProvider = "getClaimDialectURIDataProvider")
    public void testGetClaimDialectURI(Map<String, String> parameterMap, String expectedClaimDialectURI) {

        authenticatorConfig.setParameterMap(parameterMap);
        String claimDialectURI = appleAuthenticator.getClaimDialectURI();
        Assert.assertEquals(claimDialectURI, expectedClaimDialectURI);
    }

    @Test
    public void testGetQueryString() {

        testAuthenticatorProperties.put(AppleAuthenticatorConstants.ADDITIONAL_QUERY_PARAMETERS, "param1=value1");
        String queryString = appleAuthenticator.getQueryString(testAuthenticatorProperties);
        Assert.assertEquals(queryString, "param1=value1");
    }

    @Test
    public void testGetUserInfoEndpoint() {

        String userInfoEndpoint = appleAuthenticator.getUserInfoEndpoint(oAuthClientResponseMock,
                testAuthenticatorProperties);
        Assert.assertNull(userInfoEndpoint);
    }

    @DataProvider(name = "getAuthenticateUserDataProvider")
    public Object[][] getAuthenticateUserDataProvider() {

        Map<String, Object> oidcClaims1 = new HashMap<>();
        oidcClaims1.put("sub", TEST_SUB);
        oidcClaims1.put("email", TEST_EMAIL);
        oidcClaims1.put("email_verified", "true");

        Map<String, Object> oidcClaims2 = new HashMap<>();
        oidcClaims2.put("sub", TEST_SUB);
        oidcClaims2.put("email_verified", "true");

        return new Object[][]{
                {oidcClaims1, TEST_EMAIL},
                {oidcClaims2, TEST_SUB}
        };
    }

    @Test(dataProvider = "getAuthenticateUserDataProvider")
    public void testGetAuthenticateUser(Map<String, Object> oidcClaims, String expectedUserAttribute) {

        String authenticateUser = appleAuthenticator.getAuthenticateUser(authenticationContextMock,
                oidcClaims, oAuthClientResponseMock);
        Assert.assertEquals(authenticateUser, expectedUserAttribute);
    }

    @DataProvider(name = "getScopeDataProvider")
    public Object[][] getScopeDataProvider() {

        String testScope = "email";

        return new Object[][]{
                {testScope, testScope},
                {"", ""}
        };
    }

    @Test(dataProvider = "getScopeDataProvider")
    public void testGetScope(String scope, String expectedScope) {

        String returnedScope = appleAuthenticator.getScope(scope, testAuthenticatorProperties);
        Assert.assertEquals(returnedScope, expectedScope);
    }

    @Test
    public void testGetTokenEndpoint() {

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(AppleAuthenticatorConstants.APPLE_TOKEN_ENDPOINT, AppleAuthenticatorConstants.TOKEN_ENDPOINT);
        authenticatorConfig.setParameterMap(parameterMap);
        String tokenEndpoint = appleAuthenticator.getTokenEndpoint(testAuthenticatorProperties);
        Assert.assertEquals(tokenEndpoint, AppleAuthenticatorConstants.TOKEN_ENDPOINT);
    }

    @Test
    public void getAuthorizationServerEndpoint() {

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(AppleAuthenticatorConstants.APPLE_AUTHZ_ENDPOINT,
                AppleAuthenticatorConstants.AUTHORIZATION_SERVER_ENDPOINT);
        authenticatorConfig.setParameterMap(parameterMap);
        String authorizationServerEndpoint = appleAuthenticator.getAuthorizationServerEndpoint(
                testAuthenticatorProperties);
        Assert.assertEquals(authorizationServerEndpoint, AppleAuthenticatorConstants.AUTHORIZATION_SERVER_ENDPOINT);
    }
}
