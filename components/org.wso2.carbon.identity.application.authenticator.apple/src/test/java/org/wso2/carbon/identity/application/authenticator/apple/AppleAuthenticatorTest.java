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

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authenticator.apple.internal.AppleAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.REDIRECT_URL_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.SCOPE_PARAM_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.STATE_PARAM_SUFFIX;

/**
 * Unit tests for the Apple authenticator class.
 */
public class AppleAuthenticatorTest {

    private AppleAuthenticator appleAuthenticator;
    private static Map<String, String> testAuthenticatorProperties;
    private static AuthenticatorConfig authenticatorConfig;
    private static AuthenticationContext authenticationContext;
    private static boolean isAPIBased;

    private AutoCloseable autoCloseable;
    @Mock
    private RealmService realmServiceMock;
    @Mock
    private AppleAuthenticatorDataHolder appleAuthenticatorDataHolderMock;
    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilderMock;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder;
    private MockedStatic<AppleAuthenticatorDataHolder> appleAuthenticatorDataHolder;
    private MockedStatic<LoggerUtils> loggerUtilsMock;

    private static final String TEST_EMAIL = "user@test.com";
    private static final String TEST_TENANT = "testtenant";
    private static final int TEST_TENANT_ID = 1234;
    private static final String TEST_IDP_RESOURCE_ID = "resourceId";
    private static final String CONTEXT_IDENTIFIER = "contextIdentifier";

    // JWT claims.
    private static final String TEST_ISS = "https://appleid.apple.com";
    private static final String TEST_IAT = "1674907200";
    private static final String TEST_EXP = "1675080000";
    private static final String TEST_AUD = "client_id";
    private static final String TEST_SUB = "sample_subject";
    private static final String TEST_AT_HASH = "at_hash";
    private static final String TEST_AUTH_TIME = "1675062544";
    private static final String TEST_EMAIL_VERIFIED = "true";

    @BeforeClass
    public void setup() {

        appleAuthenticator = new AppleAuthenticatorTestWrapper();
        autoCloseable = openMocks(this);
        authenticatorConfig = new AuthenticatorConfig();
        initAuthenticatorProperties();
        initAuthenticationContext();

        // Initialize mocks.
        fileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilderMock);
        when(fileBasedConfigurationBuilderMock.getAuthenticatorBean(AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME))
                .thenReturn(authenticatorConfig);

        appleAuthenticatorDataHolder = mockStatic(AppleAuthenticatorDataHolder.class);
        appleAuthenticatorDataHolder.when(AppleAuthenticatorDataHolder::getInstance).thenReturn(
                appleAuthenticatorDataHolderMock);
        when(appleAuthenticatorDataHolderMock.getRealmService()).thenReturn(realmServiceMock);

        loggerUtilsMock = mockStatic(LoggerUtils.class);
        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
    }

    @AfterClass
    public void tearDown() throws Exception {

        fileBasedConfigurationBuilder.close();
        appleAuthenticatorDataHolder.close();
        autoCloseable.close();
    }

    @DataProvider(name = "initiateAuthenticationRequestDataProvider")
    public Object[][] initiateAuthenticationRequestDataProvider() {

        // {secret_regenerate_condition}.
        return new Object[][]{
                {"NONE"},
                {"EXPIRED_SECRET"},
                {"EMPTY_SECRET"},
                {"REGEN_PROPERTY"}
        };
    }

    @Test(dataProvider = "initiateAuthenticationRequestDataProvider")
    public void testInitiateAuthenticationRequest(String secretGenerateCondition)
            throws IOException, AuthenticationFailedException, IdentityProviderManagementException {

        initAuthenticatorProperties();
        initAuthenticationContext();
        HttpServletRequest httpServletRequestMock = mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponseMock = mock(HttpServletResponse.class);
        IdpManager idpManagerMock = mock(IdpManager.class);
        when(appleAuthenticatorDataHolderMock.getIdpManager()).thenReturn(idpManagerMock);

        Map<String, String[]> requestParameters = new HashMap<>();
        requestParameters.put("idp", new String[]{"Apple"});
        requestParameters.put("authenticator", new String[]{"AppleOIDCAuthenticator"});
        requestParameters.put("sessionDataKey", new String[]{"4011bbfb-gg61-4w4h-bf97-184d4b1s6j10"});
        String multiOptionURI = "/t/" + TEST_TENANT + "/authenticationendpoint/oauth2_login.do?authenticators=" +
                "AppleOIDCAuthenticator%3AApple&response_type=code&type=oidc&nonce=kz6ga8aww63&client_id=" +
                "sampleClientId&response_mode=form_post";
        requestParameters.put("multiOptionURI", new String[]{multiOptionURI});

        when(httpServletRequestMock.getParameterMap()).thenReturn(requestParameters);
        when(httpServletResponseMock.encodeRedirectURL(anyString())).thenAnswer(
                invocation -> invocation.getArgument(0));

        switch (secretGenerateCondition) {
            case "NONE":
                testAuthenticatorProperties.put(AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA,
                        Long.toString(Instant.now().getEpochSecond() + 7200));
                break;
            case "EXPIRED_SECRET":
                testAuthenticatorProperties.put(AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA,
                        Long.toString(Instant.now().getEpochSecond() - 7200));
                break;
            case "EMPTY_SECRET":
                testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "");
                break;
            case "REGEN_PROPERTY":
                testAuthenticatorProperties.put(AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET, "true");
                break;
            default:
                break;
        }

        ArgumentCaptor<String> idpResourceIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<IdentityProvider> identityProviderCaptor = ArgumentCaptor.forClass(IdentityProvider.class);
        ArgumentCaptor<String> tenantDomainCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> servelettResponseCaptor = ArgumentCaptor.forClass(String.class);

        appleAuthenticator.initiateAuthenticationRequest(httpServletRequestMock, httpServletResponseMock,
                authenticationContext);

        // Assert for identity provider update call when secret generation happens.
        if (!StringUtils.equals(secretGenerateCondition, "NONE")) {
            verify(idpManagerMock).updateIdPByResourceId(idpResourceIdCaptor.capture(),
                    identityProviderCaptor.capture(), tenantDomainCaptor.capture());
            Assert.assertEquals(idpResourceIdCaptor.getValue(), TEST_IDP_RESOURCE_ID);
            Assert.assertEquals(identityProviderCaptor.getValue(), authenticationContext.getExternalIdP()
                    .getIdentityProvider());
            Assert.assertEquals(tenantDomainCaptor.getValue(), TEST_TENANT);
        }

        // Assert servlet redirect.
        verify(httpServletResponseMock).sendRedirect(servelettResponseCaptor.capture());
        String redirectUrl = servelettResponseCaptor.getValue();
        Assert.assertTrue(redirectUrl.contains("https://appleid.apple.com/auth/authorize"));
        Assert.assertTrue(redirectUrl.contains("response_type=code"));
        Assert.assertTrue(redirectUrl.contains("client_id=testClientId"));
        Assert.assertTrue(redirectUrl.contains("scope=name%20email"));
        Assert.assertTrue(redirectUrl.contains("response_mode=form_post"));

        if (isAPIBased) {
            Assert.assertTrue(Boolean.parseBoolean(
                    (String) authenticationContext.getProperty(AppleAuthenticatorConstants.IS_API_BASED)));
            Assert.assertNotNull(authenticationContext.getProperty(AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME
                    + STATE_PARAM_SUFFIX));
            Assert.assertNotNull(authenticationContext.getProperty(AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME
                    + SCOPE_PARAM_SUFFIX));
            String redirectUrlPropertyKey = AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME + REDIRECT_URL_SUFFIX;
            Assert.assertNotNull(authenticationContext.getProperty(redirectUrlPropertyKey));
            // For API based auth flow, the redirect URL should not be equal to commonauth endpoint.
            Assert.assertFalse(redirectUrl.contains("https://localhost:9443/commonauth"));
        }
    }

    @Test(dataProvider = "initiateAuthenticationRequestDataProvider")
    public void testInitiateAuthenticationRequestForAPIBased(String secretGenerateCondition)
            throws AuthenticationFailedException, IOException, IdentityProviderManagementException {

        isAPIBased = true;
        testInitiateAuthenticationRequest(secretGenerateCondition);
    }

    @DataProvider(name = "initiateAuthenticationRequestExceptionDataProvider")
    public Object[][] initiateAuthenticationRequestExceptionDataProvider() {

        // {expected exception code}.
        return new Object[][]{
                {OIDCErrorConstants.ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getCode()},
                {AppleErrorConstants.ErrorMessages.UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY.getCode()},
                {AppleErrorConstants.ErrorMessages.REQUIRED_FIELDS_FOR_CLIENT_SECRET_NOT_FOUND.getCode()},
                {AppleErrorConstants.ErrorMessages.NULL_IDP_IN_AUTHENTICATION_CONTEXT.getCode()},
                {AppleErrorConstants.ErrorMessages.ERROR_WHILE_UPDATING_IDENTITY_PROVIDER.getCode()}
        };
    }

    @Test(dataProvider = "initiateAuthenticationRequestExceptionDataProvider")
    public void testInitiateAuthenticationRequestWithExceptions(String expectedExceptionCode)
            throws IdentityProviderManagementException {

        HttpServletRequest httpServletRequestMock = mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponseMock = mock(HttpServletResponse.class);

        if (StringUtils.equals(expectedExceptionCode, OIDCErrorConstants.ErrorMessages
                .RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getCode())) {
            authenticationContext.setAuthenticatorProperties(Collections.emptyMap());
        } else if (StringUtils.equals(expectedExceptionCode, AppleErrorConstants.ErrorMessages
                .UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY.getCode())) {
            testAuthenticatorProperties.put(AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA, "invalid");
            authenticationContext = new AuthenticationContext();
            authenticationContext.setAuthenticatorProperties(testAuthenticatorProperties);
        } else if (StringUtils.equals(expectedExceptionCode, AppleErrorConstants.ErrorMessages
                .REQUIRED_FIELDS_FOR_CLIENT_SECRET_NOT_FOUND.getCode())) {
            testAuthenticatorProperties.remove(AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA);
            testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "");
            testAuthenticatorProperties.put(AppleAuthenticatorConstants.TEAM_ID, "");
            authenticationContext = new AuthenticationContext();
            authenticationContext.setAuthenticatorProperties(testAuthenticatorProperties);
        } else if (StringUtils.equals(expectedExceptionCode, AppleErrorConstants.ErrorMessages
                .NULL_IDP_IN_AUTHENTICATION_CONTEXT.getCode())) {
            initAuthenticatorProperties();
            initAuthenticationContext();
            authenticationContext.setExternalIdP(null);
        } else if (StringUtils.equals(expectedExceptionCode, AppleErrorConstants.ErrorMessages
                .ERROR_WHILE_UPDATING_IDENTITY_PROVIDER.getCode())) {
            IdpManager idpManagerMock = mock(IdpManager.class);
            when(appleAuthenticatorDataHolderMock.getIdpManager()).thenReturn(idpManagerMock);
            when(idpManagerMock.updateIdPByResourceId(anyString(), any(), anyString())).thenThrow(
                    new IdentityProviderManagementException(IdPManagementConstants.ErrorMessage
                            .ERROR_CODE_IDP_DOES_NOT_EXIST.getCode(), IdPManagementConstants.ErrorMessage
                            .ERROR_CODE_IDP_DOES_NOT_EXIST.getMessage()));
            initAuthenticatorProperties();
            initAuthenticationContext();
        }

        try {
            appleAuthenticator.initiateAuthenticationRequest(httpServletRequestMock, httpServletResponseMock,
                    authenticationContext);
            Assert.fail("Expected AuthenticationFailedException is not thrown.");
        } catch (AuthenticationFailedException e) {
            Assert.assertEquals(e.getErrorCode(), expectedExceptionCode);
        }
    }

    @Test
    public void testProcessAuthenticationResponse() throws UserStoreException {

        initAuthenticatorProperties();
        initAuthenticationContext();
        HttpServletRequest httpServletRequestMock = mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponseMock = mock(CommonAuthResponseWrapper.class);

        Map<String, String[]> requestParameters = new HashMap<>();
        requestParameters.put("state", new String[]{"stateCode,OIDC"});
        requestParameters.put("code", new String[]{"sampleCode"});
        when(httpServletRequestMock.getParameterMap()).thenReturn(requestParameters);
        when(httpServletRequestMock.getParameter(AppleAuthenticatorConstants.APPLE_USER_INFO_KEY))
                .thenReturn("{\"name\":{\"firstName\":\"first\",\"lastName\":\"last\"},\"email\":\"user@test.com\"}");

        mockRealMServices();
        try {
            appleAuthenticator.processAuthenticationResponse(httpServletRequestMock, httpServletResponseMock,
                    authenticationContext);

            Assert.assertNotNull(((OIDCStateInfo) authenticationContext.getStateInfo()).getIdTokenHint());
            AuthenticatedUser subject = authenticationContext.getSubject();
            Assert.assertEquals(subject.getAuthenticatedSubjectIdentifier(), TEST_EMAIL);
            Assert.assertTrue(subject.isFederatedUser());

            subject.getUserAttributes().forEach((key, value) -> {
                Assert.assertEquals(key.getRemoteClaim().getClaimUri(), key.getLocalClaim().getClaimUri());
                switch (key.getLocalClaim().getClaimUri()) {
                    case OAuth2Util.ISS:
                        Assert.assertEquals(value, TEST_ISS);
                        break;
                    case OAuth2Util.IAT:
                        Assert.assertEquals(value, TEST_IAT);
                        break;
                    case OAuth2Util.EXP:
                        Assert.assertEquals(value, TEST_EXP);
                        break;
                    case OAuth2Util.AUD:
                        Assert.assertEquals(value, TEST_AUD);
                        break;
                    case OAuth2Util.SUB:
                        Assert.assertEquals(value, TEST_SUB);
                        break;
                    case OAuthConstants.OIDCClaims.AT_HASH:
                        Assert.assertEquals(value, TEST_AT_HASH);
                        break;
                    case OAuthConstants.OIDCClaims.AUTH_TIME:
                        Assert.assertEquals(value, TEST_AUTH_TIME);
                        break;
                    case OAuthConstants.OIDCClaims.EMAIL_VERIFIED:
                        Assert.assertEquals(value, TEST_EMAIL_VERIFIED);
                        break;
                }
            });

        } catch (AuthenticationFailedException e) {
            Assert.fail("Error in process authentication response.", e);
        }
    }

    private void mockRealMServices() throws UserStoreException {

        TenantManager tenantManagerMock = mock(TenantManager.class);
        UserRealm userRealmMock = mock(UserRealm.class);
        UserStoreManager userStoreManagerMock = mock(UserStoreManager.class);
        RealmConfiguration realmConfigurationMock = mock(RealmConfiguration.class);

        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        when(tenantManagerMock.getTenantId(TEST_TENANT)).thenReturn(TEST_TENANT_ID);
        when(realmServiceMock.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(userRealmMock);
        when(userRealmMock.getUserStoreManager()).thenReturn(userStoreManagerMock);
        when(userStoreManagerMock.getRealmConfiguration()).thenReturn(realmConfigurationMock);
        when(realmConfigurationMock.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR))
                .thenReturn(",,,");
    }

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

        OAuthClientResponse oAuthClientResponseMock = mock(OAuthClientResponse.class);
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

        OAuthClientResponse oAuthClientResponseMock = mock(OAuthClientResponse.class);
        String userInfoEndpoint = appleAuthenticator.getUserInfoEndpoint(oAuthClientResponseMock,
                testAuthenticatorProperties);
        Assert.assertNull(userInfoEndpoint);
    }

    @DataProvider(name = "getAuthenticateUserDataProvider")
    public Object[][] getAuthenticateUserDataProvider() {

        Map<String, Object> oidcClaims1 = new HashMap<>();
        oidcClaims1.put(OAuth2Util.SUB, TEST_SUB);
        oidcClaims1.put("email", TEST_EMAIL);
        oidcClaims1.put("email_verified", "true");

        Map<String, Object> oidcClaims2 = new HashMap<>();
        oidcClaims2.put(OAuth2Util.SUB, TEST_SUB);
        oidcClaims2.put("email_verified", "true");

        return new Object[][]{
                {oidcClaims1, TEST_EMAIL},
                {oidcClaims2, TEST_SUB}
        };
    }

    @Test(dataProvider = "getAuthenticateUserDataProvider")
    public void testGetAuthenticateUser(Map<String, Object> oidcClaims, String expectedUserAttribute) {

        OAuthClientResponse oAuthClientResponseMock = mock(OAuthClientResponse.class);
        String authenticateUser = appleAuthenticator.getAuthenticateUser(authenticationContext,
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

    @Test
    public void testGetConfigurationProperties() {

        List<Property> configurationProperties = appleAuthenticator.getConfigurationProperties();
        Assert.assertEquals(configurationProperties.size(), 11);
        configurationProperties.forEach(property -> {
            Assert.assertNotNull(property.getName());
            Assert.assertNotNull(property.getDisplayName());
            Assert.assertNotNull(property.getDescription());

            if (property.getName().equals(OIDCAuthenticatorConstants.CLIENT_ID) ||
                    property.getName().equals(AppleAuthenticatorConstants.TEAM_ID) ||
                    property.getName().equals(AppleAuthenticatorConstants.KEY_ID) ||
                    property.getName().equals(AppleAuthenticatorConstants.PRIVATE_KEY)) {
                Assert.assertTrue(property.isRequired());
            } else if (property.getName().equals(AppleAuthenticatorConstants.CLIENT_SECRET_VALIDITY_PERIOD)) {
                Assert.assertEquals(property.getValue(), "15777000");
            } else if (property.getName().equals(IdentityApplicationConstants.Authenticator.OIDC.SCOPES)) {
                Assert.assertEquals(property.getValue(), "name email");
            }
        });
    }

    @Test
    public void testGetI18nKey() {

        String facebookI18nKey = appleAuthenticator.getI18nKey();
        Assert.assertEquals(facebookI18nKey, AppleAuthenticatorConstants.AUTHENTICATOR_APPLE);
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = appleAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    private void initAuthenticatorProperties() {

        testAuthenticatorProperties = new HashMap<>();
        testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "testClientId");
        testAuthenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "testClientSecret");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.CLIENT_SECRET_VALIDITY_PERIOD, "7200");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.TEAM_ID, "testTeamId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.KEY_ID, "testKeyId");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.PRIVATE_KEY, "-----BEGIN PRIVATE KEY-----\n" +
                "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgzFs/tGqHIchtAQyxZNNo\n" +
                "Ml/8lB/FhBlUvIdAfLBF5/2hRANCAATV2pzqzrpi6PvE0u08cSEKtwv8jqTdEx1S\n" +
                "rlf5IBbG+Y4Roo1zQ4s1ztL4j9kQmea6+TvYsRXDn2599Ea5dki/\n" +
                "-----END PRIVATE KEY-----\n");
        testAuthenticatorProperties.put(IdentityApplicationConstants.OAuth2.CALLBACK_URL,
                "https://localhost:9443/commonauth");
        testAuthenticatorProperties.put(IdentityApplicationConstants.Authenticator.OIDC.SCOPES, "name email");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.ADDITIONAL_QUERY_PARAMETERS, "");
        testAuthenticatorProperties.put(AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET, "false");
    }

    private void initAuthenticationContext() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setResourceId(TEST_IDP_RESOURCE_ID);
        identityProvider.setIdentityProviderName("AppleIDP");

        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[1];
        FederatedAuthenticatorConfig federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        federatedAuthenticatorConfig.setName(AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME);
        List<Property> idpProperties = new ArrayList<>();
        testAuthenticatorProperties.forEach((key, value) -> {
            Property property = new Property();
            property.setName(key);
            property.setValue(value);
            idpProperties.add(property);
        });
        Property[] propertyArray = new Property[idpProperties.size()];
        federatedAuthenticatorConfig.setProperties(idpProperties.toArray(propertyArray));
        federatedAuthenticatorConfigs[0] = federatedAuthenticatorConfig;
        identityProvider.setFederatedAuthenticatorConfigs(federatedAuthenticatorConfigs);
        ExternalIdPConfig externalIdPConfig = new ExternalIdPConfig(identityProvider);

        authenticationContext = new AuthenticationContext();
        authenticationContext.setAuthenticatorProperties(testAuthenticatorProperties);
        authenticationContext.setTenantDomain(TEST_TENANT);
        authenticationContext.setExternalIdP(externalIdPConfig);
        authenticationContext.setContextIdentifier(CONTEXT_IDENTIFIER);

        if (isAPIBased) {
            authenticationContext.setProperty(AppleAuthenticatorConstants.IS_API_BASED, "true");
        }
    }
}
