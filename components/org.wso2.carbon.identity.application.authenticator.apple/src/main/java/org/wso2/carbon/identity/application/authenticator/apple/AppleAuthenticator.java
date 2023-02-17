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
 */

package org.wso2.carbon.identity.application.authenticator.apple;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.apple.internal.AppleAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.apple.util.AppleUtil;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.base.IdentityConstants.FEDERATED_IDP_SESSION_ID;

/**
 * Apple OIDC Authenticator implementation.
 */
public class AppleAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(AppleAuthenticator.class);
    private static final long serialVersionUID = 8172602767464603503L;
    private String oAuthEndpoint;
    private String tokenEndpoint;
    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static final Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);
    private static final String[] NON_USER_ATTRIBUTES = new String[]{
            "iss", "aud", "iat", "exp", "nonce", "nonce_supported"};

    /**
     * Initialize and redirect the authentication request.
     *
     * @param request   Authentication request.
     * @param response  Authentication response.
     * @param context   Authentication context.
     * @throws AuthenticationFailedException If an error occurs.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (MapUtils.isNotEmpty(authenticatorProperties)) {
                evaluateClientSecret(context, authenticatorProperties);

                String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
                String callbackUrl = getCallbackUrl(authenticatorProperties);
                String state = getStateParameter(context, authenticatorProperties);
                String scopes = getScope(authenticatorProperties);
                String queryString = getQueryString(authenticatorProperties);

                // If scopes are present, Apple requires sending response_mode as form_post.
                if (StringUtils.isNotBlank(scopes)) {
                    queryString += "&scope=" + scopes + "&" +
                            AppleAuthenticatorConstants.APPLE_DEFAULT_QUERY_PARAMS_FOR_SCOPE;
                }
                queryString = interpretQueryString(context, queryString, request.getParameterMap());
                Map<String, String> paramValueMap = new HashMap<>();

                if (StringUtils.isNotBlank(queryString)) {
                    String[] params = queryString.split("&");
                    for (String param : params) {
                        String[] intParam = param.split("=");
                        if (intParam.length >= 2) {
                            paramValueMap.put(intParam[0], intParam[1]);
                        }
                    }
                    context.setProperty(OIDCAuthenticatorConstants.OIDC_QUERY_PARAM_MAP_PROPERTY_KEY, paramValueMap);
                }

                queryString = getEvaluatedQueryString(paramValueMap);
                String scope = paramValueMap.get(OAuthConstants.OAuth20Params.SCOPE);
                scope = getScope(scope, authenticatorProperties);
                OAuthClientRequest.AuthenticationRequestBuilder requestBuilder =
                        OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                                .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                                .setState(state);

                if (StringUtils.isBlank(queryString) ||
                        !queryString.toLowerCase(Locale.getDefault()).contains("scope=")) {
                    requestBuilder.setScope(scope);
                }
                if (StringUtils.isBlank(queryString) ||
                        !queryString.toLowerCase(Locale.getDefault()).contains("redirect_uri=")) {
                    requestBuilder.setRedirectURI(callbackUrl);
                }

                String loginPage = requestBuilder.buildQueryMessage().getLocationUri();
                String domain = request.getParameter("domain");

                if (StringUtils.isNotBlank(domain)) {
                    loginPage = loginPage + "&fidp=" + domain;
                }
                if (StringUtils.isNotBlank(queryString)) {
                    if (!queryString.startsWith("&")) {
                        loginPage = loginPage + "&" + queryString;
                    } else {
                        loginPage = loginPage + queryString;
                    }
                }
                response.sendRedirect(response.encodeRedirectURL(loginPage.replace("\r\n", "")));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(OIDCErrorConstants.ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED
                            .getMessage());
                }
                throw new AuthenticationFailedException(
                        OIDCErrorConstants.ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getCode(),
                        OIDCErrorConstants.ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getMessage());
            }
        } catch (UnsupportedEncodingException | OAuthSystemException e) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED.getCode(),
                    e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.IO_ERROR.getCode(), e.getMessage(), e);
        }
    }

    /**
     * Process authentication response.
     *
     * @param request   Authentication request.
     * @param response  Authentication response.
     * @param context   Authentication context.
     * @throws AuthenticationFailedException If an error occurs.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse = requestAccessToken(request, context);
        mapAccessToken(request, context, oAuthResponse);
        String idToken = mapIdToken(context, request, oAuthResponse);

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if (requiredIDToken(authenticatorProperties) && StringUtils.isBlank(idToken)) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getCode(),
                    String.format(OIDCErrorConstants.ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getMessage(),
                            getTokenEndpoint(authenticatorProperties),
                            authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID))
            );
        }

        OIDCStateInfo stateInfoOIDC = new OIDCStateInfo();
        stateInfoOIDC.setIdTokenHint(idToken);
        context.setStateInfo(stateInfoOIDC);

        AuthenticatedUser authenticatedUser;
        Map<ClaimMapping, String> claimsMap = new HashMap<>();
        Map<String, Object> jwtAttributeMap = new HashMap<>();

        /*
          Apple returns user information in the response for the very first authorize call. Requires to extract
          those attributes and add to attribute map.
          Note: To prevent XSS attacks, Apple recommends to sanitize the user inputs.
         */
        String userInfoString = request.getParameter(AppleAuthenticatorConstants.APPLE_USER_INFO_KEY);
        if (StringUtils.isNotBlank(userInfoString)) {
            Map<String, Object> userInfoJSON = JSONUtils.parseJSON(userInfoString);
            for (Map.Entry<String, Object> data : userInfoJSON.entrySet()) {
                String key = Encode.forJava(data.getKey());
                Object valueObject = data.getValue();

                if (valueObject != null) {
                    if (valueObject instanceof String) {
                        jwtAttributeMap.put(key, Encode.forJava(valueObject.toString()));
                    } else if (valueObject instanceof JSONObject) {
                        Iterator<String> nameKeys = ((JSONObject) valueObject).keys();
                        while (nameKeys.hasNext()) {
                            String nameKey = Encode.forJava(nameKeys.next());
                            Object nameValue = ((JSONObject) valueObject).get(nameKey);
                            if (nameValue instanceof String) {
                                jwtAttributeMap.put(nameKey, Encode.forJava(nameValue.toString()));
                            }
                        }
                    }
                }
            }
        }

        if (StringUtils.isNotBlank(idToken)) {
            jwtAttributeMap.putAll(getIdTokenClaims(context, idToken));
            if (jwtAttributeMap.isEmpty()) {
                String errorMessage = OIDCErrorConstants.ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getMessage();
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
                throw new AuthenticationFailedException(
                        OIDCErrorConstants.ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getCode(), errorMessage);
            }

            String idpName = context.getExternalIdP().getIdPName();
            String sidClaim = (String) jwtAttributeMap.get(OIDCAuthenticatorConstants.Claim.SID);
            if (StringUtils.isNotBlank(sidClaim) && StringUtils.isNotBlank(idpName)) {
                // Add 'sid' claim into authentication context, to be stored in the UserSessionStore
                // for single logout.
                context.setProperty(FEDERATED_IDP_SESSION_ID + idpName, sidClaim);
            }

            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
                if (LoggerUtils.isLogMaskingEnable) {
                    Map<String, Object> maskedAttributeMap = new HashMap<>();
                    for (Map.Entry<String, Object> entry : jwtAttributeMap.entrySet()) {
                        if (entry.getValue() instanceof String) {
                            maskedAttributeMap.put(entry.getKey(),
                                    LoggerUtils.getMaskedContent((String) entry.getValue()));
                        }
                    }
                    log.debug("Retrieved the User Information: " + maskedAttributeMap);
                } else {
                    log.debug("Retrieved the User Information: " + jwtAttributeMap);
                }
            }

            String authenticatedUserId = getAuthenticatedUserId(context, oAuthResponse, jwtAttributeMap);
            String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

            jwtAttributeMap.entrySet().stream()
                    .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                    .forEach(entry -> buildClaimMappings(claimsMap, entry, attributeSeparator));

            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                    authenticatedUserId);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Received null id token in Apple authentication flow.");
            }
            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                    getAuthenticateUser(context, jwtAttributeMap, oAuthResponse));
        }
        claimsMap.putAll(getSubjectAttributes(oAuthResponse, authenticatorProperties));
        authenticatedUser.setUserAttributes(claimsMap);
        context.setSubject(authenticatedUser);
    }

    /**
     * Get authenticator name.
     *
     * @return Name of the authenticator.
     */
    @Override
    public String getName() {

        return AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME;
    }

    /**
     * Get authenticator friendly name.
     *
     * @return Friendly name of the authenticator.
     */
    @Override
    public String getFriendlyName() {

        return AppleAuthenticatorConstants.APPLE_CONNECTOR_FRIENDLY_NAME;
    }

    /**
     * Get authenticator configuration properties.
     *
     * @return List of properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setDescription("The Services ID of the Apple identity provider.");
        clientId.setRequired(true);
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setDescription("The client secret value of the Apple identity provider.");
        clientSecret.setConfidential(true);
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property secretValidityPeriod = new Property();
        secretValidityPeriod.setName(AppleAuthenticatorConstants.CLIENT_SECRET_VALIDITY_PERIOD);
        secretValidityPeriod.setDisplayName("Client Secret Validity Period (in seconds)");
        secretValidityPeriod.setDescription("The validity period of the generated client secret. " +
                "A new client secret will be generated after this time.");
        secretValidityPeriod.setType("integer");
        secretValidityPeriod.setValue("15777000");
        secretValidityPeriod.setDisplayOrder(3);
        configProperties.add(secretValidityPeriod);

        Property teamId = new Property();
        teamId.setName(AppleAuthenticatorConstants.TEAM_ID);
        teamId.setDisplayName("Team ID");
        teamId.setDescription("The team identifier given by Apple to your organization.");
        teamId.setRequired(true);
        teamId.setDisplayOrder(4);
        configProperties.add(teamId);

        Property keyId = new Property();
        keyId.setName(AppleAuthenticatorConstants.KEY_ID);
        keyId.setDisplayName("Key ID");
        keyId.setDescription("The key identifier value of the Apple key.");
        keyId.setRequired(true);
        keyId.setDisplayOrder(5);
        configProperties.add(keyId);

        Property privateKey = new Property();
        privateKey.setName(AppleAuthenticatorConstants.PRIVATE_KEY);
        privateKey.setDisplayName("Private Key");
        privateKey.setDescription("The private key used to sign the client secret.");
        privateKey.setRequired(true);
        privateKey.setConfidential(true);
        privateKey.setDisplayOrder(6);
        configProperties.add(privateKey);

        Property callbackUrl = new Property();
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setDescription("The callback URL used to obtain Apple credentials.");
        callbackUrl.setDisplayOrder(7);
        configProperties.add(callbackUrl);

        Property scope = new Property();
        scope.setName(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        scope.setDisplayName("Scopes");
        scope.setValue("name email");
        scope.setDescription("Enter a space separated list of permissions to request from the user.");
        scope.setDisplayOrder(8);
        configProperties.add(scope);

        Property additionalQueryParams = new Property();
        additionalQueryParams.setName(AppleAuthenticatorConstants.ADDITIONAL_QUERY_PARAMETERS);
        additionalQueryParams.setDisplayName("Additional Query Parameters");
        additionalQueryParams.setDescription("Additional query parameters to be sent to Apple.");
        additionalQueryParams.setDisplayOrder(9);
        configProperties.add(additionalQueryParams);

        Property regenerateClientSecret = new Property();
        regenerateClientSecret.setName(AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET);
        regenerateClientSecret.setDisplayName("Regenerate client secret");
        regenerateClientSecret.setType("boolean");
        regenerateClientSecret.setValue("false");
        regenerateClientSecret.setDescription("Specifies if the client secret should be re-generated in " +
                "the next authentication.");
        regenerateClientSecret.setDisplayOrder(10);
        configProperties.add(regenerateClientSecret);

        Property secretExpiryTime = new Property();
        secretExpiryTime.setName(AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA);
        secretExpiryTime.setDisplayName("Client Secret Expiry Time");
        secretExpiryTime.setDescription("Metadata property that represents the expiry time of the generated " +
                "client secret. Don't edit this property manually.");
        secretExpiryTime.setConfidential(true);
        secretExpiryTime.setDisplayOrder(11);
        configProperties.add(secretExpiryTime);

        return configProperties;
    }

    /**
     * Get authorization server endpoint.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return Authorization service endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            initOAuthEndpoint();
        }
        return this.oAuthEndpoint;
    }

    /**
     * Get token endpoint.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return Token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.tokenEndpoint)) {
            initTokenEndpoint();
        }
        return this.tokenEndpoint;
    }

    /**
     * Get scope.
     *
     * @param scope                     Scope.
     * @param authenticatorProperties   Authenticator properties.
     * @return Scope string.
     */
    @Override
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(scope)) {
            return StringUtils.EMPTY;
        }
        return scope;
    }

    /**
     * Get authenticated user identifier value. Returns value of the email claim if present.
     * If not returns value of the sub claim.
     *
     * @param context       Authentication context.
     * @param oidcClaims    Map of OIDC claims.
     * @param oidcResponse  OAuth client response.
     * @return User identifier.
     */
    @Override
    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> oidcClaims,
                                         OAuthClientResponse oidcResponse) {

        if (oidcClaims.get(OIDCAuthenticatorConstants.Claim.EMAIL) != null) {
            return (String) oidcClaims.get(OIDCAuthenticatorConstants.Claim.EMAIL);
        }
        return (String) oidcClaims.get(OIDCAuthenticatorConstants.Claim.SUB);
    }

    /**
     * Get user information endpoint.
     * Note: Returns null as Apple doesn't provide a user info endpoint.
     *
     * @param token                   OAuth client response.
     * @param authenticatorProperties Authenticator properties.
     * @return Null.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {

        return null;
    }

    /**
     * Get additional query parameters.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return Query parameters.
     */
    @Override
    protected String getQueryString(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(AppleAuthenticatorConstants.ADDITIONAL_QUERY_PARAMETERS);
    }

    /**
     * Get claim dialect uri.
     * Returns dialect defined in authentication config file or if it is empty returns OIDC dialect.
     *
     * @return Claim dialect uri.
     */
    @Override
    public String getClaimDialectURI() {

        String claimDialectUri = super.getClaimDialectURI();
        Map<String, String> parameters = readParametersFromAuthenticatorConfig();

        if (parameters != null && parameters.containsKey(
                AppleAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER)) {
            claimDialectUri = parameters.get(AppleAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Found no parameter map for the connector: " + getName());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Authenticator %s is using the claim dialect uri: %s", getName(),
                    claimDialectUri));
        }

        return claimDialectUri;
    }

    /**
     * Get subject attributes.
     * Note: Returns an empty hashmap as Apple doesn't provide a user info endpoint.
     *
     * @param token                   OAuth client response.
     * @param authenticatorProperties Authenticator properties.
     * @return Empty map.
     */
    @Override
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token,
                                                             Map<String, String> authenticatorProperties) {

        return new HashMap<>();
    }

    /**
     * Evaluates if the client secret should be generated and if required, generate and store the secret.
     *
     * @param context                   Authentication context.
     * @param authenticatorProperties   Authenticator properties.
     * @throws AuthenticationFailedException If an error occurs when generating the client secret.
     */
    private void evaluateClientSecret(AuthenticationContext context, Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {

        String tenantDomain = context.getTenantDomain();
        long currentEpochTime = Instant.now().getEpochSecond();
        long expiryEpochTime = 0;

        try {
            if (StringUtils.isNotBlank(authenticatorProperties.get(
                    AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA))) {
                expiryEpochTime = Long.parseLong(authenticatorProperties.get(AppleAuthenticatorConstants
                        .CLIENT_SECRET_EXPIRY_TIME_METADATA)) - AppleAuthenticatorConstants
                        .CLIENT_SECRET_VALIDITY_PERIOD_THRESHOLD;
            }
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException(
                    AppleErrorConstants.ErrorMessages.UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY.getCode(),
                    String.format(AppleErrorConstants.ErrorMessages
                            .UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY.getMessage(),
                            AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA, tenantDomain)
            );
        }

        if (StringUtils.isBlank(authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET)) ||
                Boolean.parseBoolean(
                        authenticatorProperties.get(AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET)) ||
                expiryEpochTime <= currentEpochTime
        ) {
            String msg = String.format("Generating Apple client secret since it is null or invalidated. " +
                    "Tenant: %s, Secret re-gen property: %s, Current time: %s, Expiry time: %s.", tenantDomain,
                    authenticatorProperties.get(AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET),
                    currentEpochTime, expiryEpochTime);
            log.info(msg);

            // Check for pre-conditions.
            if (StringUtils.isBlank(authenticatorProperties.get(AppleAuthenticatorConstants.PRIVATE_KEY))
                    || StringUtils.isBlank(authenticatorProperties.get(AppleAuthenticatorConstants.TEAM_ID))
                    || StringUtils.isBlank(authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID))
                    || StringUtils.isBlank(authenticatorProperties.get(AppleAuthenticatorConstants.KEY_ID))
            ) {
                throw new AuthenticationFailedException(
                        AppleErrorConstants.ErrorMessages.REQUIRED_FIELDS_FOR_CLIENT_SECRET_NOT_FOUND.getCode(),
                        String.format(AppleErrorConstants.ErrorMessages.REQUIRED_FIELDS_FOR_CLIENT_SECRET_NOT_FOUND
                                .getMessage(), tenantDomain));
            }

            long newExpiryEpochTime;
            if (StringUtils.isNotBlank(authenticatorProperties.get(AppleAuthenticatorConstants
                    .CLIENT_SECRET_VALIDITY_PERIOD))) {
                try {
                    newExpiryEpochTime = currentEpochTime + Long.parseLong(authenticatorProperties.get(
                            AppleAuthenticatorConstants.CLIENT_SECRET_VALIDITY_PERIOD));
                } catch (NumberFormatException e) {
                    throw new AuthenticationFailedException(AppleErrorConstants.ErrorMessages
                            .UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY.getCode(),
                            String.format(AppleErrorConstants.ErrorMessages
                                    .UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY.getMessage(),
                                    AppleAuthenticatorConstants.CLIENT_SECRET_VALIDITY_PERIOD, tenantDomain)
                    );
                }
            } else {
                newExpiryEpochTime = currentEpochTime + AppleAuthenticatorConstants
                        .CLIENT_SECRET_VALIDITY_PERIOD_DEFAULT;
            }

            // Iterate through authenticator properties and set client secret.
            if (context.getExternalIdP() != null && context.getExternalIdP().getIdentityProvider() != null) {
                IdentityProvider idp = context.getExternalIdP().getIdentityProvider();
                FederatedAuthenticatorConfig[] federatedAuthenticators = idp.getFederatedAuthenticatorConfigs();

                for (FederatedAuthenticatorConfig federatedAuthenticator : federatedAuthenticators) {
                    if (StringUtils.equals(federatedAuthenticator.getName(),
                            AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME)) {
                        Property[] idpProperties = federatedAuthenticator.getProperties();
                        for (Property idpProperty : idpProperties) {
                            switch (idpProperty.getName()) {
                                case OIDCAuthenticatorConstants.CLIENT_SECRET:
                                    idpProperty.setValue(AppleUtil.generateClientSecret(
                                            context.getAuthenticatorProperties(), currentEpochTime,
                                            newExpiryEpochTime));
                                    break;
                                case AppleAuthenticatorConstants.CLIENT_SECRET_EXPIRY_TIME_METADATA:
                                    idpProperty.setValue(String.valueOf(newExpiryEpochTime));
                                    break;
                                case AppleAuthenticatorConstants.REGENERATE_CLIENT_SECRET:
                                    idpProperty.setValue("false");
                                    break;
                                default:
                                    break;
                            }
                        }
                        break;
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug(String.format("Client secret generated for the IDP with resource ID %s of tenant %s.",
                            idp.getResourceId(), tenantDomain));
                }

                // Store the generated client secret.
                IdpManager idpManager = AppleAuthenticatorDataHolder.getInstance().getIdpManager();
                try {
                    idpManager.updateIdPByResourceId(idp.getResourceId(), idp, tenantDomain);
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("IDP with resource ID %s of tenant %s is updated with the " +
                                "generated client secret.", idp.getResourceId(), tenantDomain));
                    }
                } catch (IdentityProviderManagementException e) {
                    throw new AuthenticationFailedException(
                            AppleErrorConstants.ErrorMessages.ERROR_WHILE_UPDATING_IDENTITY_PROVIDER.getCode(),
                            AppleErrorConstants.ErrorMessages.ERROR_WHILE_UPDATING_IDENTITY_PROVIDER.getMessage(), e
                    );
                }
            } else {
                throw new AuthenticationFailedException(
                        AppleErrorConstants.ErrorMessages.NULL_IDP_IN_AUTHENTICATION_CONTEXT.getCode(),
                        AppleErrorConstants.ErrorMessages.NULL_IDP_IN_AUTHENTICATION_CONTEXT.getMessage()
                );
            }
        }
    }

    /**
     * Get authenticator parameters from the authentication config file.
     *
     * @return Map of authenticator parameters.
     */
    private Map<String, String> readParametersFromAuthenticatorConfig() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            return authConfig.getParameterMap();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FileBasedConfigBuilder returned null AuthenticatorConfig for the connector: " + getName());
            }
            return new HashMap<>();
        }
    }

    /**
     * Initialize authorization server endpoint.
     */
    private void initOAuthEndpoint() {

        this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap().get(
                AppleAuthenticatorConstants.APPLE_AUTHZ_ENDPOINT);
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            this.oAuthEndpoint = AppleAuthenticatorConstants.AUTHORIZATION_SERVER_ENDPOINT;
        }
    }

    /**
     * Initialize token endpoint.
     */
    private void initTokenEndpoint() {

        this.tokenEndpoint = getAuthenticatorConfig().getParameterMap().get(
                AppleAuthenticatorConstants.APPLE_TOKEN_ENDPOINT);
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            this.tokenEndpoint = AppleAuthenticatorConstants.TOKEN_ENDPOINT;
        }
    }

    /**
     * Get state parameter.
     *
     * @param context                   Authentication context.
     * @param authenticatorProperties   Authenticator properties.
     * @return State.
     */
    private String getStateParameter(AuthenticationContext context, Map<String, String> authenticatorProperties) {

        String state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        return getState(state, authenticatorProperties);
    }

    /**
     * Prepare the query string.
     *
     * @param context       Authentication context.
     * @param queryString   Query string.
     * @param parameters    Request parameters.
     * @return Formatted query string.
     */
    private String interpretQueryString(AuthenticationContext context, String queryString,
                                        Map<String, String[]> parameters) {

        if (StringUtils.isBlank(queryString)) {
            return null;
        }
        if (queryString.contains(OIDCAuthenticatorConstants.AUTH_PARAM)) {
            queryString = getQueryStringWithAuthenticatorParam(context, queryString);
        }

        Matcher matcher = pattern.matcher(queryString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String[] values = parameters.get(name);
            String value = "";
            if (values != null && values.length > 0) {
                value = values[0];
            }
            if (log.isDebugEnabled()) {
                log.debug("InterpretQueryString name: " + name + ", value: " + value);
            }
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Output QueryString: " + queryString);
        }

        return queryString;
    }

    /**
     * Get query string with authenticator params appended.
     *
     * @param context       Authentication context.
     * @param queryString   Query string.
     * @return Query string.
     */
    private String getQueryStringWithAuthenticatorParam(AuthenticationContext context, String queryString) {

        Matcher matcher = Pattern.compile(OIDCAuthenticatorConstants.DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX)
                .matcher(queryString);
        String value = "";

        while (matcher.find()) {
            String paramName = matcher.group(1);
            if (StringUtils.isNotEmpty(getRuntimeParams(context).get(paramName))) {
                value = getRuntimeParams(context).get(paramName);
            }
            try {
                value = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
                if (log.isDebugEnabled()) {
                    log.debug("InterpretQueryString with authenticator param: " + paramName + "," +
                            " value: " + value);
                }
            } catch (UnsupportedEncodingException e) {
                log.error("Error while encoding the authenticator param: " + paramName + " with value: " + value,
                        e);
            }
            queryString = queryString.replaceAll("\\$authparam\\{" + paramName + "}",
                    Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Output QueryString with Authenticator Params: " + queryString);
        }

        return queryString;
    }

    /**
     * Evaluate and url encode the query string.
     * Note: Apple requires space separation when requesting multiple scopes.
     *
     * @param paramMap Query parameters.
     * @return Query string.
     * @throws UnsupportedEncodingException If an error occurs.
     */
    private String getEvaluatedQueryString(Map<String, String> paramMap) throws UnsupportedEncodingException {

        StringBuilder queryString = new StringBuilder();
        if (paramMap.isEmpty()) {
            return queryString.toString();
        }
        for (Map.Entry param : paramMap.entrySet()) {
            queryString.append(param.getKey()).append("=")
                    .append(URLEncoder.encode(param.getValue().toString(), StandardCharsets.UTF_8.toString())
                            .replace("+", "%20").replace("%2C", "%20"))
                    .append("&");
        }

        return queryString.substring(0, queryString.length() - 1);
    }

    /**
     * Extract and return claims from id token.
     *
     * @param context   Authentication context.
     * @param idToken   Id token.
     * @return Id token claims map.
     */
    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes(StandardCharsets.UTF_8));
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded, StandardCharsets.UTF_8)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry: jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }

        return jwtAttributeMap;
    }

    /**
     * Get authenticated user's id based on id token claims.
     *
     * @param context       Authentication context.
     * @param oAuthResponse OAuth response.
     * @param idTokenClaims Map of id token claims.
     * @return Authenticated user's id.
     * @throws AuthenticationFailedException If an error occurs.
     */
    private String getAuthenticatedUserId(AuthenticationContext context, OAuthClientResponse oAuthResponse,
                                          Map<String, Object> idTokenClaims) throws AuthenticationFailedException {

        String authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
        if (StringUtils.isBlank(authenticatedUserId)) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getCode(),
                    OIDCErrorConstants.ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getMessage()
            );
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
        }

        return authenticatedUserId;
    }

    /**
     * Get multi attribute separator for claims.
     *
     * @param context               Authentication context.
     * @param authenticatedUserId   Authenticated user's id.
     * @return Multi attribute separator.
     * @throws AuthenticationFailedException If an error occurs.
     */
    private String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        String attributeSeparator = null;
        try {
            String tenantDomain = context.getTenantDomain();
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = AppleAuthenticatorDataHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRealm userRealm = AppleAuthenticatorDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);

            if (userRealm != null) {
                UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                attributeSeparator = userStore.getRealmConfiguration()
                        .getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                if (log.isDebugEnabled()) {
                    log.debug("For the claim mapping: " + attributeSeparator
                            + " is used as the attributeSeparator in tenant: " + tenantDomain);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getMessage(),
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }

        return attributeSeparator;
    }
}
