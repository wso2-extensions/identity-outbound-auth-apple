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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants.COMMA_SEPARATOR;
import static org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants.PLUS_SEPARATOR;
import static org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants.RESPONSE_MODE_FORM_POST;
import static org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants.RESPONSE_MODE_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants.SPACE_SEPARATOR;

/**
 * Apple OpenID Connect executor.
 * This class is used to handle the OpenID Connect specific operations for Apple authenticator.
 */
public class AppleExecutor extends OpenIDConnectExecutor {

    private static final String EXECUTOR_NAME = "AppleExecutor";

    @Override
    public String getName() {

        return EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {

        return AppleAuthenticatorConstants.APPLE_CONNECTOR_NAME;
    }

    @Override
    public String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        String authzEndpoint = authenticatorProperties.get(AppleAuthenticatorConstants.APPLE_AUTHZ_ENDPOINT);
        if (authzEndpoint == null) {
            authzEndpoint = AppleAuthenticatorConstants.AUTHORIZATION_SERVER_ENDPOINT;
        }
        return authzEndpoint;
    }

    @Override
    public String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenEndpoint = authenticatorProperties.get(AppleAuthenticatorConstants.APPLE_TOKEN_ENDPOINT);
        if (tokenEndpoint == null) {
            tokenEndpoint = AppleAuthenticatorConstants.TOKEN_ENDPOINT;
        }
        return tokenEndpoint;
    }

    @Override
    public String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return null;
    }

    @Override
    public String getAuthenticatedUserIdentifier(Map<String, Object> jsonObject) {

        Object emailClaim = jsonObject.get(OIDCAuthenticatorConstants.Claim.EMAIL);
        if (emailClaim == null) {
            return (String) jsonObject.get(OIDCAuthenticatorConstants.Claim.SUB);
        } else {
            return (String) emailClaim;
        }
    }

    @Override
    public String getScope(Map<String, String> authenticatorProperties) {

        String scopes = authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        if (StringUtils.isNotBlank(scopes)) {
            return scopes.replace(COMMA_SEPARATOR, SPACE_SEPARATOR).replace(PLUS_SEPARATOR, SPACE_SEPARATOR);
        }
        return scopes;
    }

    @Override
    public Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        String scopes = authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        Map<String, String> paramMap = new HashMap<>();
        if (StringUtils.isNotBlank(scopes)) {
            paramMap.put(RESPONSE_MODE_PARAMETER, RESPONSE_MODE_FORM_POST);
        }
        return paramMap;
    }
}
