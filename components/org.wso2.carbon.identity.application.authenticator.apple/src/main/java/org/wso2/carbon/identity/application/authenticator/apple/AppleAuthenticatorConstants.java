/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

/**
 * Constants for Apple OIDC Authenticator.
 */
public class AppleAuthenticatorConstants {

    private AppleAuthenticatorConstants() {

    }

    public static final String APPLE_CONNECTOR_FRIENDLY_NAME = "Apple";
    public static final String APPLE_CONNECTOR_NAME = "AppleOIDCAuthenticator";
    public static final String AUTHORIZATION_SERVER_ENDPOINT = "https://appleid.apple.com/auth/authorize";
    public static final String TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token";
    public static final String TEAM_ID = "TeamId";
    public static final String KEY_ID = "KeyId";
    public static final String PRIVATE_KEY = "PrivateKey";
    public static final String ADDITIONAL_QUERY_PARAMETERS = "AdditionalQueryParameters";
    public static final String CLIENT_SECRET_VALIDITY_PERIOD = "SecretValidityPeriod";
    public static final String CLIENT_SECRET_EXPIRY_TIME_METADATA = "SecretExpiryEpochTime";
    public static final String REGENERATE_CLIENT_SECRET = "RegenerateClientSecret";

    public static final String CLIENT_SECRET_JWT_AUDIENCE = "https://appleid.apple.com";
    public static final long CLIENT_SECRET_VALIDITY_PERIOD_THRESHOLD = 3600;
    public static final long CLIENT_SECRET_VALIDITY_PERIOD_DEFAULT = 15777000;
    public static final String APPLE_DEFAULT_QUERY_PARAMS_FOR_SCOPE = "response_mode=form_post";

    public static final String APPLE_AUTHZ_ENDPOINT = "AppleAuthzEndpoint";
    public static final String APPLE_TOKEN_ENDPOINT = "AppleTokenEndpoint";
    public static final String APPLE_USER_INFO_KEY = "user";
    public static final String CLAIM_DIALECT_URI_PARAMETER = "ClaimDialectUri";

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String OUTBOUND_AUTH_APPLE_SERVICE = "outbound-auth-apple";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-outbound-auth-oidc-response";
            public static final String VALIDATE_OUTBOUND_AUTH_REQUEST = "initiate-outbound-auth-oidc-request";
        }
    }
}
