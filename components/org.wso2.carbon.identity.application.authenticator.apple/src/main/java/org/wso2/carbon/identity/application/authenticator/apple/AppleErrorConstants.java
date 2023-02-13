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

/**
 * This class defines all the error codes and messages that are specific for Apple authenticator.
 */
public class AppleErrorConstants {

    private AppleErrorConstants() {

    }

    /**
     * Apple authenticator error messages.
     */
    public enum ErrorMessages {

        // Client errors.
        REQUIRED_FIELDS_FOR_CLIENT_SECRET_NOT_FOUND("60000", "One or more required properties to generate the " +
                "client secret is not found in tenant: %s."),
        UNSUPPORTED_VALUE_PROVIDED_FOR_AUTHENTICATOR_PROPERTY("60001", "Unsupported value provided for the " +
                "property: %s in tenant: %s."),

        // Server errors.
        ERROR_WHILE_GENERATING_PRIVATE_KEY("65001", "An error occurred while generating private key for the " +
                "client secret. Reason: %s"),
        ERROR_WHILE_GENERATING_CLIENT_SECRET("65002", "An error occurred while generating the client secret."),
        ERROR_WHILE_UPDATING_IDENTITY_PROVIDER("65003", "An error occurred while updating the identity provider."),
        NULL_IDP_IN_AUTHENTICATION_CONTEXT("65004", "External IDP or Identity provider is null in context.");

        private final String code;
        private final String message;

        /**
         * Constructor for error messages.
         *
         * @param code      Error code.
         * @param message   Error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * Returns the error code of the error.
         *
         * @return String error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * Returns the descriptive error message of the error.
         *
         * @return error message.
         */
        public String getMessage() {

            return message;
        }
    }
}
