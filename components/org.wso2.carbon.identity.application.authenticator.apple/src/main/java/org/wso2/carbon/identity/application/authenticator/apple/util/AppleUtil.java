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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.codec.binary.Base64;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.apple.AppleErrorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;

/**
 * Utility methods for Apple authenticator.
 */
public class AppleUtil {

    /**
     * Generate the client secret.
     *
     * @param authenticatorProperties   Authenticator properties.
     * @param currentEpochTime          Current time in epoch seconds.
     * @param expiryEpochTime           Secret expiry time in epoch seconds.
     * @return Client secret.
     * @throws AuthenticationFailedException If an error occurs.
     */
    public static String generateClientSecret(Map<String, String> authenticatorProperties, long currentEpochTime,
                                        long expiryEpochTime) throws AuthenticationFailedException {

        JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(authenticatorProperties.get(AppleAuthenticatorConstants.KEY_ID))
                .build();

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .claim(OAuth2Util.ISS, authenticatorProperties.get(AppleAuthenticatorConstants.TEAM_ID))
                .claim(OAuth2Util.IAT, currentEpochTime)
                .claim(OAuth2Util.EXP, expiryEpochTime)
                .claim(OAuth2Util.AUD, AppleAuthenticatorConstants.CLIENT_SECRET_JWT_AUDIENCE)
                .claim(OAuth2Util.SUB, authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID))
                .build();

        JWSObject jwsObject = new JWSObject(jwtHeader, new Payload(jwtClaims.toJSONObject()));
        try {
            JWSSigner jwsSigner = new ECDSASigner(
                    generatePrivateKey(authenticatorProperties.get(AppleAuthenticatorConstants.PRIVATE_KEY)),
                    Curve.P_256
            );
            jwsObject.sign(jwsSigner);
        } catch (JOSEException e) {
            throw new AuthenticationFailedException(
                    AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_CLIENT_SECRET.getCode(),
                    AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_CLIENT_SECRET.getMessage(), e
            );
        }

        return jwsObject.serialize();
    }

    /**
     * Construct the private key using the key string.
     *
     * @param keyString Private key string value.
     * @return Private key object.
     * @throws AuthenticationFailedException If an error occurs.
     */
    private static PrivateKey generatePrivateKey(String keyString) throws AuthenticationFailedException {

        // Prepare the key string by removing begin and end statements.
        keyString = keyString.replace("-----BEGIN PRIVATE KEY-----", "");
        keyString = keyString.replace("-----END PRIVATE KEY-----", "");
        byte[] bytes = Base64.decodeBase64(keyString);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);

            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationFailedException(
                    AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_PRIVATE_KEY.getCode(),
                    String.format(AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_PRIVATE_KEY.getMessage(),
                            "Requested cryptographic algorithm is not available"), e
            );
        } catch (InvalidKeySpecException e) {
            throw new AuthenticationFailedException(
                    AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_PRIVATE_KEY.getCode(),
                    String.format(AppleErrorConstants.ErrorMessages.ERROR_WHILE_GENERATING_PRIVATE_KEY.getMessage(),
                            "Invalid key specifications"), e
            );
        }
    }
}
