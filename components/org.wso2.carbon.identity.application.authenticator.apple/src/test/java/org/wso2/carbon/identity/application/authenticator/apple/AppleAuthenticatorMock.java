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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Mock class for AppleAuthenticator.
 *
 * Note:
 * AppleAuthenticator class extends the OIDCAuthenticator class which has some protected methods that
 * cannot be mocked for testing. Hence this class is created to mock those methods.
 */
public class AppleAuthenticatorMock extends AppleAuthenticator {

    private OAuthClientResponse oAuthResponseMock;

    @Override
    public OAuthClientResponse requestAccessToken(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        oAuthResponseMock = mock(OAuthClientResponse.class);
        when(oAuthResponseMock.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn("access_token");
        when(oAuthResponseMock.getParam(OIDCAuthenticatorConstants.ID_TOKEN))
                .thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29" +
                        "tIiwiaWF0IjoxNjc0OTA3MjAwLCJleHAiOjE2NzUwODAwMDAsImF1ZCI6ImNsaWVudF9pZCIsInN1YiI6InNhbX" +
                        "BsZV9zdWJqZWN0IiwiYXRfaGFzaCI6ImF0X2hhc2giLCJlbWFpbCI6InVzZXJAdGVzdC5jb20iLCJhdXRoX3Rpb" +
                        "WUiOiIxNjc1MDYyNTQ0Iiwibm9uY2Vfc3VwcG9ydGVkIjoidHJ1ZSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSJ9" +
                        ".zHX3EfCOdsmZw2wiihkz9HCr2qIeIlQvjirfDhg1X4k");

        return oAuthResponseMock;
    }
}
