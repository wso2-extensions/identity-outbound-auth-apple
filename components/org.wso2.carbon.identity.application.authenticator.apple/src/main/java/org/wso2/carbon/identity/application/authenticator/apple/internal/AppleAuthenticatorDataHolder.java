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
package org.wso2.carbon.identity.application.authenticator.apple.internal;

import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Apple authenticator service component data holder.
 */
public class AppleAuthenticatorDataHolder {

    private static final AppleAuthenticatorDataHolder instance = new AppleAuthenticatorDataHolder();

    private RealmService realmService;
    private IdpManager idpManager;

    /**
     * Get an instance of the data holder.
     *
     * @return Data holder instance.
     */
    public static AppleAuthenticatorDataHolder getInstance() {

        return instance;
    }

    /**
     * Get Realm service.
     *
     * @return Realm service.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set Realm service.
     *
     * @param realmService Realm service.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Get IDP Manager.
     *
     * @return IDP Manager.
     */
    public IdpManager getIdpManager() {

        return idpManager;
    }

    /**
     * Set IDP Manager.
     *
     * @param idpManager IDP Manager.
     */
    public void setIdpManager(IdpManager idpManager) {

        this.idpManager = idpManager;
    }
}
