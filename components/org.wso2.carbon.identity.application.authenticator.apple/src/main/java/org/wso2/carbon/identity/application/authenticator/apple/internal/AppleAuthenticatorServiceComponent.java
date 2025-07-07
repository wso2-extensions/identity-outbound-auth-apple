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

package org.wso2.carbon.identity.application.authenticator.apple.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.apple.AppleAuthenticator;
import org.wso2.carbon.identity.application.authenticator.apple.executor.AppleExecutor;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Apple authenticator service component class.
 */
@Component(
        name = "identity.application.authenticator.apple.component",
        immediate = true
)
public class AppleAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(AppleAuthenticatorServiceComponent.class);

    /**
     * Activate the OSGI service.
     *
     * @param context Component context.
     */
    @Activate
    protected void activate(ComponentContext context) {

        try {
            AppleAuthenticator appleAuthenticator = new AppleAuthenticator();
            context.getBundleContext().registerService(
                    ApplicationAuthenticator.class.getName(), appleAuthenticator, null);
            context.getBundleContext().registerService(Executor.class.getName(), new AppleExecutor(), null);
            if (log.isDebugEnabled()) {
                log.debug("Apple authenticator bundle is activated.");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating apple authenticator bundle.", e);
        }
    }

    /**
     * Deactivate the OSGI service.
     *
     * @param context Component context.
     */
    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Apple authenticator bundle is deactivated.");
        }
    }

    /**
     * Set Realm service.
     *
     * @param realmService Realm service.
     */
    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        AppleAuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    /**
     * Unset realm service.
     *
     * @param realmService Realm service.
     */
    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service.");
        }
        AppleAuthenticatorDataHolder.getInstance().setRealmService(null);
    }

    /**
     * Set IDP Manager service.
     *
     * @param idpManager IDP Manager service.
     */
    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdpManagerService"
    )
    protected void setIdpManagerService(IdpManager idpManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the IDP Manager Service.");
        }
        AppleAuthenticatorDataHolder.getInstance().setIdpManager(idpManager);
    }

    /**
     * Unset IDP Manager service.
     *
     * @param idpManager IDP Manager service.
     */
    protected void unsetIdpManagerService(IdpManager idpManager) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the IDP Manager Service.");
        }
        AppleAuthenticatorDataHolder.getInstance().setIdpManager(null);
    }
}
