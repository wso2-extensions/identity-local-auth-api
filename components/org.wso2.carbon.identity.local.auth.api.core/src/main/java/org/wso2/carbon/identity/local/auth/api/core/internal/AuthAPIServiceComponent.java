/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.api.core.internal;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.local.auth.api.core.AuthManager;
import org.wso2.carbon.identity.local.auth.api.core.AuthManagerImpl;
import org.wso2.carbon.identity.local.auth.api.core.JWTAuthTokenGenerator;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolver;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolverService;
import org.wso2.carbon.identity.local.auth.api.core.impl.AuthenticationErrorParamResolver;
import org.wso2.carbon.identity.local.auth.api.core.impl.SessionDataKeyConsentParamResolverImpl;
import org.wso2.carbon.identity.local.auth.api.core.impl.SessionDataKeyParamResolverImpl;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and un-registration of auth API service.
 */
@Component(name = "identity.local.auth.api.core.component", immediate = true)
public class AuthAPIServiceComponent {

    private static final Log log = LogFactory.getLog(AuthAPIServiceComponent.class);

    /**
     * Register AuthManager as an OSGi service.
     *
     * @param componentContext OSGi service component context.
     */
    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            BundleContext bundleContext = componentContext.getBundleContext();
            bundleContext.registerService(AuthManager.class.getName(), new AuthManagerImpl(new JWTAuthTokenGenerator
                    ()), null);

            bundleContext.registerService(ParameterResolverService.class,
                    AuthAPIServiceComponentDataHolder.getInstance().getParameterResolverService(), null);
            bundleContext.registerService(ParameterResolver.class, new SessionDataKeyParamResolverImpl(), null);
            bundleContext.registerService(ParameterResolver.class, new SessionDataKeyConsentParamResolverImpl(), null);
            bundleContext.registerService(ParameterResolver.class, new AuthenticationErrorParamResolver(), null);
            log.debug("Auth API Service Component  is activated.");
        } catch (Throwable e) {
            log.error("Error while activating Auth API Service Component.", e);
        }

    }

    @Reference(name = "realm.service", service = org.wso2.carbon.user.core.service.RealmService.class, cardinality =
            ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (realmService != null && log.isDebugEnabled()) {
            log.debug("RealmService is registered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("RealmService is unregistered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setRealmService(null);
    }

    @Reference(name = "idpmanager.service", service = org.wso2.carbon.idp.mgt.IdpManager.class, cardinality =
            ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetIdPManager")
    protected void setIdPManager(IdpManager idPManager) {

        if (idPManager != null && log.isDebugEnabled()) {
            log.debug("IdPManager is registered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setIdpManager(idPManager);
    }

    protected void unsetIdPManager(IdpManager idPManager) {

        if (log.isDebugEnabled()) {
            log.debug("IdPManager is unregistered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setIdpManager(null);
    }

    @Reference(name = "auth.api.parameter.resolver", service = ParameterResolver.class, cardinality =
            ReferenceCardinality.MULTIPLE, policy = ReferencePolicy.DYNAMIC, unbind = "removeParamResolver")
    protected void addParamResolver(ParameterResolver resolver) {

        if (resolver != null && StringUtils.isNotBlank(resolver.getRegisteredKeyType())) {
            if (log.isDebugEnabled()) {
                log.debug("Registering parameter resolver for " + resolver.getRegisteredKeyType());
            }
            AuthAPIServiceComponentDataHolder.getInstance().getParameterResolverService().registerResolver(resolver);
        } else {
            log.warn("Registering parameter resolver failed. Resolver or KeyType is null or empty");
        }
    }

    protected void removeParamResolver(ParameterResolver resolver) {

        AuthAPIServiceComponentDataHolder.getInstance().getParameterResolverService().unregisterResolver(resolver);
    }
}
