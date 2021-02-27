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

import org.wso2.carbon.identity.local.auth.api.core.ParameterResolverService;
import org.wso2.carbon.identity.local.auth.api.core.impl.ParameterResolverServiceImpl;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder that keep references for registered listened OSGi services.
 */
public class AuthAPIServiceComponentDataHolder {

    private static AuthAPIServiceComponentDataHolder instance = new AuthAPIServiceComponentDataHolder();
    private RealmService realmService;
    private IdpManager idpManager;
    private ParameterResolverService parameterResolverService = new ParameterResolverServiceImpl();
    private MultiAttributeLoginService multiAttributeLoginService;

    public MultiAttributeLoginService getMultiAttributeLoginService() {

        return multiAttributeLoginService;
    }

    public void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {

        this.multiAttributeLoginService = multiAttributeLoginService;
    }

    public static AuthAPIServiceComponentDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public IdpManager getIdpManager() {
        return idpManager;
    }

    public void setIdpManager(IdpManager idpManager) {
        this.idpManager = idpManager;
    }

    public ParameterResolverService getParameterResolverService() {

        return parameterResolverService;
    }
}
