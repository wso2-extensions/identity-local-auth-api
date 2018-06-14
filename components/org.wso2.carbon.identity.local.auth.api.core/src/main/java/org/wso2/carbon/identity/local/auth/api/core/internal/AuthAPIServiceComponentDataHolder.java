package org.wso2.carbon.identity.local.auth.api.core.internal;

import org.wso2.carbon.identity.local.auth.api.core.AuthTokenGenerator;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

public class AuthAPIServiceComponentDataHolder {

    private static AuthAPIServiceComponentDataHolder instance = new AuthAPIServiceComponentDataHolder();
    private RealmService realmService;
    private IdpManager idpManager;

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
}
