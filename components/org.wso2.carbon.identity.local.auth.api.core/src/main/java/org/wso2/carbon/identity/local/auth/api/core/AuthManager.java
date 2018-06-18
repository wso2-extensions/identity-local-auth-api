package org.wso2.carbon.identity.local.auth.api.core;

import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIException;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnMessageContext;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnRequest;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnResponse;

public interface AuthManager {

    public AuthnResponse authenticate(AuthnRequest request) throws AuthAPIException;

    public void generateAuthnToken(AuthnMessageContext context) throws AuthAPIException;

}
