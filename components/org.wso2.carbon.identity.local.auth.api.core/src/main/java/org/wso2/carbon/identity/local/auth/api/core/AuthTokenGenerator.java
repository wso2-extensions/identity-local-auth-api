package org.wso2.carbon.identity.local.auth.api.core;

import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIException;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnMessageContext;

public interface AuthTokenGenerator {

    public void init() throws AuthAPIException;

    public void generateToken(AuthnMessageContext authnMessageContext) throws AuthAPIException;

}
