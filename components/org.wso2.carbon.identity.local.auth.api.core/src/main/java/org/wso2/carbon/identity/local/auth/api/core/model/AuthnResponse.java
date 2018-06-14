package org.wso2.carbon.identity.local.auth.api.core.model;

public class AuthnResponse {

    protected AuthnMessageContext authnMessageContext;

    public AuthnResponse(AuthnMessageContext authnMessageContext) {
        this.authnMessageContext = authnMessageContext;
    }

    public AuthnStatus getAuthnStatus() {
        return authnMessageContext.getAuthnStatus();
    }

    public AuthnToken getAuthnToken() {
        return authnMessageContext.getAuthnToken();
    }

}
