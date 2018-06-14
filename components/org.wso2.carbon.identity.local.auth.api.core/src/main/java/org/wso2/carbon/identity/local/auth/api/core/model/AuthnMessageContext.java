package org.wso2.carbon.identity.local.auth.api.core.model;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.io.Serializable;

public class AuthnMessageContext extends MessageContext<String, Object> implements Serializable {

    private static final long serialVersionUID = -1668181694633646304L;

    protected User user;
    protected AuthnToken authnToken;
    protected AuthnStatus authnStatus;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public AuthnToken getAuthnToken() {
        return authnToken;
    }

    public void setAuthnToken(AuthnToken authnToken) {
        this.authnToken = authnToken;
    }

    public AuthnStatus getAuthnStatus() {
        return authnStatus;
    }

    public void setAuthnStatus(AuthnStatus authnStatus) {
        this.authnStatus = authnStatus;
    }
}
