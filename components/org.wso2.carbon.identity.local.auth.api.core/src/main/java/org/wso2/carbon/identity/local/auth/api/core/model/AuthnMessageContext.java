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

package org.wso2.carbon.identity.local.auth.api.core.model;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.io.Serializable;

/**
 * Authentication message context that holds context information within authentication flow.
 */
public class AuthnMessageContext extends MessageContext<String, Object> implements Serializable {

    private static final long serialVersionUID = -1668181694633646304L;

    protected User user;
    protected AuthnToken authnToken;
    protected AuthnStatus authnStatus;

    /**
     * Returns the authenticated user.
     *
     * @return User object
     */
    public User getUser() {
        return user;
    }

    /**
     * Sets the authenticated user.
     *
     * @param user User object
     */
    public void setUser(User user) {
        this.user = user;
    }

    /**
     * Returns the AuthToken generated for the authenticated user.
     *
     * @return AuthToken, default implementation includes a JWT
     */
    public AuthnToken getAuthnToken() {
        return authnToken;
    }

    /**
     * Set AuthToken generated for the authenticated user.
     *
     * @param authnToken AuthToken
     */
    public void setAuthnToken(AuthnToken authnToken) {
        this.authnToken = authnToken;
    }

    /**
     * Returns authentication status
     *
     * @return Authentication status as SUCCESS, FAIL, ERROR
     */
    public AuthnStatus getAuthnStatus() {
        return authnStatus;
    }

    public void setAuthnStatus(AuthnStatus authnStatus) {
        this.authnStatus = authnStatus;
    }
}
