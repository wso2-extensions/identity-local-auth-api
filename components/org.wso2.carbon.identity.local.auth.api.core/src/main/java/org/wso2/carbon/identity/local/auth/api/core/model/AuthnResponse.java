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

/**
 * This class represents the authentication response.
 */
public class AuthnResponse {

    protected AuthnMessageContext authnMessageContext;

    /**
     * Creates an instance of authentication response.
     *
     * @param authnMessageContext authentication message context
     */
    public AuthnResponse(AuthnMessageContext authnMessageContext) {
        this.authnMessageContext = authnMessageContext;
    }

    /**
     * Returns authentication status.
     *
     * @return Authentication status as SUCCESS, FAIL, ERROR
     */
    public AuthnStatus getAuthnStatus() {
        return authnMessageContext.getAuthnStatus();
    }

    /**
     * Returns AuthToken for a successful authentication.
     *
     * @return AuthToken
     */
    public AuthnToken getAuthnToken() {
        return authnMessageContext.getAuthnToken();
    }

}
