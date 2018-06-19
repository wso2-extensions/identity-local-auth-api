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
 * This class represents the token issued upon a successful authentication.
 */
public class AuthnToken {

    String tokenType;
    String token;

    /**
     * Returns the type of the token.
     *
     * @return token type
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * Sets type of the token.
     *
     * @param tokenType token type
     */
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Returns token.
     *
     * @return token
     */
    public String getToken() {
        return token;
    }

    /**
     * Sets token.
     *
     * @param token token
     */
    public void setToken(String token) {
        this.token = token;
    }
}
