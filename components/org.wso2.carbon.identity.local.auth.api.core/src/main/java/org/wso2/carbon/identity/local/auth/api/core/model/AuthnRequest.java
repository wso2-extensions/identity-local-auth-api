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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the authentication request.
 */
public class AuthnRequest {

    protected String authType;
    protected Map<String, Object> authRequestParameters = new HashMap();

    /**
     * Returns the authentication mechanism being used which denotes if the authentication happened over HTTP basic
     * auth mechanism or user credentials in request body.
     *
     * @return Authentication mechanism VIA_AUTHORIZATION_HEADER or VIA_REQUEST_BODY
     */
    public String getAuthType() {
        return authType;
    }

    /**
     * Sets the authentication mechanism used to initiate the authentication request.
     *
     * @param authType Authentication mechanism VIA_AUTHORIZATION_HEADER or VIA_REQUEST_BODY
     */
    public void setAuthType(String authType) {
        this.authType = authType;
    }

    /**
     * Sets request parameters.
     *
     * @param key   parameter key
     * @param value parameter value
     */
    public void setParameter(String key, Object value) {

        authRequestParameters.put(key, value);
    }

    /**
     * Returns the value of the given request parameter.
     *
     * @param key parameter key
     * @return parameter value
     */
    public Object getParameter(String key) {
        return authRequestParameters.get(key);
    }

    public Map<String, Object> getParameters() {

        return Collections.unmodifiableMap(authRequestParameters);
    }
}
