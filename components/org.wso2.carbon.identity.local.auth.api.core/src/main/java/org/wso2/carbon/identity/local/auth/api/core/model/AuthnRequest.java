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

public class AuthnRequest {

    protected String authType;
    protected Map<String, Object> authRequestParameters = new HashMap();

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public void setParameter(String key, Object value) {

        authRequestParameters.put(key, value);
    }

    public Object getParameter(String key) {
        return authRequestParameters.get(key);
    }

    public Map<String, Object> getParameters() {

        return Collections.unmodifiableMap(authRequestParameters);
    }
}
