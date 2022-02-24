/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.api.core.impl;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationError;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolver;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Implementation of the {@link ParameterResolver} to get values for authentication error messages
 * to be displayed in retry page.
 */
public class AuthenticationErrorParamResolver implements ParameterResolver {

    public static final String KEY_TYPE = "AuthenticationError";

    @Override
    public Map<String, Serializable> getParameters(String key, Set<String> filter) {

        return getParameterMap(key, filter, false);
    }

    @Override
    public Map<String, Serializable> consumeParameters(String key, Set<String> filter) {

        return getParameterMap(key, filter, true);
    }


    /**
     * Retrieve and optionally delete the parameters available for the given key. Optionally filter them if a nonempty
     * filter is provided.
     *
     * @param key           The correlation key.
     * @param filter        Set of attributes which are required.
     * @param deleteOnRead  Whether to remove the parameters on read.
     * @return              Map where key as the name of the parameter and the value as the parameter.
     */
    public Map<String, Serializable> getParameterMap(String key, Set<String> filter, boolean deleteOnRead) {

        AuthenticationError error = FrameworkUtils.getAuthenticationErrorFromCache(key);
        if (error != null) {
            Map<String, Serializable> endpointParams = new HashMap<>(error.getFailureData());
            if (filter != null && !filter.isEmpty()) {
                endpointParams.entrySet().retainAll(filter);
            }
            if (deleteOnRead) {
                FrameworkUtils.removeAuthenticationErrorFromCache(key);
            }
            return endpointParams;
        }
        return Collections.emptyMap();
    }

    @Override
    public String getRegisteredKeyType() {

        return KEY_TYPE;
    }
}
