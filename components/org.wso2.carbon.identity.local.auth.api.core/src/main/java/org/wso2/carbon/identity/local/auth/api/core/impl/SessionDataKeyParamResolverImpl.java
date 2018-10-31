package org.wso2.carbon.identity.local.auth.api.core.impl;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolver;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Implementation of the {@link ParameterResolver} to get values for sessionDataKey in authentication context.
 */
public class SessionDataKeyParamResolverImpl implements ParameterResolver {

    public static final String KEY_TYPE = "AuthRequestKey";

    @Override
    public Map<String, Serializable> getParameters(String key, Set<String> filter) {

        return getParameterMap(key, filter, false);
    }

    @Override
    public Map<String, Serializable> consumeParameters(String key, Set<String> filter) {

        return getParameterMap(key, filter, true);
    }

    /**
     * Retrieve and optionally delete the parameters available for the given key. Optionally filter them if a non empty
     * filter is provided.
     * @param key The correlation key
     * @param filter Set of attributes which are required.
     * @param deleteOnRead Whether to remove the parameters on read.
     * @return Map where key represent the name of the parameter and value represent the value of the parameter
     */
    protected Map<String, Serializable> getParameterMap(String key, Set<String> filter, boolean deleteOnRead) {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(key);
        if (context != null && !context.getEndpointParams().isEmpty()) {
            Map<String, Serializable> endpointParams = new HashMap<>(context.getEndpointParams());
            if (filter != null && !filter.isEmpty()) {
                endpointParams.keySet().retainAll(filter);
            }
            if (deleteOnRead) {
                context.getEndpointParams().keySet().removeAll(endpointParams.keySet());
                FrameworkUtils.removeAuthenticationContextFromCache(key);
                FrameworkUtils.addAuthenticationContextToCache(key, context);
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
