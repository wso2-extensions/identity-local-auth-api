package org.wso2.carbon.identity.local.auth.api.core.impl;

import org.wso2.carbon.identity.local.auth.api.core.ParameterResolver;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Implementation of the {@link ParameterResolver} to get values for sessionDataKeyConsent in oauth context.
 */
public class SessionDataKeyConsentParamResolverImpl implements ParameterResolver {

    public static final String KEY_TYPE = "OauthConsentKey";

    @Override
    public Map<String, Serializable> consumeParameters(String key, Set<String> filter) {

        return getParameterMap(key, filter, true);
    }

    @Override
    public Map<String, Serializable> getParameters(String key, Set<String> filter) {

        return getParameterMap(key, filter, false);
    }

    /**
     * Retrieve and optionally delete the parameters available for the given key. Optionally filter them if a non empty
     * filter is provided.
     * @param key The correlation key
     * @param filter Set of attributes which are required.
     * @param deleteOnRead Whether to remove the parameters on read.
     * @return Map where key represent the name of the parameter and value represent the value of the parameter
     */
    public Map<String, Serializable> getParameterMap(String key, Set<String> filter, boolean deleteOnRead) {

        SessionDataCacheKey cacheKey = new SessionDataCacheKey(key);
        SessionDataCacheEntry cacheEntry = SessionDataCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry != null && !cacheEntry.getEndpointParams().isEmpty()) {
            Map<String, Serializable> endpointParams = new HashMap<>(cacheEntry.getEndpointParams());
            if (filter != null && !filter.isEmpty()) {
                endpointParams.keySet().retainAll(filter);
            }
            if (deleteOnRead || cacheEntry.isRemoveOnConsume()) {
                cacheEntry.getEndpointParams().keySet().removeAll(endpointParams.keySet());
                SessionDataCache.getInstance().clearCacheEntry(cacheKey);
                SessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);
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
