package org.wso2.carbon.identity.local.auth.api.core.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolver;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolverService;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Implementation for {@link ParameterResolverService}.
 */
public class ParameterResolverServiceImpl implements ParameterResolverService {

    private static final Log LOG = LogFactory.getLog(ParameterResolverServiceImpl.class);

    private Map<String, ParameterResolver> resolversMap = new HashMap<>();

    @Override
    public void registerResolver(ParameterResolver resolver) {

        if (resolversMap.containsKey(resolver.getRegisteredKeyType())) {
            LOG.warn("Already existing Resolver for " + resolver.getRegisteredKeyType() + " was replaced with a new " +
                    "resolver. This might lead to any unexpected behaviours.");
        }
        resolversMap.put(resolver.getRegisteredKeyType(), resolver);
    }

    @Override
    public void unregisterResolver(ParameterResolver resolver) {

        resolversMap.remove(resolver.getRegisteredKeyType());
    }

    @Override
    public boolean isResolverRegisteredForKey(String keyType) {

        return resolversMap.containsKey(keyType);
    }

    @Override
    public Map<String, Serializable> resolveParameters(String keyType, String correlationKey, Set<String> filter) {

        if (resolversMap.containsKey(keyType)) {
            if (FrameworkUtils.isRemoveAPIParamsOnConsume()) {
                return resolversMap.get(keyType).consumeParameters(correlationKey, filter);
            } else {
                return resolversMap.get(keyType).getParameters(correlationKey, filter);
            }
        }
        return Collections.emptyMap();
    }
}
