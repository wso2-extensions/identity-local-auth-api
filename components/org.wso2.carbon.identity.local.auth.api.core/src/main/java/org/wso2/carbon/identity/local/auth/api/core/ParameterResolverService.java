package org.wso2.carbon.identity.local.auth.api.core;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/**
 * Represents the resolver service for API parameter API.
 */
public interface ParameterResolverService {

    /**
     * Register a new resolver which can resolve parameters of a given type.
     *
     * @param resolver The resolver to be registered.
     */
    void registerResolver(ParameterResolver resolver);

    /**
     * Unregister a resolver which is already registered.
     * @param resolver The resolver to be unregistered.
     */
    void unregisterResolver(ParameterResolver resolver);

    /**
     * Check if there are any resolvers registered for a given type.
     * @param keyType The key type to be checked for.
     * @return <code>true</code> if there is a resolver registered for the given type. <code>false otherwise.</code>
     */
    boolean isResolverRegisteredForKey(String keyType);

    /**
     * Resolves the parameters available for given key of given type.
     * @param keyType Type of the correlation key
     * @param correlationKey Correlation key
     * @param filter If present and not empty, only returns the values for specified keys here.
     * @return Map with a key value pairs of parameters that are available for the given key.
     */
    Map<String, Serializable> resolveParameters(String keyType, String correlationKey, Set<String> filter);

}
