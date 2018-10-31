package org.wso2.carbon.identity.local.auth.api.core;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/**
 * Interface for authentication API parameter resolver. Any Implementation should be registered as an OSGi Service.
 */
public interface ParameterResolver {

    /**
     * Retrieve the parameters available for the given key. Optionally filter them if a non empty filter is provided.
     * @param key The correlation key
     * @param filter Set of attributes which are required.
     * @return Map where key represent the name of the parameter and value represent the value of the parameter
     */
    Map<String, Serializable> getParameters(String key, Set<String> filter);

    /**
     * Retrieve and remove the parameters available for the given key. Optionally filter them if a non empty filter is
     * provided.
     * @param key The correlation key
     * @param filter Set of attributes which are required.
     * @return Map where key represent the name of the parameter and value represent the value of the parameter
     */
    Map<String, Serializable> consumeParameters(String key, Set<String> filter);

    /**
     * Get the registered key type.
     * @return The key type this resolver can handle.
     */
    String getRegisteredKeyType();

}
