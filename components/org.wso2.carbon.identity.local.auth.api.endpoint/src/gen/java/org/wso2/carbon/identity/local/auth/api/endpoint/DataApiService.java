package org.wso2.carbon.identity.local.auth.api.endpoint;

import javax.ws.rs.core.Response;

public abstract class DataApiService {

    public abstract Response getSensitiveParameters(String keyType, String correlationKey, String parameters);
}

