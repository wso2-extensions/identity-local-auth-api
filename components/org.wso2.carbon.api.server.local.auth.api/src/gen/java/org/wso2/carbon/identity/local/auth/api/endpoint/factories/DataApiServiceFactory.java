package org.wso2.carbon.identity.local.auth.api.endpoint.factories;

import org.wso2.carbon.identity.local.auth.api.endpoint.DataApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.impl.DataApiServiceImpl;

public class DataApiServiceFactory {

    private final static DataApiService service = new DataApiServiceImpl();

    public static DataApiService getDataApi() {

        return service;
    }
}
