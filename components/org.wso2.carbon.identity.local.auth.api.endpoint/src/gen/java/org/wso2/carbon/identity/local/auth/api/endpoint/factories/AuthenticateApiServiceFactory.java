package org.wso2.carbon.identity.local.auth.api.endpoint.factories;

import org.wso2.carbon.identity.local.auth.api.endpoint.AuthenticateApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.impl.AuthenticateApiServiceImpl;

public class AuthenticateApiServiceFactory {

   private final static AuthenticateApiService service = new AuthenticateApiServiceImpl();

   public static AuthenticateApiService getAuthenticateApi()
   {
      return service;
   }
}
