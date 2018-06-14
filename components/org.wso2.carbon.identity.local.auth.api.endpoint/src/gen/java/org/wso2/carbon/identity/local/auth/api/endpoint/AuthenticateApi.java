package org.wso2.carbon.identity.local.auth.api.endpoint;

import org.wso2.carbon.identity.local.auth.api.endpoint.dto.*;
import org.wso2.carbon.identity.local.auth.api.endpoint.AuthenticateApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.factories.AuthenticateApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AuthenticationRequestDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AuthenticationSuccessResponseDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/authenticate")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/authenticate", description = "the authenticate API")
public class AuthenticateApi  {

   private final AuthenticateApiService delegate = AuthenticateApiServiceFactory.getAuthenticateApi();

    @POST
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Authenticate User \n", notes = "This API is used to authenticate the user and to get a JWT that can be used to identify the user authenticated\n", response = AuthenticationSuccessResponseDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 202, message = "Authentication accepted"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response authenticatePost(@ApiParam(value = "Authorization header that contains the 'Basic' word followed by a space and a base64-encoded username:password string. Required unless username, password not passed in request body."  )@HeaderParam("Authorization") String authorization,
    @ApiParam(value = "Username and password in request body. Required unless username, password not passed with 'Authorization' header."  ) AuthenticationRequestDTO credentials)
    {
    return delegate.authenticatePost(authorization,credentials);
    }
}

