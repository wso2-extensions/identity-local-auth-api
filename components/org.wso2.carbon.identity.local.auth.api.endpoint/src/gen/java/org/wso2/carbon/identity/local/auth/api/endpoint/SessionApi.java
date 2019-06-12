package org.wso2.carbon.identity.local.auth.api.endpoint;

import io.swagger.annotations.ApiParam;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AllSessionsDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.factories.SessionApiServiceFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("/session")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/session", description = "the session API")
public class SessionApi  {

   private final SessionApiService delegate = SessionApiServiceFactory.getSessionApi();

    @GET
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Get active sessions", notes = "This API is used to retrieve user's session information.", response = AllSessionsDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful response"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getUserSession(@Context MessageContext context)
    {
    return delegate.getUserSession(context);
    }
    @DELETE
    @Path("/{sessionId}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Terminate a session", notes = "This API is used to terminate user's session.", response = void.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful response"),
        
        @io.swagger.annotations.ApiResponse(code = 204, message = "No content"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response terminateASession(@Context MessageContext context ,@ApiParam(value = "id of the session",required=true ) @PathParam("sessionId")  String sessionId)
    {
     return delegate.terminateASession(context, sessionId);
    }
    @DELETE
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Terminate all sessions", notes = "This API is used to terminate user's session.", response = void.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful response"),
        
        @io.swagger.annotations.ApiResponse(code = 204, message = "No content"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response terminateAllSessions(@Context MessageContext context)
    {
     return delegate.terminateAllSessions(context);
    }
}

