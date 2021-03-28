package org.wso2.carbon.identity.local.auth.api.endpoint;

import io.swagger.annotations.ApiParam;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ParametersDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.factories.DataApiServiceFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

@Path("/data")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/data", description = "the data API")
public class DataApi  {

   private final DataApiService delegate = DataApiServiceFactory.getDataApi();

    @GET
    @Path("/{keyType}/{correlationKey}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Retrieve sensitive parameters used at authentication flow\n", notes = "This API is used to retrieve the sensitive parameters can't be sent as query parameters during the authentication flow.\n<b>Note:</b> This call may not be idempotent if IS is configured to clear the data on retrieval to prevent multiple retrievals.\n", response = ParametersDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "OK"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 401, message = "Unauthorized"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getSensitiveParameters(@ApiParam(value = "This represents the corelation key type. eg. sessionDataKey",required=true ) @PathParam("keyType")  String keyType,
    @ApiParam(value = "This represents correlation key which is of type 'keyType'",required=true ) @PathParam("correlationKey")  String correlationKey,
    @ApiParam(value = "Comma separated list of parameters to filter. If none provided all available parameters will be sent.") @QueryParam("parameters")  String parameters)
    {
    return delegate.getSensitiveParameters(keyType,correlationKey,parameters);
    }
}

