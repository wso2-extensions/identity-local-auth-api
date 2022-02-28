package org.wso2.carbon.identity.local.auth.api.endpoint.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.local.auth.api.core.ParameterResolverService;
import org.wso2.carbon.identity.local.auth.api.endpoint.DataApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ParametersDTO;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.ws.rs.core.Response;

public class DataApiServiceImpl extends DataApiService {

    private static final Log LOG = LogFactory.getLog(DataApiServiceImpl.class);

    @Override
    public Response getSensitiveParameters(String keyType, String correlationKey, String parameters) {

        Object serviceObj = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(ParameterResolverService.class, null);
        if (serviceObj instanceof ParameterResolverService) {
            ParameterResolverService resolverService = (ParameterResolverService) serviceObj;
            if (!resolverService.isResolverRegisteredForKey(keyType)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Parameter resolver is not registered for key type : " + keyType);
                }
                return buildError(Response.Status.BAD_REQUEST, "Provided key type is invalid");
            }

            Set<String> filter;
            if (StringUtils.isNotBlank(parameters)) {
                filter = new HashSet<>(Arrays.asList(parameters.split(",")));
            } else {
                filter = Collections.emptySet();
            }
            Map<String, Serializable> paramMap = (resolverService).resolveParameters(keyType,
                    correlationKey, filter);
            if (paramMap.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("No parameters available for key %s (of type %s). Possibly due to expired " +
                            "context, invalid correlation key, or replay request.", correlationKey, keyType));
                }
                return buildError(Response.Status.NOT_FOUND, "Requested parameters are not available.");
            }
            return buildResponse(paramMap);
        } else {
            LOG.error("Parameter resolver service is not available.");
            return buildError(Response.Status.SERVICE_UNAVAILABLE, "Service is not registered.");
        }
    }

    private Response buildResponse(Map<String, Serializable> params) {

        ParametersDTO parametersDTO = new ParametersDTO();

        parametersDTO.putAll(params);
        return Response.ok(parametersDTO).build();
    }

    private Response buildError(Response.Status status, String description) {

        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(String.valueOf(status.getStatusCode()));
        errorDTO.setMessage(status.getReasonPhrase());
        errorDTO.setDescription(description);
        return Response.status(status).entity(errorDTO).build();
    }
}
