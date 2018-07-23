/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.local.auth.api.endpoint.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.local.auth.api.endpoint.ContextApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ParametersDTO;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Map;
import javax.ws.rs.core.Response;

public class ContextApiServiceImpl extends ContextApiService {

    private static final Log LOG = LogFactory.getLog(ContextApiServiceImpl.class);

    @Override
    public Response getContextParameters(String sessionKey, String parameters) {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(sessionKey);
        if (context != null) {
            Map<String, Serializable> endpointParams = context.getEndpointParams();
            if (StringUtils.isNotBlank(parameters)) {
                String[] paramArray = parameters.split(",");
                endpointParams.entrySet().retainAll(Arrays.asList(paramArray));
            }
            return buildResponse(endpointParams);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authentication context not found for session key: " + sessionKey);
            }
            ErrorDTO errorDTO = new ErrorDTO();
            errorDTO.setCode("404");
            errorDTO.setMessage("Invalid Session Key");
            errorDTO.setDescription("Session key is either invalid or expired");
            return Response.status(Response.Status.NOT_FOUND).entity(errorDTO).build();
        }
    }

    private Response buildResponse(Map<String, Serializable> params) {

        ParametersDTO parametersDTO = new ParametersDTO();

        parametersDTO.putAll(params);
        return Response.ok(parametersDTO).build();
    }
}
