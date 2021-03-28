/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.api.endpoint.exception;


import org.wso2.carbon.identity.local.auth.api.endpoint.constant.AuthEndpointConstants;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;

import javax.ws.rs.core.Response;

/**
 * This exception represents a error upon an Unacceptable Request.
 */
public class NotAcceptableException extends ClientErrorException {

    public NotAcceptableException(ErrorDTO errorDTO) {

        super(Response.status(Response.Status.NOT_ACCEPTABLE).entity(errorDTO).header(AuthEndpointConstants
                .HEADER_CONTENT_TYPE, AuthEndpointConstants.DEFAULT_RESPONSE_CONTENT_TYPE).build());
        message = errorDTO.getDescription();
    }

    public NotAcceptableException() {

        super(Response.Status.NOT_ACCEPTABLE);
    }
}
