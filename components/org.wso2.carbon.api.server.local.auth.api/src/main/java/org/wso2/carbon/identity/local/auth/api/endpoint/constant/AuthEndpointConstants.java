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

package org.wso2.carbon.identity.local.auth.api.endpoint.constant;

/**
 * This class defines constants used within this component.
 */
public class AuthEndpointConstants {

    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";
    public static final String DEFAULT_RESPONSE_CONTENT_TYPE = APPLICATION_JSON;

    public static final String STATUS_BAD_REQUEST_MESSAGE_DEFAULT = "Bad Request";
    public static final String STATUS_NOT_ACCEPTABLE_MESSAGE_DEFAULT = "Not Acceptable";
    public static final String STATUS_NOT_FOUND_MESSAGE_DEFAULT = "Not Found";
    public static final String STATUS_INTERNAL_SERVER_ERROR_MESSAGE_DEFAULT = "Internal server error";
    public static final String STATUS_INTERNAL_SERVER_ERROR_DESCRIPTION_DEFAULT = "The server encountered "
            + "an internal error. Please contact administrator.";

    private AuthEndpointConstants() {
    }
}
