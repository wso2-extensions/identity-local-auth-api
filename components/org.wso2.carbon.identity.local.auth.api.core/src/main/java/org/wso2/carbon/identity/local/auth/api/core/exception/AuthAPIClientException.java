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

package org.wso2.carbon.identity.local.auth.api.core.exception;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is used to define the client side errors which needs to be handled.
 */
public class AuthAPIClientException extends AuthAPIException {

    private ErrorType errorType;

    private Map<String, String> properties;

    public AuthAPIClientException(String message, String errorCode, ErrorType errorType) {

        super(message, errorCode);
        this.errorType = errorType;
    }

    public AuthAPIClientException(String message, String errorCode) {

        super(message, errorCode);
    }

    public AuthAPIClientException(String message, String errorCode, HashMap<String,String> properties) {

        super(message, errorCode);
        this.properties = properties;
    }

    public AuthAPIClientException(String message, String errorCode, ErrorType errorType, HashMap<String, String>
            properties) {

        super(message, errorCode);
        this.errorType = errorType;
        this.properties = properties;
    }

    public AuthAPIClientException(String message, String errorCode, HashMap<String,String> properties, Throwable cause) {

        super(message, errorCode, cause);
        this.properties = properties;
    }

    public AuthAPIClientException(String message, String errorCode, ErrorType errorType, HashMap<String, String>
            properties, Throwable cause) {

        super(message, errorCode, cause);
        this.errorType = errorType;
        this.properties = properties;
    }

    public AuthAPIClientException(Throwable cause) {

        super(cause);
    }

    public Map<String, String> getProperties() {

        if (properties != null) {
            return Collections.unmodifiableMap(properties);
        }
        return null;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    public ErrorType getErrorType() {
        return errorType;
    }

    public enum ErrorType {
        BAD_REQUEST, NOT_ACCEPTABLE, NOT_FOUND, CONFLICT, UNAUTHORIZED;
    }
}
