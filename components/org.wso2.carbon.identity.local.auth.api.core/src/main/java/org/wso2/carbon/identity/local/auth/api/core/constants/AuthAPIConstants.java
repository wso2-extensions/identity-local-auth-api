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

package org.wso2.carbon.identity.local.auth.api.core.constants;

/**
 * This class includes all the constants defined within this component.
 */
public class AuthAPIConstants {

    // Authentication Request Parameter Keys
    public static final String AUTH_PARAM_AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTH_PARAM_USERNAME = "Username";
    public static final String AUTH_PARAM_PASSWORD = "Password";

    public static final String JWT_TOKEN_TYPE = "JWT";
    public static final String JWT_CLAIM_NONCE = "nonce";

    public static final String FAILED_USERNAME = "failedUsername";
    public static final String CONFIRMATION_PARAM = "confirmation";
    public static final String AUTH_FAILURE = "authFailure";
    public static final String AUTH_FAILURE_MSG = "authFailureMsg";
    public static final String TENANT_DOMAIN_PARAM = "tenantdomain";
    public static final String REMAINING_ATTEMPTS = "remainingAttempts";
    public static final String LOCKED_REASON = "lockedReason";


    public enum Error {

        ERROR_INVALID_USER("18003", "Username cannot be empty."),
        ERROR_INVALID_AUTHORIZATION_HEADER("30001", "Authorization header does not comply with HTTP Basic " +
                "authentication scheme."),
        ERROR_INVALID_AUTH_REQUEST("30002", "Request should comply with HTTP Basic authentication scheme or " +
                "credentials should be communicated over request body."),
        ERROR_INVALID_CREDENTIALS("17002", "Login failed! Please recheck the username and password and try again."),
        ERROR_MISSING_REQUIRED_PARAMETERS("17013", "Authentication failed due to missing required parameter"),
        ERROR_CONTEXT_DOES_NOT_EXIST("17014", "Context does not exist. Probably due to invalidated cache."),
        ERROR_UNEXPECTED("18013", "Unexpected error."),
        ;

        private final String code;
        private final String message;

        Error(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return code + " - " + message;
        }

    }

    public enum AuthType {
        VIA_AUTHORIZATION_HEADER, VIA_REQUEST_BODY;
    }

}
