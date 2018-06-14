package org.wso2.carbon.identity.local.auth.api.endpoint.constant;

public class AuthEndpointConstants {

    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";
    public static final String DEFAULT_RESPONSE_CONTENT_TYPE = APPLICATION_JSON;

    public static final String STATUS_BAD_REQUEST_MESSAGE_DEFAULT = "Bad Request";
    public static final String STATUS_INTERNAL_SERVER_ERROR_MESSAGE_DEFAULT = "Internal server error";
    public static final String STATUS_INTERNAL_SERVER_ERROR_DESCRIPTION_DEFAULT = "The server encountered "
            + "an internal error. Please contact administrator.";

    private AuthEndpointConstants() {
    }
}
