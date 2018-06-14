package org.wso2.carbon.identity.local.auth.api.core.constants;

public class AuthAPIConstants {

    // Authentication Request Parameter Keys
    public static final String AUTH_PARAM_AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTH_PARAM_USERNAME = "Username";
    public static final String AUTH_PARAM_PASSWORD = "Password";

    public static final String JWT_TOKEN_TYPE = "JWT";
    public static final String JWT_CLAIM_NONCE = "nonce";

    public enum Error {

        ERROR_INVALID_USER("18003", "Username cannot be empty."),
        ERROR_INVALID_AUTHORIZATION_HEADER("30001", "Authorization header does not comply with HTTP Basic " +
                "authentication scheme."),
        ERROR_INVALID_AUTH_REQUEST("30002", "Request should comply with HTTP Basic authentication scheme or " +
                "credentials should be communicated over request body."),
        ERROR_INVALID_CREDENTIALS("17002", "Authentication failed due to invalid credentials provided."),
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
