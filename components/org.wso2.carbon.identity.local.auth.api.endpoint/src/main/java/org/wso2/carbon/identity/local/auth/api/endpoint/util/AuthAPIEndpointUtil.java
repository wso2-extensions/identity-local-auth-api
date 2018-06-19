package org.wso2.carbon.identity.local.auth.api.endpoint.util;

import org.apache.commons.logging.Log;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.local.auth.api.core.AuthManager;
import org.wso2.carbon.identity.local.auth.api.endpoint.constant.AuthEndpointConstants;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.BadRequestException;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.InternalServerErrorException;

import java.util.Map;

public class AuthAPIEndpointUtil {

    private AuthAPIEndpointUtil() {
    }

    public static AuthManager getAuthManager() {

        return (AuthManager) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService(AuthManager.class,
                null);
    }

    /**
     * This method is used to create a BadRequestException with the known errorCode and message.
     *
     * @param description Error Message Desription.
     * @param code        Error Code.
     * @return BadRequestException with the given errorCode and description.
     */
    public static BadRequestException buildBadRequestException(String description, String code,  Map<String,String> properties,
                                                               Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(AuthEndpointConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, description, code,
                properties);
        logDebug(log, e);
        return new BadRequestException(errorDTO);
    }

    /**
     * This method is used to create an InternalServerErrorException with the known errorCode.
     *
     * @param code Error Code.
     * @return a new InternalServerErrorException with default details.
     */
    public static InternalServerErrorException buildInternalServerErrorException(String code, Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(AuthEndpointConstants.STATUS_INTERNAL_SERVER_ERROR_MESSAGE_DEFAULT,
                AuthEndpointConstants.STATUS_INTERNAL_SERVER_ERROR_MESSAGE_DEFAULT, code, null);
        logError(log, e);
        return new InternalServerErrorException(errorDTO);
    }

    private static ErrorDTO getErrorDTO(String message, String description, String code, Map<String,String>
            properties) {
        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(message);
        errorDTO.setDescription(description);
        errorDTO.setProperties(properties);
        return errorDTO;
    }

    private static void logError(Log log, Throwable throwable) {

        log.error(throwable.getMessage(), throwable);
    }

    private static void logDebug(Log log, Throwable throwable) {

        if (log.isDebugEnabled()) {
            log.debug(AuthEndpointConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, throwable);
        }
    }
}
