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

package org.wso2.carbon.identity.local.auth.api.endpoint.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.local.auth.api.core.AuthManager;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIClientException;
import org.wso2.carbon.identity.local.auth.api.endpoint.constant.AuthEndpointConstants;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AllSessionsDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ApplicationDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.SessionDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.BadRequestException;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.ClientErrorException;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.ForbiddenException;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.InternalServerErrorException;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.NotAcceptableException;
import org.wso2.carbon.identity.local.auth.api.endpoint.exception.NotFoundException;
import org.wso2.carbon.identity.user.session.constant.SessionConstants;
import org.wso2.carbon.identity.user.session.manager.SessionManager;
import org.wso2.carbon.identity.user.session.model.Application;
import org.wso2.carbon.identity.user.session.model.UserSession;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class includes utility methods.
 */
public class AuthAPIEndpointUtil {

    private AuthAPIEndpointUtil() {
    }

    public static AuthManager getAuthManager() {

        return (AuthManager) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService(AuthManager.class,
                null);
    }

    public static SessionManager getSessionManager() {

        return (SessionManager) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(SessionManager.class, null);
    }


    public static AllSessionsDTO getSessionResponse(UserSession[] userSessionList) {
        AllSessionsDTO initiateAllSessionsDTO = new AllSessionsDTO();

        List<SessionDTO> userSessionDTOS = new ArrayList<>();

        for (UserSession userSession : userSessionList) {
            SessionDTO sessionDTO = new SessionDTO();
            sessionDTO.setApplications(getApplicationDTO(userSession.getApplications()));
            sessionDTO.setUserAgent(userSession.getUserAgent());
            sessionDTO.setIp(userSession.getIp());
            sessionDTO.setLoginTime(userSession.getLoginTime());
            sessionDTO.setLastAccessTime(userSession.getLastAccessTime());
            sessionDTO.setSessionId(DigestUtils.sha256Hex(userSession.getSessionId()));
            userSessionDTOS.add(sessionDTO);
        }
        initiateAllSessionsDTO.setSessions(userSessionDTOS);
        return initiateAllSessionsDTO;
    }

    private static List<ApplicationDTO> getApplicationDTO(Application[] applicationList) {
        List<ApplicationDTO> applicationDTOList = new ArrayList<>();

        for (Application application : applicationList) {
            ApplicationDTO applicationDTO = new ApplicationDTO();
            applicationDTO.setApp(application.getAppName());
            applicationDTO.setSubject(application.getSubject());
            applicationDTOList.add(applicationDTO);
        }
        return applicationDTOList;
    }

    private static ErrorDTO getErrorDTO(String message, String description, String code) {

        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(message);
        errorDTO.setDescription(description);
        return errorDTO;
    }
    /**
     * This method is used to create a client exceptions with the known errorCode and message based on error type.
     *
     * @param description Error message description
     * @param code        Error code
     * @param errorType   Error type
     * @param properties  Additional properties
     * @param log         Logger
     * @param e           Exception object
     * @return ClientErrorException with the given errorCode and description.
     */
    public static ClientErrorException buildClientErrorException(String description, String code,
                                                                 AuthAPIClientException.ErrorType errorType,
                                                                 Map<String, String> properties, Log log, Throwable e) {

        if (AuthAPIClientException.ErrorType.BAD_REQUEST.equals(errorType)) {
            return buildBadRequestException(description, code, properties, log, e);
        } else if (AuthAPIClientException.ErrorType.NOT_ACCEPTABLE.equals(errorType)) {
            return buildNotAcceptableException(description, code, properties, log, e);
        } else if (AuthAPIClientException.ErrorType.NOT_FOUND.equals(errorType)) {
            return buildNotFoundException(description, code, properties, log, e);
        }

        return buildBadRequestException(description, code, properties, log, e);
    }

    /**
     * This method is used to create a BadRequestException with the known errorCode and message.
     *
     * @param description Error message description.
     * @param code        Error code.
     * @param properties Additional properties
     * @param log Logger
     * @param e Exception object
     * @return BadRequestException with the given errorCode and description.
     */
    public static BadRequestException buildBadRequestException(String description, String code,
                                                               Map<String, String> properties, Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(AuthEndpointConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, description, code,
                properties);
        logDebug(AuthEndpointConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, log, e);
        return new BadRequestException(errorDTO);
    }

    /**
     * This method is used to create a NotAcceptableException with the known errorCode and message.
     *
     * @param description Error message description.
     * @param code        Error code.
     * @param properties  Additional properties
     * @param log         Logger
     * @param e           Exception object
     * @return BadRequestException with the given errorCode and description.
     */
    public static NotAcceptableException buildNotAcceptableException(String description, String code, Map<String,
            String> properties, Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(AuthEndpointConstants.STATUS_NOT_ACCEPTABLE_MESSAGE_DEFAULT, description,
                code, properties);
        logDebug(AuthEndpointConstants.STATUS_NOT_ACCEPTABLE_MESSAGE_DEFAULT, log, e);
        return new NotAcceptableException(errorDTO);
    }

    /**
     * This method is used to create a NotFoundException with the known errorCode and message.
     *
     * @param description Error message description.
     * @param code        Error code.
     * @param properties  Additional properties
     * @param log         Logger
     * @param e           Exception object
     * @return NotFoundException with the given errorCode and description.
     */
    public static NotFoundException buildNotFoundException(String description, String code, Map<String, String>
            properties, Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(AuthEndpointConstants.STATUS_NOT_FOUND_MESSAGE_DEFAULT, description, code,
                properties);
        logDebug(AuthEndpointConstants.STATUS_NOT_FOUND_MESSAGE_DEFAULT, log, e);
        return new NotFoundException(errorDTO);
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

    private static ErrorDTO getErrorDTO(String message, String description, String code, Map<String, String>
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

    private static void logDebug(String message, Log log, Throwable throwable) {

        if (log.isDebugEnabled()) {
            log.debug(message, throwable);
        }
    }

    /**
     * This method is used to create a BadRequestException with the known errorCode and message.
     *
     * @param description Error Message Desription.
     * @param code        Error Code.
     * @return BadRequestException with the given errorCode and description.
     */
    public static BadRequestException buildBadRequestException(String description, String code,
                                                               Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(SessionConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, description, code);
        logDebug(AuthEndpointConstants.STATUS_NOT_FOUND_MESSAGE_DEFAULT, log, e);
        return new BadRequestException(errorDTO);
    }

    /**
     * This method is used to create a NotFoundException with the known errorCode and message.
     *
     * @param description Error Message Description.
     * @param code        Error Code.
     * @return NotFoundException with the given errorCode and description.
     */
    public static NotFoundException buildNotFoundRequestException(String description, String code,
                                                                  Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(SessionConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, description, code);
        logDebug(AuthEndpointConstants.STATUS_NOT_FOUND_MESSAGE_DEFAULT, log, e);
        return new NotFoundException(errorDTO);
    }

    /**
     * This method is used to create a Forbidden Exception with the known errorCode and message.
     *
     * @param description Error Message Description.
     * @param code        Error Code.
     * @return ForbiddenException with the given errorCode and description.
     */
    public static ForbiddenException buildForbiddenException(String description, String code,
                                                             Log log, Throwable e) {

        ErrorDTO errorDTO = getErrorDTO(SessionConstants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, description, code);
        logDebug(AuthEndpointConstants.STATUS_NOT_FOUND_MESSAGE_DEFAULT, log, e);
        return new ForbiddenException(errorDTO);
    }

}
