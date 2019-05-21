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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.local.auth.api.endpoint.SessionApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AllSessionsDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.util.AuthAPIEndpointUtil;
import org.wso2.carbon.identity.user.session.exception.SessionManagementClientException;
import org.wso2.carbon.identity.user.session.exception.SessionManagementException;
import org.wso2.carbon.identity.user.session.model.UserSession;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.local.auth.api.endpoint.util.AuthAPIEndpointUtil.getSessionManager;
import static org.wso2.carbon.identity.local.auth.api.endpoint.util.AuthAPIEndpointUtil.getSessionResponse;
import static org.wso2.carbon.identity.user.session.constant.SessionConstants.ErrorMessages.ERROR_CODE_NO_AUTH_USER_FOUND;
import static org.wso2.carbon.identity.user.session.constant.SessionConstants.ErrorMessages.ERROR_CODE_SESSION_ID_INVALID;
import static org.wso2.carbon.identity.user.session.constant.SessionConstants.ErrorMessages.ERROR_CODE_UNEXPECTED;
import static org.wso2.carbon.identity.user.session.constant.SessionConstants.ErrorMessages.ERROR_CODE_USER_NOT_AUTHORIZED;

public class SessionApiServiceImpl extends SessionApiService {

    private static final Log log = LogFactory.getLog(SessionApiServiceImpl.class);

    @Override
    public Response getUserSession(MessageContext context) {
        try {
            String sessionId = getSessionContextKey(context.getHttpServletRequest());
            if (sessionId != null) {
                UserSession[] userSessions = getSessionManager().viewSession(sessionId);
                AllSessionsDTO sessionResponse = getSessionResponse(userSessions);
                return Response.ok().entity(sessionResponse).build();
            }
            return Response.ok().build();
        } catch (SessionManagementClientException e) {
            return handleBadRequestResponse(e);
        } catch (SessionManagementException e) {
            return handleServerErrorResponse(e);
        } catch (Throwable throwable) {
            return handleUnexpectedServerError(throwable);
        }
    }

    @Override
    public Response terminateASession(MessageContext context, String sessionId) {
        try {
            String currentSessionId = getSessionContextKey(context.getHttpServletRequest());
            boolean terminateSession = getSessionManager().terminateASession(currentSessionId, sessionId);
            return Response.ok().entity(terminateSession).build();
        } catch (SessionManagementClientException e) {
            return handleBadRequestResponse(e);
        } catch (SessionManagementException e) {
            return handleServerErrorResponse(e);
        } catch (Throwable throwable) {
            return handleUnexpectedServerError(throwable);
        }
    }

    @Override
    public Response terminateAllSessions(MessageContext context) {
        try {
            String sessionId = getSessionContextKey(context.getHttpServletRequest());
            boolean terminateSession = getSessionManager().terminateAllSession(sessionId);
            return Response.ok().entity(terminateSession).build();
        } catch (SessionManagementClientException e) {
            return handleBadRequestResponse(e);
        } catch (SessionManagementException e) {
            return handleServerErrorResponse(e);
        } catch (Throwable throwable) {
            return handleUnexpectedServerError(throwable);
        }
    }

    /**
     * Method to get sessionContextKey from http request.
     *
     * @param request Http request
     * @return SessionContextKey of particular session.
     */
    private String getSessionContextKey(HttpServletRequest request) {
        String commonAuthCookie;
        String sessionContextKey = null;
        if (FrameworkUtils.getAuthCookie(request) != null) {
            commonAuthCookie = FrameworkUtils.getAuthCookie(request).getValue();
            if (commonAuthCookie != null) {
                sessionContextKey = DigestUtils.sha256Hex(commonAuthCookie);
            }
        }
        return sessionContextKey;
    }

    private Response handleBadRequestResponse(SessionManagementClientException e) {

        if (isForbiddenError(e)) {
            throw AuthAPIEndpointUtil.buildForbiddenException(e.getMessage(), e.getErrorCode(), log, e);
        }
        if (isNotFoundError(e)) {
            throw AuthAPIEndpointUtil.buildNotFoundRequestException(e.getMessage(), e.getErrorCode(), log, e);
        }
        throw AuthAPIEndpointUtil.buildBadRequestException(e.getMessage(), e.getErrorCode(), log, e);
    }

    private boolean isForbiddenError(SessionManagementClientException e) {

        return ERROR_CODE_NO_AUTH_USER_FOUND.getCode().equals(e.getErrorCode()) ||
                ERROR_CODE_USER_NOT_AUTHORIZED.getCode()
                        .equals(e.getErrorCode());
    }

    private boolean isNotFoundError(SessionManagementClientException e) {

        return ERROR_CODE_SESSION_ID_INVALID.getCode().equals(e.getErrorCode());
    }

    private Response handleServerErrorResponse(SessionManagementException e) {

        throw AuthAPIEndpointUtil.buildInternalServerErrorException(e.getErrorCode(), log, e);
    }

    private Response handleUnexpectedServerError(Throwable e) {

        throw AuthAPIEndpointUtil.buildInternalServerErrorException(ERROR_CODE_UNEXPECTED.getCode(), log, e);
    }

}
