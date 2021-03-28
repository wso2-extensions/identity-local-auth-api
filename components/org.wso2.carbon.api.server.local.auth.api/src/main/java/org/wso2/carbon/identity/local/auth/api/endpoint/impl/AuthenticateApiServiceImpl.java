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

package org.wso2.carbon.identity.local.auth.api.endpoint.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.api.core.constants.AuthAPIConstants;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIClientException;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIException;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnRequest;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnResponse;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnStatus;
import org.wso2.carbon.identity.local.auth.api.endpoint.AuthenticateApiService;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AuthenticationRequestDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AuthenticationSuccessResponseDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.util.AuthAPIEndpointUtil;

import javax.ws.rs.core.Response;

/**
 * Authentication Service class
 */
public class AuthenticateApiServiceImpl extends AuthenticateApiService {

    private static final Log log = LogFactory.getLog(AuthenticateApiServiceImpl.class);

    @Override
    public Response authenticatePost(String authorization, AuthenticationRequestDTO credentials) {

        try {
            if (StringUtils.isNotBlank(authorization)) {
                if (log.isDebugEnabled()) {
                    log.debug("Credentials received from 'Authorization' header.");
                }

                AuthenticationSuccessResponseDTO successResponseDTO = authenticateWithAuthorizationHeader
                        (authorization);
                return Response.ok().entity(successResponseDTO).build();

            } else if (credentials != null && StringUtils.isNotBlank(credentials.getUsername()) && StringUtils
                    .isNotBlank(credentials.getPassword())) {
                if (log.isDebugEnabled()) {
                    log.debug("Credentials received in request body.");
                }

                AuthenticationSuccessResponseDTO successResponseDTO = authenticateWithRequestBodyParameters
                        (credentials);
                return Response.ok().entity(successResponseDTO).build();
            } else {
                throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_AUTH_REQUEST.getMessage(),
                        AuthAPIConstants.Error.ERROR_INVALID_AUTH_REQUEST.getCode(), AuthAPIClientException.ErrorType
                        .BAD_REQUEST);

            }
        } catch (AuthAPIClientException e) {
            return handleClientErrorResponse(e);
        } catch (AuthAPIException e) {
            return handleServerErrorResponse(e);
        } catch (Throwable e) {
            return handleUnexpectedServerError(e);
        }
    }

    /**
     * Authenticates with the credentials in authorization header.
     *
     * @param authorizationHeader Authorization header value
     * @return Upon successful authentication return an instance of AuthenticationSuccessResponseDTO
     * @throws AuthAPIException Thrown when authentication fails or server error occurs
     */
    protected AuthenticationSuccessResponseDTO authenticateWithAuthorizationHeader(String authorizationHeader) throws
            AuthAPIException {

        AuthnRequest authnRequest = new AuthnRequest();
        authnRequest.setAuthType(AuthAPIConstants.AuthType.VIA_AUTHORIZATION_HEADER.name());
        authnRequest.setParameter(AuthAPIConstants.AUTH_PARAM_AUTHORIZATION_HEADER, authorizationHeader);
        return authenticate(authnRequest);
    }

    /**
     * Authenticates with the credentials in the request body.
     *
     * @param credentials AuthenticationRequestDTO containing user credentials
     * @return Upon successful authentication return an instance of AuthenticationSuccessResponseDTO
     * @throws AuthAPIException Thrown when authentication fails or server error occurs
     */
    protected AuthenticationSuccessResponseDTO authenticateWithRequestBodyParameters(AuthenticationRequestDTO
                                                                                             credentials) throws
            AuthAPIException {

        AuthnRequest authnRequest = new AuthnRequest();
        authnRequest.setAuthType(AuthAPIConstants.AuthType.VIA_REQUEST_BODY.name());
        authnRequest.setParameter(AuthAPIConstants.AUTH_PARAM_USERNAME, credentials.getUsername());
        authnRequest.setParameter(AuthAPIConstants.AUTH_PARAM_PASSWORD, credentials.getPassword());
        return authenticate(authnRequest);
    }

    /**
     * Authenticates with credentials received from AuthnRequest instance.
     *
     * @param authnRequest AuthnRequest instance
     * @return Upon successful authentication return an instance of AuthenticationSuccessResponseDTO
     * @throws AuthAPIException Thrown when authentication fails or server error occurs
     */
    protected AuthenticationSuccessResponseDTO authenticate(AuthnRequest authnRequest) throws AuthAPIException {

        AuthnResponse authnResponse = AuthAPIEndpointUtil.getAuthManager().authenticate(authnRequest);
        AuthenticationSuccessResponseDTO authenticationSuccessResponseDTO = new AuthenticationSuccessResponseDTO();
        if (AuthnStatus.SUCCESS.equals(authnResponse.getAuthnStatus()) && authnResponse.getAuthnToken() != null) {
            authenticationSuccessResponseDTO.setToken(authnResponse.getAuthnToken().getToken());
        } else {
            authenticationSuccessResponseDTO.setToken(StringUtils.EMPTY);
        }

        return authenticationSuccessResponseDTO;
    }


    private Response handleClientErrorResponse(AuthAPIClientException e) {

        throw AuthAPIEndpointUtil.buildClientErrorException(e.getMessage(), e.getErrorCode(), e.getErrorType(), e
                        .getProperties(),
                log, e);
    }

    private Response handleServerErrorResponse(AuthAPIException e) {

        throw AuthAPIEndpointUtil.buildInternalServerErrorException(e.getErrorCode(), log, e);
    }

    private Response handleUnexpectedServerError(Throwable e) {

        throw AuthAPIEndpointUtil.buildInternalServerErrorException(AuthAPIConstants.Error.ERROR_UNEXPECTED.getCode()
                , log, e);
    }
}

