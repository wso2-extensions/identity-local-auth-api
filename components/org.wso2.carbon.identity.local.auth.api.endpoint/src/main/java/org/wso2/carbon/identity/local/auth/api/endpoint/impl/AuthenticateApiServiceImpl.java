package org.wso2.carbon.identity.local.auth.api.endpoint.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
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

public class AuthenticateApiServiceImpl extends AuthenticateApiService {

    private final Log log = LogFactory.getLog(AuthenticateApiServiceImpl.class);

    @Override
    public Response authenticatePost(String authorization, AuthenticationRequestDTO credentials) {

        try {
            String sessionDataKey = credentials.getSessionDataKey();
            if(sessionDataKey == null){
                log.error("SessionDataKey is not sent in the request.");
                throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_MISSING_REQUIRED_PARAMETERS.getMessage
                        () + " sessionDataKey",
                        AuthAPIConstants.Error.ERROR_MISSING_REQUIRED_PARAMETERS.getCode());
            }
            AuthenticationContext authenticationContextFromCache = FrameworkUtils.getAuthenticationContextFromCache(sessionDataKey);
            if (authenticationContextFromCache == null){
                log.error("Context does not exist. Probably due to invalidated cache");
                throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_CONTEXT_DOES_NOT_EXIST.getMessage(),
                        AuthAPIConstants.Error.ERROR_CONTEXT_DOES_NOT_EXIST.getCode(), ConfigurationFacade
                        .getInstance().getAuthenticationEndpointRetryURL());
            }
            if (StringUtils.isNotBlank(authorization)) {
                if (log.isDebugEnabled()) {
                    log.debug("Credentials received from 'Authorization' header.");
                }

                AuthenticationSuccessResponseDTO successResponseDTO = authenticateWithAuthorizationHeader
                        (authorization, authenticationContextFromCache);
                return Response.ok().entity(successResponseDTO).build();

            } else if (credentials != null && StringUtils.isNotBlank(credentials.getUsername()) && StringUtils
                    .isNotBlank(credentials.getPassword())) {
                if (log.isDebugEnabled()) {
                    log.debug("Credentials received in request body.");
                }

                AuthenticationSuccessResponseDTO successResponseDTO = authenticateWithRequestBodyParameters
                        (credentials, authenticationContextFromCache);
                return Response.ok().entity(successResponseDTO).build();
            } else {
                throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_AUTH_REQUEST.getMessage(),
                        AuthAPIConstants.Error.ERROR_INVALID_AUTH_REQUEST.getCode());

            }
        } catch (AuthAPIClientException e) {
            return handleBadRequestResponse(e);
        } catch (AuthAPIException e) {
            return handleServerErrorResponse(e);
        } catch (Throwable e) {
            return handleUnexpectedServerError(e);
        }
    }

    protected AuthenticationSuccessResponseDTO authenticateWithAuthorizationHeader(String authorizationHeader, AuthenticationContext context) throws
            AuthAPIException {

        AuthnRequest authnRequest = new AuthnRequest();
        authnRequest.setAuthType(AuthAPIConstants.AuthType.VIA_AUTHORIZATION_HEADER.name());
        authnRequest.setParameter(AuthAPIConstants.AUTH_PARAM_AUTHORIZATION_HEADER, authorizationHeader);
        authnRequest.setParameter(AuthAPIConstants.AUTH_CONTEXT, context);
        return authenticate(authnRequest);
    }

    protected AuthenticationSuccessResponseDTO authenticateWithRequestBodyParameters(AuthenticationRequestDTO
                                                                                             credentials, AuthenticationContext context) throws
            AuthAPIException {

        AuthnRequest authnRequest = new AuthnRequest();
        authnRequest.setAuthType(AuthAPIConstants.AuthType.VIA_REQUEST_BODY.name());
        authnRequest.setParameter(AuthAPIConstants.AUTH_PARAM_USERNAME, credentials.getUsername());
        authnRequest.setParameter(AuthAPIConstants.AUTH_PARAM_PASSWORD, credentials.getPassword());
        authnRequest.setParameter(AuthAPIConstants.AUTH_CONTEXT, context);
        return authenticate(authnRequest);
    }

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


    private Response handleBadRequestResponse(AuthAPIClientException e) {

        throw AuthAPIEndpointUtil.buildBadRequestException(e.getMessage(), e.getErrorCode(), e.getRedirectURL(),
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

