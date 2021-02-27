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

package org.wso2.carbon.identity.local.auth.api.core;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.local.auth.api.core.constants.AuthAPIConstants;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIClientException;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIException;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIServerException;
import org.wso2.carbon.identity.local.auth.api.core.internal.AuthAPIServiceComponentDataHolder;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnMessageContext;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnRequest;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnResponse;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnStatus;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class AuthManagerImpl implements AuthManager {

    private static final Log log = LogFactory.getLog(AuthManagerImpl.class);
    protected AuthTokenGenerator authTokenGenerator;
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";

    public AuthManagerImpl(AuthTokenGenerator authTokenGenerator) {
        this.authTokenGenerator = authTokenGenerator;
    }

    @Override
    public AuthnResponse authenticate(AuthnRequest request) throws AuthAPIException {

        AuthnMessageContext authnMessageContext = new AuthnMessageContext();
        if (AuthAPIConstants.AuthType.VIA_AUTHORIZATION_HEADER.name().equals(request.getAuthType())) {

            authenticate(String.valueOf(request.getParameter(AuthAPIConstants.AUTH_PARAM_AUTHORIZATION_HEADER)),
                    authnMessageContext);

        } else if (AuthAPIConstants.AuthType.VIA_REQUEST_BODY.name().equals(request.getAuthType())) {

            authenticate(String.valueOf(request.getParameter(AuthAPIConstants.AUTH_PARAM_USERNAME)), request
                    .getParameter(AuthAPIConstants.AUTH_PARAM_PASSWORD), authnMessageContext);
        } else {
            throw new AuthAPIServerException("Unknown authentication request type. Request type is expected to be " +
                    "either " + AuthAPIConstants.AuthType.VIA_AUTHORIZATION_HEADER.name() + " or " + AuthAPIConstants
                    .AuthType.VIA_REQUEST_BODY);
        }

        if (AuthnStatus.SUCCESS.equals(authnMessageContext.getAuthnStatus())) {
            generateAuthnToken(authnMessageContext);
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(AuthAPIConstants.AUTH_TOKEN)) {
                log.debug("Generated Auth token for user:  " + authnMessageContext.getUser() + "\nToken Type: " +
                        authnMessageContext.getAuthnToken().getToken() + "\nToken: " + authnMessageContext
                        .getAuthnToken().getToken());
            }
        }

        return new AuthnResponse(authnMessageContext);
    }

    @Override
    public void generateAuthnToken(AuthnMessageContext context) throws AuthAPIException {

        authTokenGenerator.generateToken(context);
    }

    protected void authenticate(String authorizationHeader, AuthnMessageContext authnMessageContext) throws
            AuthAPIException {

        if (StringUtils.isNotBlank(authorizationHeader)) {
            String[] splitValues = authorizationHeader.trim().split(" ");
            if (splitValues.length == 2) {
                byte[] decodedBytes = Base64.decodeBase64(splitValues[1].trim().getBytes());
                String credentialString = new String(decodedBytes, StandardCharsets.UTF_8);
                String[] splitCredentials = credentialString.split(":", 2);
                if (splitCredentials.length == 2) {
                    String username = splitCredentials[0];
                    String password = splitCredentials[1];

                    authenticate(username, password, authnMessageContext);
                } else {
                    authnMessageContext.setAuthnStatus(AuthnStatus.ERROR);
                    throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER
                            .getMessage(), AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER.getCode(),
                            AuthAPIClientException.ErrorType.BAD_REQUEST);
                }
            } else {
                authnMessageContext.setAuthnStatus(AuthnStatus.ERROR);
                throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER.getMessage
                        (), AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER.getCode(),
                        AuthAPIClientException.ErrorType.BAD_REQUEST);
            }
        }
    }

    protected void authenticate(String username, Object credential, AuthnMessageContext authnMessageContext) throws
            AuthAPIException {

        if (StringUtils.isBlank(username)) {
            authnMessageContext.setAuthnStatus(AuthnStatus.ERROR);
            throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_USER.getMessage(), AuthAPIConstants
                    .Error.ERROR_INVALID_USER.getCode(), AuthAPIClientException.ErrorType.BAD_REQUEST);
        }

        String userTenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserStoreManager userStoreManager = getUserStoreManager(userTenantDomain);
        if (AuthAPIServiceComponentDataHolder.getInstance().getMultiAttributeLoginService().
                isEnabled(userTenantDomain)) {
            ResolvedUserResult resolvedUser = AuthAPIServiceComponentDataHolder.getInstance().
                    getMultiAttributeLoginService().resolveUser(tenantAwareUsername, userTenantDomain);
            if (resolvedUser != null &&  ResolvedUserResult.UserResolvedStatus.SUCCESS.
                    equals(resolvedUser.getResolvedStatus())) {
                tenantAwareUsername = resolvedUser.getUser().getUsername();
                username = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, userTenantDomain);
            }
        }
        if (authenticate(tenantAwareUsername, credential, userStoreManager)) {
            User user = new User();
            user.setUserName(tenantAwareUsername);
            user.setTenantDomain(userTenantDomain);
            user.setUserStoreDomain(getUserStoreDomain(username));

            authnMessageContext.setUser(user);
            authnMessageContext.setAuthnStatus(AuthnStatus.SUCCESS);

            if (log.isDebugEnabled()) {
                log.debug("User: " + user + " is successfully authenticated.");
            }
        } else {
            authnMessageContext.setAuthnStatus(AuthnStatus.FAIL);
            Map<String, String> errorProperties = getAuthFailureErrorProperties(username);
            if (log.isDebugEnabled()) {
                log.debug("Authentication failed for user: " + username);
            }
            throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getMessage(),
                    AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getCode(), AuthAPIClientException.ErrorType
                    .BAD_REQUEST, errorProperties);
        }
    }

    private boolean authenticate(String username, Object credential, UserStoreManager userStoreManager) throws
            AuthAPIClientException {

        try {
            return userStoreManager.authenticate(username, credential);
        } catch (UserStoreException e) {
            throw handleAuthError(username, credential, e);
        }
    }

    private UserStoreManager getUserStoreManager(String tenantDomain) throws AuthAPIServerException {

        RealmService realmService = AuthAPIServiceComponentDataHolder.getInstance().getRealmService();
        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm != null) {
                return userRealm.getUserStoreManager();
            } else {
                throw new AuthAPIServerException("Failed to retrieve user realm for tenant id: " + tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthAPIServerException("Failed to retrieve user store manager for tenant: " + tenantDomain, e);
        }
    }

    private String getUserStoreDomain(String username) {

        if (!username.contains("/")) {
            if (UserCoreUtil.getDomainFromThreadLocal() != null && !UserCoreUtil.getDomainFromThreadLocal().isEmpty()) {
                return UserCoreUtil.getDomainFromThreadLocal();
            }
        }

        return UserCoreUtil.extractDomainFromName(username);
    }

    private Map<String, String> getAuthFailureErrorProperties(String username) {

        HashMap<String, String> errorProperties = new HashMap<>();
        errorProperties.put(AuthAPIConstants.AUTH_FAILURE, "true");
        errorProperties.put(AuthAPIConstants.AUTH_FAILURE_MSG, "login.fail.message");
        errorProperties.put(AuthAPIConstants.FAILED_USERNAME, username);

        return errorProperties;
    }

    private IdentityErrorMsgContext getIdentityErrorContext() {

        IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
        IdentityUtil.clearIdentityErrorMsg();

        return errorContext;
    }

    private AuthAPIClientException buildUserAccountNotConfirmedError(String username, IdentityErrorMsgContext
            errorMsgContext, Map<String, String> errorProperties, Throwable e) {

        String errorMessage = "User Account is not yet confirmed.";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_ACCEPTABLE;
        errorProperties.put(AuthAPIConstants.AUTH_FAILURE_MSG, "account.confirmation.pending");
        Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
        if (domain != null) {
            username = IdentityUtil.addDomainToName(username, domain.toString());
            errorProperties.put(AuthAPIConstants.FAILED_USERNAME, username);
        }

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException buildAdminForcedPasswordResetViaEmailError(String username,
                                                                              IdentityErrorMsgContext
                                                                                      errorMsgContext, Map<String,
            String> errorProperties, Throwable e) {

        String errorMessage = "Password reset is required. A password reset link has been sent to your " +
                "registered email address.";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_ACCEPTABLE;
        errorProperties.put(AuthAPIConstants.AUTH_FAILURE_MSG, "password.reset.pending");

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException buildAdminForcedPasswordResetViaOTPError(String username, Object credential,
                                                                            IdentityErrorMsgContext errorMsgContext,
                                                                            Map<String, String> errorProperties,
                                                                            Throwable e) {

        String errorMessage = "Password reset is required.";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_ACCEPTABLE;
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        errorProperties.put(AuthAPIConstants.AUTH_FAILURE_MSG, "password.reset.pending");
        errorProperties.put(AuthAPIConstants.TENANT_DOMAIN_PARAM, tenantDomain);
        errorProperties.put(AuthAPIConstants.CONFIRMATION_PARAM, credential.toString());

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException buildInvalidCredentialError(String username, IdentityErrorMsgContext
            errorMsgContext, Map<String, String> errorProperties, Throwable e) {


        String errorMessage = AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getMessage();
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.BAD_REQUEST;
        int remainingAttempts = errorMsgContext.getMaximumLoginAttempts() - errorMsgContext.getFailedLoginAttempts();
        errorProperties.put(AuthAPIConstants.REMAINING_ATTEMPTS, Integer.toString(remainingAttempts));

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException buildAccountLockedError(String username, IdentityErrorMsgContext errorMsgContext,
                                                           Map<String, String> errorProperties, Throwable e) {

        String errorMessage = "User Account is Locked. ";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_ACCEPTABLE;

        int remainingAttempts = getRemainingLoginAttempts(errorMsgContext);
        errorProperties.put(AuthAPIConstants.REMAINING_ATTEMPTS, Integer.toString(remainingAttempts));

        String errorCode = errorMsgContext.getErrorCode();
        String reason = null;
        if (errorCode.contains(AuthAPIConstants.ERROR_REASON_SEPARATOR)) {
            String[] errorCodeReason = errorCode.split(AuthAPIConstants.ERROR_REASON_SEPARATOR);
            errorCode = errorCodeReason[0];
            if (errorCodeReason.length > 1) {
                reason = errorCodeReason[1];
            }
        }

        if (!StringUtils.isBlank(reason)) {
            errorProperties.put(AuthAPIConstants.LOCKED_REASON, reason);
            errorMessage = errorMessage + reason;
        }

        return new AuthAPIClientException(errorMessage, errorCode, errorType, errorProperties, e);
    }

    private AuthAPIClientException buildUserNotFoundError(String username, IdentityErrorMsgContext errorMsgContext,
                                                          Map<String, String> errorProperties, Throwable e) {

        String errorMessage = "User Account Does not exists";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_FOUND;

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException buildUserAccountDisabledError(String username, IdentityErrorMsgContext
            errorMsgContext, Map<String, String> errorProperties, Throwable e) {

        String errorMessage = "User Account is Disabled.";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_ACCEPTABLE;

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException buildAdminForcedPasswordResetViaOTPMismatchedError(String username,
                                                                                      IdentityErrorMsgContext
                                                                                              errorMsgContext,
                                                                                      Map<String, String>
                                                                                              errorProperties,
                                                                                      Throwable e) {

        String errorMessage = "Password Reset is required.";
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.NOT_ACCEPTABLE;

        return new AuthAPIClientException(errorMessage, errorMsgContext.getErrorCode(), errorType, errorProperties, e);
    }

    private AuthAPIClientException handleAuthError(String username, Object credential, UserStoreException e) {

        String errorMessage = AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getMessage();
        String errorCode = AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getCode();
        AuthAPIClientException.ErrorType errorType = AuthAPIClientException.ErrorType.BAD_REQUEST;
        Map<String, String> errorProperties = getAuthFailureErrorProperties(username);
        IdentityErrorMsgContext errorContext = getIdentityErrorContext();

        if (log.isDebugEnabled()) {
            log.debug("Authentication error occurred while authenticating user: " + username);
        }

        if (errorContext != null && errorContext.getErrorCode() != null) {

            errorCode = errorContext.getErrorCode();
            if (log.isDebugEnabled()) {
                StringBuilder debugString = new StringBuilder();
                debugString.append("Identity error message context is not null. Error details are as follows.\n");
                debugString.append("errorCode : " + errorCode + "\n");
                debugString.append("username : " + username + "\n");
                debugString.append("remainingLoginAttempts : " + getRemainingLoginAttempts(errorContext) + "\n");
                log.debug(debugString.toString());
            }

            switch (errorCode) {
                case IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE:
                    return buildUserAccountNotConfirmedError(username, errorContext, errorProperties, e);
                case IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE:
                    return buildAdminForcedPasswordResetViaEmailError(username, errorContext, errorProperties, e);
                case IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE:
                    return buildAdminForcedPasswordResetViaOTPError(username, credential, errorContext,
                            errorProperties, e);
                case UserCoreConstants.ErrorCode.INVALID_CREDENTIAL:
                    return buildInvalidCredentialError(username, errorContext, errorProperties, e);
                case UserCoreConstants.ErrorCode.USER_IS_LOCKED:
                    return buildAccountLockedError(username, errorContext, errorProperties, e);
                case UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST:
                    return buildUserNotFoundError(username, errorContext, errorProperties, e);
                case IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE:
                    return buildUserAccountDisabledError(username, errorContext, errorProperties, e);
                case IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE:
                    return buildAdminForcedPasswordResetViaOTPMismatchedError(username, errorContext,
                            errorProperties, e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Identity error message context is null.");
            }
        }

        return new AuthAPIClientException(errorMessage, errorCode, errorType, errorProperties, e);
    }

    private int getRemainingLoginAttempts(IdentityErrorMsgContext errorMsgContext) {

        return errorMsgContext.getMaximumLoginAttempts() - errorMsgContext.getFailedLoginAttempts();
    }

}
