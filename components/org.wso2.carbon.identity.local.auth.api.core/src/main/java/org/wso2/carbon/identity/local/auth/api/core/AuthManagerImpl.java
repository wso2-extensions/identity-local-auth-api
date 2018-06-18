package org.wso2.carbon.identity.local.auth.api.core;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
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

import static org.wso2.carbon.identity.local.auth.api.core.constants.AuthAPIConstants.AUTH_FAILURE_MSG;

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
                String[] splitCredentials = credentialString.split(":");
                if (splitCredentials.length == 2) {
                    String username = splitCredentials[0];
                    String password = splitCredentials[1];

                    authenticate(username, password, authnMessageContext);
                } else {
                    authnMessageContext.setAuthnStatus(AuthnStatus.ERROR);
                    throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER
                            .getMessage(), AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER.getCode());
                }
            } else {
                authnMessageContext.setAuthnStatus(AuthnStatus.ERROR);
                throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER.getMessage
                        (), AuthAPIConstants.Error.ERROR_INVALID_AUTHORIZATION_HEADER.getCode());
            }
        }
    }

    protected void authenticate(String username, Object credential, AuthnMessageContext authnMessageContext) throws
            AuthAPIException {

        if (StringUtils.isBlank(username)) {
            authnMessageContext.setAuthnStatus(AuthnStatus.ERROR);
            throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_USER.getMessage(), AuthAPIConstants
                    .Error.ERROR_INVALID_USER.getCode());
        }

        String userTenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserStoreManager userStoreManager = getUserStoreManager(userTenantDomain);

        if (authenticate(tenantAwareUsername, credential, userStoreManager)) {
            User user = new User();
            user.setUserName(tenantAwareUsername);
            user.setTenantDomain(userTenantDomain);
            user.setUserStoreDomain(getUserStoreDomain(username));

            authnMessageContext.setUser(user);
            authnMessageContext.setAuthnStatus(AuthnStatus.SUCCESS);
        } else {
            authnMessageContext.setAuthnStatus(AuthnStatus.FAIL);
            throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getMessage(),
                    AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getCode());
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

    private boolean authenticate(String username, Object credential, UserStoreManager userStoreManager) throws
            AuthAPIClientException {

        try {
            return userStoreManager.authenticate(username, credential);
        } catch (UserStoreException e) {
            String errorMessage = AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getMessage();
            String errorCode = AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getCode();
            HashMap<String, String> errorProperties = new HashMap<>();
            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            IdentityUtil.clearIdentityErrorMsg();
            errorProperties.put(AUTH_FAILURE_MSG, "login.fail.message");
            errorProperties.put(AuthAPIConstants.FAILED_USERNAME, username);

            if (errorContext != null && errorContext.getErrorCode() != null) {
                if (log.isDebugEnabled()) {
                    StringBuilder debugString = new StringBuilder();
                    debugString.append("Identity error message context is not null. Error details are as follows.");
                    debugString.append("errorCode : " + errorCode + "\n");
                    debugString.append("username : " + username + "\n");
                    log.debug(debugString.toString());
                }
                errorCode = errorContext.getErrorCode();
                if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE)) {
                    errorMessage = "User Account is not yet confirmed.";
                    errorProperties.put(AUTH_FAILURE_MSG, "account.confirmation.pending");
                    Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
                    if (domain != null) {
                        username = IdentityUtil.addDomainToName(username, domain.toString());
                        errorProperties.put(AuthAPIConstants.FAILED_USERNAME, username);
                    }
                } else if (errorCode.equals(IdentityCoreConstants
                        .ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE)) {
                    errorMessage = "Password reset is required. A password reset link has been sent to your " +
                            "registered email address.";
                    errorProperties.put(AUTH_FAILURE_MSG, "password.reset.pending");
                } else if (errorCode.equals(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE)) {
                    errorMessage = "Password reset is required. Redirect to password reset page.";
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);
                    errorProperties.put(AUTH_FAILURE_MSG, "password.reset.pending");
                    errorProperties.put(AuthAPIConstants.TENANT_DOMAIN_PARAM, tenantDomain);
                    errorProperties.put(AuthAPIConstants.CONFIRMATION_PARAM, credential.toString());
                } else if (isShowAuthFailureReason()) {

                    String reason = null;
                    if (errorCode.contains(":")) {
                        String[] errorCodeReason = errorCode.split(":");
                        errorCode = errorCodeReason[0];
                        if (errorCodeReason.length > 1) {
                            reason = errorCodeReason[1];
                        }
                    }
                    int remainingAttempts = errorContext.getMaximumLoginAttempts() - errorContext
                            .getFailedLoginAttempts();

                    if (log.isDebugEnabled()) {
                        StringBuilder debugString = new StringBuilder();
                        debugString.append("Identity error message context is not null. Error details are as follows.");
                        debugString.append("errorCode : " + errorCode + "\n");
                        debugString.append("username : " + username + "\n");
                        debugString.append("remainingAttempts : " + remainingAttempts);
                        log.debug(debugString.toString());
                    }
                    if (errorCode.equals(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL)) {
                        errorProperties.put(AuthAPIConstants.REMAINING_ATTEMPTS, Integer.toString(remainingAttempts));
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                        errorMessage = "User Account is Locked.";
                        if (remainingAttempts == 0) {
                            if (StringUtils.isBlank(reason)) {
                                errorProperties.put(AuthAPIConstants.REMAINING_ATTEMPTS, "0");
                            } else {
                                errorProperties.put(AuthAPIConstants.REMAINING_ATTEMPTS, Integer.toString
                                        (remainingAttempts));
                                errorProperties.put(AuthAPIConstants.LOCKED_REASON, reason);
                                errorMessage = errorMessage + reason;
                            }
                        } else {
                            if (!StringUtils.isBlank(reason)) {
                                errorProperties.put(AuthAPIConstants.LOCKED_REASON, reason);
                                errorMessage = errorMessage + reason;
                            }
                        }
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
                            errorMessage = "User Account Does not exists";
                    } else if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
                        errorMessage = "User Account is Disabled.";
                    } else if (errorCode.equals(
                            IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE)) {
                        errorMessage = "Password Reset is required.";
                        errorProperties.put(AuthAPIConstants.AUTH_FAILURE_MSG, "login.fail.message");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown identity error code.");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
            }
            throw new AuthAPIClientException(errorMessage, errorCode, errorProperties, e);
        }
    }

    public String getUserStoreDomain(String username) {

        if (!username.contains("/")) {
            if (UserCoreUtil.getDomainFromThreadLocal() != null && !UserCoreUtil.getDomainFromThreadLocal().isEmpty()) {
                return UserCoreUtil.getDomainFromThreadLocal();
            }
        }

        return UserCoreUtil.extractDomainFromName(username);
    }

    private boolean isShowAuthFailureReason(){
        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = null;
        if (parameterMap != null) {
            showAuthFailureReason = parameterMap.get(FrameworkConstants.SHOW_AUTHFAILURE_RESON_CONFIG);
            if (log.isDebugEnabled()) {
                log.debug("showAuthFailureReason has been set as : " + showAuthFailureReason);
            }
        }
        return showAuthFailureReason != null && "true".equals(showAuthFailureReason);
    }

    private AuthenticatorConfig getAuthenticatorConfig() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean
                (FrameworkConstants.BASIC_AUTHENTICATOR_CLASS);
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap());
        }
        return authConfig;
    }

}
