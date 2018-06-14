package org.wso2.carbon.identity.local.auth.api.core;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
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
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.StandardCharsets;

public class AuthManagerImpl implements AuthManager {

    private static final Log log = LogFactory.getLog(AuthManagerImpl.class);
    protected AuthTokenGenerator authTokenGenerator;

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
            throw new AuthAPIClientException(AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getMessage(),
                    AuthAPIConstants.Error.ERROR_INVALID_CREDENTIALS.getCode(), e);
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

}
