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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.local.auth.api.core.constants.AuthAPIConstants;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIException;
import org.wso2.carbon.identity.local.auth.api.core.exception.AuthAPIServerException;
import org.wso2.carbon.identity.local.auth.api.core.internal.AuthAPIServiceComponentDataHolder;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnMessageContext;
import org.wso2.carbon.identity.local.auth.api.core.model.AuthnToken;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class is used to generate a JWT token upon a successful authentication.
 */
public class JWTAuthTokenGenerator implements AuthTokenGenerator {

    private static final String KEY_STORE_EXTENSION = ".jks";
    // We are keeping a private key map which will have private key for each tenant domain. We are keeping this as a
    // static Map since then we don't need to read the key from keystore every time.
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();

    private JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS256.getName());
    // Validity period is set as 3 m by default.
    private long validityPeriod = 180L;

    @Override
    public void init() throws AuthAPIException {

        // TODO: Allow configuring signing algorithms, encrypting and encryption algorithms, requested claim set as
        // preferred
    }

    @Override
    public void generateToken(AuthnMessageContext authnMessageContext) throws AuthAPIException {

        AuthnToken authnToken = new AuthnToken();
        authnToken.setTokenType(AuthAPIConstants.JWT_TOKEN_TYPE);

        JWTClaimsSet jwtClaimsSet = createWTClaimSet(authnMessageContext);
        authnToken.setToken(signJWTWithRSA(jwtClaimsSet, authnMessageContext));
        authnMessageContext.setAuthnToken(authnToken);
    }

    protected JWTClaimsSet createWTClaimSet(AuthnMessageContext authnMessageContext) throws AuthAPIServerException {

        User authenticatedUser = authnMessageContext.getUser();

        IdentityProvider residentIdP;
        try {
            residentIdP = AuthAPIServiceComponentDataHolder.getInstance().getIdpManager().getResidentIdP
                    (authnMessageContext.getUser().getTenantDomain());
        } catch (IdentityProviderManagementException e) {
            throw new AuthAPIServerException("Error occurred while loading resident IdP for tenant: " +
                    authenticatedUser.getTenantDomain(), e);
        }

        String issuer = residentIdP.getHomeRealmId();

        //generating expiring timestamp
        long currentTime = Calendar.getInstance().getTimeInMillis();
        long expireIn = currentTime + 1000 * validityPeriod;

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(authenticatedUser.toString());
        jwtClaimsSet.setIssueTime(new Date(currentTime));
        jwtClaimsSet.setExpirationTime(new Date(expireIn));
        jwtClaimsSet.setJWTID(UUID.randomUUID().toString());
        jwtClaimsSet.setClaim(AuthAPIConstants.JWT_CLAIM_NONCE, generateNonce());

        return jwtClaimsSet;
    }

    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, AuthnMessageContext authnMessageContext) throws
            AuthAPIServerException {

        String tenantDomain = authnMessageContext.getUser().getTenantDomain();
        int tenantId = getTenantId(tenantDomain);

        Key privateKey;
        if (privateKeys.containsKey(tenantId)) {
            privateKey = privateKeys.get(tenantId);
        } else {
            // Get tenant's key store manager.
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                try {
                    privateKey = tenantKSM.getDefaultPrivateKey();
                } catch (Exception e) {
                    throw new AuthAPIServerException("Error while loading private key for super tenant", e);
                }
            } else {
                // Obtain private key.
                privateKey = tenantKSM.getPrivateKey(getTenantKeyStoreName(tenantDomain), tenantDomain);
            }
            // Add the private key to the static concurrent hash map for later uses.
            privateKeys.put(tenantId, privateKey);
        }

        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(signatureAlgorithm), jwtClaimsSet);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new AuthAPIServerException("Error occurred while signing the JWT from private key of tenant: " +
                    tenantDomain, e);
        }
        return signedJWT.serialize();
    }

    protected String generateNonce() {

        String generatedString = RandomStringUtils.randomAlphanumeric(32);
        return new String(Base64.encodeBase64(generatedString.getBytes()), StandardCharsets.UTF_8);
    }

    private int getTenantId(String tenantDomain) throws AuthAPIServerException {

        RealmService realmService = AuthAPIServiceComponentDataHolder.getInstance().getRealmService();
        int tenantId = MultitenantConstants.INVALID_TENANT_ID;
        try {
            tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            throw new AuthAPIServerException("Failed to retrieve user realm for tenant id: " + tenantId, e);
        }

        return tenantId;
    }

    private String getTenantKeyStoreName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(".", "-");
        return ksName + KEY_STORE_EXTENSION;
    }
}
