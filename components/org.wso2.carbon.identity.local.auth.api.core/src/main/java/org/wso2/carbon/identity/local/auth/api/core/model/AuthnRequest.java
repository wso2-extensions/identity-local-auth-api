package org.wso2.carbon.identity.local.auth.api.core.model;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class AuthnRequest {

    protected String authType;
    protected Map<String, Object> authRequestParameters = new HashMap();

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public void setParameter(String key, Object value) {

        authRequestParameters.put(key, value);
    }

    public Object getParameter(String key) {
        return authRequestParameters.get(key);
    }

    public Map<String, Object> getParameters() {

        return Collections.unmodifiableMap(authRequestParameters);
    }
}
