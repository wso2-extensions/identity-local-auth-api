package org.wso2.carbon.identity.local.auth.api.endpoint;

import org.apache.cxf.jaxrs.ext.MessageContext;

import javax.ws.rs.core.Response;

public abstract class SessionApiService {
    public abstract Response getUserSession(MessageContext context);
    public abstract Response terminateASession(MessageContext context, String sessionId);
    public abstract Response terminateAllSessions(MessageContext context);
}

