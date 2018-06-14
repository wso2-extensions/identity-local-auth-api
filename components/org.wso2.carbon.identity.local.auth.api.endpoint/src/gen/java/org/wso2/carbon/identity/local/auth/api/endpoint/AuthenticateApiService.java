package org.wso2.carbon.identity.local.auth.api.endpoint;

import org.wso2.carbon.identity.local.auth.api.endpoint.*;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.*;

import org.wso2.carbon.identity.local.auth.api.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AuthenticationRequestDTO;
import org.wso2.carbon.identity.local.auth.api.endpoint.dto.AuthenticationSuccessResponseDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;

import javax.ws.rs.core.Response;

public abstract class AuthenticateApiService {
    public abstract Response authenticatePost(String authorization,AuthenticationRequestDTO credentials);
}

