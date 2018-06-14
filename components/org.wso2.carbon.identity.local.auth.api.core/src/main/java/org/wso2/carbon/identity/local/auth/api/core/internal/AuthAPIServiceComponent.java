package org.wso2.carbon.identity.local.auth.api.core.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.local.auth.api.core.AuthManager;
import org.wso2.carbon.identity.local.auth.api.core.AuthManagerImpl;
import org.wso2.carbon.identity.local.auth.api.core.JWTAuthTokenGenerator;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and un-registration of auth API service.
 */
@Component(name = "identity.local.auth.api.core.component", immediate = true)
public class AuthAPIServiceComponent {

    private static final Log log = LogFactory.getLog(AuthAPIServiceComponent.class);

    /**
     * Register AuthManager as an OSGi service.
     *
     * @param componentContext OSGi service component context.
     */
    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            BundleContext bundleContext = componentContext.getBundleContext();
            bundleContext.registerService(AuthManager.class.getName(), new AuthManagerImpl(new JWTAuthTokenGenerator
                    ()), null);
            log.info("Auth API Service Component  is activated.");
        } catch (Throwable e) {
            log.error("Error while activating Auth API Service Component.", e);
        }

    }

    @Reference(name = "realm.service", service = org.wso2.carbon.user.core.service.RealmService.class, cardinality =
            ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (realmService != null && log.isDebugEnabled()) {
            log.debug("RealmService is registered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("RealmService is unregistered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setRealmService(null);
    }

    @Reference(name = "idpmanager.service", service = org.wso2.carbon.idp.mgt.IdpManager.class, cardinality =
            ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetIdPManager")
    protected void setIdPManager(IdpManager idPManager) {

        if (idPManager != null && log.isDebugEnabled()) {
            log.debug("IdPManager is registered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setIdpManager(idPManager);
    }

    protected void unsetIdPManager(IdpManager idPManager) {

        if (log.isDebugEnabled()) {
            log.debug("IdPManager is unregistered in Auth API Service Component.");
        }
        AuthAPIServiceComponentDataHolder.getInstance().setIdpManager(null);
    }
}
