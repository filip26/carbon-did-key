package com.apicatalog.did.key;

import java.util.Map;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.VerificationMethod;

class MethodProviderSelector implements DidKeyMethodProvider {

    protected final Map<String, DidKeyMethodProvider> providers;

    protected MethodProviderSelector(final Map<String, DidKeyMethodProvider> providers) {
        this.providers = providers;
    }

    @Override
    public VerificationMethod get(DidKey key, DidUrl url, String type) {

        final DidKeyMethodProvider provider = providers.get(type);

        if (provider == null) {
            throw new IllegalArgumentException("Unsupported " + type + ", no method provider is associated with the type.");
        }
        
        return provider.get(key, url, type);
    }
}
