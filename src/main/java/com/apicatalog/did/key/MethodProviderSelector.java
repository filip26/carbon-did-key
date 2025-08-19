package com.apicatalog.did.key;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.VerificationMethod;

public class MethodProviderSelector implements DidKeyMethodProvider {

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

    public static Builder with(String type, DidKeyMethodProvider provider) {
        return (new Builder()).with(type, provider);
    }

    public static class Builder {

        final Map<String, DidKeyMethodProvider> providers;

        protected Builder() {
            this.providers = new LinkedHashMap<>();
        }

        public Builder with(String type, DidKeyMethodProvider provider) {
            providers.put(type, provider);
            return this;
        }

        public DidKeyMethodProvider build() {
            if (providers.size() == 1) {
                return providers.values().iterator().next();
            }
            return new MethodProviderSelector(Collections.unmodifiableMap(providers));
        }
    }
}
