package com.apicatalog.did.key;

import java.util.HashMap;
import java.util.Map;

import com.apicatalog.did.DidResource;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.primitive.MultiKey;
import com.apicatalog.did.resolver.DidResolutionException;
import com.apicatalog.did.resolver.DidResourceResolver;

/**
 * {@link DidResourceResolver} implementation for the {@code did:key} method.
 *
 * <p>
 * Resolves {@link DidKey} identifiers into minimal {@link DidResource}
 * containing material encoded in the DID.
 * </p>
 *
 */
public class DidKeyResourceResolver implements DidResourceResolver {

    public static final String DEFAULT_CONTEXT = "https://www.w3.org/ns/did/v1.1";

    public static final String OPTION_PUBLIC_KEY_FORMAT = "publicKeyFormat";
    public static final String OPTION_EXPERIMENTAL_KEY_TYPES = "enableExperimentalPublicKeyTypes";
    public static final String OPTION_DEFAULT_CONTEXT = "defaultContext";

    private final Map<String, VerificationMethodProvider> methodProviders;
    
    public DidKeyResourceResolver(Map<String, VerificationMethodProvider> methodProviders) {
        this.methodProviders = methodProviders;
    }
    
    @Override
    public DidResource resolve(DidUrl url, Map<String, Object> options) throws DidResolutionException {

        if (!DidKey.containsDidKey(url)) {
            throw new IllegalArgumentException();
        }

        var didKey = DidKey.from(url.methodSpecificId());

        if ("vm".equals(url.fragment()) || url.methodSpecificId().equals(url.fragment())) {
            
            var type = options.getOrDefault(OPTION_PUBLIC_KEY_FORMAT, MultiKey.TYPE_NAME);
            
            var methodProvider = methodProviders.get(type);
            
            if (methodProvider == null) {
                throw new IllegalArgumentException();
            }
            
            return methodProvider.get(url, didKey);
        }

        // TODO Auto-generated method stub
        return null;
    }
    
    private static MultiKey createMultiKey(DidUrl url, DidKey key) {
        return new MultiKey(url, url.toDid(), null, null, key.publicKey(), null);        
    }
    
    public static class Builder {
        
        Map<String, VerificationMethodProvider> methodProviders;
        
        private Builder() {
            this.methodProviders = new HashMap<String, VerificationMethodProvider>();
            this.methodProviders.put(MultiKey.TYPE_NAME, DidKeyResourceResolver::createMultiKey);
        }
    }
}
