package com.apicatalog.did.key;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidDocument;
import com.apicatalog.did.DidResource;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.DidVerificationMethod;
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
    public static final String OPTION_ENCRYPTION_KEY_DERIVATION = "encryptionKeyDerivation";

    private final Map<String, VerificationMethodProvider> methodProviders;

    public DidKeyResourceResolver(Map<String, VerificationMethodProvider> methodProviders) {
        this.methodProviders = methodProviders;
    }

    @Override
    public DidResource resolve(DidUrl url, Map<String, Object> options) throws DidResolutionException {

        if (!DidKey.containsDidKey(url)) {
            throw new IllegalArgumentException();
        }

        if (url.query() != null || url.path() != null) {
            throw new IllegalArgumentException();
        }
        
        // verification method?
        if (("vm".equals(url.fragment()) || url.methodSpecificId().equals(url.fragment()))) {
            return getMethod(url, options);
        }

        // DID document?
        if (url.fragment() == null) {
            var method = getMethod(url, options);
            return new Document(url.toDid(), List.of(method));
        }

        throw new IllegalArgumentException();
    }

    private DidVerificationMethod getMethod(DidUrl url, Map<String, Object> options) {
        
        var didKey = DidKey.from(url.methodSpecificId());
        
        var type = options.getOrDefault(OPTION_PUBLIC_KEY_FORMAT, MultiKey.TYPE_NAME);

        var methodProvider = methodProviders.get(type);

        if (methodProvider == null) {
            throw new IllegalArgumentException();
        }
        
        return methodProvider.get(url, didKey);

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

        /**
         * Registers a verification method type and provider.
         *
         * @param methodType verification method type URI
         * @param provider   provider implementation
         * @return this builder
         * @throws NullPointerException if any argument is {@code null}
         */
        public Builder method(String methodType, VerificationMethodProvider provider) {
            Objects.requireNonNull(methodType, "Verification method type must not be null.");
            Objects.requireNonNull(provider, "Verification method provider must not be null.");
            methodProviders.put(methodType, provider);
            return this;
        }

        /**
         * Builds a new {@link DidKeyResourceResolver}.
         *
         * @return a resolver instance
         * @throws IllegalStateException if no providers were registered
         */
        public DidKeyResourceResolver build() {

            if (methodProviders.isEmpty()) {
                throw new IllegalStateException("At least one verification method provider must be registered.");
            }

            return new DidKeyResourceResolver(Map.copyOf(methodProviders));
        }
    }

    private static record Document(
            Did id,
            Collection<DidVerificationMethod> methods
            ) implements DidDocument {

        private static final Collection<Relationship> REL = Set.of(
                DidDocument.Relationship.ASSERTION,
                DidDocument.Relationship.AUTHENTICATION,
                DidDocument.Relationship.VERIFICATION,
                DidDocument.Relationship.CAPABILITY_DELETATION,
                DidDocument.Relationship.CAPABILITY_INVOCATION);

        @Override
        public Collection<Relationship> relationships() {
            return REL;
        }

        @Override
        public Collection<DidVerificationMethod> methods(Relationship relationship) {
            if (REL.contains(relationship)) {
                return methods;
            }
            return List.of();
        }
    }
}
