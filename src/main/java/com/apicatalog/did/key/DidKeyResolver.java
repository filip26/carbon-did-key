package com.apicatalog.did.key;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.DidDocument;
import com.apicatalog.did.document.DidVerificationMethod;
import com.apicatalog.did.key.jwk.DidKeyJwkMethodProvider;
import com.apicatalog.did.resolver.DidResolutionException;
import com.apicatalog.did.resolver.DidResolutionException.Code;
import com.apicatalog.did.resolver.DidResolver;
import com.apicatalog.did.resolver.ResolvedDidDocument;
import com.apicatalog.multicodec.MulticodecDecoder;

public class DidKeyResolver implements DidResolver {

    public static String MULTIKEY_TYPE = "https://w3id.org/security#Multikey";
    public static String JWK_2020_TYPE = "https://w3id.org/security#JsonWebKey2020";
    public static String JWK_TYPE = "https://w3id.org/security#JsonWebKey";

    // supported multicodecs
    protected final MulticodecDecoder codecs;

    // options
    protected String methodType;
    protected VerificationMethodProvider methodProvider;
    protected boolean encryptionKeyDerivation;

    protected DidKeyResolver(final MulticodecDecoder codecs, String methodType, VerificationMethodProvider methodProvider) {
        this.codecs = codecs;
        this.methodType = methodType;
        this.methodProvider = methodProvider;
        this.encryptionKeyDerivation = false;
    }

    public static Builder multikey(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new Builder(codecs, MULTIKEY_TYPE).with(MULTIKEY_TYPE, DidKeyResolver::multikey);
    }

    public static Builder jwk(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new Builder(codecs, JWK_TYPE).with(JWK_TYPE, DidKeyJwkMethodProvider.getInstance());
    }

    @Override
    public ResolvedDidDocument resolve(final Did did) throws DidResolutionException {

        Objects.requireNonNull(did);

        if (!DidKey.METHOD_NAME.equals(did.getMethod())) {
            throw new DidResolutionException(did, Code.UnsupportedMethod);
        }

        if (encryptionKeyDerivation) {
            throw new UnsupportedOperationException();
        }

        final DidKey didKey = DidKey.of(did, codecs);

        return ResolvedDidDocument.of(
                Document.of(
                        did,
                        DidKeyResolver.createSignatureMethod(didKey, methodType, methodProvider)));
    }

    public static DidVerificationMethod multikey(final DidKey key, final String type) {
        return DidVerificationMethod.multibase(
                DidUrl.fragment(key, key.getMethodSpecificId()),
                type,
                key,
                key);
    }

    public static final DidVerificationMethod createSignatureMethod(final DidKey didKey, final String methodType, final VerificationMethodProvider method) {

        Objects.requireNonNull(didKey);
        Objects.requireNonNull(methodType);
        Objects.requireNonNull(method);

        return method.get(didKey, methodType);
    }

    public boolean encryptionKeyDerivation() {
        return this.encryptionKeyDerivation;
    }

    public DidKeyResolver encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
        return this;
    }

    public String methodType() {
        return methodType;
    }

    public DidKeyResolver methodType(String methodType) {
        this.methodType = methodType;
        return this;
    }

    public DidKeyResolver methodProvider(VerificationMethodProvider methodProvider) {
        this.methodProvider = methodProvider;
        return this;
    }

    public static class Builder {

        final MulticodecDecoder codecs;
        final Map<String, VerificationMethodProvider> providers;
        final String keyType;

        protected Builder(final MulticodecDecoder codecs, final String keyType) {
            this.codecs = codecs;
            this.keyType = keyType;
            this.providers = new LinkedHashMap<>();
        }

        public Builder with(String type, VerificationMethodProvider provider) {
            providers.put(type, provider);
            return this;
        }

        public DidKeyResolver build() {

            final VerificationMethodProvider provider;

            if (providers.size() == 1) {
                provider = providers.values().iterator().next();
            } else {
                provider = new Providers(Collections.unmodifiableMap(providers));
            }

            return new DidKeyResolver(codecs, keyType, provider);
        }
    }
    
    final static class Providers implements VerificationMethodProvider {

        final Map<String, VerificationMethodProvider> providers;

        Providers(final Map<String, VerificationMethodProvider> providers) {
            this.providers = providers;
        }

        @Override
        public DidVerificationMethod get(DidKey key, String type) {

            final VerificationMethodProvider provider = providers.get(type);

            if (provider == null) {
                throw new IllegalArgumentException("Unsupported " + type + ", no method provider is associated with the type.");
            }
            
            return provider.get(key, type);
        }
    }
    
    final static class Document implements DidDocument {

        final Did id;
        final Set<DidVerificationMethod> method;

        Document(Did id, Set<DidVerificationMethod> method) {
            this.id = id;
            this.method = method;
        }

        public static Document of(Did id, DidVerificationMethod method) {
            return new Document(id, Collections.singleton(method));
        }

        @Override
        public Did id() {
            return id;
        }

        @Override
        public Set<DidVerificationMethod> verification() {
            return method;
        }
        
        @Override
        public Set<DidVerificationMethod> authentication() {
            return method;
        }
        
        @Override
        public Set<DidVerificationMethod> assertion() {
            return method;
        }
        
        @Override
        public Set<DidVerificationMethod> capabilityInvocation() {
            return method;
        }
        
        @Override
        public Set<DidVerificationMethod> capabilityDelegation() {
            return method;
        }
    }
}
