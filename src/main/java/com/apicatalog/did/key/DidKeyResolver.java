package com.apicatalog.did.key;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

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
    protected final Map<String, VerificationMethodProvider> providers;

    // options
    protected boolean encryptionKeyDerivation;

    protected DidKeyResolver(final MulticodecDecoder codecs, final Map<String, VerificationMethodProvider> methods) {
        this.codecs = codecs;
        this.providers = methods;
        this.encryptionKeyDerivation = false;
    }

    public static Builder with(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new Builder(codecs);
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

        Collection<DidVerificationMethod> methods;

        if (providers.size() == 1) {
            final Entry<String, VerificationMethodProvider> provider = providers.entrySet().iterator().next();
            methods = Collections.singleton(provider.getValue().get(didKey, provider.getKey()));

        } else {
            methods = new ArrayList<DidVerificationMethod>(providers.size());
            for (Entry<String, VerificationMethodProvider> provider : providers.entrySet()) {
                methods.add(provider.getValue().get(didKey, provider.getKey()));
            }
        }

        return ResolvedDidDocument.of(Document.of(did, methods));
    }

    public static DidVerificationMethod multikey(final DidKey key, final String type) {
        return DidVerificationMethod.multibase(
                DidUrl.fragment(key, key.getMethodSpecificId()),
                type,
                key,
                key);
    }

    public boolean encryptionKeyDerivation() {
        return this.encryptionKeyDerivation;
    }

    public DidKeyResolver encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
        return this;
    }

    public static class Builder {

        final MulticodecDecoder codecs;
        final Map<String, VerificationMethodProvider> providers;

        protected Builder(final MulticodecDecoder codecs) {
            this.codecs = codecs;
            this.providers = new LinkedHashMap<>();
        }

        public Builder method(String methodType, VerificationMethodProvider provider) {
            providers.put(methodType, provider);
            return this;
        }

        public Builder multikey() {
            return multibase(MULTIKEY_TYPE);
        }

        public Builder multibase(String methodType) {
            return method(methodType, DidKeyResolver::multikey);
        }

        public Builder jwk() {
            return jwk(JWK_TYPE);
        }

        public Builder jwk(String methodType) {
            return method(methodType, DidKeyJwkMethodProvider.getInstance());
        }

        public DidKeyResolver build() {
            return new DidKeyResolver(codecs, Collections.unmodifiableMap(providers));
        }
    }

    final static class Document implements DidDocument {

        final Did id;
        final Collection<DidVerificationMethod> method;

        Document(Did id, Collection<DidVerificationMethod> method) {
            this.id = id;
            this.method = method;
        }

        public static Document of(Did id, Collection<DidVerificationMethod> methods) {
            return new Document(id, methods);
        }

        @Override
        public Did id() {
            return id;
        }

        @Override
        public Collection<DidVerificationMethod> verification() {
            return method;
        }

        @Override
        public Collection<DidVerificationMethod> authentication() {
            return method;
        }

        @Override
        public Collection<DidVerificationMethod> assertion() {
            return method;
        }

        @Override
        public Collection<DidVerificationMethod> capabilityInvocation() {
            return method;
        }

        @Override
        public Collection<DidVerificationMethod> capabilityDelegation() {
            return method;
        }
    }
}
