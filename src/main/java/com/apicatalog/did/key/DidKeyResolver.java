package com.apicatalog.did.key;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.function.Function;

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

/**
 * {@link DidResolver} implementation for the {@code did:key} method.
 *
 * <p>
 * Resolves {@link DidKey} identifiers into minimal {@link DidDocument}
 * instances containing verification methods derived from the public key
 * material encoded in the DID.
 * </p>
 *
 * <p>
 * Verification method types can be configured using the {@link Builder}. Common
 * types include:
 * </p>
 * <ul>
 * <li>{@link #MULTIKEY_TYPE} – Multikey</li>
 * <li>{@link #JWK_2020_TYPE} – JsonWebKey2020</li>
 * <li>{@link #JWK_TYPE} – JsonWebKey</li>
 * </ul>
 *
 * @see <a href="https://w3c-ccg.github.io/did-key-spec/">DID Key Method
 *      Specification</a>
 */
public class DidKeyResolver implements DidResolver {

    /** Verification method type URI for Multikey. */
    public static String MULTIKEY_TYPE = "https://w3id.org/security#Multikey";
    /** Verification method type URI for JsonWebKey2020. */
    public static String JWK_2020_TYPE = "https://w3id.org/security#JsonWebKey2020";
    /** Verification method type URI for JsonWebKey. */
    public static String JWK_TYPE = "https://w3id.org/security#JsonWebKey";

    /** Supported multicodecs. */
    protected final MulticodecDecoder codecs;
    /** Provider that derives verification methods from a {@link DidKey}. */
    protected final Function<DidKey, Collection<DidVerificationMethod>> provider;
    /** Placeholder for optional encryption key derivation support. */
    protected boolean encryptionKeyDerivation;

    protected DidKeyResolver(final MulticodecDecoder codecs,
            final Function<DidKey, Collection<DidVerificationMethod>> provider) {
        this.codecs = codecs;
        this.provider = provider;
        this.encryptionKeyDerivation = false;
    }

    /**
     * Creates a new {@link Builder} for constructing a {@link DidKeyResolver}.
     *
     * @param codecs multicodec decoder to use
     * @return a new {@link Builder} instance
     * @throws NullPointerException if {@code codecs} is {@code null}
     */
    public static Builder with(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new Builder(codecs);
    }

    /**
     * Resolves a {@link URI} into a {@link ResolvedDidDocument}.
     *
     * @param did the DID URI to resolve
     * @return the resolved DID document
     * @throws NullPointerException   if {@code did} is {@code null}
     * @throws DidResolutionException if resolution fails
     */
    public ResolvedDidDocument resolve(final URI did) throws DidResolutionException {
        Objects.requireNonNull(did, "DID URI must not be null.");
        try {
            return resolve(DidKey.of(did, codecs));
        } catch (IllegalArgumentException e) {
            throw new DidResolutionException(did.toASCIIString(), "Failed to resolve DID URI: " + did, e);
        }
    }

    /**
     * Resolves a {@link Did} into a {@link ResolvedDidDocument}.
     *
     * @param did the DID to resolve
     * @return the resolved DID document
     * @throws NullPointerException   if {@code did} is {@code null}
     * @throws DidResolutionException if resolution fails
     */
    @Override
    public ResolvedDidDocument resolve(final Did did) throws DidResolutionException {
        Objects.requireNonNull(did, "DID must not be null.");

        if (!DidKey.METHOD_NAME.equals(did.getMethod())) {
            throw new DidResolutionException(did.toString(),
                    Code.UnsupportedMethod,
                    "Unsupported DID method '" + did.getMethod() + "', expected 'key'.");
        }

        final DidKey didKey;
        try {
            didKey = DidKey.of(did, codecs);
        } catch (IllegalArgumentException e) {
            throw new DidResolutionException(did.toString(), Code.InvalidDid,  "Invalid did:key value: " + did, e);
        }

        return resolve(didKey);
    }

    /**
     * Resolves a {@link DidKey} into a {@link ResolvedDidDocument}.
     *
     * @param didKey the DID key to resolve
     * @return the resolved DID document
     * @throws NullPointerException   if {@code didKey} is {@code null}
     * @throws DidResolutionException if resolution fails
     */
    public ResolvedDidDocument resolve(final DidKey didKey) throws DidResolutionException {
        Objects.requireNonNull(didKey, "DidKey must not be null.");

        if (encryptionKeyDerivation) {
            throw new DidResolutionException(didKey.toString(),
                    Code.Internal,
                    "Encryption key derivation is not yet supported.");
        }

        return ResolvedDidDocument.of(Document.of(didKey, provider.apply(didKey)));
    }

    /**
     * Creates a multibase verification method entry for the given DID key.
     *
     * @param key  the DID key
     * @param type the verification method type
     * @return a new verification method
     */
    public static DidVerificationMethod multikey(final DidKey key, final String type) {
        return DidVerificationMethod.multibase(
                DidUrl.fragment(key, key.getMethodSpecificId()),
                type,
                key,
                key);
    }

    /** @return {@code true} if encryption key derivation is enabled */
    public boolean encryptionKeyDerivation() {
        return this.encryptionKeyDerivation;
    }

    /**
     * Enables or disables encryption key derivation.
     *
     * @param encryptionKeyDerivation flag value
     * @return this resolver instance
     */
    public DidKeyResolver encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
        return this;
    }

    /**
     * Builder for {@link DidKeyResolver}.
     */
    public static class Builder {

        final MulticodecDecoder codecs;
        final Map<String, VerificationMethodProvider> providers;

        protected Builder(final MulticodecDecoder codecs) {
            this.codecs = codecs;
            this.providers = new LinkedHashMap<>();
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
            providers.put(methodType, provider);
            return this;
        }

        /** Registers {@link #MULTIKEY_TYPE} verification methods. */
        public Builder multikey() {
            return multibase(MULTIKEY_TYPE);
        }

        /** Registers a multibase verification method under the given type URI. */
        public Builder multibase(String methodType) {
            return method(methodType, DidKeyResolver::multikey);
        }

        /** Registers {@link #JWK_TYPE} verification methods. */
        public Builder jwk() {
            return jwk(JWK_TYPE);
        }

        /** Registers a JWK verification method under the given type URI. */
        public Builder jwk(String methodType) {
            return method(methodType, DidKeyJwkMethodProvider.getInstance());
        }

        /**
         * Builds a new {@link DidKeyResolver}.
         *
         * @return a resolver instance
         * @throws IllegalStateException if no providers were registered
         */
        public DidKeyResolver build() {
            if (providers.isEmpty()) {
                throw new IllegalStateException("At least one verification method provider must be registered.");
            }
            if (providers.size() == 1) {
                final Entry<String, VerificationMethodProvider> provider = providers.entrySet().iterator().next();
                return new DidKeyResolver(codecs, key -> Collections.singleton(provider.getValue().get(key, provider.getKey())));
            }
            return new DidKeyResolver(codecs, key -> createSignatureMethods(key, providers));
        }
    }

    static final Collection<DidVerificationMethod> createSignatureMethods(
            DidKey didKey,
            Map<String, VerificationMethodProvider> providers) {

        Objects.requireNonNull(didKey, "DidKey must not be null.");
        Objects.requireNonNull(providers, "Verification method providers must not be null.");

        Collection<DidVerificationMethod> methods = new ArrayList<>(providers.size());
        for (Entry<String, VerificationMethodProvider> provider : providers.entrySet()) {
            methods.add(provider.getValue().get(didKey, provider.getKey()));
        }
        return Collections.unmodifiableCollection(methods);
    }

    /**
     * Minimal DID Document implementation used by {@link DidKeyResolver}.
     */
    static final class Document implements DidDocument {

        final Did id;
        final Collection<DidVerificationMethod> method;

        Document(Did id, Collection<DidVerificationMethod> method) {
            this.id = Objects.requireNonNull(id, "DID must not be null.");
            this.method = Objects.requireNonNull(method, "Verification methods must not be null.");
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
