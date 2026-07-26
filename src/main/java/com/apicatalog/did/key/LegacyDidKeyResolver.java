package com.apicatalog.did.key;

import java.util.Collection;
import java.util.function.Function;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.DidDocument;
import com.apicatalog.did.VerificationMethod;
import com.apicatalog.multicodec.MulticodecDecoder;

/**
 * implementation for the {@code did:key} method.
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
@Deprecated
public class LegacyDidKeyResolver {

    /** Verification method type URI for Multikey. */
    public static String MULTIKEY_TYPE = "https://w3id.org/security#Multikey";
    /** Verification method type URI for JsonWebKey2020. */
    public static String JWK_2020_TYPE = "https://w3id.org/security#JsonWebKey2020";
    /** Verification method type URI for JsonWebKey. */
    public static String JWK_TYPE = "https://w3id.org/security#JsonWebKey";

    /** Supported multicodecs. */
    protected final MulticodecDecoder codecs;
    /** Provider that derives verification methods from a {@link DidKey}. */
    protected final Function<DidKey, Collection<VerificationMethod>> provider;
    /** Provides unique verification method identifier for the given did:key */
    protected final Function<DidKey, DidUrl> keyToId;
    /** Placeholder for optional encryption key derivation support. */
    protected boolean encryptionKeyDerivation;

    protected LegacyDidKeyResolver(final MulticodecDecoder codecs,
            final Function<DidKey, Collection<VerificationMethod>> provider,
            final Function<DidKey, DidUrl> keyToId) {
        this.codecs = codecs;
        this.provider = provider;
        this.keyToId = keyToId;
        this.encryptionKeyDerivation = false;
    }
//
//    /**
//     * Creates a new {@link Builder} for constructing a {@link LegacyDidKeyResolver}.
//     *
//     * @param codecs multicodec decoder to use
//     * @return a new {@link Builder} instance
//     * @throws NullPointerException if {@code codecs} is {@code null}
//     */
//    public static Builder with(final MulticodecDecoder codecs) {
//        Objects.requireNonNull(codecs);
//        return new Builder(codecs);
//    }
//
//    /**
//     * Resolves a {@link URI} into a {@link ResolvedDidDocument}.
//     *
//     * @param did the DID URI to resolve
//     * @return the resolved DID document
//     * @throws NullPointerException   if {@code did} is {@code null}
//     * @throws DidResolutionException if resolution fails
//     */
//    public ResolvedDidDocument resolve(final URI did) throws DidResolutionException {
//        Objects.requireNonNull(did, "DID URI must not be null.");
//        try {
//            return resolve(DidKey.from(did));
//        } catch (IllegalArgumentException e) {
//            throw new DidResolutionException(did.toASCIIString(), "Failed to resolve DID URI: " + did, e);
//        }
//    }
//
//    /**
//     * Resolves a {@link Did} into a {@link ResolvedDidDocument}.
//     *
//     * @param did the DID to resolve
//     * @param options
//     * @return the resolved DID document
//     * @throws NullPointerException   if {@code did} is {@code null}
//     * @throws DidResolutionException if resolution fails
//     */
//    public ResolvedDidDocument resolve(Did did, Map<String, Object> options) throws DidResolutionException {
//        Objects.requireNonNull(did, "DID must not be null.");
//
//        if (!DidKey.METHOD_NAME.equals(did.method())) {
//            throw new DidResolutionException(did.toString(),
//                    ErrorCode.UNSUPPORTED_METHOD,
//                    "Unsupported DID method '" + did.method() + "', expected 'key'.");
//        }
//
//        final DidKey didKey;
//        try {
//            didKey = DidKey.from(did);
//        } catch (IllegalArgumentException e) {
//            throw new DidResolutionException(did.toString(), ErrorCode.INVALID_DID, "Invalid did:key value: " + did, e);
//        }
//
//        return resolve(didKey);
//    }

    /**
     * Resolves a {@link DidKey} into a {@link ResolvedDidDocument}.
     *
     * @param didKey the DID key to resolve
     * @return the resolved DID document
     * @throws NullPointerException   if {@code didKey} is {@code null}
     * @throws DidResolutionException if resolution fails
     */
//    public ResolvedDidDocument resolve(final DidKey didKey) throws DidResolutionException {
//        Objects.requireNonNull(didKey, "DidKey must not be null.");
//
//        if (encryptionKeyDerivation) {
//            throw new DidResolutionException(didKey.toString(),
//                    ErrorCode.INTERNAL,
//                    "Encryption key derivation is not yet supported.");
//        }
//
////        return ResolvedDidDocument.of(Document.of(didKey, provider.apply(didKey)));
//        //FIXME
//        return null;
//    }

    /**
     * Creates a multikey verification method entry for the given DID key.
     *
     * @param id   the DID URL uniquely identifying the method
     * @param key  the DID key
     * @param type the verification method type
     * @return a new verification method
     */
    public static VerificationMethod multikey(final DidUrl id, final DidKey key, final String type) {
        return null;//TODO
//        return DidVerificationMethod.multibase(
//                id,
//                type,
//                key,
//                key);
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
    public LegacyDidKeyResolver encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
        return this;
    }

    /**
     * Builder for {@link LegacyDidKeyResolver}.
     */
//    public static class Builder {
//
//        final MulticodecDecoder codecs;
//        final Map<String, VerificationMethodProvider> providers;
//        Function<DidKey, DidUrl> keyToId;
//
//        protected Builder(final MulticodecDecoder codecs) {
//            this.codecs = codecs;
//            this.providers = new LinkedHashMap<>();
////            this.keyToId = key -> DidUrl.of(key, key.methodSpecificId());
//        }
//
//        /**
//         * Sets the function used to derive the {@link DidUrl} identifier for
//         * verification methods created from a given {@link DidKey}.
//         *
//         * <p>
//         * The mapper is applied during resolution to produce the verification method ID
//         * (for example, mapping a {@code did:key:...} to a fragment
//         * {@code did:key:...#...}). By default, this builder uses
//         * {@code DidUrl.fragment(key, key.getMethodSpecificId())}.
//         * </p>
//         *
//         * @param keyToId mapping from {@link DidKey} to the verification method
//         *                {@link DidUrl}
//         * @return this builder
//         * @throws NullPointerException if {@code keyToId} is {@code null}
//         */
//        public Builder verificationMethodId(Function<DidKey, DidUrl> keyToId) {
//            this.keyToId = Objects.requireNonNull(keyToId, "keyToId must not be null");
//            return this;
//        }
//
//        /**
//         * Registers a verification method type and provider.
//         *
//         * @param methodType verification method type URI
//         * @param provider   provider implementation
//         * @return this builder
//         * @throws NullPointerException if any argument is {@code null}
//         */
//        public Builder method(String methodType, VerificationMethodProvider provider) {
//            Objects.requireNonNull(methodType, "Verification method type must not be null.");
//            Objects.requireNonNull(provider, "Verification method provider must not be null.");
//            providers.put(methodType, provider);
//            return this;
//        }
//
//        /** Registers {@link #MULTIKEY_TYPE} verification methods. */
//        public Builder multikey() {
//            return multibase(MULTIKEY_TYPE);
//        }
//
//        /** Registers a multibase verification method under the given type URI. */
//        public Builder multibase(String methodType) {
////            return method(methodType, DidKeyResolver::multikey);
//            return null;
//        }
//
//        /** Registers {@link #JWK_TYPE} verification methods. */
//        public Builder jwk() {
//            return jwk(JWK_TYPE);
//        }
//
//        /** Registers a JWK verification method under the given type URI. */
//        public Builder jwk(String methodType) {
//            return method(methodType, DidKeyJwkMethodProvider.getInstance());
//        }
//
//        /**
//         * Builds a new {@link LegacyDidKeyResolver}.
//         *
//         * @return a resolver instance
//         * @throws IllegalStateException if no providers were registered
//         */
//        public LegacyDidKeyResolver build() {
//            if (providers.isEmpty()) {
//                throw new IllegalStateException("At least one verification method provider must be registered.");
//            }
//            if (providers.size() == 1) {
//                final Entry<String, VerificationMethodProvider> provider = providers.entrySet().iterator().next();
//                return new LegacyDidKeyResolver(
//                        codecs,
//                        key -> Collections
//                                .singleton(provider.getValue().get(keyToId.apply(key), key
//                                        //, provider.getKey()
//                                        )),
//                        keyToId);
//            }
//            return new LegacyDidKeyResolver(
//                    codecs,
//                    key -> createSignatureMethods(key, providers, keyToId),
//                    keyToId);
//        }
//    }
//
//    static final Collection<VerificationMethod> createSignatureMethods(
//            DidKey didKey,
//            Map<String, VerificationMethodProvider> providers,
//            Function<DidKey, DidUrl> keyToId) {
//
//        Objects.requireNonNull(didKey, "DidKey must not be null.");
//        Objects.requireNonNull(providers, "Verification method providers must not be null.");
//
//        Collection<VerificationMethod> methods = new ArrayList<>(providers.size());
//        for (Entry<String, VerificationMethodProvider> provider : providers.entrySet()) {
//            methods.add(provider.getValue().get(keyToId.apply(didKey), didKey 
////                    ,provider.getKey()
//                    )
//                    );
//        }
//        return Collections.unmodifiableCollection(methods);
//    }

    /**
     * Minimal DID Document implementation used by {@link DidKeyResolver}.
     */
//    static final class Document implements DidDocument {
//
//        final Did id;
//        final Collection<DidVerificationMethod> method;
//
//        Document(Did id, Collection<DidVerificationMethod> method) {
//            this.id = Objects.requireNonNull(id, "DID must not be null.");
//            this.method = Objects.requireNonNull(method, "Verification methods must not be null.");
//        }
//
//        public static Document of(Did id, Collection<DidVerificationMethod> methods) {
//            return new Document(id, methods);
//        }
//
//        @Override
//        public Did id() {
//            return id;
//        }
//
//        @Override
//        public Collection<DidVerificationMethod> verification() {
//            return method;
//        }
//
//        @Override
//        public Collection<DidVerificationMethod> authentication() {
//            return method;
//        }
//
//        @Override
//        public Collection<DidVerificationMethod> assertion() {
//            return method;
//        }
//
//        @Override
//        public Collection<DidVerificationMethod> capabilityInvocation() {
//            return method;
//        }
//
//        @Override
//        public Collection<DidVerificationMethod> capabilityDelegation() {
//            return method;
//        }
//    }
}
