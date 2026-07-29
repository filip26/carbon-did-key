package com.apicatalog.did.key;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidDocument;
import com.apicatalog.did.DidDocument.Relationship;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.VerificationMethod;
import com.apicatalog.did.primitive.MultiKey;

/**
 * {@link DidResolver} implementation for the {@code did:key} method.
 *
 * <p>
 * Resolves {@link DidKey} identifiers into minimal {@link DidResource}
 * containing material encoded in the DID.
 * </p>
 *
 */
public class DidKeyResolver implements
        VerificationMethod.Resolver,
        VerificationMethod.Dereferencer,
        DidDocument.Resolver {

    /**
     * Provider of {@link VerificationMethod} instances for a given {@link DidKey}.
     *
     * <p>
     * Implementations create verification methods (e.g., {@code Multikey},
     * {@code JsonWebKey}) from the DID key and its associated type identifier.
     * </p>
     */
    @FunctionalInterface
    public interface MethodFactory {

        /**
         * Creates a {@link VerificationMethod} for the given {@link DidKey}.
         *
         * @param id  the DID URL uniquely identifying the method
         * @param key the DID key to build a verification method from, must not be
         *            {@code null}
         * @return a new {@link VerificationMethod} instance
         */
        VerificationMethod createMethod(DidUrl id, DidKey key);
    }

    private static final Set<Relationship> SUPPORTED_RELS = Set.of(
            Relationship.ASSERTION,
            Relationship.AUTHENTICATION,
            Relationship.VERIFICATION,
            Relationship.CAPABILITY_DELEGATION,
            Relationship.CAPABILITY_INVOCATION);

    public static final String DEFAULT_CONTEXT = "https://www.w3.org/ns/did/v1.1";

    public static final String OPTION_PUBLIC_KEY_FORMAT = "publicKeyFormat";
    public static final String OPTION_EXPERIMENTAL_KEY_TYPES = "enableExperimentalPublicKeyTypes";
    public static final String OPTION_DEFAULT_CONTEXT = "defaultContext";
    public static final String OPTION_ENCRYPTION_KEY_DERIVATION = "encryptionKeyDerivation";

    private final DidKey.Parser didKeyParser;
    private final Map<String, MethodFactory> methodProviders;
    private final String defaultMethod;

    public DidKeyResolver(DidKey.Parser didKeyParser, Map<String, MethodFactory> methodProviders,
            String defaultMethod) {
        this.didKeyParser = didKeyParser;
        this.methodProviders = methodProviders;
        this.defaultMethod = defaultMethod;
    }

    @Override
    public DidDocument.WithMetadata resolve(DidUrl url, Map<String, Object> options) {
        if (!DidKey.isDidKey(url)) {
            throw new IllegalArgumentException();
        }

        if (url.query() != null || url.path() != null) {
            throw new IllegalArgumentException();
        }
        var didKey = didKeyParser.from(url.methodSpecificId());

        var type = options.getOrDefault(OPTION_PUBLIC_KEY_FORMAT, defaultMethod);

        var methodProvider = methodProviders.get(type);

        if (methodProvider == null) {
            throw new IllegalArgumentException();
        }

        return new Document.WithMetadata(null,
                new Document(url.toDid(), SUPPORTED_RELS, List.of(methodProvider.createMethod(url, didKey))));
    }

    @Override
    public Optional<VerificationMethod> resolveMethod(DidUrl url, Relationship rel, Map<String, Object> options) {

        if (url.fragment() == null || url.fragment().isBlank()) {
            throw new IllegalArgumentException();
        }

        var didKey = didKeyParser.from(url.methodSpecificId());

        var type = options.getOrDefault(OPTION_PUBLIC_KEY_FORMAT, defaultMethod);

        var methodProvider = methodProviders.get(type);

        if (methodProvider == null) {
            throw new IllegalArgumentException();
        }

        return Optional.of(methodProvider.createMethod(url, didKey));
    }

    @Override
    public Optional<VerificationMethod> findMethod(DidDocument document, DidUrl url, Relationship rel) {

        if (url.fragment() == null || url.fragment().isBlank()) {
            throw new IllegalArgumentException();
        }

        var methods = document.methods(rel);

        if (methods == null || methods.isEmpty()) {
            return Optional.empty();
        }

        for (var method : methods) {
            if (method.id().equals(url)) {
                return Optional.of(method);
            }
        }

        return Optional.empty();
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    private static MultiKey createMultiKey(DidUrl url, DidKey key) {
        return new MultiKey(url, url.toDid(), null, null, key.publicKey(), null);
    }

    public static class Builder {

        private Function<String, byte[]> multibaseDecoder;
        private final Map<String, MethodFactory> methods;
        private String defaultMethod;

        private Builder() {
            this.methods = new LinkedHashMap<>();
            this.defaultMethod = null;
        }

        /**
         * Registers a verification method type and provider.
         *
         * @param type    verification method type URI
         * @param factory provider implementation
         * @return this builder
         * @throws NullPointerException if any argument is {@code null}
         */
        public Builder method(String type, MethodFactory factory) {
            Objects.requireNonNull(type, "Verification method type must not be null.");
            Objects.requireNonNull(factory, "Verification method provider must not be null.");
            methods.put(type, factory);
            return this;
        }

        /** Registers {@link MultiKey#TYPE_NAME} verification method. */
        public Builder multikey() {
            return method(MultiKey.TYPE_NAME, DidKeyResolver::createMultiKey);
        }

        public Builder multibaseDecoder(Function<String, byte[]> multibaseDecoder) {
            this.multibaseDecoder = multibaseDecoder;
            return this;
        }

        public Builder defaultMethod(String type) {
            this.defaultMethod = type;
            return this;
        }

        /**
         * Builds a new {@link DidKeyResolver}.
         *
         * @return a resolver instance
         * @throws IllegalStateException if no providers were registered
         */
        public DidKeyResolver build() {

            if (multibaseDecoder == null) {
                throw new IllegalArgumentException();
            }

            if (methods.isEmpty()) {
                throw new IllegalStateException("At least one verification method provider must be registered.");
            }

            if (defaultMethod == null) {
                defaultMethod = methods.keySet().iterator().next();
            }

            return new DidKeyResolver(DidKey.parser(multibaseDecoder), Map.copyOf(methods), defaultMethod);
        }
    }

    private static record Document(
            Did id,
            Set<Relationship> relationships,
            Collection<VerificationMethod> methods) implements DidDocument {

        @Override
        public Collection<VerificationMethod> methods(Relationship rel) {
            if (relationships.contains(rel)) {
                return methods;
            }
            return List.of();
        }
    }
}
