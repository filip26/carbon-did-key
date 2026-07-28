package com.apicatalog.did.key.jwk;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.key.DidKey;
import com.apicatalog.did.key.DidKeyResolver;
import com.apicatalog.did.primitive.JsonWebKey;

/**
 * A {@link JwkMethodFactory} that creates verification methods for
 * {@link DidKey} identifiers using the JWK (JSON Web Key) representation.
 *
 * <p>
 * The returned verification methods contain a JWK-formatted public key.
 * </p>
 */
public class JwkMethodFactory implements DidKeyResolver.MethodFactory {

    private final String typeName;
    private final Function<byte[], Integer> codecDecoder;
    private final Map<Integer, JwkGenerator> generators;

    public JwkMethodFactory(
            Function<byte[], Integer> codecDecoder,
            Map<Integer, JwkGenerator> jwkProviders) {
        this(JsonWebKey.TYPE_NAME, codecDecoder, jwkProviders);
    }

    public JwkMethodFactory(
            String typeName,
            Function<byte[], Integer> codecProvider,
            Map<Integer, JwkGenerator> jwkProviders) {
        this.typeName = typeName;
        this.codecDecoder = codecProvider;
        this.generators = jwkProviders;
    }

    @Override
    public JsonWebKey createMethod(DidUrl url, DidKey key) {

        var codec = codecDecoder.apply(key.publicKey());
        if (codec == null) {
            throw new IllegalArgumentException();
        }

        final JwkGenerator provider = generators.get(codec);

        if (provider == null) {
            throw new IllegalArgumentException("No provider is configured for codec [" + codec + "].");
        }

        return new JsonWebKey(
                url,
                typeName,
                url.toDid(),
                null,
                null,
                provider.get(key),
                null);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static class Builder {

        private String typeName;
        private Function<byte[], Integer> codecDecoder;
        private Map<Integer, JwkGenerator> generators;

        private Builder() {
            this.typeName = JsonWebKey.TYPE_NAME;
            this.codecDecoder = null;
            this.generators = new HashMap<>();
        }

        public Builder typeName(String typeName) {
            this.typeName = typeName;
            return this;
        }

        public Builder codecDecoder(Function<byte[], Integer> codecDecoder) {
            this.codecDecoder = codecDecoder;
            return this;
        }

        public Builder generator(Integer codec, JwkGenerator generator) {
            generators.put(codec, generator);
            return this;
        }

        public JwkMethodFactory build() {
            if (typeName == null) {
                throw new IllegalArgumentException();
            }
            if (codecDecoder == null) {
                throw new IllegalArgumentException();
            }
            if (generators.isEmpty()) {
                throw new IllegalArgumentException();
            }

            return new JwkMethodFactory(typeName, codecDecoder, generators);
        }
    }
}
