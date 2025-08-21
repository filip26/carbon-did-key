package com.apicatalog.did.key.jwk;

import java.util.Map;

import com.apicatalog.did.key.DidKey;

/**
 * Functional interface for generating a JWK (JSON Web Key) representation from
 * a {@link DidKey}.
 *
 * <p>
 * Implementations are responsible for converting the raw key material into a
 * JWK-compliant map, including mandatory JWK parameters such as {@code kty},
 * {@code crv}, and key material coordinates or values.
 * </p>
 */
@FunctionalInterface
public interface JwkProvider {

    /**
     * Produces a JWK representation of the given {@link DidKey}.
     *
     * @param key the {@link DidKey} containing raw key material
     * @return an unmodifiable JWK map
     * @throws IllegalArgumentException if the key type is unsupported or cannot be
     *                                  converted
     */
    Map<String, Object> get(DidKey key);
}
