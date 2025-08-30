package com.apicatalog.did.key;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.DidVerificationMethod;

/**
 * Provider of {@link DidVerificationMethod} instances for a given
 * {@link DidKey}.
 *
 * <p>
 * Implementations create verification methods (e.g., {@code Multikey},
 * {@code JsonWebKey}) from the DID key and its associated type identifier.
 * </p>
 */
@FunctionalInterface
public interface VerificationMethodProvider {

    /**
     * Creates a {@link DidVerificationMethod} for the given {@link DidKey}.
     *
     * @param id   the DID URL uniquely identifying the method
     * @param key  the DID key to build a verification method from, must not be
     *             {@code null}
     * @param type the verification method type identifier (e.g.,
     *             {@code https://w3id.org/security#Multikey}), must not be
     *             {@code null}
     * @return a new {@link DidVerificationMethod} instance
     */
    DidVerificationMethod get(final DidUrl id, final DidKey key, String type);
}
