/**
 * Provides support for the {@code did:key} method.
 *
 * This package contains:
 * <ul>
 * <li>{@link com.apicatalog.did.key.DidKey} — an immutable representation of a
 * {@code did:key} identifier.</li>
 * <li>{@link com.apicatalog.did.key.DidKeyResolver} — a {@code DidResolver}
 * implementation for {@code did:key} identifiers.</li>
 * <li>{@link com.apicatalog.did.key.VerificationMethodProvider} — a functional
 * interface for creating
 * {@link com.apicatalog.did.document.DidVerificationMethod} instances from
 * {@link com.apicatalog.did.key.DidKey} identifiers.</li>
 * </ul>
 *
 * @see <a href="https://w3c-ccg.github.io/did-key-spec/">DID Key Method
 *      Specification</a>
 */
package com.apicatalog.did.key;