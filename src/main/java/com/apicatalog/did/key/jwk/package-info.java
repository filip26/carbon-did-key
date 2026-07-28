/**
 * Provides support for expressing {@code did:key} verification methods in JSON
 * Web Key (JWK) format.
 *
 * The {@code jwk} subpackage contains:
 * <ul>
 * <li>{@link com.apicatalog.did.key.jwk.JwkMethodFactory} – a provider that maps
 * supported {@code did:key} codecs to
 * {@link com.apicatalog.did.primitive.JsonWebKey}.</li>
 * <li>{@link com.apicatalog.did.key.jwk.JwkGenerator} – a functional interface
 * for custom JWK generation strategies.</li>
 * </ul>
 *
 * <p>
 * Implementations follow the W3C DID Core specification and the JWK standard
 * defined in <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</a>.
 * </p>
 */
package com.apicatalog.did.key.jwk;
