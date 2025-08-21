/**
 * Provides support for expressing {@code did:key} verification methods in JSON
 * Web Key (JWK) format.
 *
 * <p>
 * The {@code jwk} subpackage contains:
 * </p>
 * <ul>
 * <li>{@link com.apicatalog.did.key.jwk.DidKeyJwkMethodProvider} – a provider
 * that maps supported {@code did:key} codecs to JWK representations.</li>
 * <li>{@link com.apicatalog.did.key.jwk.JwkProvider} – a functional interface
 * for custom JWK generation strategies.</li>
 * </ul>
 *
 * <p>
 * Implementations follow the W3C DID Core specification and the JWK standard
 * defined in <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</a>.
 * </p>
 */
package com.apicatalog.did.key.jwk;
