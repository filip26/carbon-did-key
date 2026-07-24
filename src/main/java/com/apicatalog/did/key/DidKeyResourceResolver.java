package com.apicatalog.did.key;

import java.util.Map;

import com.apicatalog.did.DidResource;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.primitive.MultiKey;
import com.apicatalog.did.resolver.DidResolutionException;
import com.apicatalog.did.resolver.DidResourceResolver;

/**
 * {@link DidResourceResolver} implementation for the {@code did:key} method.
 *
 * <p>
 * Resolves {@link DidKey} identifiers into minimal {@link DidResource}
 * containing material encoded in the DID.
 * </p>
 *
 */
public class DidKeyResourceResolver implements DidResourceResolver {

    public static final String DEFAULT_CONTEXT = "https://www.w3.org/ns/did/v1.1";

    public static final String OPTION_PUBLIC_KEY_FORMAT = "publicKeyFormat";
    public static final String OPTION_EXPERIMENTAL_KEY_TYPES = "enableExperimentalPublicKeyTypes";
    public static final String OPTION_DEFAULT_CONTEXT = "defaultContext";

    @Override
    public DidResource resolve(DidUrl url, Map<String, Object> options) throws DidResolutionException {

        if (!DidKey.isDidKey(url)) {
            throw new IllegalArgumentException();
        }

        var didKey = DidKey.from(url.methodSpecificId());

        if ("vm".equals(url.fragment()) || url.methodSpecificId().equals(url.fragment())) {
            return switch (options.getOrDefault(OPTION_PUBLIC_KEY_FORMAT, MultiKey.TYPE_NAME)) {
            case MultiKey.TYPE_NAME -> new MultiKey(url, url.toDid(), null, null, didKey.publicKey(), null);
//     TODO       case JsonWebKey.TYPE_NAME -> new JsonWebKey(url, url.toDid(), null, null, didKey.publicKey(), null);
            default -> throw new IllegalArgumentException();
            };
        }

        // TODO Auto-generated method stub
        return null;
    }
}
