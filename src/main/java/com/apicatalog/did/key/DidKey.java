package com.apicatalog.did.key;

import java.net.URI;
import java.util.Objects;
import java.util.function.Function;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidUrl;

/**
 * Immutable {@code did:key} identifier.
 *
 * <p>
 * The {@code did:key} method encodes a public key directly into the DID itself.
 * </p>
 *
 * <p>
 * Format:
 * </p>
 * 
 * <pre>
 * did:key:[version]:MULTIBASE(base, MULTICODEC(public-key-codec, public-key-bytes))
 * </pre>
 *
 * @see <a href="https://w3c-ccg.github.io/did-key-spec/">DID Key Method
 *      Specification</a>
 */
public record DidKey(
        String version,
        String methodSpecificId,
        byte[] publicKey) {

    /** DID method name for {@code did:key}. */
    public static final String METHOD_NAME = "key";

    /** Default version string. */
    public static final String DEFAULT_VERSION = "1";

    public String method() {
        return METHOD_NAME;
    }

    /**
     * Tests whether the given {@link Did} is a {@code did:key}.
     *
     * @param did the DID to test
     * @return {@code true} if the DID uses the {@code did:key} method
     */
    public static boolean isDidKey(final Did did) {
        return did != null && METHOD_NAME.equals(did.method());
    }

    /**
     * Tests whether the given {@link DidUrl} contains a {@code did:key}.
     *
     * @param url the DID URL to test
     * @return {@code true} if the DID uses the {@code did:key} method
     */
    public static boolean isDidKey(DidUrl url) {
        return url != null && METHOD_NAME.equals(url.method());
    }

    /**
     * Tests whether the given {@link URI} is a {@code did:key}.
     *
     * @param uri the URI to test
     * @return {@code true} if the URI is a valid {@code did:key}
     */
    public static boolean isDidKey(final URI uri) {
        return uri != null
                && uri.getRawSchemeSpecificPart().startsWith(METHOD_NAME + ":")
                && isMethodSpecificId(uri.getRawSchemeSpecificPart().substring(METHOD_NAME.length() + 1));
    }

    /**
     * Tests whether the given string is a {@code did:key}.
     *
     * @param uri the string to test
     * @return {@code true} if the string is a valid {@code did:key}
     */
    public static boolean isDidKey(final String uri) {
        return uri != null
                && uri.startsWith(Did.SCHEME + ":" + METHOD_NAME + ":")
                && isMethodSpecificId(uri.substring(Did.SCHEME.length() + METHOD_NAME.length() + 2));
    }

    public Did toDid() {
        return new Did(METHOD_NAME, methodSpecificId);
    }

    @Override
    public final String toString() {
        if (version == null || DEFAULT_VERSION.equals(version)) {
            return Did.SCHEME + ":" + METHOD_NAME + ":" + methodSpecificId;
        }
        return Did.SCHEME + ":" + METHOD_NAME + ":" + version + ":" + methodSpecificId;
    }

    /**
     * @return the version string, or {@link #DEFAULT_VERSION} if none is present
     */
    public String version() {
        return version;
    }

    public static boolean isMethodSpecificId(String input) {
        if (input == null || input.length() < 2) {
            return false;
        }

        int len = input.length();
        char prefix = input.charAt(0);

        if (prefix == 'z') {
            for (int i = 1; i < len; i++) {
                char c = input.charAt(i);
                if ((c < '1' || c > '9') &&
                        (c < 'A' || c > 'H') &&
                        (c < 'J' || c > 'N') &&
                        (c < 'P' || c > 'Z') &&
                        (c < 'a' || c > 'k') &&
                        (c < 'm' || c > 'z')) {
                    return false;
                }
            }
            return true;
        }

        if (prefix == 'u') {
            for (int i = 1; i < len; i++) {
                char c = input.charAt(i);
                if ((c < 'A' || c > 'Z') &&
                        (c < 'a' || c > 'z') &&
                        (c < '0' || c > '9') &&
                        c != '-' &&
                        c != '_') {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    public static Parser parser(Function<String, byte[]> multibaseDecoder) {
        return new Parser(multibaseDecoder);
    }

    /**
     * @return {@code true} if the value is non-null and not blank after
     *         {@code trim()}
     */
    private static final boolean isNotBlank(String value) {
        return value != null && !value.isBlank();
    }

    public static class Parser {

        private final Function<String, byte[]> multibaseDecoder;

        private Parser(Function<String, byte[]> multibaseDecoder) {
            this.multibaseDecoder = multibaseDecoder;
        }

        public DidKey parse(final String did) {

            if (!did.startsWith(Did.SCHEME + ":" + METHOD_NAME + ":")) {
                throw new IllegalArgumentException();
            }

            var methodSpecificId = did.substring(Did.SCHEME.length() + METHOD_NAME.length() + 2);

            if (!isMethodSpecificId(methodSpecificId)) {
                throw new IllegalArgumentException();
            }

            return from(methodSpecificId);
        }

        public DidKey from(URI uri) {

            Objects.requireNonNull(uri);

            if (!Did.SCHEME.equals(uri.getScheme())
                    || uri.getRawSchemeSpecificPart() == null
                    || !uri.getRawSchemeSpecificPart().startsWith(METHOD_NAME + ":")
                    || isNotBlank(uri.getAuthority())
                    || isNotBlank(uri.getUserInfo())
                    || isNotBlank(uri.getHost())
                    || isNotBlank(uri.getRawPath())
                    || isNotBlank(uri.getRawQuery())
                    || uri.getRawFragment() != null) {

                throw new IllegalArgumentException();
            }

            var methodSpecificId = uri.getRawSchemeSpecificPart().substring(METHOD_NAME.length() + 1);

            return from(methodSpecificId);
        }

        /**
         * Creates a new {@link DidKey} instance from the given {@link Did}.
         *
         * @param did the {@link Did} to interpret as a {@code did:key}
         * @return a new {@link DidKey} instance
         *
         * @throws IllegalArgumentException if the given {@link Did} is not a valid
         *                                  {@code did:key}
         */
        public final DidKey from(final Did did) {
            Objects.requireNonNull(did);

            if (!METHOD_NAME.equalsIgnoreCase(did.method())) {
                throw new IllegalArgumentException(
                        "Not a did:key DID; unsupported method '" + did.method() + "'. DID [" + did + "].");
            }

            return from(did.methodSpecificId());
        }

        public final DidKey from(final String methodSpecificId) {

            final var parts = methodSpecificId.split(":", 2);

            String version = DEFAULT_VERSION;
            String encoded = parts[0];

            // explicit version present
            if (parts.length == 2) {
                version = parts[0];
                encoded = parts[1];
            }

            var debased = multibaseDecoder.apply(encoded);

            return new DidKey(version, methodSpecificId, debased);
        }
    }
}
