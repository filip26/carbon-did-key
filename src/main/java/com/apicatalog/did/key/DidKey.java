package com.apicatalog.did.key;

import java.net.URI;
import java.util.Objects;

import com.apicatalog.did.Did;
import com.apicatalog.did.datatype.MultibaseEncoded;
import com.apicatalog.did.datatype.MulticodecEncoded;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.MulticodecDecoder;

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
 * did:key:[version]:MULTIBASE(base58-btc, MULTICODEC(key-type + key-bytes))
 * </pre>
 *
 * @see <a href="https://w3c-ccg.github.io/did-key-spec/">DID Key Method
 *      Specification</a>
 */
public class DidKey extends Did implements MultibaseEncoded, MulticodecEncoded {

    private static final long serialVersionUID = 1557847670130252936L;

    /** DID method name for {@code did:key}. */
    public static final String METHOD_NAME = "key";

    /** Default version string. */
    public static final String DEFAULT_VERSION = "1";

    protected final String version;
    protected final Multicodec codec;
    protected final byte[] rawKeyBytes;

    protected DidKey(String version, String specificId, Multicodec codec, byte[] rawKeyBytes) {
        super(METHOD_NAME, specificId);
        this.version = version;
        this.codec = codec;
        this.rawKeyBytes = rawKeyBytes;
    }

    /**
     * Creates a new {@link DidKey} instance from the given {@link URI}.
     *
     * @param uri    the {@link URI} to parse
     * @param codecs the {@link MulticodecDecoder} used to decode the key material
     * @return a new {@link DidKey} instance
     *
     * @throws NullPointerException     if {@code uri} or {@code codecs} is
     *                                  {@code null}
     * @throws IllegalArgumentException if the given {@code uri} is not a valid
     *                                  {@code did:key}
     */
    public static final DidKey of(final URI uri, final MulticodecDecoder codecs) {
        Objects.requireNonNull(uri);
        Objects.requireNonNull(codecs);
        return of(Did.of(uri), codecs);
    }

    /**
     * Creates a new {@link DidKey} instance from the given {@link Did}.
     *
     * @param did    the {@link Did} to interpret as a {@code did:key}
     * @param codecs the {@link MulticodecDecoder} used to decode the key material
     * @return a new {@link DidKey} instance
     *
     * @throws NullPointerException     if {@code did} or {@code codecs} is
     *                                  {@code null}
     * @throws IllegalArgumentException if the given {@link Did} is not a valid
     *                                  {@code did:key}
     */
    public static final DidKey of(final Did did, final MulticodecDecoder codecs) {
        Objects.requireNonNull(did);
        Objects.requireNonNull(codecs);

        if (!METHOD_NAME.equalsIgnoreCase(did.getMethod())) {
            throw new IllegalArgumentException("Not a did:key DID; unsupported method '" + did.getMethod() + "'. DID [" + did + "].");
        }

        final String[] parts = did.getMethodSpecificId().split(":", 2);

        String version = DEFAULT_VERSION;
        String encoded = parts[0];

        // explicit version present
        if (parts.length == 2) {
            version = parts[0];
            encoded = parts[1];
        }

        if (!Multibase.BASE_58_BTC.isEncoded(encoded)) {
            throw new IllegalArgumentException("Invalid did:key encoding: expected multibase base58btc. DID [" + did + "].");
        }

        final byte[] debased = Multibase.BASE_58_BTC.decode(encoded);

        final Multicodec codec = codecs.getCodec(debased)
                .orElseThrow(() -> new IllegalArgumentException("Unsupported did:key multicodec prefix. DID [" + did + "]."));

        final byte[] raw = codec.decode(debased);

        return new DidKey(version, did.getMethodSpecificId(), codec, raw);
    }

    /**
     * Creates a new {@link DidKey} directly from raw key bytes and a codec.
     *
     * @param key   the raw key bytes
     * @param codec the {@link Multicodec} representing the key type
     * @return a new {@link DidKey} instance
     */
    public static final DidKey of(byte[] key, Multicodec codec) {
        return new DidKey(
                DEFAULT_VERSION,
                Multibase.BASE_58_BTC.encode(codec.encode(key)),
                codec,
                key);
    }

    /**
     * Tests whether the given {@link Did} is a {@code did:key}.
     *
     * @param did the DID to test
     * @return {@code true} if the DID uses the {@code did:key} method
     */
    public static boolean isDidKey(final Did did) {
        return did != null && METHOD_NAME.equals(did.getMethod());
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
                && Did.isDid(uri);
    }

    /**
     * Tests whether the given string is a {@code did:key}.
     *
     * @param uri the string to test
     * @return {@code true} if the string is a valid {@code did:key}
     */
    public static boolean isDidKey(final String uri) {
        return uri != null
                && uri.startsWith(SCHEME + ":" + METHOD_NAME + ":")
                && Did.isDid(uri);
    }

    /**
     * @return the version string, or {@link #DEFAULT_VERSION} if none is present
     */
    public String version() {
        return version;
    }

    /** @return the {@link Multicodec} codec used for this key */
    public Multicodec codec() {
        return codec;
    }

    /**
     * @return the {@link Multibase} encoding used, always base58btc for
     *         {@code did:key}
     */
    public Multibase base() {
        return Multibase.BASE_58_BTC;
    }

    @Override
    public String baseName() {
        return Multibase.BASE_58_BTC.name();
    }

    /**
     * Returns the multicodec-encoded form of the key bytes.
     * <p>
     * This includes the multicodec prefix for the key type, suitable for multibase
     * encoding.
     * </p>
     *
     * @return multicodec-encoded key material
     */
    @Override
    public byte[] debased() {
        return codec.encode(rawKeyBytes);
    }

    /**
     * Returns the raw key bytes (decoded public key material).
     *
     * @return raw key bytes
     */
    @Override
    public byte[] decoded() {
        return rawKeyBytes;
    }

    /**
     * Returns the numeric multicodec code of this key type.
     *
     * @return codec identifier
     */
    @Override
    public long codecCode() {
        return codec.code();
    }
}
