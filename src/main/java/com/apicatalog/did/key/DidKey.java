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
 * Immutable DID Key
 * <p>
 * did-key-format := did:key:[version]:MULTIBASE(base58-btc,
 * MULTICODEC(key-type, raw-key-bytes))
 * </p>
 *
 * @see <a href= "https://w3c-ccg.github.io/did-key-spec/">DID Key Method</a>
 *
 */
public class DidKey extends Did implements MultibaseEncoded, MulticodecEncoded {

    private static final long serialVersionUID = 1557847670130252936L;

    public static final String METHOD_NAME = "key";

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
     * Creates a new DID Key method instance from the given {@link URI}.
     *
     * @param uri    The source URI to be transformed into {@link DidKey} instance
     * @param codecs
     * @return a new instance
     *
     * @throws NullPointerException     If {@code uri} is {@code null}
     *
     * @throws IllegalArgumentException If the given {@code uri} is not valid DID
     *                                  Key method
     */
    public static final DidKey of(final URI uri, final MulticodecDecoder codecs) {

        Objects.requireNonNull(uri);
        Objects.requireNonNull(codecs);

        return of(Did.of(uri), codecs);
    }

    public static final DidKey of(final Did did, final MulticodecDecoder codecs) {

        Objects.requireNonNull(did);
        Objects.requireNonNull(codecs);

        if (!METHOD_NAME.equalsIgnoreCase(did.getMethod())) {
            throw new IllegalArgumentException("The given DID [" + did + "] is not valid DID key method, does not start with 'did:key'.");
        }

        final String[] parts = did.getMethodSpecificId().split(":", 2);

        String version = DEFAULT_VERSION;
        String encoded = parts[0];

        // has a version, length == 1 otherwise
        if (parts.length == 2) {
            version = parts[0];
            encoded = parts[1];
        }

        if (!Multibase.BASE_58_BTC.isEncoded(encoded)) {
            throw new IllegalArgumentException("Unsupported did:key base encoding, expected base58btc. DID [" + did.toString() + "].");
        }

        final byte[] debased = Multibase.BASE_58_BTC.decode(encoded);

        final Multicodec codec = codecs.getCodec(debased)
                .orElseThrow(() -> new IllegalArgumentException("Unsupported did:key codec. DID [" + did.toString() + "]."));

        final byte[] raw = codec.decode(debased);

        return new DidKey(version, did.getMethodSpecificId(), codec, raw);
    }

    public static final DidKey of(byte[] key, Multicodec codec) {
        return new DidKey(DEFAULT_VERSION,
                Multibase.BASE_58_BTC.encode(codec.encode(key)),
                codec,
                key);
    }

    public static boolean isDidKey(final Did did) {
        return did != null && METHOD_NAME.equals(did.getMethod());
    }

    public static boolean isDidKey(final URI uri) {
        return uri != null
                && uri.getRawSchemeSpecificPart().startsWith(METHOD_NAME + ":")
                && Did.isDid(uri);
    }

    public static boolean isDidKey(final String uri) {
        return uri != null
                && uri.startsWith(SCHEME + ":" + METHOD_NAME + ":")
                && Did.isDid(uri);
    }

    public String version() {
        return version;
    }

    public Multicodec codec() {
        return codec;
    }

    public Multibase base() {
        return Multibase.BASE_58_BTC;
    }

    @Override
    public String baseName() {
        return base().name();
    }

    @Override
    public byte[] debased() {
        return codec.encode(rawKeyBytes);
    }

    @Override
    public byte[] decoded() {
        return rawKeyBytes;
    }

    @Override
    public long codecCode() {
        return codec.code();
    }
}
