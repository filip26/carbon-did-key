package com.apicatalog.did.key.jwk;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.DidVerificationMethod;
import com.apicatalog.did.key.DidKey;
import com.apicatalog.did.key.VerificationMethodProvider;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.codec.KeyCodec;

/**
 * A {@link VerificationMethodProvider} that generates verification methods for
 * {@link DidKey} identifiers using the JWK (JSON Web Key) representation.
 *
 * <p>
 * Supports common key types such as:
 * </p>
 * <ul>
 * <li>Ed25519</li>
 * <li>BLS12-381 (G1, G2)</li>
 * <li>P-256, P-384, secp256k1</li>
 * </ul>
 *
 * <p>
 * The returned verification methods contain a JWK-formatted public key.
 * </p>
 */
public class DidKeyJwkMethodProvider implements VerificationMethodProvider {

    static final Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /** Default provider instance with common key types pre-registered. */
    static final DidKeyJwkMethodProvider DEFAULT = with(KeyCodec.ED25519_PUBLIC_KEY, key -> getJwk("Ed25519", key))
            .with(KeyCodec.BLS12_381_G1_PUBLIC_KEY, key -> getJwk("Bls12381G1", key))
            .with(KeyCodec.BLS12_381_G2_PUBLIC_KEY, key -> getJwk("Bls12381G2", key))
            .with(KeyCodec.P256_PUBLIC_KEY, key -> getECJwk("P-256", "secp256r1", key, 32))
            .with(KeyCodec.P384_PUBLIC_KEY, key -> getECJwk("P-384", "secp384r1", key, 48))
            .with(KeyCodec.SECP256K1_PUBLIC_KEY, key -> getECJwk("secp256k1", "secp256k1", key, 32))
            .build();

    final Map<Multicodec, JwkProvider> jwkProviders;

    protected DidKeyJwkMethodProvider(Map<Multicodec, JwkProvider> jwkProviders) {
        this.jwkProviders = jwkProviders;
    }

    /**
     * Returns the default provider instance with built-in key type mappings.
     *
     * @return default {@link DidKeyJwkMethodProvider}
     */
    public static DidKeyJwkMethodProvider getInstance() {
        return DEFAULT;
    }

    /**
     * Returns a builder pre-populated with the defaults.
     *
     * @return a builder initialized with the default providers
     */
    public static Builder withDefaults() {
        return (new Builder(new LinkedHashMap<>(DEFAULT.jwkProviders)));
    }

    /**
     * Creates a new builder starting with a single codec/provider mapping.
     *
     * @param codec    the multicodec
     * @param provider the JWK provider
     * @return a builder
     */
    public static Builder with(Multicodec codec, JwkProvider provider) {
        return (new Builder(new LinkedHashMap<>())).with(codec, provider);
    }

    @Override
    public DidVerificationMethod get(DidUrl id, DidKey key, String type) {

        final JwkProvider provider = jwkProviders.get(key.codec());

        if (provider == null) {
            throw new IllegalArgumentException("Curve type [" + key.codec() + "] is not supported.");
        }

        return DidVerificationMethod.jwk(
                id,
                type,
                key,
                provider.get(key));
    }

    /**
     * Creates a JWK representation for an OKP-type key (e.g., Ed25519).
     *
     * @param curveType the JWK "crv" parameter value
     * @param key       the {@link DidKey}
     * @return an unmodifiable JWK map
     */
    public static final Map<String, Object> getJwk(String curveType, DidKey key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", curveType);
        jwk.put("x", BASE64_ENCODER.encodeToString(key.decoded()));
        return Collections.unmodifiableMap(jwk);
    }

    /**
     * Creates a JWK representation for an EC key (P-256, P-384, secp256k1).
     *
     * @param curve         the JWK "crv" parameter
     * @param curveSpecName the JCA curve spec name
     * @param key           the {@link DidKey}
     * @param length        coordinate byte length
     * @return an unmodifiable JWK map
     */
    public static final Map<String, Object> getECJwk(String curve, String curveSpecName, DidKey key, int length) {

        try {
            final ECPoint point = decompress(curveSpecName, key.decoded());

            final Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "EC");
            jwk.put("crv", curve);
            jwk.put("x", BASE64_ENCODER.encodeToString(normalize(point.getAffineX().toByteArray(), length)));
            jwk.put("y", BASE64_ENCODER.encodeToString(normalize(point.getAffineY().toByteArray(), length)));
            return Collections.unmodifiableMap(jwk);

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to construct EC JWK for curve [" + curve + "].", e);
        }
    }

    /** Ensures EC coordinate byte arrays are of the expected length. */
    static final byte[] normalize(byte[] v, int len) {
        if (v.length == len)
            return v;
        if (v.length == len + 1 && v[0] == 0)
            return Arrays.copyOfRange(v, 1, v.length);
        byte[] out = new byte[len];
        System.arraycopy(v, 0, out, len - v.length, v.length);
        return out;
    }

    /** Decompresses a compressed EC point. */
    static final ECPoint decompress(String curveSpecName, byte[] compressed) throws InvalidParameterSpecException, NoSuchAlgorithmException {

        if (compressed.length < 2 || (compressed[0] & 0xFE) != 0x02) {
            throw new IllegalArgumentException("Compressed EC point required.");
        }

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveSpecName));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);

        int length = (spec.getCurve().getField().getFieldSize() + 7) / 8;

        if (compressed.length != 1 + length) {
            throw new IllegalArgumentException("Unexpected EC point length for curve [" + curveSpecName + "].");
        }

        BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
        BigInteger a = spec.getCurve().getA(), b = spec.getCurve().getB();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, compressed.length));
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
        BigInteger y = sqrtMod(rhs, p);

        if (y.testBit(0) != ((compressed[0] & 1) == 1)) {
            y = p.subtract(y);
        }
        return new ECPoint(x, y);
    }

    /**
     * Computes modular square root using Tonelli–Shanks algorithm.
     */
    static final BigInteger sqrtMod(BigInteger n, BigInteger p) {
        if (n.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }
        if (p.testBit(1)) { // p % 4 == 3
            return n.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        }
        // Tonelli–Shanks
        BigInteger q = p.subtract(BigInteger.ONE);
        int s = 0;
        while (!q.testBit(0)) {
            q = q.shiftRight(1);
            s++;
        }
        BigInteger z = BigInteger.ONE.add(BigInteger.ONE);
        while (z.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE)) {
            z = z.add(BigInteger.ONE);
        }
        BigInteger m = BigInteger.valueOf(s);
        BigInteger c = z.modPow(q, p);
        BigInteger t = n.modPow(q, p);
        BigInteger r = n.modPow(q.add(BigInteger.ONE).shiftRight(1), p);
        while (!t.equals(BigInteger.ONE)) {
            int i = 1;
            BigInteger tt = t.multiply(t).mod(p);
            while (!tt.equals(BigInteger.ONE)) {
                tt = tt.multiply(tt).mod(p);
                i++;
            }
            BigInteger b = c.modPow(BigInteger.ONE.shiftLeft((int) (m.intValue() - i - 1)), p);
            m = BigInteger.valueOf(i);
            c = b.multiply(b).mod(p);
            t = t.multiply(c).mod(p);
            r = r.multiply(b).mod(p);
        }
        return r;
    }

    /**
     * Builder for customizing supported codecs → JWK providers mapping.
     */
    public static class Builder {

        final Map<Multicodec, JwkProvider> providers;

        Builder(Map<Multicodec, JwkProvider> providers) {
            this.providers = providers;
        }

        /** Registers a new codec → provider mapping. */
        public Builder with(Multicodec codec, JwkProvider provider) {
            providers.put(codec, provider);
            return this;
        }

        /** Builds the provider, falling back to default if empty. */
        public DidKeyJwkMethodProvider build() {
            if (providers.isEmpty()) {
                return DEFAULT;
            }
            return new DidKeyJwkMethodProvider(Collections.unmodifiableMap(providers));
        }
    }
}
