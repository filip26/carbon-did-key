package com.apicatalog.did.key.jwk;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.key.DidKey;
import com.apicatalog.did.key.DidKeyResolver;
import com.apicatalog.did.primitive.JsonWebKey;

/**
 * A {@link JwkMethodFactory} that creates verification methods for
 * {@link DidKey} identifiers using the JWK (JSON Web Key) representation.
 *
 * <p>
 * The returned verification methods contain a JWK-formatted public key.
 * </p>
 */
public class JwkMethodFactory implements DidKeyResolver.MethodFactory {

    public static final int ED25519_PUBLIC_KEY_CODE = 0xed;
    public static final int P256_PUBLIC_KEY_CODE = 0x1200;
    public static final int P384_PUBLIC_KEY_CODE = 0x1201;
    public static final int SECP256K1_PUBLIC_KEY_CODE = 0xe7;

    private final String typeName;
    private final Function<byte[], Integer> codecDecoder;
    private final Map<Integer, JwkGenerator> generators;

    public JwkMethodFactory(
            Function<byte[], Integer> codecDecoder,
            Map<Integer, JwkGenerator> jwkProviders) {
        this(JsonWebKey.TYPE_NAME, codecDecoder, jwkProviders);
    }

    public JwkMethodFactory(
            String typeName,
            Function<byte[], Integer> codecProvider,
            Map<Integer, JwkGenerator> jwkProviders) {
        this.typeName = typeName;
        this.codecDecoder = codecProvider;
        this.generators = jwkProviders;
    }

    @Override
    public JsonWebKey createMethod(DidUrl url, DidKey key) {

        var codec = codecDecoder.apply(key.publicKey());
        if (codec == null) {
            throw new IllegalArgumentException();
        }

        final JwkGenerator provider = generators.get(codec);

        if (provider == null) {
            throw new IllegalArgumentException("No provider is configured for multicodec code: " + codec);
        }

        return new JsonWebKey(
                url,
                typeName,
                url.toDid(),
                null,
                null,
                provider.get(key),
                null);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static class Builder {

        private static final Map<String, ECParameterSpec> EC_SPECS_CACHE = new ConcurrentHashMap<>();
        private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

        private String typeName;
        private Function<byte[], Integer> codecDecoder;
        private Map<Integer, JwkGenerator> generators;

        private Builder() {
            this.typeName = JsonWebKey.TYPE_NAME;
            this.codecDecoder = null;
            this.generators = new HashMap<>();
        }

        public Builder typeName(String typeName) {
            this.typeName = typeName;
            return this;
        }

        public Builder codecDecoder(Function<byte[], Integer> codecDecoder) {
            this.codecDecoder = codecDecoder;
            return this;
        }

        public Builder generator(Integer codec, JwkGenerator generator) {
            Objects.requireNonNull(codec);
            Objects.requireNonNull(generator);
            generators.put(codec, generator);
            return this;
        }

        public Builder ed25519() {
            generators.put(ED25519_PUBLIC_KEY_CODE, key -> getJwk("Ed25519", key.publicKey(), 2, 32));
            return this;
        }

        public Builder p256() {
            generators.put(P256_PUBLIC_KEY_CODE, key -> getECJwk("P-256", "secp256r1", key.publicKey(), 2, 32));
            return this;
        }

        public Builder secp256r1() {
            return p256();
        }

        public Builder p384() {
            generators.put(P384_PUBLIC_KEY_CODE, key -> getECJwk("P-384", "secp384r1", key.publicKey(), 2, 48));
            return this;
        }

        public Builder secp384r1() {
            return p384();
        }

        public Builder secp256k1() {
            generators.put(SECP256K1_PUBLIC_KEY_CODE,
                    key -> getECJwk("secp256k1", "secp256k1", key.publicKey(), 2, 32));
            return this;
        }

        public JwkMethodFactory build() {
            if (typeName == null) {
                throw new IllegalArgumentException();
            }
            if (codecDecoder == null) {
                throw new IllegalArgumentException();
            }
            if (generators.isEmpty()) {
                throw new IllegalArgumentException();
            }

            return new JwkMethodFactory(typeName, codecDecoder, Map.copyOf(generators));
        }

        /**
         * Creates a JWK representation for an OKP-type key (e.g., Ed25519).
         *
         * @param curveType   the JWK "crv" parameter value
         * @param encoded     multicodec-encoded public key
         * @param codecLength the byte length of the multicodec prefix
         * @param length      coordinate byte length
         * @return an unmodifiable JWK map
         */
        public static final Map<String, Object> getJwk(String curveType, byte[] encoded, int codecLength, int length) {

            var publicKey = Arrays.copyOfRange(encoded, codecLength, encoded.length);

            if (publicKey.length != length) {
                throw new IllegalArgumentException(
                        "Invalid public key length: " + publicKey.length + ", expected: " + length);
            }

            return Map.of(
                    "kty", "OKP",
                    "crv", curveType,
                    "x", BASE64_URL.encodeToString(publicKey));
        }

        /**
         * Creates a JWK representation for an EC key (P-256, P-384, secp256k1).
         *
         * @param curve         the JWK "crv" parameter
         * @param curveSpecName the JCA curve spec name
         * @param encoded       multicodec-encoded compressed public key
         * @param codecLength   the byte length of the multicodec prefix
         * @param length        coordinate byte length
         * @return an unmodifiable JWK map
         */
        public static final Map<String, Object> getECJwk(
                String curve,
                String curveSpecName,
                byte[] encoded,
                int codecLength,
                int length) {

            var publicKey = Arrays.copyOfRange(encoded, codecLength, encoded.length);

            try {
                final ECPoint point = decompress(curveSpecName, publicKey);

                return Map.of(
                        "kty", "EC",
                        "crv", curve,
                        "x", BASE64_URL.encodeToString(normalize(point.getAffineX().toByteArray(), length)),
                        "y", BASE64_URL.encodeToString(normalize(point.getAffineY().toByteArray(), length)));

            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to construct EC JWK for curve [" + curve + "].", e);
            }
        }

        /** Ensures EC coordinate byte arrays are of the expected length. */
        static byte[] normalize(byte[] value, int length) {

            if (value.length == length) {
                return value;
            }

            if (value.length == length + 1 && value[0] == 0) {
                return Arrays.copyOfRange(value, 1, value.length);
            }

            if (value.length > length) {
                throw new IllegalArgumentException(
                        "Coordinate exceeds expected length.");
            }

            byte[] out = new byte[length];
            System.arraycopy(value, 0, out, length - value.length, value.length);
            return out;
        }
//        static final byte[] normalize(byte[] v, int len) {
//            if (v.length == len)
//                return v;
//            if (v.length == len + 1 && v[0] == 0)
//                return Arrays.copyOfRange(v, 1, v.length);
//            byte[] out = new byte[len];
//            System.arraycopy(v, 0, out, len - v.length, v.length);
//            return out;
//        }

        /** Decompresses a compressed EC point. */
        static final ECPoint decompress(String curveSpecName, byte[] compressed) {

            if (compressed.length < 2 || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
                throw new IllegalArgumentException("Compressed EC point required.");
            }

            ECParameterSpec spec = EC_SPECS_CACHE.computeIfAbsent(curveSpecName, name -> {
                try {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                    params.init(new ECGenParameterSpec(name));
                    return params.getParameterSpec(ECParameterSpec.class);
                } catch (GeneralSecurityException e) {
                    throw new IllegalArgumentException("Failed to load EC parameters for " + name, e);
                }
            });

            int length = (spec.getCurve().getField().getFieldSize() + 7) / 8;

            if (compressed.length != 1 + length) {
                throw new IllegalArgumentException("Unexpected EC point length for curve [" + curveSpecName + "].");
            }

            BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
            BigInteger a = spec.getCurve().getA(), b = spec.getCurve().getB();
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, compressed.length));
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
            BigInteger y = sqrtMod(rhs, p);

            if (!y.multiply(y).mod(p).equals(rhs)) {
                throw new IllegalArgumentException("Invalid EC point.");
            }

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
    }
}
