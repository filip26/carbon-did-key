package com.apicatalog.did.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.did.DidDocument.Relationship;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.key.jwk.JwkMethodFactory;
import com.apicatalog.did.primitive.JsonWebKey;
import com.apicatalog.did.primitive.MultiKey;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.uvarint.UVarInt;

@DisplayName("DID Key Resolver")
class DidKeyResolverTest {

    static final JwkMethodFactory FACTORY = JwkMethodFactory.newBuilder()
            .codecDecoder(b -> (int) UVarInt.decode(b))
            .p256().p384().ed25519().secp256k1()
            .generator(KeyCodec.BLS12_381_G1_PUBLIC_CODE,
                    key -> JwkMethodFactory.Builder.getJwk("Bls12381G1", key.publicKey(), 2, 48))
            .generator(KeyCodec.BLS12_381_G2_PUBLIC_CODE,
                    key -> JwkMethodFactory.Builder.getJwk("Bls12381G2", key.publicKey(), 2, 96))
            .build();

    static final DidKeyResolver KEY_RESOLVER = DidKeyResolver.newBuilder()
            .multibaseDecoder(MultibaseDecoder.getInstance()::decode)
            .multikey()
            .method(JsonWebKey.TYPE_NAME, FACTORY)
            .build();

    static final Set<Relationship> RELS = Set.of(
            Relationship.ASSERTION,
            Relationship.AUTHENTICATION,
            Relationship.VERIFICATION,
            Relationship.CAPABILITY_DELEGATION,
            Relationship.CAPABILITY_INVOCATION);

    @ParameterizedTest(name = "{0}")
    @MethodSource({ "vectors" })
    void resolveMultikey(String did) {

        var didUrl = DidUrl.parse(did);

        var documentWitMetadata = KEY_RESOLVER.resolve(didUrl, Map.of());
        assertNotNull(documentWitMetadata);
        assertNull(documentWitMetadata.metadata());

        var document = documentWitMetadata.document();
        assertNotNull(document);

        assertEquals(didUrl.toDid(), document.id());
        assertEquals(List.of(), document.controller());
        assertEquals(List.of(), document.alsoKnownAs());

        assertEquals(RELS, document.relationships());

        for (var rel : RELS) {
            var methods = document.methods(rel);
            assertEquals(1, methods.size());
            assertMultikeyMethod((MultiKey) methods.iterator().next(), didUrl);
        }

        assertEquals(List.of(), document.service());
        assertTrue(document.hasRequiredProperties());
    }

    static void assertMultikeyMethod(MultiKey method, DidUrl url) {
        assertNotNull(method);
        assertEquals(url, method.id());
        assertEquals(MultiKey.TYPE_NAME, method.type());
        assertEquals(url.toDid(), method.controller());
        assertArrayEquals(MultibaseDecoder.getInstance().decode(url.methodSpecificId()), method.publicKey());
        assertNull(method.secretKey());
        assertTrue(method.hasRequiredProperties());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource({ "vectors" })
    void resolveJwk(String did, Map<String, Object> expected) {

        var didUrl = DidUrl.parse(did);

        var documentWitMetadata = KEY_RESOLVER.resolve(
                didUrl,
                Map.of(
                        DidKeyResolver.OPTION_PUBLIC_KEY_FORMAT,
                        JsonWebKey.TYPE_NAME));

        assertNotNull(documentWitMetadata);
        assertNull(documentWitMetadata.metadata());

        var document = documentWitMetadata.document();
        assertNotNull(document);

        assertEquals(didUrl.toDid(), document.id());
        assertEquals(List.of(), document.controller());
        assertEquals(List.of(), document.alsoKnownAs());

        assertEquals(RELS, document.relationships());

        for (var rel : RELS) {
            var methods = document.methods(rel);
            assertEquals(1, methods.size());
            JwkMethodFactoryTest.assertJwkMethod((JsonWebKey) methods.iterator().next(), didUrl, expected);
        }

        assertEquals(List.of(), document.service());
        assertTrue(document.hasRequiredProperties());

    }

    static Stream<Arguments> vectors() {
        return Stream.of(
                // P-256
                Arguments.of("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-256",
                                "x", "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
                                "y", "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM")),
                Arguments.of("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-256",
                                "x", "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
                                "y", "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU")),
                // P-384
                Arguments.of("did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-384",
                                "x", "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc",
                                "y", "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv")),
                Arguments.of("did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-384",
                                "x", "CA-iNoHDg1lL8pvX3d1uvExzVfCz7Rn6tW781Ub8K5MrDf2IMPyL0RTDiaLHC1JT",
                                "y", "Kpnrn8DkXUD3ge4mFxi-DKr0DYO2KuJdwNBrhzLRtfMa3WFMZBiPKUPfJj8dYNl_")),
                Arguments.of("did:key:z82Lkytz3HqpWiBmt2853ZgNgNG8qVoUJnyoMvGw6ZEBktGcwUVdKpUNJHct1wvp9pXjr7Y",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-384",
                                "x", "bKq-gg3sJmfkJGrLl93bsumOTX1NubBySttAV19y5ClWK3DxEmqPy0at5lLqBiiv",
                                "y", "PJQtdHnInU9SY3e8Nn9aOPoP51OFbs-FWJUsU0TGjRtZ4bnhoZXtS92wdzuAotL9")),
                // BLS12_381 G2
                Arguments.of(
                        "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Bls12381G2",
                                "x",
                                "tKWJu0SOY7onl4tEyOOH11XBriQN2JgzV-UmjgBMSsNkcAx3_l97SVYViSDBouTVBkBfrLh33C5icDD-4UEDxNO3Wn1ijMHvn2N63DU4pkezA3kGN81jGbwbrsMPpiOF")),
                Arguments.of(
                        "did:key:zUC7DWA2FazpvPXmiXeTWuLjdMGXXmmWXbwoKNo554L3E4PD5ZsoZPqzCvkFkkQGvWp6uLZ3PKQJMfXYzLGNoiMyqXYSQa19cvWTiH3QpzddfRVWW6FtFMWTcvUb7wg4o9khbDt",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Bls12381G2",
                                "x",
                                "pH-hch6qNUP2kongy1-r6VqPiHnPBcPN9CGqWXU2_LdfkfkhmEXmKFJwfXw7fRVaFAuLsX7K94WFtlxU-vrfP5KmgH9zxFphjzPQqds7WYSnSo4A3H0skSSc2TQMV3Cj")),
                // BLS12_381 G1
                Arguments.of("did:key:z3tEFS9q2WkwvvVvr1BrYwNreqcudmcCQGGRSQ8r73recEqAUHGeLPWzwK6toBdKJgX3Fs",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Bls12381G1",
                                "x", "lsfOFOAzlEpPIIKf-7vlvWiDYazg5M7VnAXblKuvB9GV66GeXw_UgoNhCZdixk_m")),
                // Secp256k1
                Arguments.of("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                        Map.of(
                                "kty", "EC",
                                "crv", "secp256k1",
                                "x", "h0wVx_2iDlOcblulc8E5iEw1EYh5n1RYtLQfeSTyNc0",
                                "y", "O2EATIGbu6DezKFptj5scAIRntgfecanVNXxat1rnwE")),
                // Ed25519
                Arguments.of("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Ed25519",
                                "x", "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik")),
                Arguments.of("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Ed25519",
                                "x", "TLWr9q15-_WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluik")),
                Arguments.of("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Ed25519",
                                "x", "lJZrfAjkBXdfjebMHEUI9usidAPhAlssitLXR3OYxbI")),
                Arguments.of("did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
                        Map.of(
                                "kty", "OKP",
                                "crv", "Ed25519",
                                "x", "Zmq-CJA17UpFeVmJ-nIKDuDEhUnoRSNIXFbxyBtCh6Y")));
    }

}
