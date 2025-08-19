package com.apicatalog.did.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Collection;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.DidDocument;
import com.apicatalog.did.document.VerificationMethod;
import com.apicatalog.did.resolver.ResolvedDocument;
import com.apicatalog.multicodec.Multicodec.Tag;
import com.apicatalog.multicodec.MulticodecDecoder;

@DisplayName("DID Key -> Multikey")
class MultikeyResolverTest {

    static MulticodecDecoder CODECS = MulticodecDecoder.getInstance(Tag.Key);
    static DidKeyResolver RESOLVER = DidKeyResolver.with(CODECS);

    @DisplayName("resolve()")
    @ParameterizedTest(name = "{0}")
    @MethodSource({ "vectors" })
    void resolve(URI did) {

        final DidKey didKey = DidKey.of(did, CODECS);

        ResolvedDocument result = RESOLVER.resolve(didKey);
        assertNotNull(result);
        assertNull(result.metadata());
        assertNotNull(result.document());

        DidDocument document = result.document();
        assertNotNull(document);

        assertEquals(didKey, document.id());
        assertEquals(0, document.controller().size());

        assertMethod(document.assertion(), didKey);
        assertMethod(document.authentication(), didKey);
        assertMethod(document.capabilityDelegation(), didKey);
        assertMethod(document.capabilityInvocation(), didKey);
        assertMethod(document.verification(), didKey);

        assertEquals(0, document.alsoKnownAs().size());
        assertEquals(0, document.keyAgreement().size());
        assertEquals(0, document.service().size());

        assertTrue(document.hasRequiredProperties());
    }

    static void assertMethod(Collection<VerificationMethod> methods, DidKey didKey) {

        assertNotNull(methods);
        assertEquals(1, methods.size());

        VerificationMethod method = methods.iterator().next();

        assertNotNull(method);
        assertEquals(DidUrl.fragment(didKey, didKey.getMethodSpecificId()), method.id());
        assertEquals(DidKeyResolver.MULTIKEY_TYPE, method.type());
        assertEquals(didKey, method.controller());
        assertEquals(didKey.baseName(), method.publicKeyMultibase().baseName());
        assertArrayEquals(didKey.debased(), method.publicKeyMultibase().debased());
        assertNull(method.publicKeyJwk());
    }

    static Stream<Arguments> vectors() {
        return Stream.of(
                // P-256
                Arguments.of("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"),
                // P-384
                Arguments.of("did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"),
                // BLS12_381 G2
                Arguments.of("did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY"),
                // Secp256k1
                Arguments.of("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"),
                // Ed25519
                Arguments.of("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"));
    }

}
