package com.apicatalog.did.key;

import java.util.Objects;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.VerificationMethod;
import com.apicatalog.did.key.jwk.DidKeyJwkMethodProvider;
import com.apicatalog.did.primitive.ImmutableMultibaseMethod;
import com.apicatalog.did.resolver.DidResolver;
import com.apicatalog.did.resolver.ResolvedDocument;
import com.apicatalog.multicodec.MulticodecDecoder;

public class DidKeyResolver implements DidResolver {

    public static String MULTIKEY_TYPE = "https://w3id.org/security#Multikey";
    public static String JWK_2020_TYPE = "https://w3id.org/security#JsonWebKey2020";
    public static String JWK_TYPE = "https://w3id.org/security#JsonWebKey";
    
    protected final MulticodecDecoder codecs;

    protected String keyType;
    protected DidKeyMethodProvider methodProvider;
    protected boolean encryptionKeyDerivation;

    protected DidKeyResolver(final MulticodecDecoder codecs, String keyType, DidKeyMethodProvider methodProvider) {
        this.codecs = codecs;
        this.keyType = keyType;
        this.methodProvider = methodProvider;
        this.encryptionKeyDerivation = false;
    }

    public static DidKeyResolver multikey(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new DidKeyResolver(codecs, MULTIKEY_TYPE, DidKeyResolver::multikey);
    }
    
    public static DidKeyResolver jwk(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new DidKeyResolver(codecs, JWK_TYPE, new DidKeyJwkMethodProvider());
    }

    @Override
    public ResolvedDocument resolve(final Did did) {

        Objects.requireNonNull(did);

        if (encryptionKeyDerivation) {
            throw new UnsupportedOperationException();
        }

        final DidKey didKey = DidKey.of(did, codecs);

        return ResolvedDocument.immutable(
                DidKeyDocument.of(
                        did,
                        DidKeyResolver.createSignatureMethod(didKey, keyType, methodProvider)));
    }

    public static VerificationMethod multikey(final DidKey key, final DidUrl url, String type) {
        return ImmutableMultibaseMethod.of(
                url,
                type,
                key,
                key);
    }

    public static final VerificationMethod createSignatureMethod(final DidKey didKey, final String keyType, final DidKeyMethodProvider method) {

        Objects.requireNonNull(didKey);
        Objects.requireNonNull(keyType);
        Objects.requireNonNull(method);

        final DidUrl url = DidUrl.fragment(didKey, didKey.getMethodSpecificId());

        return method.get(didKey, url, keyType);
    }

    public boolean encryptionKeyDerivation() {
        return this.encryptionKeyDerivation;
    }

    public DidKeyResolver encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
        return this;
    }

    public String keyType() {
        return keyType;
    }

    public DidKeyResolver keyType(String keyType) {
        this.keyType = keyType;
        return this;
    }

    public DidKeyResolver methodProvider(DidKeyMethodProvider methodProvider) {
        this.methodProvider = methodProvider;
        return this;
    }
}
