package com.apicatalog.did.key;

import java.util.Objects;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.VerificationMethod;
import com.apicatalog.did.primitive.ImmutableVerificationMethod;
import com.apicatalog.did.resolver.DidResolver;
import com.apicatalog.did.resolver.ResolvedDocument;
import com.apicatalog.multicodec.MulticodecDecoder;

public class DidKeyResolver implements DidResolver {

    public static String MULTIKEY_TYPE = "https://w3id.org/security#Multikey";

    protected final MulticodecDecoder codecs;

    protected String keyType;
    protected DidKeyMethodProvider methodProvider;
    protected boolean encryptionKeyDerivation;

    protected DidKeyResolver(final MulticodecDecoder codecs) {
        this.codecs = codecs;
        this.keyType = MULTIKEY_TYPE;
        this.methodProvider = DidKeyResolver::multikey;
        this.encryptionKeyDerivation = false;
    }

    public static DidKeyResolver with(final MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);
        return new DidKeyResolver(codecs);
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
        return ImmutableVerificationMethod.of(
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

    public void encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
    }

    public String keyType() {
        return keyType;
    }

    public void keyType(String keyType) {
        this.keyType = keyType;
    }

    public void methodProvider(DidKeyMethodProvider methodProvider) {
        this.methodProvider = methodProvider;
    }
}
