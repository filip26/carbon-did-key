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

    protected String keyFormat;
    protected boolean encryptionKeyDerivation;

    
    protected DidKeyResolver(final MulticodecDecoder codecs) {        
        this.codecs = codecs;
        this.keyFormat = MULTIKEY_TYPE;
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
                        DidKeyResolver.createSignatureMethod(didKey, keyFormat)));
    }

    public static VerificationMethod createSignatureMethod(final DidKey didKey, final String keyFormat) {

        Objects.requireNonNull(didKey);

        final DidUrl url = DidUrl.fragment(didKey, didKey.getMethodSpecificId());

        return ImmutableVerificationMethod.of(
                url,
                keyFormat,
                didKey,
                didKey);
    }

    public boolean encryptionKeyDerivation() {
        return this.encryptionKeyDerivation;
    }

    public void encryptionKeyDerivation(boolean encryptionKeyDerivation) {
        this.encryptionKeyDerivation = encryptionKeyDerivation;
    }

    public String keyFormat() {
        return keyFormat;
    }
    
    public void keyFormat(String keyFormat) {
        this.keyFormat = keyFormat;
    }
}
