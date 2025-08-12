package com.apicatalog.did.key;

import java.util.Objects;

import com.apicatalog.did.Did;
import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.VerificationMethod;
import com.apicatalog.did.primitive.ImmutableResolvedDocument;
import com.apicatalog.did.primitive.ImmutableVerificationMethod;
import com.apicatalog.did.resolver.DidResolver;
import com.apicatalog.did.resolver.ResolvedDocument;
import com.apicatalog.multicodec.MulticodecDecoder;

public class DidKeyResolver implements DidResolver {

    protected final MulticodecDecoder codecs;

    protected DidKeyResolver(MulticodecDecoder codecs) {        
        this.codecs = codecs;
    }
    
    public static DidKeyResolver with(MulticodecDecoder codecs) {
        Objects.requireNonNull(codecs);        
        return new DidKeyResolver(codecs);
    }

    @Override
    public ResolvedDocument resolve(final Did did, final Options options) {

        Objects.requireNonNull(did);

        final DidKey didKey = DidKey.of(did, codecs);

        return ResolvedDocument.immutable(
                DidKeyDocument.of(
                        did,
                        DidKeyResolver.createMethod(didKey)));
    }

    public static VerificationMethod createMethod(final DidKey didKey) {

        Objects.requireNonNull(didKey);

        final DidUrl url = DidUrl.fragment(didKey, didKey.getMethodSpecificId());

        return ImmutableVerificationMethod.of(
                url,
                "https://w3id.org/security#Multikey",
                didKey,
                didKey);
    }
}
