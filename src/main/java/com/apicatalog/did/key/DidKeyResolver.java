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

    protected final MulticodecDecoder codecs;

    public DidKeyResolver(MulticodecDecoder codecs) {
        this.codecs = codecs;
    }

    @Override
    public ResolvedDocument resolve(final Did did, final Options options) {

        Objects.requireNonNull(did);
        
        if (!DidKey.isDidKey(did)) {
            throw new IllegalArgumentException();
        }

        final DidKey didKey = DidKey.of(did, codecs);

        //FIXME
//        return DidKeyDocument.of(
//                did,
//                DidKeyResolver.createMethod(didKey));
        return null;
    }

    public static VerificationMethod createMethod(final DidKey didKey) {

        Objects.requireNonNull(didKey);
        
        final DidUrl url = DidUrl.of(didKey, null, null, didKey.getMethodSpecificId());

        return ImmutableVerificationMethod.of(
                url,
                didKey.toString(),
                didKey);
    }
//
//    @Override
//    public boolean isAccepted(URI id) {
//        return DidKey.isDidKey(id);
//    }

}
