package com.apicatalog.did.key;

import com.apicatalog.did.document.DidVerificationMethod;

@FunctionalInterface
public interface VerificationMethodProvider {

    DidVerificationMethod get(final DidKey key, String type);
    
}
