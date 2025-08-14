package com.apicatalog.did.key;

import com.apicatalog.did.DidUrl;
import com.apicatalog.did.document.VerificationMethod;

@FunctionalInterface
public interface DidKeyMethodProvider {

    VerificationMethod get(final DidKey key, final DidUrl url, String type);
    
}
