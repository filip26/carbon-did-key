package com.apicatalog.did.key;

import java.util.Collections;
import java.util.Set;

import com.apicatalog.did.Did;
import com.apicatalog.did.document.DidDocument;
import com.apicatalog.did.document.DidVerificationMethod;

final class Document implements DidDocument {

    final Did id;
    final Set<DidVerificationMethod> method;

    Document(Did id, Set<DidVerificationMethod> method) {
        this.id = id;
        this.method = method;
    }

    public static Document of(Did id, DidVerificationMethod method) {
        return new Document(id, Collections.singleton(method));
    }

    @Override
    public Did id() {
        return id;
    }

    @Override
    public Set<DidVerificationMethod> verification() {
        return method;
    }
    
    @Override
    public Set<DidVerificationMethod> authentication() {
        return method;
    }
    
    @Override
    public Set<DidVerificationMethod> assertion() {
        return method;
    }
    
    @Override
    public Set<DidVerificationMethod> capabilityInvocation() {
        return method;
    }
    
    @Override
    public Set<DidVerificationMethod> capabilityDelegation() {
        return method;
    }
}
