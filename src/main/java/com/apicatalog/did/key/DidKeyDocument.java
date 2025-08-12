package com.apicatalog.did.key;

import java.util.Collections;
import java.util.Set;

import com.apicatalog.did.Did;
import com.apicatalog.did.document.DidDocument;
import com.apicatalog.did.document.VerificationMethod;

class DidKeyDocument implements DidDocument {

    protected final Did id;
//    protected final Collection<Did> controller;
    protected final Set<VerificationMethod> method;

    protected DidKeyDocument(Did id, Set<VerificationMethod> method) {
        this.id = id;
        this.method = method;
    }

    public static DidKeyDocument of(Did id, VerificationMethod method) {
        return new DidKeyDocument(id, Collections.singleton(method));
    }

    @Override
    public Did id() {
        return id;
    }

    @Override
    public Set<VerificationMethod> verification() {
        return method;
    }
}
