package com.apicatalog.did.key.jwk;

import java.util.Map;

import com.apicatalog.did.key.DidKey;

@FunctionalInterface
public interface JwkProvider {

    Map<String, Object> get(DidKey key);

}
