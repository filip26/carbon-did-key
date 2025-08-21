# Carbon DID Key Method

An implementation of the [`did:key`](https://w3c-ccg.github.io/did-key-spec) method for static cryptographic keys in Java.

[![Java 8 CI](https://github.com/filip26/carbon-did-key/actions/workflows/java8-build.yml/badge.svg)](https://github.com/filip26/carbon-did-key/actions/workflows/java8-build.yml)
[![Maven Central](https://img.shields.io/maven-central/v/com.apicatalog/carbon-did-key.svg?label=Maven%20Central)](https://search.maven.org/artifact/com.apicatalog/carbon-did-key)
[![javadoc](https://javadoc.io/badge2/com.apicatalog/carbon-did-key/javadoc.svg)](https://javadoc.io/doc/com.apicatalog/carbon-did-key)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


## Features

- **DidKey API & Resolver** – work with `did:key` identifiers programmatically.
- **Verification Methods**
  - Multikey
  - JSON Web Key (JWK):
    - Ed25519
    - Bls12381G1, Bls12381G2
    - P-256 (secp256r1)
    - P-384 (secp384r1)
    - secp256k1

## Examples

```javascript

DidKeyResolver resolver = DidKeyResolver
    .with(codecs)
    .multikey()
    .build();

// Parse an existing `did:key`
var didKey = Did.of("did:key:z6MkvG5D...", ...);

var didDoc = resolver.resolve(didKey);

System.out.println(didDoc.document().id());
didDooc.document().verification().forEach(vm -> System.out.println(vm.id()));
```

## Installation

### Maven

```xml
<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>carbon-did-key</artifactId>
    <version>0.9.2</version>
</dependency>

```


## Contributing

All PR's welcome!


### Building

Fork and clone the project repository.

```bash
> cd carbon-did-key
> mvn clean package
```

## Resources

- [The did:key Method v0.7](https://w3c-ccg.github.io/did-key-spec)
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [Carbon DID Core](https://github.com/filip26/carbon-did-core)
- [Carbon Controlled Identifiers](https://github.com/filip26/carbon-cid)

## Sponsors

<a href="https://github.com/digitalbazaar">
  <img src="https://avatars.githubusercontent.com/u/167436?s=200&v=4" width="40" />
</a> 

## Commercial Support
Commercial support is available at filip26@gmail.com
  