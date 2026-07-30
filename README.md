# 🔐 Carbon DID Key Method

The [`did:key`](https://w3c-ccg.github.io/did-key-spec) method represents static cryptographic keys as Decentralized Identifiers (DIDs).

`did:key` is self-contained. The identifier encodes the public key material required to verify signatures or perform encryption without relying on any external registry or multi-party resolution process.  

`did:key` is suited for portable and lightweight use cases such as verifiable credentials, decentralized identifiers (DIDs), and other decentralized or domain-specific deployments that operate without blockchains or centralized registries.
 
It can also be used for testing and local development where a simple, self-contained DID method is required.

[![Java 25 CI](https://github.com/filip26/carbon-did-key/actions/workflows/java25-build.yml/badge.svg)](https://github.com/filip26/carbon-did-key/actions/workflows/java25-build.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/7f783f2e5d0b4fc6a08094d312a58309)](https://app.codacy.com/gh/filip26/carbon-did-key/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![javadoc](https://javadoc.io/badge2/com.apicatalog/carbon-did-key/javadoc.svg)](https://javadoc.io/doc/com.apicatalog/carbon-did-key)
[![Maven Central](https://img.shields.io/maven-central/v/com.apicatalog/carbon-did-key.svg?label=Maven%20Central)](https://mvnrepository.com/artifact/com.apicatalog/carbon-did-key)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## ✨ Features

- Deliberate engineering; zero vibe coding.
- Modular, fully configurable, and extensible.
- Zero third-party dependencies, `did-core` only.

## 📦 Installation

```xml
<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>carbon-did-key</artifactId>
    <version>${didkey.version}</version>
</dependency>

```

## 🤝 Contributing

Contributions of all kinds are welcome - whether it’s code, documentation, testing, or community support! Please open PR or issue to get started.

## 📚 Resources

- [The did:key Method v0.9](https://w3c-ccg.github.io/did-key-spec)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)

## 💼 Commercial Support

Commercial support and consulting are available.
For inquiries, please contact: filip26@gmail.com

