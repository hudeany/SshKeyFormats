# SshKeyFormats

[![Maven Central](https://img.shields.io/maven-central/v/de.soderer/sshkeyformats)](https://central.sonatype.com/artifact/de.soderer/sshkeyformats)

A Java library for **reading, writing and converting SSH key files** in various OpenSSH, PuTTY, OpenSSL / PKCS#8 and PKCS#1 formats.

## Features

- **OpenSSH**: read and write OpenSSH version 1 key files
- **PuTTY**: support for PuTTY Private Key (PPK) format versions 2 and 3
- **OpenSSL / PKCS#8**: read and write PKCS#8 private keys
- **PKCS#1**: support for PKCS#1 key encoding
- **Password protection**: supported where provided by the respective key format
- **Key conversion**: convert keys between supported formats
- **Multiple encodings**: supports ISO-8859-1 and UTF-8 where required by the individual formats
- **RSA, DSA, ECDSA and EdDSA** key algorithms
- **Ed25519 and Ed448** support with Java 15 or newer

## Contents

- [Installation](#installation)
- [Supported formats](#supported-formats)
- [Supported algorithms](#supported-algorithms)
- [Basic usage](#basic-usage)
- [Reading a key](#reading-a-key)
- [Writing a key](#writing-a-key)
- [Converting between formats](#converting-between-formats)
- [Password-protected keys](#password-protected-keys)
- [Java version](#java-version)
- [Dependencies](#dependencies)
- [Main classes](#main-classes)

## Installation

The library is available on Maven Central. Replace `VERSION` with the version shown in the badge above.

**Maven**

```xml
<dependency>
	<groupId>de.soderer</groupId>
	<artifactId>sshkeyformats</artifactId>
	<version>VERSION</version>
</dependency>
```

**Gradle**

```groovy
implementation "de.soderer:sshkeyformats:VERSION"
```

**Without a build tool**

Download the JAR from the [GitHub releases](https://github.com/hudeany/sshkeyformats/releases).

## Supported formats

The library supports the following SSH key formats:

| Format | Read | Write | Password protection |
|---|:---:|:---:|:---:|
| OpenSSH version 1 | ✓ | ✓ | ✓ |
| PuTTY PPK version 2 | ✓ | ✓ | ✓ |
| PuTTY PPK version 3 | ✓ | ✓ | ✓ |
| OpenSSL / PKCS#8 | ✓ | ✓ | ✓ |
| PKCS#1 | ✓ | ✓ | — |

For OpenSSH and PKCS#8, the library supports the encodings required by PuTTY and `ssh-keygen`, including ISO-8859-1 and UTF-8.

## Supported algorithms

The following key algorithms are supported:

- **RSA**
- **DSA**
- **ECDSA**
  - nistp256
  - nistp384
  - nistp521
- **EdDSA**
  - Ed25519
  - Ed448

Ed25519 and Ed448 require **Java 15 or newer**.

## Basic usage

The main API consists of:

- `de.soderer.sshkeyformats.SshKeyReader`
- `de.soderer.sshkeyformats.SshKeyWriter`

A key can be read from an input stream and subsequently written in another supported format.

## Reading a key

Use `SshKeyReader` to read a key from an input stream:

```java
final SshKey sshKey = SshKeyReader.readKey(
	new FileInputStream("test.ppk"),
	"password".toCharArray()
);
```

The returned `SshKey` contains the key information and can be passed to the writer for conversion to another format.

For an unprotected key, the password can be omitted or supplied according to the respective reader API.

## Writing a key

The `SshKeyWriter` provides methods for writing keys in the supported formats.

For example, a PKCS#8 key can be written as follows:

```java
SshKeyWriter.writePKCS8Format(
	new FileOutputStream("test.pem"),
	sshKey,
	"password".toCharArray()
);
```

Similarly, PuTTY PPK files can be generated from a `KeyPair`:

```java
final KeyPairGenerator keyPairGenerator =
	KeyPairGenerator.getInstance("RSA");

keyPairGenerator.initialize(4096);

final KeyPair keyPair = keyPairGenerator.generateKeyPair();

final SshKey sshKey =
	new SshKey(SshKeyFormat.Putty2, "TestKey", keyPair);

SshKeyWriter.writePuttyVersion2Key(
	new FileOutputStream("test.ppk"),
	sshKey,
	"password".toCharArray()
);
```

## Converting between formats

Because the reader and writer operate on the common `SshKey` representation, keys can be converted between the supported formats.

For example, a PuTTY PPK key can be read and written as a PKCS#8 PEM key:

```java
final SshKey readSshKey = SshKeyReader.readKey(
	new FileInputStream("test.ppk"),
	"password".toCharArray()
);

SshKeyWriter.writePKCS8Format(
	new FileOutputStream("test.pem"),
	readSshKey,
	"password".toCharArray()
);
```

This makes `SshKeyFormats` useful not only as a reader and writer, but also as a **key format converter**.

## Password-protected keys

Password protection is supported for the formats that provide encrypted private-key storage.

For example:

```java
final char[] password = "password".toCharArray();

final SshKey sshKey = SshKeyReader.readKey(
	new FileInputStream("test.ppk"),
	password
);
```

The password is passed as a `char[]` rather than a `String`, allowing applications to clear the password from memory when it is no longer needed.

## Java version

The project is basically a **Java 11** project.

Support for **Ed25519** and **Ed448** requires **Java 15 or newer**, because these algorithms depend on cryptographic functionality available from that Java version onward.

## Dependencies

The project uses **Bouncy Castle** for functionality that is not provided directly by the Java runtime.

Bouncy Castle is used for:

- ECDSA key factory functionality
- Argon2 password derivation required by PuTTY PPK version 3

The project currently uses:

```text
org.bouncycastle:bcpkix-jdk18on
org.bouncycastle:bcprov-jdk18on
```

## Main classes

### `SshKeyReader`

`de.soderer.sshkeyformats.SshKeyReader`

Responsible for reading supported SSH key formats and creating the common `SshKey` representation.

### `SshKeyWriter`

`de.soderer.sshkeyformats.SshKeyWriter`

Responsible for writing an `SshKey` to one of the supported output formats.

## License

See the project repository for licensing information.

## Source code

The source code and further information are available on GitHub:

[github.com/hudeany/sshkeyformats](https://github.com/hudeany/sshkeyformats)
