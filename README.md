# SshKeyFormats

[![Maven Central](https://img.shields.io/maven-central/v/de.soderer/sshkeyformats)](https://central.sonatype.com/artifact/de.soderer/sshkeyformats)

A Java library for **reading, writing and converting SSH key files** in the formats of OpenSSH, PuTTY and OpenSSL, including OpenSSH `authorized_keys` files.

## Features

- **OpenSSH**: read and write private keys in the OpenSSH v1 format (`-----BEGIN OPENSSH PRIVATE KEY-----`) and public keys
- **authorized_keys**: parse and create `authorized_keys` lines including all OpenSSH options (`command`, `from`, `restrict`, `no-pty`, ...)
- **PuTTY**: read and write PuTTY private key files (PPK) version 2 and 3
- **OpenSSL**: read and write traditional PEM keys (`RSA/DSA/EC PRIVATE KEY`), read PKCS#8 keys (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`) as written by OpenSSL 3
- **Public key formats**: OpenSSH public keys, RFC 4716 (`---- BEGIN SSH2 PUBLIC KEY ----`), X.509 (`PUBLIC KEY`) and PKCS#1 (`RSA PUBLIC KEY`)
- **Password protection**: supported for all private key formats that provide encryption
- **Key conversion**: convert keys between the supported formats
- **Fingerprints**: MD5, SHA-256, SHA-384 and SHA-512 fingerprints, hex or Base64 encoded
- **Key generation**: helper methods for creating new key pairs
- **RSA, DSA, ECDSA, Ed25519 and Ed448** key algorithms
- **Robust against malicious input**: sizes and key derivation work factors of read key files are limited

## Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Supported formats](#supported-formats)
- [Supported algorithms](#supported-algorithms)
- [Reading a key](#reading-a-key)
- [Writing a key](#writing-a-key)
- [Converting between formats](#converting-between-formats)
- [Public keys and authorized_keys](#public-keys-and-authorized_keys)
- [Fingerprints](#fingerprints)
- [Password-protected keys](#password-protected-keys)
- [Security notes](#security-notes)
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

Download the JAR from the [GitHub releases](https://github.com/hudeany/sshkeyformats/releases) and add the Bouncy Castle libraries (see [Dependencies](#dependencies)) to the classpath.

## Requirements

**Java 17** or newer.

## Supported formats

### Private keys

| Format | PEM type / file header | Read | Write | Encryption |
|---|---|:---:|:---:|---|
| OpenSSH v1 | `OPENSSH PRIVATE KEY` | ✓ | ✓ | bcrypt KDF + AES (read: aes128/192/256-ctr and -cbc, write: aes256-ctr) |
| PuTTY PPK version 3 | `PuTTY-User-Key-File-3` | ✓ | ✓ | Argon2 + AES-256-CBC |
| PuTTY PPK version 2 | `PuTTY-User-Key-File-2` | ✓ | ✓ | SHA-1 + AES-256-CBC |
| OpenSSL traditional | `RSA PRIVATE KEY`, `DSA PRIVATE KEY`, `EC PRIVATE KEY` | ✓ | ✓ | legacy PEM encryption (`DEK-Info`): AES-128/192/256-CBC, DES-EDE3-CBC |
| PKCS#8 | `PRIVATE KEY` | ✓ | ✓ (Ed25519 / Ed448 only) | — |
| PKCS#8 encrypted | `ENCRYPTED PRIVATE KEY` | ✓ | — | PBES2 with PBKDF2 + AES-CBC or DES-EDE3-CBC |

`SshKeyWriter.writePKCS8Format` writes RSA, DSA and ECDSA keys in the traditional OpenSSL format and Ed25519 / Ed448 keys as PKCS#8, because there is no traditional format for EdDSA keys.

Not supported: encrypted PKCS#8 keys using scrypt, OpenSSH v1 keys encrypted with aes-gcm or chacha20-poly1305, OpenSSH certificates and FIDO keys (`sk-*`).

### Public keys

| Format | Example | Read | Write |
|---|---|:---:|:---:|
| OpenSSH public key / authorized_keys line | `ssh-ed25519 AAAA... comment` | ✓ | ✓ |
| RFC 4716 | `---- BEGIN SSH2 PUBLIC KEY ----` | ✓ | ✓ |
| X.509 SubjectPublicKeyInfo | `-----BEGIN PUBLIC KEY-----` | ✓ | — |
| PKCS#1 | `-----BEGIN RSA PUBLIC KEY-----` | ✓ | — |

The reader detects the format automatically. Public key data is also read from all private key formats which store it unencrypted.

## Supported algorithms

| Algorithm | SSH key type |
|---|---|
| RSA | `ssh-rsa` |
| DSA | `ssh-dss` |
| ECDSA nistp256 | `ecdsa-sha2-nistp256` |
| ECDSA nistp384 | `ecdsa-sha2-nistp384` |
| ECDSA nistp521 | `ecdsa-sha2-nistp521` |
| Ed25519 | `ssh-ed25519` |
| Ed448 | `ssh-ed448` |

DSA keys are supported for reading and converting existing keys. Current OpenSSH versions do not accept DSA keys anymore.

## Reading a key

`SshKeyReader.readKey` reads the first key of an input stream. The format is detected automatically. For unencrypted keys pass `null` as password.

```java
final SshKey sshKey;
try (InputStream inputStream = new FileInputStream("id_ed25519")) {
	sshKey = SshKeyReader.readKey(inputStream, "password".toCharArray());
}

System.out.println(sshKey.getFormat());      // e.g. OpenSSHv1
System.out.println(sshKey.getAlgorithm());   // e.g. ED25519
System.out.println(sshKey.getKeyStrength()); // e.g. 256
System.out.println(sshKey.getComment());
```

The returned `SshKey` contains the `java.security.KeyPair` (`sshKey.getKeyPair()`), which can be used directly with the Java cryptography APIs.

## Writing a key

`SshKeyWriter` writes keys in the supported formats. A password of `null` or an empty password writes an unencrypted key.

Create a new key pair and write it in the OpenSSH format like `ssh-keygen` does:

```java
final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
final SshKey sshKey = new SshKey(SshKeyFormat.OpenSSHv1, "user@host", keyPair);

try (OutputStream outputStream = new FileOutputStream("id_ed25519")) {
	SshKeyWriter.writeOpenSshv1Key(outputStream, sshKey, "password".toCharArray(), null);
}

try (OutputStream outputStream = new FileOutputStream("id_ed25519.pub")) {
	outputStream.write((sshKey.encodePublicKeyForAuthorizedKeys() + " " + sshKey.getComment() + "\n").getBytes(StandardCharsets.UTF_8));
}
```

The writer methods:

| Method | Output |
|---|---|
| `writeOpenSshv1Key(outputStream, sshKey, password, passwordAndCommentEncoding)` | OpenSSH v1 private key |
| `writePuttyVersion3Key(outputStream, sshKey, password)` | PuTTY PPK version 3 |
| `writePuttyVersion2Key(outputStream, sshKey, password)` | PuTTY PPK version 2 |
| `writePKCS8Format(outputStream, keyPair, password, passwordEncoding)` | OpenSSL traditional PEM (Ed25519 / Ed448: PKCS#8), encrypted with AES-128-CBC |
| `writePKCS8Format(outputStream, keyPair, cipherName, password, passwordEncoding)` | as above with cipher `AES-128-CBC`, `AES-192-CBC`, `AES-256-CBC` or `DES-EDE3-CBC` |
| `writeDerFormat(outputStream, keyPair)` | unencrypted binary DER |
| `writePKCS1Format(outputStream, publicKey)` | RFC 4716 public key (`---- BEGIN SSH2 PUBLIC KEY ----`) |

The encoding parameters default to UTF-8 when `null` is passed.

## Converting between formats

Because reader and writer operate on the common `SshKey` representation, keys can be converted between all supported formats.

For example, convert an OpenSSH key to a PuTTY key:

```java
final char[] password = "password".toCharArray();

final SshKey sshKey;
try (InputStream inputStream = new FileInputStream("id_ed25519")) {
	sshKey = SshKeyReader.readKey(inputStream, password);
}

try (OutputStream outputStream = new FileOutputStream("id_ed25519.ppk")) {
	SshKeyWriter.writePuttyVersion3Key(outputStream, sshKey, password);
}
```

Or write a key in the OpenSSL PEM format with AES-256 encryption:

```java
try (OutputStream outputStream = new FileOutputStream("key.pem")) {
	SshKeyWriter.writePKCS8Format(outputStream, sshKey.getKeyPair(), "AES-256-CBC", password, null);
}
```

## Public keys and authorized_keys

`SshKeyReader.readAllPublicKeys` reads all public keys of an input stream, for example an `authorized_keys` file or a file with several public keys. Empty lines and comment lines (`#`) are skipped. Private keys contribute their public key, if it is stored unencrypted. No password is needed.

```java
final List<SshKey> publicKeys;
try (InputStream inputStream = new FileInputStream(System.getProperty("user.home") + "/.ssh/authorized_keys")) {
	publicKeys = SshKeyReader.readAllPublicKeys(inputStream);
}

for (final SshKey publicKey : publicKeys) {
	System.out.println(publicKey.getAlgorithm() + " " + publicKey.getSha256FingerprintBase64() + " " + publicKey.getComment());
	if (publicKey instanceof AuthorizedKey) {
		final AuthorizedKey authorizedKey = (AuthorizedKey) publicKey;
		System.out.println("  command: " + authorizedKey.getCommand() + ", no-pty: " + authorizedKey.isNoPty());
	}
}
```

Lines of `authorized_keys` files are returned as `AuthorizedKey`, which provides all options of the OpenSSH syntax as specified in `sshd(8)`: options are separated by commas, values are enclosed in double quotes. Unknown options are rejected, like `sshd` does.

An `authorized_keys` line can also be created or modified:

```java
final AuthorizedKey authorizedKey = AuthorizedKeyLineParser.parseAuthorizedKeyLine("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX deploy key")
	.withRestrict(true)
	.withCommand("/usr/local/bin/deploy")
	.withFromList("10.0.0.0/8");
authorizedKey.setEnvironmentValue("DEPLOY_ENV", "production");

System.out.println(authorizedKey.toAuthorizedKeysLine());
// restrict,command="/usr/local/bin/deploy",environment="DEPLOY_ENV=production",from="10.0.0.0/8" ssh-ed25519 AAAA... deploy key
```

Use `toAuthorizedKeysLine()` to write `authorized_keys` files. `toString()` only returns key type, key data and comment without the options.

`environment` options only take effect, if `PermitUserEnvironment` is enabled in the `sshd_config` of the server.

## Fingerprints

```java
sshKey.getSha256FingerprintBase64(); // like "ssh-keygen -l" without the "SHA256:" prefix, but with Base64 padding
sshKey.getSha256Fingerprint();       // hex, colon separated
sshKey.getMd5Fingerprint();          // hex, colon separated, upper case
```

SHA-384 and SHA-512 fingerprints are also available. `KeyPairUtilities` provides the same methods for `KeyPair` and `PublicKey` objects, including SHA-1 fingerprints.

## Password-protected keys

Passwords are passed as `char[]` instead of `String`, so that applications can clear them from memory after use. The library works on internal copies and clears them after use.

A missing or wrong password is reported by `de.soderer.sshkeyformats.data.WrongPasswordException`:

```java
try (InputStream inputStream = new FileInputStream("id_ed25519")) {
	sshKey = SshKeyReader.readKey(inputStream, password);
} catch (final WrongPasswordException e) {
	// ask the user for the password again
}
```

**Password encoding:** `ssh-keygen` and OpenSSL encode passwords in UTF-8, PuTTY on Windows uses ISO-8859-1 (Windows codepage). When reading, the library tries both encodings, so keys of both tools can be read with passwords containing special characters. When writing, the encoding can be chosen for OpenSSH and OpenSSL keys. PuTTY keys are always written with ISO-8859-1 password encoding.

## Security notes

- **Prefer OpenSSH v1 or PuTTY PPK version 3 for new encrypted keys.** These formats use the work factor based key derivation functions bcrypt and Argon2.
- The legacy PEM encryption of traditional OpenSSL keys (`DEK-Info`) derives the key with a single MD5 round and is weak against brute force attacks. It is supported for compatibility only.
- PuTTY PPK version 2 uses a single SHA-1 round for key derivation. Prefer version 3.
- The reader is designed to process untrusted input: line lengths, data sizes, the number of headers and the work factors of key derivation functions (bcrypt rounds, PBKDF2 iterations, Argon2 memory and passes) are limited, so that malicious key files cannot exhaust memory or CPU. Key files exceeding these limits are rejected with an exception.
- `readAllPublicKeys` returns all keys of the input. Limit the size of the input stream, if it comes from an untrusted source.

## Dependencies

The project uses **Bouncy Castle** for functionality that is not provided by the Java runtime:

- ECDSA key handling and point validation
- Argon2 key derivation for PuTTY PPK version 3
- Derivation of Ed25519 / Ed448 public keys from PKCS#8 private keys

```text
org.bouncycastle:bcprov-jdk18on
org.bouncycastle:bcpkix-jdk18on
```

## Main classes

| Class | Purpose |
|---|---|
| `de.soderer.sshkeyformats.SshKeyReader` | Reads keys of all supported formats into `SshKey` objects |
| `de.soderer.sshkeyformats.SshKeyWriter` | Writes `SshKey` / `KeyPair` objects in the supported formats |
| `de.soderer.sshkeyformats.SshKey` | Common key representation: format, comment, `KeyPair`, fingerprints |
| `de.soderer.sshkeyformats.AuthorizedKey` | `SshKey` with the options of an `authorized_keys` line |
| `de.soderer.sshkeyformats.data.AuthorizedKeyLineParser` | Parser for single `authorized_keys` lines |
| `de.soderer.sshkeyformats.data.KeyPairUtilities` | Key generation, fingerprints, key algorithm and strength detection |
| `de.soderer.sshkeyformats.data.WrongPasswordException` | Signals a missing or wrong password |

## License

See [LICENSE.txt](LICENSE.txt).

## Source code

The source code and further information are available on GitHub:

[github.com/hudeany/sshkeyformats](https://github.com/hudeany/sshkeyformats)
