# SshKeyFormats

Supported SSH key formats:
- OpenSSH version 1 (with optional password protection)
- PuTTY key format version 2 (with optional password protection)
- PuTTY key format version 3 (with optional password protection)
- OpenSSL / PKCS#8 (with optional password protection)
- PKCS#1

Main classes:
- de.soderer.sshkeyformats.SshKeyReader
- de.soderer.sshkeyformats.SshKeyWriter

This project depends on BouncyCastle for following reasons:
- EcDSA Keyfactory
- Putty key version 3 Argon3 password deriving hashing algorithm

Used BouncyCastle libs:
- bcpkix-jdk15on-1.69.jar
- bcprov-jdk15on-1.69.jar
