# SshKeyFormats (Reader & Writer and therefore also Converter)

Supported SSH key formats:
- OpenSSH version 1 (with optional password protection, in ISO-8859-1 (for PuTTY) and UTF-8 (for ssh-keygen))
- PuTTY key format version 2 (with optional password protection)
- PuTTY key format version 3 (with optional password protection)
- OpenSSL / PKCS#8 (with optional password protection, in ISO-8859-1 (for PuTTY) and UTF-8 (for ssh-keygen))
- PKCS#1

Supported SSH algorithms:
- RSA
- DSA
- EcDSA (nistp256, nistp384, nistp521)
- EdDSA (Ed25519, Ed448, only with JAVA 15+)

Main classes:
- de.soderer.sshkeyformats.SshKeyReader
- de.soderer.sshkeyformats.SshKeyWriter

This is basically a JAVA 11 project, but it needs JAVA 15 for support of Ed25519 and Ed448 cipher algorithms.

This project depends on BouncyCastle for following reasons:
- EcDSA Keyfactory
- Putty key version 3 "Argon2" password deriving hashing algorithm

Used BouncyCastle libs:
- bcpkix-jdk15on-1.69.jar
- bcprov-jdk15on-1.69.jar

Example code for putty key (ppk) generation and conversion to PKCS#8 (pem)

	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(4096);
	KeyPair keyPair = keyPairGenerator.generateKeyPair();
	SshKey sshKey = new SshKey(SshKeyFormat.Putty2, "TestKey (ÄÖÜäöüß)", keyPair);
	SshKeyWriter.writePuttyVersion2Key(new FileOutputStream("test.ppk"), sshKey, "password".toCharArray());
	SshKey readSshKey = SshKeyReader.readKey(new FileInputStream("test.ppk"), "passwörd".toCharArray());
	SshKeyWriter.writePuttyVersion2Key(new FileOutputStream("test.pem"), readSshKey, "password".toCharArray());
