package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.data.Asn1Codec;
import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;
import de.soderer.sshkeyformats.data.CryptographicUtilities;
import de.soderer.sshkeyformats.data.KeyPairUtilities;
import de.soderer.sshkeyformats.data.OID;
import de.soderer.sshkeyformats.data.Password;
import de.soderer.sshkeyformats.data.WrongPasswordException;

/**
 * Regression tests for bugs found in the review of the SshKeyFormats library.
 */
@SuppressWarnings("static-method")
public class SshKeyRegressionTest {
	private static final char[] TESTPASSWORD = "pÄsswOrd".toCharArray();
	private static final String RESOURCE_DIR = "sshkey/OpenSSL3/";

	@Test
	public void testPasswordCloseClearsAllEncodings() {
		try (final Password password = new Password("geheim".toCharArray())) {
			final byte[] utfBytes = password.getPasswordBytesUtfEncoded();
			final byte[] isoBytes = password.getPasswordBytesIsoEncoded();
			password.close();
			for (final byte nextByte : utfBytes) {
				assertEquals(0, nextByte);
			}
			for (final byte nextByte : isoBytes) {
				assertEquals(0, nextByte);
			}
		}
	}

	@Test
	public void testDerTagLargerThanReadBuffer() throws Exception {
		final byte[] content = new byte[20000];
		content[19999] = 42;
		final DerTag derTag = Asn1Codec.readDerTag(Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OCTET_STRING, content));
		assertEquals(20000, derTag.getData().length);
		assertEquals(42, derTag.getData()[19999]);
	}

	@Test
	public void testDerTagInvalidLengths() {
		// Length larger than available data
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x30, (byte) 0x82, 0x10, 0x00, 0x01 }));
		// Length encoding with more than 4 bytes (would overflow int)
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x30, (byte) 0x85, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }));
		// Empty data
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[0]));
	}

	@Test
	public void testOidConstantsAreImmutable() {
		final byte[] encoding = OID.ECDSA_CURVE_NISTP256.getByteArrayEncoding();
		final byte[] original = encoding.clone();
		encoding[0] = 0;
		assertTrue(OID.ECDSA_CURVE_NISTP256.matches(original));
		assertEquals("1.2.840.10045.3.1.7", OID.ECDSA_CURVE_NISTP256.getStringEncoding());
	}

	@Test
	public void testEcOpenSslKeyWithHighBitScalar() throws Exception {
		for (final String fileName : new String[] {
				"Testkey_ECDSA_nistp256_HighBitScalar_Private_OpenSSL_no_password_(797FA87A8238637E2DE4B046D417AE0B).pem",
				"Testkey_ECDSA_nistp256_HighBitScalar_Private_PKCS#8_no_password_(797FA87A8238637E2DE4B046D417AE0B).pem" }) {
			final SshKey sshKey = readResource(fileName, null);
			assertTrue(((ECPrivateKey) sshKey.getKeyPair().getPrivate()).getS().signum() > 0, fileName);
			assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic()), fileName);
		}
	}

	@Test
	public void testEcWriterUsesFixedLengthUnsignedScalar() throws Exception {
		// Find a key with high bit set in the private scalar, which was written with a leading zero byte before
		KeyPair keyPair;
		do {
			keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");
		} while (((ECPrivateKey) keyPair.getPrivate()).getS().bitLength() != 256);

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writeDerFormat(output, keyPair);
		final List<DerTag> derTags = Asn1Codec.readDerTags(Asn1Codec.readDerTag(output.toByteArray()).getData());
		assertEquals(32, derTags.get(1).getData().length);

		final ByteArrayOutputStream pemOutput = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(pemOutput, keyPair, null, null);
		final SshKey readKey = SshKeyReader.readKey(new ByteArrayInputStream(pemOutput.toByteArray()), null);
		assertEquals(((ECPrivateKey) keyPair.getPrivate()).getS(), ((ECPrivateKey) readKey.getKeyPair().getPrivate()).getS());
		assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readKey.getKeyPair().getPrivate(), readKey.getKeyPair().getPublic()));
	}

	@Test
	public void testCorruptUnencryptedOpenSshv1KeyIsNoWrongPassword() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(output, new SshKey(SshKeyFormat.OpenSSHv1, "comment", keyPair), null, null);

		final byte[] keyData = decodePem(output.toString(StandardCharsets.UTF_8));
		// Corrupt the padding at the end of the private key section
		keyData[keyData.length - 1] ^= 0x55;
		final byte[] corruptPem = toPem("OPENSSH PRIVATE KEY", keyData);

		final Exception exception = assertThrows(Exception.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(corruptPem), null));
		assertFalse(exception instanceof WrongPasswordException, "Corrupt unencrypted key must not be reported as wrong password");
	}

	@Test
	public void testOpenSshv1BcryptRoundsLimit() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(output, new SshKey(SshKeyFormat.OpenSSHv1, "comment", keyPair), TESTPASSWORD, null);

		final byte[] keyData = decodePem(output.toString(StandardCharsets.UTF_8));
		// "openssh-key-v1\0" (15) + string "aes256-ctr" (14) + string "bcrypt" (10) + kdf info length (4) + string salt (20) = offset of rounds
		final int roundsOffset = 15 + 14 + 10 + 4 + 20;
		assertEquals(16, new BigInteger(1, java.util.Arrays.copyOfRange(keyData, roundsOffset, roundsOffset + 4)).intValue());
		keyData[roundsOffset] = 0x7F;
		final byte[] maliciousPem = toPem("OPENSSH PRIVATE KEY", keyData);

		final long start = System.currentTimeMillis();
		final Exception exception = assertThrows(Exception.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(maliciousPem), TESTPASSWORD));
		assertTrue(exception.getMessage().contains("kdfRounds"), exception.getMessage());
		assertTrue(System.currentTimeMillis() - start < 5000);
	}

	@Test
	public void testPuttyArgon2ParameterLimits() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion3Key(output, new SshKey(SshKeyFormat.Putty3, "comment", keyPair), TESTPASSWORD);
		final String keyText = output.toString(StandardCharsets.ISO_8859_1);

		for (final String maliciousKeyText : new String[] {
				keyText.replace("Argon2-Memory: 8192", "Argon2-Memory: 2147483647"),
				keyText.replace("Argon2-Passes: 21", "Argon2-Passes: 2000000000"),
				keyText.replace("Argon2-Parallelism: 1", "Argon2-Parallelism: 100000"),
				keyText.replace("Argon2-Memory: 8192", "Argon2-Memory: abc") }) {
			final Exception exception = assertThrows(Exception.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(maliciousKeyText.getBytes(StandardCharsets.ISO_8859_1)), TESTPASSWORD));
			assertTrue(exception.getMessage().contains("Argon2"), exception.getMessage());
		}
	}

	@Test
	public void testPuttyKeysWithoutComment() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);
		for (final char[] password : new char[][] { null, TESTPASSWORD }) {
			final ByteArrayOutputStream outputV2 = new ByteArrayOutputStream();
			SshKeyWriter.writePuttyVersion2Key(outputV2, new SshKey(SshKeyFormat.Putty2, null, keyPair), password);
			assertFalse(outputV2.toString(StandardCharsets.ISO_8859_1).contains("Comment: null"));
			final SshKey readV2 = SshKeyReader.readKey(new ByteArrayInputStream(outputV2.toByteArray()), password);
			assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readV2.getKeyPair().getPrivate(), readV2.getKeyPair().getPublic()));

			final ByteArrayOutputStream outputV3 = new ByteArrayOutputStream();
			SshKeyWriter.writePuttyVersion3Key(outputV3, new SshKey(SshKeyFormat.Putty3, null, keyPair), password);
			final SshKey readV3 = SshKeyReader.readKey(new ByteArrayInputStream(outputV3.toByteArray()), password);
			assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readV3.getKeyPair().getPrivate(), readV3.getKeyPair().getPublic()));
		}
	}

	@Test
	public void testPuttyCommentWithLinebreakIsRejected() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		assertThrows(IllegalArgumentException.class, () -> SshKeyWriter.writePuttyVersion2Key(new ByteArrayOutputStream(), new SshKey(SshKeyFormat.Putty2, "a\nPrivate-MAC: x", keyPair), null));
	}

	@Test
	public void testEmptyPasswordWritesUnencryptedKeys() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final SshKey sshKey = new SshKey(SshKeyFormat.Putty2, "comment", keyPair);

		final ByteArrayOutputStream outputV2 = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion2Key(outputV2, sshKey, new char[0]);
		assertNotNull(SshKeyReader.readKey(new ByteArrayInputStream(outputV2.toByteArray()), null).getKeyPair().getPrivate());

		final ByteArrayOutputStream outputV3 = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion3Key(outputV3, sshKey, new char[0]);
		assertNotNull(SshKeyReader.readKey(new ByteArrayInputStream(outputV3.toByteArray()), null).getKeyPair().getPrivate());

		final ByteArrayOutputStream outputOpenSsh = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(outputOpenSsh, sshKey, new char[0], null);
		assertNotNull(SshKeyReader.readKey(new ByteArrayInputStream(outputOpenSsh.toByteArray()), null).getKeyPair().getPrivate());
	}

	@Test
	public void testOpenSshv1CommentEncodings() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		for (final java.nio.charset.Charset charset : new java.nio.charset.Charset[] { StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1 }) {
			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			SshKeyWriter.writeOpenSshv1Key(output, new SshKey(SshKeyFormat.OpenSSHv1, "Schlüssel", keyPair), null, charset);
			assertEquals("Schlüssel", SshKeyReader.readKey(new ByteArrayInputStream(output.toByteArray()), null).getComment(), charset.name());
		}
	}

	@Test
	public void testKeyStrength() throws Exception {
		assertEquals(256, new SshKey(null, null, KeyPairUtilities.createEd25519CurveKeyPair()).getKeyStrength());
		assertEquals(448, new SshKey(null, null, KeyPairUtilities.createEd448CurveKeyPair()).getKeyStrength());
		assertEquals(1024, new SshKey(null, null, KeyPairUtilities.createDsaKeyPair()).getKeyStrength());
		final KeyPair rsaKeyPair = KeyPairUtilities.createRsaKeyPair(2048);
		assertEquals(2048, new SshKey(null, null, new KeyPair(null, rsaKeyPair.getPrivate())).getKeyStrength());
	}

	@Test
	public void testReadAllPublicKeysContinuesAfterPrivateKeys() throws Exception {
		final KeyPair edKeyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final KeyPair rsaKeyPair = KeyPairUtilities.createRsaKeyPair(2048);

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		// Unencrypted private key: its public key is returned
		SshKeyWriter.writePKCS8Format(output, rsaKeyPair, null, null);
		// Encrypted private key without public key data: skipped
		SshKeyWriter.writePKCS8Format(output, KeyPairUtilities.createRsaKeyPair(2048), TESTPASSWORD, null);
		output.write("\n".getBytes(StandardCharsets.UTF_8));
		output.write((KeyPairUtilities.encodePublicKeyForAuthorizedKeys(edKeyPair) + " comment\n").getBytes(StandardCharsets.UTF_8));
		// PuTTY key: must not swallow the following key
		SshKeyWriter.writePuttyVersion2Key(output, new SshKey(SshKeyFormat.Putty2, "putty", edKeyPair), null);
		output.write((KeyPairUtilities.encodePublicKeyForAuthorizedKeys(rsaKeyPair) + "\n").getBytes(StandardCharsets.UTF_8));

		final List<SshKey> publicKeys = SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(output.toByteArray()));
		assertEquals(4, publicKeys.size());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(rsaKeyPair), publicKeys.get(0).getMd5Fingerprint());
		assertNull(publicKeys.get(0).getKeyPair().getPrivate());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(edKeyPair), publicKeys.get(1).getMd5Fingerprint());
		assertEquals("putty", publicKeys.get(2).getComment());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(rsaKeyPair), publicKeys.get(3).getMd5Fingerprint());
	}

	@Test
	public void testWrongPasswordIsReportedAsWrongPasswordException() throws Exception {
		final char[] wrongPassword = "falsch".toCharArray();
		for (final String fileName : new String[] {
				"Testkey_RSA_Private_OpenSSL-AES256_p#U00c4sswOrd_(324783DFE578C076EFAA9C0649C62188).pem",
				"Testkey_RSA_Private_PKCS#8-PBES2-AES256_p#U00c4sswOrd_(324783DFE578C076EFAA9C0649C62188).pem",
				"Testkey_ECDSA_nistp256_HighBitScalar_Private_OpenSSL-AES192_p#U00c4sswOrd_(797FA87A8238637E2DE4B046D417AE0B).pem" }) {
			assertThrows(WrongPasswordException.class, () -> readResource(fileName, wrongPassword));
			assertThrows(WrongPasswordException.class, () -> readResource(fileName, null));
		}

		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final ByteArrayOutputStream openSshOutput = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(openSshOutput, new SshKey(SshKeyFormat.OpenSSHv1, "comment", keyPair), TESTPASSWORD, null);
		assertThrows(WrongPasswordException.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(openSshOutput.toByteArray()), wrongPassword));

		final ByteArrayOutputStream puttyOutput = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion3Key(puttyOutput, new SshKey(SshKeyFormat.Putty3, "comment", keyPair), TESTPASSWORD);
		assertThrows(WrongPasswordException.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(puttyOutput.toByteArray()), wrongPassword));
	}

	@Test
	public void testLegacyPemEncryptionCiphers() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");
		for (final String cipherName : new String[] { "DES-EDE3-CBC", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC" }) {
			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			SshKeyWriter.writePKCS8Format(output, keyPair, cipherName, TESTPASSWORD, null);
			assertTrue(output.toString(StandardCharsets.UTF_8).contains("DEK-Info: " + cipherName + ","));
			final SshKey readKey = SshKeyReader.readKey(new ByteArrayInputStream(output.toByteArray()), TESTPASSWORD);
			assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), readKey.getMd5Fingerprint(), cipherName);
		}
	}

	@Test
	public void testSsh2PublicKeyComment() throws Exception {
		final String keyText = "---- BEGIN SSH2 PUBLIC KEY ----\r\n"
				+ "Comment: \"Testkey with a very long comment, which is continued on the next \\\r\n"
				+ "line\"\r\n"
				+ "AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX\r\n"
				+ "---- END SSH2 PUBLIC KEY ----\r\n";
		final SshKey sshKey = SshKeyReader.readKey(new ByteArrayInputStream(keyText.getBytes(StandardCharsets.ISO_8859_1)), null);
		assertEquals("Testkey with a very long comment, which is continued on the next line", sshKey.getComment());
	}

	@Test
	public void testAuthorizedKeySetEnvironmentValueOnNewKey() throws Exception {
		final AuthorizedKey authorizedKey = new AuthorizedKey(de.soderer.sshkeyformats.data.Algorithm.ED25519, "AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX");
		authorizedKey.setEnvironmentValue("NAME", "value");
		assertEquals("value", authorizedKey.getEnvironment().get("NAME"));
	}

	@Test
	public void testMismatchingKeyTypesAreRejected() throws Exception {
		final KeyPair edKeyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final KeyPair rsaKeyPair = KeyPairUtilities.createRsaKeyPair(1024);
		assertThrows(IllegalArgumentException.class, () -> new SshKey(null, null, new KeyPair(edKeyPair.getPublic(), rsaKeyPair.getPrivate())));
	}

	private SshKey readResource(final String fileName, final char[] password) throws Exception {
		try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(RESOURCE_DIR + fileName)) {
			assertNotNull(inputStream, fileName);
			return SshKeyReader.readKey(inputStream, password);
		}
	}

	private static byte[] decodePem(final String pemText) {
		final String base64 = pemText.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
		return Base64.getDecoder().decode(base64);
	}

	private static byte[] toPem(final String typeName, final byte[] data) {
		return ("-----BEGIN " + typeName + "-----\n" + Base64.getMimeEncoder(70, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(data) + "\n-----END " + typeName + "-----\n").getBytes(StandardCharsets.UTF_8);
	}
}
