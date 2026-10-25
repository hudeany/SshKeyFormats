package de.soderer.sshkeyformats;

import static de.soderer.sshkeyformats.TestKeyData.derBitString;
import static de.soderer.sshkeyformats.TestKeyData.derContext0;
import static de.soderer.sshkeyformats.TestKeyData.derContext1;
import static de.soderer.sshkeyformats.TestKeyData.derInteger;
import static de.soderer.sshkeyformats.TestKeyData.derNull;
import static de.soderer.sshkeyformats.TestKeyData.derOctetString;
import static de.soderer.sshkeyformats.TestKeyData.derOid;
import static de.soderer.sshkeyformats.TestKeyData.derSequence;
import static de.soderer.sshkeyformats.TestKeyData.pem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.data.CryptographicUtilities;
import de.soderer.sshkeyformats.data.KeyPairUtilities;
import de.soderer.sshkeyformats.data.WrongPasswordException;

/**
 * Tests of {@link SshKeyReader} for PEM, RFC 4716, legacy OpenSSL encrypted, PKCS#8 and X.509 key data, mostly with
 * manipulated or unsupported data.
 */
@SuppressWarnings("static-method")
public class SshKeyReaderPemTest {
	private static final char[] PASSWORD = "password".toCharArray();

	private static final String OID_PBES2 = "1.2.840.113549.1.5.13";
	private static final String OID_PBKDF2 = "1.2.840.113549.1.5.12";
	private static final String OID_SCRYPT = "1.3.6.1.4.1.11591.4.11";
	private static final String OID_AES128_CBC = "2.16.840.1.101.3.4.1.2";
	private static final String OID_AES192_CBC = "2.16.840.1.101.3.4.1.22";
	private static final String OID_AES256_CBC = "2.16.840.1.101.3.4.1.42";
	private static final String OID_DES_EDE3_CBC = "1.2.840.113549.3.7";
	private static final String OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
	private static final String OID_NISTP256 = "1.2.840.10045.3.1.7";
	private static final String OID_NISTP384 = "1.3.132.0.34";
	private static final String OID_SECP256K1 = "1.3.132.0.10";
	private static final String OID_X25519 = "1.3.101.110";

	private static SshKey read(final byte[] data, final char[] password) throws Exception {
		return SshKeyReader.readKey(new ByteArrayInputStream(data), password);
	}

	private static SshKey read(final String text, final char[] password) throws Exception {
		return read(text.getBytes(StandardCharsets.ISO_8859_1), password);
	}

	private static String errorMessage(final byte[] data, final char[] password) {
		return assertThrows(Exception.class, () -> read(data, password)).getMessage();
	}

	private static String errorMessage(final String text, final char[] password) {
		return errorMessage(text.getBytes(StandardCharsets.ISO_8859_1), password);
	}

	// Dispatching of key types

	@Test
	public void testEmptyInput() throws Exception {
		assertNull(read("", null));
		assertNull(read("# only a comment\n\n", null));
		assertTrue(SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(new byte[0])).isEmpty());
	}

	@Test
	public void testUnknownPemType() {
		assertTrue(errorMessage(pem("CERTIFICATE", new byte[] { 1, 2, 3 }), null).contains("Unknown key identifier found: CERTIFICATE"));
	}

	@Test
	public void testSsh2PrivateKeyIsUnsupported() {
		final String keyText = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nAAAA\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n";
		assertTrue(errorMessage(keyText, null).contains("Unsupported SSH.com private key format"));
	}

	@Test
	public void testUnknownSsh2KeyType() {
		final String keyText = "---- BEGIN SSH2 SECRET KEY ----\nAAAA\n---- END SSH2 SECRET KEY ----\n";
		assertTrue(errorMessage(keyText, null).contains("Unknown key identifier found"));
	}

	@Test
	public void testSsh2PublicKeyWrittenAsPkcs1Format() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(521);
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS1Format(output, keyPair.getPublic());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), read(output.toByteArray(), null).getMd5Fingerprint());
	}

	@Test
	public void testEcParametersBlockIsSkipped() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		// Written by "openssl ecparam -genkey" before the key
		output.write(pem("EC PARAMETERS", derOid(OID_NISTP256)));
		SshKeyWriter.writePKCS8Format(output, keyPair, null, null);

		final SshKey sshKey = read(output.toByteArray(), null);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint());
		assertEquals(1, SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(output.toByteArray())).size());
	}

	// PEM and RFC 4716 block structure

	@Test
	public void testPemBlockErrors() throws Exception {
		final String keyText = new String(pem("PUBLIC KEY", KeyPairUtilities.createEd25519CurveKeyPair().getPublic().getEncoded()), StandardCharsets.ISO_8859_1);

		assertTrue(errorMessage(keyText.replace("-----END PUBLIC KEY-----", ""), null).contains("End line is missing"));
		assertTrue(errorMessage("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n", null).contains("Missing key data"));
		final String headerAfterData = keyText.replace("\n-----END", "\nComment: late header\n-----END");
		assertTrue(errorMessage(headerAfterData, null).contains("Headers found after keydata start"));
	}

	@Test
	public void testPemHeaderContinuationLines() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output, keyPair, "AES-256-CBC", PASSWORD, null);
		// RFC 1421 header values may be continued in lines starting with whitespace
		final String keyText = output.toString(StandardCharsets.ISO_8859_1).replaceFirst("DEK-Info: AES-256-CBC,", "DEK-Info: AES-256-CBC,\n ");
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), read(keyText, PASSWORD).getMd5Fingerprint());
	}

	@Test
	public void testRfc4716BlockErrors() throws Exception {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS1Format(output, KeyPairUtilities.createEd25519CurveKeyPair().getPublic());
		final String keyText = output.toString(StandardCharsets.ISO_8859_1);

		assertTrue(errorMessage(keyText.replace("---- END SSH2 PUBLIC KEY ----", ""), null).contains("End line is missing"));
		assertTrue(errorMessage("---- BEGIN SSH2 PUBLIC KEY ----\nComment: x\n---- END SSH2 PUBLIC KEY ----\n", null).contains("Missing key data"));
		assertTrue(errorMessage(keyText.replace("\r\n---- END", "\r\nComment: late\r\n---- END"), null).contains("Headers found after keydata start"));
		assertTrue(errorMessage("---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"continued \\", null).contains("Missing header continuation line"));
	}

	// Legacy OpenSSL encryption ("Proc-Type: 4,ENCRYPTED")

	private static String writeLegacyEncrypted(final KeyPair keyPair, final String cipherName) throws Exception {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output, keyPair, cipherName, PASSWORD, StandardCharsets.UTF_8);
		return output.toString(StandardCharsets.ISO_8859_1);
	}

	@Test
	public void testLegacyEncryptionHeaderErrors() throws Exception {
		final String keyText = writeLegacyEncrypted(KeyPairUtilities.createEllipticCurveKeyPair(256), "AES-128-CBC");
		final String dekInfoLine = keyText.lines().filter(line -> line.startsWith("DEK-Info: ")).findFirst().get();
		final String iv = dekInfoLine.substring(dekInfoLine.indexOf(',') + 1);

		assertTrue(errorMessage(keyText.replace(dekInfoLine + "\n", ""), PASSWORD).contains("Missing key encryption info"));
		assertTrue(errorMessage(keyText.replace(dekInfoLine, "DEK-Info: AES-128-CBC"), PASSWORD).contains("Invalid key encryption info"));
		assertTrue(errorMessage(keyText.replace(dekInfoLine, "DEK-Info: BF-CBC," + iv), PASSWORD).contains("Unknown key encryption cipher"));
		assertTrue(errorMessage(keyText.replace(dekInfoLine, "DEK-Info: AES-128-CBC,0011"), PASSWORD).contains("Invalid initialization vector length"));
		// DES-EDE3-CBC uses 8 byte blocks
		assertTrue(errorMessage(keyText.replace(dekInfoLine, "DEK-Info: DES-EDE3-CBC," + iv), PASSWORD).contains("Invalid initialization vector length"));
		assertTrue(errorMessage(pem("EC PRIVATE KEY", new byte[5], "Proc-Type: 4,ENCRYPTED", dekInfoLine), PASSWORD).contains("Invalid encrypted key data length"));
	}

	@Test
	public void testLegacyEncryptedKeyWithoutPassword() throws Exception {
		final String keyText = writeLegacyEncrypted(KeyPairUtilities.createEllipticCurveKeyPair(256), "AES-192-CBC");
		assertThrows(WrongPasswordException.class, () -> read(keyText, null));
		// Encrypted keys contain no public key data, so they are skipped when reading public keys
		assertTrue(SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(keyText.getBytes(StandardCharsets.ISO_8859_1))).isEmpty());
	}

	@Test
	public void testLegacyEncryptedEdDsaKey() throws Exception {
		// EdDSA keys are written as PKCS#8 "PRIVATE KEY", which may be legacy encrypted as well
		final KeyPair keyPair = KeyPairUtilities.createEd448CurveKeyPair();
		final String keyText = writeLegacyEncrypted(keyPair, "DES-EDE3-CBC");
		assertTrue(keyText.startsWith("-----BEGIN PRIVATE KEY-----"));
		final SshKey sshKey = read(keyText, PASSWORD);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint());
	}

	/**
	 * Encrypts data like OpenSSL's legacy PEM encryption with AES-128-CBC, but without adding a padding.
	 */
	private static byte[] encryptLegacyAes128WithoutPadding(final byte[] plainData, final byte[] iv) throws Exception {
		final byte[] key = SshKeyReader.stretchPasswordForOpenSsl(new String(PASSWORD).getBytes(StandardCharsets.UTF_8), iv, 8, 16);
		final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
		return cipher.doFinal(plainData);
	}

	@Test
	public void testLegacyDecryptionWithInvalidPadding() throws Exception {
		final byte[] iv = new byte[16];
		final byte[] plainData = new byte[16];
		// Padding length 2, but the second last byte is no padding byte
		plainData[15] = 2;
		plainData[14] = 3;
		final byte[] pemData = pem("RSA PRIVATE KEY", encryptLegacyAes128WithoutPadding(plainData, iv), "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC," + "00".repeat(16));
		assertThrows(WrongPasswordException.class, () -> read(pemData, PASSWORD));
	}

	@Test
	public void testLegacyDecryptionWithValidPaddingButGarbage() throws Exception {
		final byte[] iv = new byte[16];
		final byte[] plainData = new byte[16];
		Arrays.fill(plainData, (byte) 0x7F);
		plainData[15] = 1;
		final byte[] pemData = pem("RSA PRIVATE KEY", encryptLegacyAes128WithoutPadding(plainData, iv), "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC," + "00".repeat(16));
		final WrongPasswordException exception = assertThrows(WrongPasswordException.class, () -> read(pemData, PASSWORD));
		// The parse error of the decrypted garbage is kept as cause
		assertNotNull(exception.getCause());
	}

	// PKCS#8 encrypted private keys ("ENCRYPTED PRIVATE KEY", PBES2)

	/**
	 * Creates a PKCS#8 "EncryptedPrivateKeyInfo" with PBES2.
	 *
	 * @param prfOid OID of the PBKDF2 pseudo random function, or null for the default HmacSHA1
	 */
	private static byte[] createEncryptedPkcs8(final byte[] privateKeyInfo, final String encryptionAlgorithmOid, final String keyDerivationOid, final String prfOid, final String prfName, final int iterations, final String encryptionSchemeOid, final int keySize, final int ivLength) throws Exception {
		final byte[] salt = "saltsalt".getBytes(StandardCharsets.US_ASCII);
		final byte[] iv = new byte[ivLength];
		Arrays.fill(iv, (byte) 7);

		final boolean isDes = OID_DES_EDE3_CBC.equals(encryptionSchemeOid);
		// Invalid iteration counts are rejected before decryption, so the encryption itself uses a valid and fast count for them
		final int encryptionIterations = Math.min(Math.max(iterations, 1), 1000);
		final byte[] key = SecretKeyFactory.getInstance("PBKDF2With" + prfName).generateSecret(new PBEKeySpec(PASSWORD, salt, encryptionIterations, keySize * 8)).getEncoded();
		final Cipher cipher = Cipher.getInstance(isDes ? "DESede/CBC/PKCS5Padding" : "AES/CBC/PKCS5Padding");
		final int cipherIvLength = isDes ? 8 : 16;
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, isDes ? "DESede" : "AES"), new IvParameterSpec(Arrays.copyOf(iv, cipherIvLength)));
		final byte[] encryptedData = cipher.doFinal(privateKeyInfo);

		final byte[] pbkdf2Parameters;
		if (prfOid == null) {
			pbkdf2Parameters = derSequence(derOctetString(salt), derInteger(iterations));
		} else {
			// With optional key length and pseudo random function
			pbkdf2Parameters = derSequence(derOctetString(salt), derInteger(iterations), derInteger(keySize), derSequence(derOid(prfOid), derNull()));
		}
		final byte[] keyDerivation = derSequence(derOid(keyDerivationOid), pbkdf2Parameters);
		final byte[] encryptionScheme = derSequence(derOid(encryptionSchemeOid), derOctetString(iv));
		final byte[] encryptionAlgorithm = derSequence(derOid(encryptionAlgorithmOid), derSequence(keyDerivation, encryptionScheme));
		return pem("ENCRYPTED PRIVATE KEY", derSequence(encryptionAlgorithm, derOctetString(encryptedData)));
	}

	private static byte[] createEncryptedPkcs8(final byte[] privateKeyInfo, final String prfOid, final String prfName, final String encryptionSchemeOid, final int keySize) throws Exception {
		return createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_PBKDF2, prfOid, prfName, 1000, encryptionSchemeOid, keySize, OID_DES_EDE3_CBC.equals(encryptionSchemeOid) ? 8 : 16);
	}

	@Test
	public void testEncryptedPkcs8Variants() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(384);
		final byte[] privateKeyInfo = keyPair.getPrivate().getEncoded();
		final String expectedFingerprint = KeyPairUtilities.getMd5Fingerprint(keyPair);

		final Object[][] variants = new Object[][] {
				{ null, "HmacSHA1", OID_AES128_CBC, 16 },
				{ "1.2.840.113549.2.7", "HmacSHA1", OID_AES192_CBC, 24 },
				{ "1.2.840.113549.2.8", "HmacSHA224", OID_AES256_CBC, 32 },
				{ "1.2.840.113549.2.9", "HmacSHA256", OID_AES128_CBC, 16 },
				{ "1.2.840.113549.2.10", "HmacSHA384", OID_DES_EDE3_CBC, 24 },
				{ "1.2.840.113549.2.11", "HmacSHA512", OID_AES256_CBC, 32 } };
		for (final Object[] variant : variants) {
			final byte[] pemData = createEncryptedPkcs8(privateKeyInfo, (String) variant[0], (String) variant[1], (String) variant[2], (Integer) variant[3]);
			final SshKey sshKey = read(pemData, PASSWORD);
			assertEquals(expectedFingerprint, sshKey.getMd5Fingerprint(), variant[1] + " " + variant[2]);
			assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic()));
		}
	}

	@Test
	public void testEncryptedPkcs8Errors() throws Exception {
		final byte[] privateKeyInfo = KeyPairUtilities.createEd25519CurveKeyPair().getPrivate().getEncoded();

		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, "1.2.840.113549.1.5.3", OID_PBKDF2, null, "HmacSHA1", 1000, OID_AES128_CBC, 16, 16), PASSWORD).contains("only PBES2 is supported"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_SCRYPT, null, "HmacSHA1", 1000, OID_AES128_CBC, 16, 16), PASSWORD).contains("scrypt"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, "1.2.3.4", null, "HmacSHA1", 1000, OID_AES128_CBC, 16, 16), PASSWORD).contains("only PBKDF2 is supported"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_PBKDF2, null, "HmacSHA1", 0, OID_AES128_CBC, 16, 16), PASSWORD).contains("iteration count"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_PBKDF2, null, "HmacSHA1", SshKeyReader.MAX_PBKDF2_ITERATIONS + 1, OID_AES128_CBC, 16, 16), PASSWORD).contains("iteration count"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_PBKDF2, "1.2.3.4", "HmacSHA1", 1000, OID_AES128_CBC, 16, 16), PASSWORD).contains("pseudo random function"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_PBKDF2, null, "HmacSHA1", 1000, "1.2.3.4", 16, 16), PASSWORD).contains("encryption scheme"));
		assertTrue(errorMessage(createEncryptedPkcs8(privateKeyInfo, OID_PBES2, OID_PBKDF2, null, "HmacSHA1", 1000, OID_AES128_CBC, 16, 8), PASSWORD).contains("Invalid PKCS#8 encrypted data"));
	}

	@Test
	public void testEncryptedPkcs8PasswordHandling() throws Exception {
		final byte[] pemData = createEncryptedPkcs8(KeyPairUtilities.createEd25519CurveKeyPair().getPrivate().getEncoded(), null, "HmacSHA1", OID_AES128_CBC, 16);
		assertThrows(WrongPasswordException.class, () -> read(pemData, null));
		assertThrows(WrongPasswordException.class, () -> read(pemData, "wrong".toCharArray()));
		assertTrue(SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(pemData)).isEmpty());
	}

	// DER structure errors

	@Test
	public void testDerStructureErrors() throws Exception {
		assertTrue(errorMessage(pem("RSA PRIVATE KEY", derInteger(0)), null).contains("Missing enclosing sequence"));
		assertTrue(errorMessage(pem("RSA PRIVATE KEY", derSequence(derInteger(0))), null).contains("Missing data element 1"));
		assertTrue(errorMessage(pem("RSA PRIVATE KEY", derSequence(derInteger(0), derOctetString(new byte[1]))), null).contains("Unexpected data element type"));
		// Multi prime RSA keys (version 1) are not supported
		assertTrue(errorMessage(pem("RSA PRIVATE KEY", derSequence(derInteger(1))), null).contains("multi prime"));
		assertTrue(errorMessage(pem("DSA PRIVATE KEY", derSequence(derInteger(1))), null).contains("Invalid key data version"));
		assertTrue(errorMessage(pem("PRIVATE KEY", derSequence(derInteger(2))), null).contains("Invalid PKCS#8 key data version"));
		assertTrue(errorMessage(pem("PRIVATE KEY", derSequence(derInteger(0), derSequence(derOid(OID_X25519)), derOctetString(new byte[34]))), null).contains("Unknown ssh algorithm OID"));
	}

	// X.509 public keys ("PUBLIC KEY")

	@SuppressWarnings("deprecation")
	@Test
	public void testX509PublicKeys() throws Exception {
		for (final KeyPair keyPair : new KeyPair[] {
				KeyPairUtilities.createDsaKeyPair(2048),
				KeyPairUtilities.createEllipticCurveKeyPair(256),
				KeyPairUtilities.createEd25519CurveKeyPair(),
				KeyPairUtilities.createEd448CurveKeyPair() }) {
			final SshKey sshKey = read(pem("PUBLIC KEY", keyPair.getPublic().getEncoded()), null);
			assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint(), keyPair.getPublic().getAlgorithm());
			assertNull(sshKey.getKeyPair().getPrivate());
		}
	}

	@Test
	public void testUnsupportedX509PublicKeys() throws Exception {
		final KeyPair xdhKeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
		assertTrue(errorMessage(pem("PUBLIC KEY", xdhKeyPair.getPublic().getEncoded()), null).contains("Unknown ssh algorithm OID"));

		final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
		generator.initialize(new ECGenParameterSpec("secp256k1"));
		assertTrue(errorMessage(pem("PUBLIC KEY", generator.generateKeyPair().getPublic().getEncoded()), null).contains("Unsupported ec curve oid"));
	}

	// SEC1 EC private keys ("EC PRIVATE KEY")

	private static byte[] ecPrivateKeyPem(final byte[]... parts) throws Exception {
		return pem("EC PRIVATE KEY", derSequence(parts));
	}

	@Test
	public void testEcPrivateKeyWithoutPublicKeyData() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		final BigInteger s = ((ECPrivateKey) keyPair.getPrivate()).getS();
		// The public key is derived from the private value
		final SshKey sshKey = read(ecPrivateKeyPem(derInteger(1), derOctetString(toUnsigned(s)), derContext0(derOid(OID_NISTP256))), null);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint());
		assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic()));
	}

	@Test
	public void testEcPrivateKeyErrors() throws Exception {
		final byte[] privateValue = new byte[] { 0x01 };
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(2), derOctetString(privateValue)), null).contains("Invalid key data version"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue), derContext0(derSequence(derInteger(1)))), null).contains("explicit ec curve parameters"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue)), null).contains("Missing ec curve definition"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue), derContext0(derOid(OID_SECP256K1))), null).contains("Unsupported ec curve oid"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(new byte[] { 0 }), derContext0(derOid(OID_NISTP256))), null).contains("not in interval"));

		// Invalid public key data
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue), derContext0(derOid(OID_NISTP256)), derContext1(derBitString(new byte[] { 1, 4 }))), null).contains("Invalid ec public key data"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue), derContext0(derOid(OID_NISTP256)), derContext1(derOctetString(new byte[] { 0, 4 }))), null).contains("Invalid ec public key data"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue), derContext0(derOid(OID_NISTP256)), derContext1(derBitString(new byte[] { 0, 2, 1, 2 }))), null).contains("Unsupported or invalid EC point encoding"));
		assertTrue(errorMessage(ecPrivateKeyPem(derInteger(1), derOctetString(privateValue), derContext0(derOid(OID_NISTP256)), derContext1(derBitString(new byte[] { 0, 4, 1, 2, 3 }))), null).contains("Invalid EC point length"));
	}

	@Test
	public void testInconsistentEcCurveInPkcs8() throws Exception {
		final byte[] sec1Key = derSequence(derInteger(1), derOctetString(new byte[] { 1 }), derContext0(derOid(OID_NISTP384)));
		final byte[] pkcs8Key = derSequence(derInteger(0), derSequence(derOid(OID_EC_PUBLIC_KEY), derOid(OID_NISTP256)), derOctetString(sec1Key));
		assertTrue(errorMessage(pem("PRIVATE KEY", pkcs8Key), null).contains("Inconsistent ec curve definitions"));
	}

	private static byte[] toUnsigned(final BigInteger value) {
		final byte[] data = value.toByteArray();
		return data[0] == 0 ? Arrays.copyOfRange(data, 1, data.length) : data;
	}
}
