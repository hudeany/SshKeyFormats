package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.TestKeyData.OpenSshv1Parts;
import de.soderer.sshkeyformats.TestKeyData.WireWriter;
import de.soderer.sshkeyformats.data.BCryptPBKDF;
import de.soderer.sshkeyformats.data.CryptographicUtilities;
import de.soderer.sshkeyformats.data.KeyPairUtilities;
import de.soderer.sshkeyformats.data.WrongPasswordException;

/**
 * Tests of {@link SshKeyReader} for OpenSSH v1 private keys and SSH wire format public keys, mostly with manipulated
 * key data.
 */
@SuppressWarnings("static-method")
public class SshKeyReaderOpenSshTest {
	private static final char[] PASSWORD = "password".toCharArray();

	private static String writeOpenSshv1(final KeyPair keyPair, final char[] password) throws Exception {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(output, new SshKey(SshKeyFormat.OpenSSHv1, "comment", keyPair), password, null);
		return output.toString(StandardCharsets.ISO_8859_1);
	}

	private static String errorMessage(final OpenSshv1Parts parts, final char[] password) throws Exception {
		final byte[] pemData = parts.toPem();
		return assertThrows(Exception.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(pemData), password)).getMessage();
	}

	private static SshKey read(final OpenSshv1Parts parts, final char[] password) throws Exception {
		return SshKeyReader.readKey(new ByteArrayInputStream(parts.toPem()), password);
	}

	@Test
	public void testUnchangedPartsCanBeRead() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), read(OpenSshv1Parts.parse(writeOpenSshv1(keyPair, null)), null).getMd5Fingerprint());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), read(OpenSshv1Parts.parse(writeOpenSshv1(keyPair, PASSWORD)), PASSWORD).getMd5Fingerprint());
	}

	@Test
	public void testInvalidContainerData() throws Exception {
		final String keyText = writeOpenSshv1(KeyPairUtilities.createEd25519CurveKeyPair(), null);

		final OpenSshv1Parts wrongMagic = OpenSshv1Parts.parse(keyText);
		wrongMagic.magic = "openssh-key-v2";
		assertTrue(errorMessage(wrongMagic, null).contains("Invalid keyFormat name"));

		final OpenSshv1Parts tooLongMagic = OpenSshv1Parts.parse(keyText);
		tooLongMagic.magic = "x".repeat(40);
		assertTrue(errorMessage(tooLongMagic, null).contains("Missing zero terminator"));

		final OpenSshv1Parts twoKeys = OpenSshv1Parts.parse(keyText);
		twoKeys.numberOfKeys = 2;
		assertTrue(errorMessage(twoKeys, null).contains("Invalid amountOfKeys 2"));

		final OpenSshv1Parts trailingData = OpenSshv1Parts.parse(keyText);
		trailingData.trailingData = new byte[] { 0 };
		assertTrue(errorMessage(trailingData, null).contains("unexpected trailing data"));

		final OpenSshv1Parts kdfWithoutCipher = OpenSshv1Parts.parse(keyText);
		kdfWithoutCipher.kdfName = "bcrypt";
		assertTrue(errorMessage(kdfWithoutCipher, null).contains("for unencrypted key"));
	}

	@Test
	public void testTruncatedContainerData() throws Exception {
		// Container ends directly after the key derivation options
		final byte[] truncatedData = new WireWriter().writeRaw("openssh-key-v1\0".getBytes(StandardCharsets.UTF_8)).writeString("none").writeString("none").writeData(new byte[0]).toByteArray();
		final byte[] pemData = TestKeyData.pem("OPENSSH PRIVATE KEY", truncatedData);
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(pemData), null)).getMessage().contains("Key block read error"));

		// Container without zero terminator of the format name
		final byte[] pemData2 = TestKeyData.pem("OPENSSH PRIVATE KEY", "openssh".getBytes(StandardCharsets.UTF_8));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.readKey(new ByteArrayInputStream(pemData2), null)).getMessage().contains("Key block read error"));
	}

	@Test
	public void testInvalidEncryptionParameters() throws Exception {
		final String keyText = writeOpenSshv1(KeyPairUtilities.createEd25519CurveKeyPair(), PASSWORD);

		final OpenSshv1Parts wrongKdf = OpenSshv1Parts.parse(keyText);
		wrongKdf.kdfName = "none";
		assertTrue(errorMessage(wrongKdf, PASSWORD).contains("Only 'bcrypt' allowed"));

		final OpenSshv1Parts unsupportedCipher = OpenSshv1Parts.parse(keyText);
		unsupportedCipher.cipherName = "chacha20-poly1305@openssh.com";
		assertTrue(errorMessage(unsupportedCipher, PASSWORD).contains("Unsupported key encryption cipher"));

		final OpenSshv1Parts emptySalt = OpenSshv1Parts.parse(keyText);
		emptySalt.kdfOptions = new WireWriter().writeData(new byte[0]).writeInt(16).toByteArray();
		assertTrue(errorMessage(emptySalt, PASSWORD).contains("kdfSalt"));

		final OpenSshv1Parts zeroRounds = OpenSshv1Parts.parse(keyText);
		zeroRounds.kdfOptions = new WireWriter().writeData(new byte[16]).writeInt(0).toByteArray();
		assertTrue(errorMessage(zeroRounds, PASSWORD).contains("kdfRounds = 0"));

		final OpenSshv1Parts shortPrivateKey = OpenSshv1Parts.parse(keyText);
		shortPrivateKey.privateKeyBlock = new byte[7];
		assertTrue(errorMessage(shortPrivateKey, PASSWORD).contains("Invalid encrypted private key data length"));

		final OpenSshv1Parts unalignedPrivateKey = OpenSshv1Parts.parse(keyText);
		unalignedPrivateKey.privateKeyBlock = new byte[20];
		assertTrue(errorMessage(unalignedPrivateKey, PASSWORD).contains("Invalid encrypted private key data length"));

		assertThrows(WrongPasswordException.class, () -> read(OpenSshv1Parts.parse(keyText), null));
	}

	@Test
	public void testEncryptedKeyIsReadInPublicKeyOnlyMode() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final String keyText = writeOpenSshv1(keyPair, PASSWORD);
		// The public key of OpenSSH v1 keys is not encrypted
		final SshKey publicKey = SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(keyText.getBytes(StandardCharsets.ISO_8859_1))).get(0);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), publicKey.getMd5Fingerprint());
		assertNull(publicKey.getKeyPair().getPrivate());
	}

	@Test
	public void testPublicKeyNotMatchingPrivateKey() throws Exception {
		final OpenSshv1Parts parts = OpenSshv1Parts.parse(writeOpenSshv1(KeyPairUtilities.createEd25519CurveKeyPair(), null));
		parts.publicKey = KeyPairUtilities.getPublicKeyBytes(KeyPairUtilities.createEd25519CurveKeyPair().getPublic());
		assertTrue(errorMessage(parts, null).contains("do not match"));
	}

	@Test
	public void testCheckIntsOfUnencryptedKeyDoNotMatch() throws Exception {
		final OpenSshv1Parts parts = OpenSshv1Parts.parse(writeOpenSshv1(KeyPairUtilities.createEd25519CurveKeyPair(), null));
		parts.privateKeyBlock[0] ^= 0x01;
		assertThrows(WrongPasswordException.class, () -> read(parts, null));
	}

	/**
	 * Creates the private key section of an OpenSSH v1 key with valid check ints, comment and padding.
	 */
	private static byte[] createPrivateKeyBlock(final WireWriter keyData, final int blockSize) throws Exception {
		final ByteArrayOutputStream block = new ByteArrayOutputStream();
		block.write(new WireWriter().writeInt(0x12345678).writeInt(0x12345678).toByteArray());
		block.write(keyData.toByteArray());
		block.write(new WireWriter().writeString("comment").toByteArray());
		int padding = 1;
		while (block.size() % blockSize != 0) {
			block.write(padding++);
		}
		return block.toByteArray();
	}

	private static OpenSshv1Parts createUnencryptedParts(final byte[] publicKey, final byte[] privateKeyBlock) throws Exception {
		final OpenSshv1Parts parts = OpenSshv1Parts.parse(writeOpenSshv1(KeyPairUtilities.createEd25519CurveKeyPair(), null));
		parts.publicKey = publicKey;
		parts.privateKeyBlock = privateKeyBlock;
		return parts;
	}

	@Test
	public void testInvalidPrivateKeyData() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(keyPair.getPublic());
		final byte[] rawPublicKey = Arrays.copyOfRange(publicKeyBytes, publicKeyBytes.length - 32, publicKeyBytes.length);
		final byte[] seed = Arrays.copyOfRange(keyPair.getPrivate().getEncoded(), keyPair.getPrivate().getEncoded().length - 32, keyPair.getPrivate().getEncoded().length);

		// Valid composition first
		// OpenSSH stores the seed followed by the public key as secret key
		final byte[] secretKey = concat(seed, rawPublicKey);
		final SshKey validKey = read(createUnencryptedParts(publicKeyBytes, createPrivateKeyBlock(new WireWriter().writeString("ssh-ed25519").writeData(rawPublicKey).writeData(secretKey), 8)), null);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), validKey.getMd5Fingerprint());
		assertEquals("comment", validKey.getComment());

		assertTrue(errorMessage(createUnencryptedParts(publicKeyBytes, createPrivateKeyBlock(new WireWriter().writeString("ssh-ed25519").writeData(rawPublicKey).writeData(seed), 8)), null).contains("Invalid Ed25519 key data length"));
		assertTrue(errorMessage(createUnencryptedParts(publicKeyBytes, createPrivateKeyBlock(new WireWriter().writeString("ssh-ed25519").writeData(rawPublicKey).writeData(concat(seed, new byte[32])), 8)), null).contains("inconsistent public key data"));

		// ECDSA curve name not matching the key type
		assertTrue(errorMessage(createUnencryptedParts(publicKeyBytes, createPrivateKeyBlock(new WireWriter().writeString("ecdsa-sha2-nistp256").writeString("nistp384"), 8)), null).contains("mismatching ECDSA curveName"));

		// RSA values must be positive (an empty mpint is zero)
		final WireWriter rsaKeyData = new WireWriter().writeString("ssh-rsa");
		for (int i = 0; i < 6; i++) {
			rsaKeyData.writeData(new byte[0]);
		}
		assertTrue(errorMessage(createUnencryptedParts(publicKeyBytes, createPrivateKeyBlock(rsaKeyData, 8)), null).contains("Invalid RSA key data"));
	}

	/**
	 * Encrypts a private key section like ssh-keygen with bcrypt_pbkdf and the given AES mode.
	 */
	private static OpenSshv1Parts encrypt(final OpenSshv1Parts parts, final String cipherName, final String javaCipherName, final int keySize) throws Exception {
		final byte[] salt = new byte[16];
		Arrays.fill(salt, (byte) 3);
		final int rounds = 2;
		final byte[] derivedKey = new byte[keySize + 16];
		new BCryptPBKDF().derivePassword(new String(PASSWORD).getBytes(StandardCharsets.UTF_8), salt, rounds, derivedKey);
		final Cipher cipher = Cipher.getInstance(javaCipherName);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derivedKey, 0, keySize, "AES"), new IvParameterSpec(derivedKey, keySize, 16));

		final OpenSshv1Parts encryptedParts = new OpenSshv1Parts();
		encryptedParts.magic = parts.magic;
		encryptedParts.cipherName = cipherName;
		encryptedParts.kdfName = "bcrypt";
		encryptedParts.kdfOptions = new WireWriter().writeData(salt).writeInt(rounds).toByteArray();
		encryptedParts.numberOfKeys = 1;
		encryptedParts.publicKey = parts.publicKey;
		encryptedParts.privateKeyBlock = cipher.doFinal(parts.privateKeyBlock);
		return encryptedParts;
	}

	@Test
	public void testAllSupportedCiphers() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(keyPair.getPublic());
		final byte[] rawPublicKey = Arrays.copyOfRange(publicKeyBytes, publicKeyBytes.length - 32, publicKeyBytes.length);
		final byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();
		final byte[] seed = Arrays.copyOfRange(encodedPrivateKey, encodedPrivateKey.length - 32, encodedPrivateKey.length);
		final OpenSshv1Parts unencryptedParts = createUnencryptedParts(publicKeyBytes, createPrivateKeyBlock(new WireWriter().writeString("ssh-ed25519").writeData(rawPublicKey).writeData(concat(seed, rawPublicKey)), 16));

		for (final String[] cipher : new String[][] {
				{ "aes128-ctr", "AES/CTR/NoPadding", "16" },
				{ "aes192-ctr", "AES/CTR/NoPadding", "24" },
				{ "aes256-ctr", "AES/CTR/NoPadding", "32" },
				{ "aes128-cbc", "AES/CBC/NoPadding", "16" },
				{ "aes192-cbc", "AES/CBC/NoPadding", "24" },
				{ "aes256-cbc", "AES/CBC/NoPadding", "32" } }) {
			final OpenSshv1Parts encryptedParts = encrypt(unencryptedParts, cipher[0], cipher[1], Integer.parseInt(cipher[2]));
			final SshKey sshKey = read(encryptedParts, PASSWORD);
			assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint(), cipher[0]);
			assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic()));
			assertThrows(WrongPasswordException.class, () -> read(encryptedParts, "wrong".toCharArray()), cipher[0]);
		}
	}

	// SSH wire format public keys

	@Test
	public void testParsePublicKeyBytesErrors() throws Exception {
		final KeyPair ecKeyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		final byte[] ecPublicKeyBytes = KeyPairUtilities.getPublicKeyBytes(ecKeyPair.getPublic());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(ecKeyPair), KeyPairUtilities.getMd5Fingerprint(SshKeyReader.parsePublicKeyBytes(ecPublicKeyBytes)));

		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.parsePublicKeyBytes(concat(ecPublicKeyBytes, new byte[] { 0 }))).getMessage().contains("unexpected trailing data"));
		final byte[] mismatchingCurve = new WireWriter().writeString("ecdsa-sha2-nistp256").writeString("nistp521").writeData(new byte[] { 4 }).toByteArray();
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.parsePublicKeyBytes(mismatchingCurve)).getMessage().contains("mismatching ECDSA curveName"));
		assertThrows(Exception.class, () -> SshKeyReader.parsePublicKeyBytes(new WireWriter().writeString("ssh-unknown").toByteArray()));

		// Invalid block sizes
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.parsePublicKeyBytes(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF })).getMessage().contains("Key blocksize error"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.parsePublicKeyBytes(new byte[] { 0, 0, 0, 10, 1 })).getMessage().contains("exceeds available data"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.parsePublicKeyBytes(new byte[] { 0, 0 })).getMessage().contains("Key block read error"));
	}

	@Test
	public void testKeyCreationHelpers() throws Exception {
		assertThrows(Exception.class, () -> SshKeyReader.createEdDsaPublicKey(null, "Ed25519"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.createEdDsaPublicKey(new byte[31], "Ed25519")).getMessage().contains("expected 32"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.createEdDsaPublicKey(new byte[32], "Ed448")).getMessage().contains("expected 57"));
		assertThrows(Exception.class, () -> SshKeyReader.createEdDsaPrivateKey(null, "Ed25519"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.createEdDsaPrivateKey(new byte[56], "Ed448")).getMessage().contains("expected 57"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyReader.createEcPrivateKey(BigInteger.ONE, "nistp192")).getMessage().contains("Unsupported ECDSA curveName"));
		assertThrows(Exception.class, () -> SshKeyReader.createEcPublicKey(null, "nistp256"));
	}

	@Test
	public void testHexHelpers() throws Exception {
		assertEquals("00FF10", SshKeyReader.toHexString(new byte[] { 0, -1, 16 }));
		assertEquals(3, SshKeyReader.fromHexString("00ff10").length);
		assertThrows(Exception.class, () -> SshKeyReader.fromHexString(null));
		assertThrows(Exception.class, () -> SshKeyReader.fromHexString("abc"));
		assertThrows(Exception.class, () -> SshKeyReader.fromHexString("zz"));
		assertThrows(Exception.class, () -> SshKeyReader.fromHexString("0z"));
	}

	@Test
	public void testDecodeComment() {
		assertNull(SshKeyReader.decodeComment(null));
		assertNull(SshKeyReader.decodeComment(new byte[0]));
		assertEquals("Schlüssel", SshKeyReader.decodeComment("Schlüssel".getBytes(StandardCharsets.UTF_8)));
		// Invalid UTF-8 data is decoded as ISO-8859-1
		assertEquals("Schlüssel", SshKeyReader.decodeComment("Schlüssel".getBytes(StandardCharsets.ISO_8859_1)));
		// Comments encoded twice in UTF-8 are fixed
		final byte[] doubleEncoded = new String("Schlüssel".getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1).getBytes(StandardCharsets.UTF_8);
		assertEquals("Schlüssel", SshKeyReader.decodeComment(doubleEncoded));
		// Characters outside of ISO-8859-1 are kept
		assertEquals("Ã€uro €", SshKeyReader.decodeComment("Ã€uro €".getBytes(StandardCharsets.UTF_8)));
		// A lead byte character, which is no valid double encoding, is kept
		assertEquals("Ã x", SshKeyReader.decodeComment("Ã x".getBytes(StandardCharsets.UTF_8)));
		assertFalse(SshKeyReader.decodeComment("plain".getBytes(StandardCharsets.UTF_8)).isEmpty());
	}

	private static byte[] concat(final byte[] first, final byte[] second) {
		final byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}
}
