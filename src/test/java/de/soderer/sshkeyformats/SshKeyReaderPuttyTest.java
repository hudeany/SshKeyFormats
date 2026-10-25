package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.data.KeyPairUtilities;
import de.soderer.sshkeyformats.data.WrongPasswordException;

/**
 * Tests of {@link SshKeyReader} for PuTTY keys, mostly with manipulated key data.
 */
@SuppressWarnings("static-method")
public class SshKeyReaderPuttyTest {
	private static final char[] PASSWORD = "password".toCharArray();

	private static String writePutty(final int version, final KeyPair keyPair, final String comment, final char[] password) throws Exception {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		if (version == 2) {
			SshKeyWriter.writePuttyVersion2Key(output, new SshKey(SshKeyFormat.Putty2, comment, keyPair), password);
		} else {
			SshKeyWriter.writePuttyVersion3Key(output, new SshKey(SshKeyFormat.Putty3, comment, keyPair), password);
		}
		return output.toString(StandardCharsets.ISO_8859_1);
	}

	private static SshKey read(final String keyText, final char[] password) throws Exception {
		return SshKeyReader.readKey(new ByteArrayInputStream(keyText.getBytes(StandardCharsets.ISO_8859_1)), password);
	}

	private static String errorMessage(final String keyText, final char[] password) {
		return assertThrows(Exception.class, () -> read(keyText, password)).getMessage();
	}

	/**
	 * Replaces the whole line starting with the given prefix.
	 */
	private static String replaceLine(final String keyText, final String linePrefix, final String newLine) {
		final StringBuilder result = new StringBuilder();
		for (final String line : TestKeyData.lines(keyText)) {
			if (line.startsWith(linePrefix)) {
				if (newLine != null) {
					result.append(newLine).append("\r\n");
				}
			} else {
				result.append(line).append("\r\n");
			}
		}
		return result.toString();
	}

	@Test
	public void testPropertyErrors() throws Exception {
		final String keyText = writePutty(2, KeyPairUtilities.createEd25519CurveKeyPair(), "comment", null);

		assertTrue(errorMessage(replaceLine(keyText, "Public-Lines: ", "Public-Lines: abc"), null).contains("Invalid value for 'Public-Lines'"));
		assertTrue(errorMessage(replaceLine(keyText, "Public-Lines: ", "Public-Lines: -1"), null).contains("Invalid value for 'Public-Lines'"));
		assertTrue(errorMessage(replaceLine(keyText, "Private-Lines: ", "Private-Lines: 100"), null).contains("Missing some lines for 'Private-Lines'"));
		assertTrue(errorMessage(replaceLine(keyText, "Private-MAC: ", null), null).contains("Missing 'Private-MAC'"));
		assertTrue(errorMessage(replaceLine(keyText, "Comment: ", "unexpected line"), null).contains("Unexpected line"));
		assertTrue(errorMessage(replaceLine(keyText, "Encryption: ", null), null).contains("Missing 'Encryption'"));
		assertTrue(errorMessage(replaceLine(keyText, "Encryption: ", "Encryption: aes128-cbc"), PASSWORD).contains("Unsupported key encryption method"));
	}

	@Test
	public void testKeyTypeMismatch() throws Exception {
		final String keyText = writePutty(2, KeyPairUtilities.createEd25519CurveKeyPair(), "comment", null);
		assertTrue(errorMessage(keyText.replace("PuTTY-User-Key-File-2: ssh-ed25519", "PuTTY-User-Key-File-2: ssh-rsa"), null).contains("PuTTY key type mismatch"));
	}

	@Test
	public void testMacMismatchOfUnencryptedKey() throws Exception {
		for (final int version : new int[] { 2, 3 }) {
			final String keyText = writePutty(version, KeyPairUtilities.createEllipticCurveKeyPair(256), "comment", null);
			// The comment is part of the MAC
			assertTrue(errorMessage(keyText.replace("Comment: comment", "Comment: changed"), null).contains("MAC checksum mismatch"), "Version " + version);
		}
	}

	@Test
	public void testEncryptedKeyErrors() throws Exception {
		final String keyText = writePutty(2, KeyPairUtilities.createEd25519CurveKeyPair(), "comment", PASSWORD);

		assertThrows(WrongPasswordException.class, () -> read(keyText, null));
		assertThrows(WrongPasswordException.class, () -> read(keyText, "wrong".toCharArray()));

		// Encrypted data with an invalid length for AES
		String invalidLength = replaceLine(keyText, "Private-Lines: ", "Private-Lines: 1");
		final StringBuilder withoutPrivateData = new StringBuilder();
		boolean skip = false;
		for (final String line : TestKeyData.lines(invalidLength)) {
			if (line.startsWith("Private-Lines: ")) {
				withoutPrivateData.append(line).append("\r\n").append("AAAA").append("\r\n");
				skip = true;
			} else if (line.startsWith("Private-MAC: ")) {
				withoutPrivateData.append(line).append("\r\n");
				skip = false;
			} else if (!skip) {
				withoutPrivateData.append(line).append("\r\n");
			}
		}
		invalidLength = withoutPrivateData.toString();
		assertTrue(errorMessage(invalidLength, PASSWORD).contains("Invalid encrypted data length"));
	}

	@Test
	public void testInvalidArgon2Parameters() throws Exception {
		final String keyText = writePutty(3, KeyPairUtilities.createEd25519CurveKeyPair(), "comment", PASSWORD);

		assertTrue(errorMessage(replaceLine(keyText, "Argon2-Memory: ", "Argon2-Memory: 4"), PASSWORD).contains("Argon2-Memory"));
		assertTrue(errorMessage(replaceLine(keyText, "Argon2-Passes: ", "Argon2-Passes: 0"), PASSWORD).contains("Argon2-Passes"));
		// Each value is allowed, but not their product
		final String largeProduct = replaceLine(replaceLine(keyText, "Argon2-Memory: ", "Argon2-Memory: " + SshKeyReader.MAX_ARGON2_MEMORY_KB), "Argon2-Passes: ", "Argon2-Passes: " + SshKeyReader.MAX_ARGON2_PASSES);
		assertTrue(errorMessage(largeProduct, PASSWORD).contains("Argon2-Memory * Argon2-Passes"));
		assertTrue(errorMessage(replaceLine(keyText, "Argon2-Parallelism: ", "Argon2-Parallelism: 0"), PASSWORD).contains("Argon2-Parallelism"));
		assertTrue(errorMessage(replaceLine(keyText, "Argon2-Salt: ", "Argon2-Salt: "), PASSWORD).contains("Argon2-Salt"));
		assertTrue(errorMessage(replaceLine(keyText, "Key-Derivation: ", "Key-Derivation: scrypt"), PASSWORD).contains("Unsupported Key-Derivation"));
	}

	@Test
	public void testArgon2Types() throws Exception {
		final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = new byte[16];
		final byte[] argon2i = SshKeyReader.deriveArgon2Key(password, "Argon2i", 64, 1, 1, salt);
		final byte[] argon2d = SshKeyReader.deriveArgon2Key(password, "argon2d", 64, 1, 1, salt);
		final byte[] argon2id = SshKeyReader.deriveArgon2Key(password, "ARGON2ID", 64, 1, 1, salt);
		assertEquals(80, argon2i.length);
		assertFalse(Arrays.equals(argon2i, argon2d));
		assertFalse(Arrays.equals(argon2d, argon2id));
		assertArrayEquals(argon2id, SshKeyReader.deriveArgon2Key(password, "Argon2id", 64, 1, 1, salt));
	}

	@Test
	public void testCommentWithCharactersOutsideOfLatin1() throws Exception {
		// Such comments are written in UTF-8 and must be decoded as UTF-8 again
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		for (final int version : new int[] { 2, 3 }) {
			final String keyText = writePutty(version, keyPair, "Schlüssel 5€", null);
			assertEquals("Schlüssel 5€", read(keyText, null).getComment(), "Version " + version);
		}
	}

	@Test
	public void testPublicKeyOnlyMode() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(384);
		final String keyText = writePutty(3, keyPair, "comment", PASSWORD);
		final SshKey publicKey = SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(keyText.getBytes(StandardCharsets.ISO_8859_1))).get(0);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), publicKey.getMd5Fingerprint());
		assertEquals("comment", publicKey.getComment());
		assertEquals(SshKeyFormat.Putty3, publicKey.getFormat());
	}

	@Test
	public void testCorruptPrivateKeyData() throws Exception {
		// A valid MAC over private key data, which cannot be parsed
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(keyPair.getPublic());
		final byte[] privateKeyBytes = new byte[] { 0, 0, 0, 1, 0 };
		final String mac = SshKeyReader.calculatePuttyMac(3, new byte[0], de.soderer.sshkeyformats.data.Algorithm.ED25519, "none", new byte[0], publicKeyBytes, privateKeyBytes);
		final String keyText = "PuTTY-User-Key-File-3: ssh-ed25519\r\n"
				+ "Encryption: none\r\n"
				+ "Public-Lines: 1\r\n"
				+ java.util.Base64.getEncoder().encodeToString(publicKeyBytes) + "\r\n"
				+ "Private-Lines: 1\r\n"
				+ java.util.Base64.getEncoder().encodeToString(privateKeyBytes) + "\r\n"
				+ "Private-MAC: " + mac + "\r\n";
		assertTrue(errorMessage(keyText, null).contains("Cannot read key data"));
	}
}
