package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.data.KeyPairUtilities;

/**
 * Tests of the accessors and parameter checks of {@link SshKey}.
 */
@SuppressWarnings("static-method")
public class SshKeyApiTest {
	@Test
	public void testFormatAndComment() throws Exception {
		final SshKey sshKey = new SshKey(null, null, null);
		assertEquals(SshKeyFormat.Undefined, sshKey.getFormat());
		assertNull(sshKey.getComment());
		assertNull(sshKey.getKeyPair());

		assertSame(sshKey, sshKey.withFormat(SshKeyFormat.Putty3).withComment("comment"));
		assertEquals(SshKeyFormat.Putty3, sshKey.getFormat());
		assertEquals("comment", sshKey.getComment());

		sshKey.setFormat(null);
		assertEquals(SshKeyFormat.Undefined, sshKey.getFormat());
		sshKey.setComment(null);
		assertNull(sshKey.getComment());
	}

	@Test
	public void testFormatDisplayTexts() {
		assertEquals("", SshKeyFormat.Undefined.getDisplayText());
		assertEquals("OpenSSL / PKCS#8", SshKeyFormat.OpenSSL.getDisplayText());
		assertEquals("OpenSSH Version 1", SshKeyFormat.OpenSSHv1.getDisplayText());
		assertEquals("PuTTY Version 2", SshKeyFormat.Putty2.getDisplayText());
		assertEquals("PuTTY Version 3", SshKeyFormat.Putty3.getDisplayText());
		assertEquals("PKCS#1", SshKeyFormat.PKCS1.getDisplayText());
		assertEquals(SshKeyFormat.PKCS1, SshKeyFormat.valueOf("PKCS1"));
	}

	@Test
	public void testFingerprintsDelegateToKeyPairUtilities() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final SshKey sshKey = new SshKey(SshKeyFormat.OpenSSHv1, "comment", keyPair);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint());
		assertEquals(KeyPairUtilities.getSha256Fingerprint(keyPair), sshKey.getSha256Fingerprint());
		assertEquals(KeyPairUtilities.getSha256FingerprintBase64(keyPair), sshKey.getSha256FingerprintBase64());
		assertEquals(KeyPairUtilities.getSha384Fingerprint(keyPair), sshKey.getSha384Fingerprint());
		assertEquals(KeyPairUtilities.getSha384FingerprintBase64(keyPair), sshKey.getSha384FingerprintBase64());
		assertEquals(KeyPairUtilities.getSha512Fingerprint(keyPair), sshKey.getSha512Fingerprint());
		assertEquals(KeyPairUtilities.getSha512FingerprintBase64(keyPair), sshKey.getSha512FingerprintBase64());
		assertEquals(KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair), sshKey.encodePublicKeyForAuthorizedKeys());
	}

	@Test
	public void testInvalidKeyPairs() throws Exception {
		assertTrue(assertThrows(IllegalArgumentException.class, () -> new SshKey(null, null, new KeyPair(null, null))).getMessage().contains("neither a public nor a private key"));

		final KeyPair xdhKeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
		assertThrows(IllegalArgumentException.class, () -> new SshKey(null, null, new KeyPair(xdhKeyPair.getPublic(), null)));
		assertThrows(IllegalArgumentException.class, () -> new SshKey(null, null, new KeyPair(null, xdhKeyPair.getPrivate())));
	}

	@Test
	public void testSetKeyPairToNull() throws Exception {
		final SshKey sshKey = new SshKey(null, null, KeyPairUtilities.createEd25519CurveKeyPair());
		sshKey.setKeyPair(null);
		assertNull(sshKey.getKeyPair());
	}

	@Test
	public void testEdDsaKeysOfOtherProviders() throws Exception {
		// Keys, which do not implement EdECKey, are recognized by their algorithm name
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		for (final String algorithmName : new String[] { "EdDSA", "Ed25519", "Ed448" }) {
			final KeyPair foreignKeyPair = new KeyPair(new ForeignPublicKey(algorithmName, keyPair.getPublic()), new ForeignPrivateKey(algorithmName, keyPair.getPrivate()));
			assertSame(foreignKeyPair, new SshKey(null, null, foreignKeyPair).getKeyPair());
		}
		final KeyPair unknownKeyPair = new KeyPair(new ForeignPublicKey("Unknown", keyPair.getPublic()), null);
		assertThrows(IllegalArgumentException.class, () -> new SshKey(null, null, unknownKeyPair));
	}

	/**
	 * Key of a foreign provider, which implements none of the specific key interfaces.
	 */
	private static class ForeignKey implements Key {
		private static final long serialVersionUID = 1L;

		private final String algorithm;
		private final Key delegate;

		ForeignKey(final String algorithm, final Key delegate) {
			this.algorithm = algorithm;
			this.delegate = delegate;
		}

		@Override
		public String getAlgorithm() {
			return algorithm;
		}

		@Override
		public String getFormat() {
			return delegate.getFormat();
		}

		@Override
		public byte[] getEncoded() {
			return delegate.getEncoded();
		}
	}

	private static class ForeignPublicKey extends ForeignKey implements PublicKey {
		private static final long serialVersionUID = 1L;

		ForeignPublicKey(final String algorithm, final PublicKey delegate) {
			super(algorithm, delegate);
		}
	}

	private static class ForeignPrivateKey extends ForeignKey implements PrivateKey {
		private static final long serialVersionUID = 1L;

		ForeignPrivateKey(final String algorithm, final PrivateKey delegate) {
			super(algorithm, delegate);
		}
	}
}
