package de.soderer.sshkeyformats.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class KeyPairUtilitiesTest {
	@Test
	public void testCreateKeyPairParameterChecks() {
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.createRsaKeyPair(1024)).getMessage().contains("minimum 2048"));
		assertThrows(Exception.class, () -> KeyPairUtilities.createEllipticCurveKeyPair(null));
		assertThrows(Exception.class, () -> KeyPairUtilities.createEllipticCurveKeyPair(" "));
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.createEllipticCurveKeyPair("nistp192")).getMessage().contains("Unknown ECDSA curve name"));
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.createEllipticCurveKeyPair(192)).getMessage().contains("Invalid ECDSA curve id"));
	}

	@Test
	public void testCreateEllipticCurveKeyPairs() throws Exception {
		assertEquals(Algorithm.NISTP256, KeyPairUtilities.getAlgorithm(KeyPairUtilities.createEllipticCurveKeyPair(256)));
		assertEquals(Algorithm.NISTP384, KeyPairUtilities.getAlgorithm(KeyPairUtilities.createEllipticCurveKeyPair(384)));
		assertEquals(Algorithm.NISTP521, KeyPairUtilities.getAlgorithm(KeyPairUtilities.createEllipticCurveKeyPair(521)));
		// SEC names are accepted as well
		assertEquals(Algorithm.NISTP256, KeyPairUtilities.getAlgorithm(KeyPairUtilities.createEllipticCurveKeyPair(" SECP256 ")));
	}

	@Test
	public void testGetAlgorithmOfKeyPairParts() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd448CurveKeyPair();
		assertEquals(Algorithm.ED448, KeyPairUtilities.getAlgorithm(keyPair));
		assertEquals(Algorithm.ED448, KeyPairUtilities.getAlgorithm(new KeyPair(keyPair.getPublic(), null)));
		assertEquals(Algorithm.ED448, KeyPairUtilities.getAlgorithm(new KeyPair(null, keyPair.getPrivate())));
		assertEquals(Algorithm.ED448, KeyPairUtilities.getAlgorithm(keyPair.getPublic()));

		assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm((KeyPair) null));
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm(new KeyPair(null, null))).getMessage().contains("empty"));
		assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm((PublicKey) null));
		assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm((java.security.PrivateKey) null));
	}

	@Test
	public void testUnsupportedKeyTypes() throws Exception {
		final KeyPair xdhKeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm(xdhKeyPair.getPublic())).getMessage().contains("XDH"));
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm(xdhKeyPair.getPrivate())).getMessage().contains("XDH"));
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.getSha256Fingerprint(xdhKeyPair.getPublic())).getMessage().contains("Cannot create SHA-256 fingerprint"));

		// secp256k1 is no SSH curve
		final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
		generator.initialize(new ECGenParameterSpec("secp256k1"));
		final KeyPair secp256k1KeyPair = generator.generateKeyPair();
		assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm(secp256k1KeyPair.getPublic()));
		assertThrows(Exception.class, () -> KeyPairUtilities.getAlgorithm(secp256k1KeyPair.getPrivate()));
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testKeyStrength() throws Exception {
		final KeyPair rsaKeyPair = KeyPairUtilities.createRsaKeyPair(2048);
		assertEquals(2048, KeyPairUtilities.getKeyStrength(rsaKeyPair));
		assertEquals(2048, KeyPairUtilities.getKeyStrength(rsaKeyPair.getPublic()));

		final KeyPair dsaKeyPair = KeyPairUtilities.createDsaKeyPair(2048);
		assertEquals(2048, KeyPairUtilities.getKeyStrength(new KeyPair(null, dsaKeyPair.getPrivate())));
		assertEquals(2048, KeyPairUtilities.getKeyStrength(dsaKeyPair.getPublic()));

		final KeyPair ecKeyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		assertEquals(256, KeyPairUtilities.getKeyStrength(ecKeyPair));
		assertEquals(256, KeyPairUtilities.getKeyStrength(new KeyPair(null, ecKeyPair.getPrivate())));
		assertEquals(384, KeyPairUtilities.getKeyStrength(KeyPairUtilities.createEllipticCurveKeyPair(384)));
		assertEquals(521, KeyPairUtilities.getKeyStrength(KeyPairUtilities.createEllipticCurveKeyPair(521)));
		assertEquals(256, KeyPairUtilities.getKeyStrength(KeyPairUtilities.createEd25519CurveKeyPair().getPublic()));
		assertEquals(448, KeyPairUtilities.getKeyStrength(new KeyPair(null, KeyPairUtilities.createEd448CurveKeyPair().getPrivate())));

		assertThrows(Exception.class, () -> KeyPairUtilities.getKeyStrength((KeyPair) null));
		assertThrows(Exception.class, () -> KeyPairUtilities.getKeyStrength(new KeyPair(null, null)));
		assertThrows(Exception.class, () -> KeyPairUtilities.getKeyStrength((PublicKey) null));
	}

	@Test
	public void testFingerprints() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(keyPair.getPublic());

		assertEquals(hex("MD5", publicKeyBytes), KeyPairUtilities.getMd5Fingerprint(keyPair).toLowerCase());
		assertEquals(hex("SHA-1", publicKeyBytes), KeyPairUtilities.getSha1Fingerprint(keyPair));
		assertEquals(hex("SHA-256", publicKeyBytes), KeyPairUtilities.getSha256Fingerprint(keyPair));
		assertEquals(hex("SHA-384", publicKeyBytes), KeyPairUtilities.getSha384Fingerprint(keyPair));
		assertEquals(hex("SHA-512", publicKeyBytes), KeyPairUtilities.getSha512Fingerprint(keyPair));

		assertEquals(base64("SHA-1", publicKeyBytes), KeyPairUtilities.getSha1FingerprintBase64(keyPair));
		assertEquals(base64("SHA-256", publicKeyBytes), KeyPairUtilities.getSha256FingerprintBase64(keyPair));
		assertEquals(base64("SHA-384", publicKeyBytes), KeyPairUtilities.getSha384FingerprintBase64(keyPair));
		assertEquals(base64("SHA-512", publicKeyBytes), KeyPairUtilities.getSha512FingerprintBase64(keyPair));
	}

	@Test
	public void testFingerprintParameterChecks() {
		assertThrows(Exception.class, () -> KeyPairUtilities.getSha256Fingerprint((KeyPair) null));
		assertTrue(assertThrows(Exception.class, () -> KeyPairUtilities.getSha256Fingerprint(new KeyPair(null, null))).getMessage().contains("Missing public key"));
		assertThrows(Exception.class, () -> KeyPairUtilities.getSha256Fingerprint((PublicKey) null));
		assertThrows(Exception.class, () -> KeyPairUtilities.getPublicKeyBytes(null));
	}

	@Test
	public void testEncodePublicKeyForAuthorizedKeys() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(384);
		final String authorizedKey = KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair);
		assertEquals("ecdsa-sha2-nistp384 " + Base64.getEncoder().encodeToString(KeyPairUtilities.getPublicKeyBytes(keyPair.getPublic())), authorizedKey);
		assertEquals(authorizedKey, KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair.getPublic()));

		assertThrows(Exception.class, () -> KeyPairUtilities.encodePublicKeyForAuthorizedKeys((KeyPair) null));
		assertThrows(Exception.class, () -> KeyPairUtilities.encodePublicKeyForAuthorizedKeys(new KeyPair(null, keyPair.getPrivate())));
		assertThrows(Exception.class, () -> KeyPairUtilities.encodePublicKeyForAuthorizedKeys((PublicKey) null));
	}

	private static String hex(final String digestAlgorithm, final byte[] data) throws Exception {
		return BitUtilities.toHexString(MessageDigest.getInstance(digestAlgorithm).digest(data), ":");
	}

	private static String base64(final String digestAlgorithm, final byte[] data) throws Exception {
		return Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance(digestAlgorithm).digest(data));
	}
}
