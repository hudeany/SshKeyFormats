package de.soderer.sshkeyformats.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class CryptographicUtilitiesTest {
	private static final Provider BC_PROVIDER = new BouncyCastleProvider();

	@Test
	public void testMissingKeys() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		assertTrue(assertThrows(Exception.class, () -> CryptographicUtilities.checkPrivateKeyFitsPublicKey(null, keyPair.getPublic())).getMessage().contains("PrivateKey"));
		assertTrue(assertThrows(Exception.class, () -> CryptographicUtilities.checkPrivateKeyFitsPublicKey(keyPair.getPrivate(), null)).getMessage().contains("PublicKey"));
	}

	@Test
	public void testNonMatchingKeys() throws Exception {
		final KeyPair keyPair1 = KeyPairUtilities.createEllipticCurveKeyPair(256);
		final KeyPair keyPair2 = KeyPairUtilities.createEllipticCurveKeyPair(256);
		assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(keyPair1.getPrivate(), keyPair1.getPublic()));
		assertFalse(CryptographicUtilities.checkPrivateKeyFitsPublicKey(keyPair1.getPrivate(), keyPair2.getPublic()));
	}

	@Test
	public void testEdDsaPrivateKeyWithOtherPublicKey() throws Exception {
		final KeyPair edKeyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final KeyPair ecKeyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		assertTrue(assertThrows(Exception.class, () -> CryptographicUtilities.checkPrivateKeyFitsPublicKey(edKeyPair.getPrivate(), ecKeyPair.getPublic())).getMessage().contains("not an EdDSA public key"));
	}

	@Test
	public void testBouncyCastleEdDsaKeys() throws Exception {
		// BouncyCastle keys report the algorithm names "Ed25519" and "Ed448" instead of "EdDSA"
		final KeyPair ed25519KeyPair = KeyPairGenerator.getInstance("Ed25519", BC_PROVIDER).generateKeyPair();
		assertEquals("Ed25519", ed25519KeyPair.getPrivate().getAlgorithm());
		assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(ed25519KeyPair.getPrivate(), ed25519KeyPair.getPublic()));

		final KeyPair ed448KeyPair = KeyPairGenerator.getInstance("Ed448", BC_PROVIDER).generateKeyPair();
		assertEquals("Ed448", ed448KeyPair.getPrivate().getAlgorithm());
		assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(ed448KeyPair.getPrivate(), ed448KeyPair.getPublic()));
	}

	@Test
	public void testEcDsaCurveNames() throws Exception {
		for (final int curveId : new int[] { 256, 384, 521 }) {
			final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(curveId);
			assertEquals("nistp" + curveId, CryptographicUtilities.getEcDsaEllipticCurveName((ECPublicKey) keyPair.getPublic()));
			assertEquals("nistp" + curveId, CryptographicUtilities.getEcDsaEllipticCurveName((ECPrivateKey) keyPair.getPrivate()));
		}
	}

	@Test
	public void testUnsupportedEcDsaCurve() throws Exception {
		final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
		generator.initialize(new ECGenParameterSpec("secp256k1"));
		final KeyPair keyPair = generator.generateKeyPair();
		assertTrue(assertThrows(Exception.class, () -> CryptographicUtilities.getEcDsaEllipticCurveName((ECPublicKey) keyPair.getPublic())).getMessage().contains("Unknown SSH EcDSA curve OID"));
		assertTrue(assertThrows(Exception.class, () -> CryptographicUtilities.getEcDsaEllipticCurveName((ECPrivateKey) keyPair.getPrivate())).getMessage().contains("Unknown SSH EcDSA curve OID"));
	}
}
