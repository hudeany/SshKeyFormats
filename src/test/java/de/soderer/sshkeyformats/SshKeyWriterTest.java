package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateKeySpec;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.data.Asn1Codec;
import de.soderer.sshkeyformats.data.CryptographicUtilities;
import de.soderer.sshkeyformats.data.KeyPairUtilities;

/**
 * Tests of {@link SshKeyWriter} for the DER format, the parameter checks and the password encodings.
 */
@SuppressWarnings("static-method")
public class SshKeyWriterTest {
	private static final char[] PASSWORD = "password".toCharArray();
	private static final char[] NON_LATIN1_PASSWORD = "pass€word".toCharArray();

	@SuppressWarnings("deprecation")
	private static KeyPair[] createKeyPairsOfAllAlgorithms() throws Exception {
		return new KeyPair[] {
				KeyPairUtilities.createRsaKeyPair(2048),
				KeyPairUtilities.createDsaKeyPair(1024),
				KeyPairUtilities.createEllipticCurveKeyPair(256),
				KeyPairUtilities.createEllipticCurveKeyPair(384),
				KeyPairUtilities.createEllipticCurveKeyPair(521),
				KeyPairUtilities.createEd25519CurveKeyPair(),
				KeyPairUtilities.createEd448CurveKeyPair() };
	}

	@Test
	public void testDerFormatOfAllAlgorithms() throws Exception {
		for (final KeyPair keyPair : createKeyPairsOfAllAlgorithms()) {
			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			SshKeyWriter.writeDerFormat(output, keyPair);
			final byte[] derData = output.toByteArray();
			assertEquals(Asn1Codec.DER_TAG_SEQUENCE, Asn1Codec.readDerTag(derData).getTagId());

			// The DER data is the content of the corresponding PEM block
			final ByteArrayOutputStream pemOutput = new ByteArrayOutputStream();
			SshKeyWriter.writePKCS8Format(pemOutput, keyPair, null, null);
			assertArrayEquals(derData, TestKeyData.decodePem(pemOutput.toString(StandardCharsets.UTF_8)), keyPair.getPublic().getAlgorithm());
		}
	}

	@Test
	public void testPkcs8FormatPasswordEncodings() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		final char[] latin1Password = "pässword".toCharArray();
		for (final java.nio.charset.Charset charset : new java.nio.charset.Charset[] { null, StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1 }) {
			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			// An empty cipher name selects the default cipher
			SshKeyWriter.writePKCS8Format(output, keyPair, " ", latin1Password, charset);
			assertTrue(output.toString(StandardCharsets.UTF_8).contains("DEK-Info: AES-128-CBC,"));
			// The reader tries both encodings
			final SshKey sshKey = SshKeyReader.readKey(new ByteArrayInputStream(output.toByteArray()), latin1Password);
			assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint(), String.valueOf(charset));
		}
	}

	@Test
	public void testPkcs8FormatErrors() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writePKCS8Format(new ByteArrayOutputStream(), keyPair, PASSWORD, StandardCharsets.US_ASCII)).getMessage().contains("Unsupported passwordEncoding"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writePKCS8Format(new ByteArrayOutputStream(), keyPair, NON_LATIN1_PASSWORD, StandardCharsets.ISO_8859_1)).getMessage().contains("not representable in ISO-8859-1"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writePKCS8Format(new ByteArrayOutputStream(), keyPair, "BF-CBC", PASSWORD, null)).getMessage().contains("Unknown key encryption cipher"));
	}

	@Test
	public void testPrivateKeyChecks() throws Exception {
		final KeyPair ecKeyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		assertThrows(Exception.class, () -> SshKeyWriter.writeDerFormat(new ByteArrayOutputStream(), null));
		assertThrows(Exception.class, () -> SshKeyWriter.writeDerFormat(new ByteArrayOutputStream(), new KeyPair(ecKeyPair.getPublic(), null)));
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writeDerFormat(new ByteArrayOutputStream(), new KeyPair(null, ecKeyPair.getPrivate()))).getMessage().contains("publicKey"));

		// RSA keys without CRT parameters cannot be written
		final KeyPair rsaKeyPair = KeyPairUtilities.createRsaKeyPair(2048);
		final RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
		final PrivateKey nonCrtKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(crtKey.getModulus(), crtKey.getPrivateExponent()));
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writePKCS8Format(new ByteArrayOutputStream(), new KeyPair(rsaKeyPair.getPublic(), nonCrtKey), null, null)).getMessage().contains("without CRT parameters"));
	}

	@Test
	public void testOpenSshv1Errors() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final SshKey sshKey = new SshKey(SshKeyFormat.OpenSSHv1, "comment", keyPair);
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writeOpenSshv1Key(new ByteArrayOutputStream(), sshKey, PASSWORD, StandardCharsets.UTF_16)).getMessage().contains("Unsupported passwordAndCommentEncoding"));
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writeOpenSshv1Key(new ByteArrayOutputStream(), sshKey, NON_LATIN1_PASSWORD, StandardCharsets.ISO_8859_1)).getMessage().contains("password"));
		final SshKey nonLatin1Comment = new SshKey(SshKeyFormat.OpenSSHv1, "5€", keyPair);
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writeOpenSshv1Key(new ByteArrayOutputStream(), nonLatin1Comment, null, StandardCharsets.ISO_8859_1)).getMessage().contains("comment"));

		final SshKey publicKeyOnly = new SshKey(SshKeyFormat.OpenSSHv1, null, new KeyPair(keyPair.getPublic(), null));
		assertTrue(assertThrows(Exception.class, () -> SshKeyWriter.writeOpenSshv1Key(new ByteArrayOutputStream(), publicKeyOnly, null, null)).getMessage().contains("privateKey"));
		final SshKey privateKeyOnly = new SshKey(SshKeyFormat.OpenSSHv1, null, new KeyPair(null, keyPair.getPrivate()));
		assertThrows(Exception.class, () -> SshKeyWriter.writeOpenSshv1Key(new ByteArrayOutputStream(), privateKeyOnly, null, null));
	}

	@Test
	public void testOpenSshv1WithIsoEncodingAndWithoutComment() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(521);
		final char[] latin1Password = "pässword".toCharArray();
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(output, new SshKey(SshKeyFormat.OpenSSHv1, null, keyPair), latin1Password, StandardCharsets.ISO_8859_1);
		final SshKey sshKey = SshKeyReader.readKey(new ByteArrayInputStream(output.toByteArray()), latin1Password);
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint());
		assertEquals(null, sshKey.getComment());
	}

	@Test
	public void testPuttyKeysOfAllAlgorithmsWithNonLatin1Password() throws Exception {
		// Passwords outside of ISO-8859-1 are encoded in UTF-8
		for (final KeyPair keyPair : createKeyPairsOfAllAlgorithms()) {
			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			SshKeyWriter.writePuttyVersion2Key(output, new SshKey(SshKeyFormat.Putty2, "comment", keyPair), NON_LATIN1_PASSWORD);
			final SshKey sshKey = SshKeyReader.readKey(new ByteArrayInputStream(output.toByteArray()), NON_LATIN1_PASSWORD);
			assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic()), keyPair.getPublic().getAlgorithm());
		}
	}

	@Test
	public void testPuttyKeyWithoutPrivateKey() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		final SshKey publicKeyOnly = new SshKey(SshKeyFormat.Putty2, null, new KeyPair(keyPair.getPublic(), null));
		assertThrows(Exception.class, () -> SshKeyWriter.writePuttyVersion2Key(new ByteArrayOutputStream(), publicKeyOnly, null));
		assertThrows(Exception.class, () -> SshKeyWriter.writePuttyVersion3Key(new ByteArrayOutputStream(), publicKeyOnly, null));
	}

	@Test
	public void testEcScalarWithLeadingZeroBytes() throws Exception {
		// A very short private value must be written with leading zero bytes, the public key is derived by the reader
		final BigInteger s = BigInteger.valueOf(123456789);
		final byte[] sec1Key = TestKeyData.derSequence(TestKeyData.derInteger(1), TestKeyData.derOctetString(s.toByteArray()), TestKeyData.derContext0(TestKeyData.derOid("1.2.840.10045.3.1.7")));
		final KeyPair keyPair = SshKeyReader.readKey(new ByteArrayInputStream(TestKeyData.pem("EC PRIVATE KEY", sec1Key)), null).getKeyPair();

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output, keyPair, null, null);
		final SshKey sshKey = SshKeyReader.readKey(new ByteArrayInputStream(output.toByteArray()), null);
		assertEquals(s, ((java.security.interfaces.ECPrivateKey) sshKey.getKeyPair().getPrivate()).getS());
		assertEquals(KeyPairUtilities.getMd5Fingerprint(keyPair), sshKey.getMd5Fingerprint());

		// The OpenSSH v1 and PuTTY formats write the scalar as mpint
		final ByteArrayOutputStream openSshOutput = new ByteArrayOutputStream();
		SshKeyWriter.writeOpenSshv1Key(openSshOutput, new SshKey(SshKeyFormat.OpenSSHv1, null, keyPair), null, null);
		assertEquals(s, ((java.security.interfaces.ECPrivateKey) SshKeyReader.readKey(new ByteArrayInputStream(openSshOutput.toByteArray()), null).getKeyPair().getPrivate()).getS());
	}
}
