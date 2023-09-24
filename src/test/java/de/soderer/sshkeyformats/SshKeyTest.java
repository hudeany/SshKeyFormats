package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.data.CryptographicUtilities;
import de.soderer.sshkeyformats.data.KeyPairUtilities;

@SuppressWarnings("static-method")
public class SshKeyTest {
	private static char[] TESTPASSWORD = "pÄsswOrd".toCharArray();
	private static String TESTCOMMENT = "Test key with Ümlaut";

	@Test
	public void testTestKeyFiles() throws Exception {
		final ByteArrayOutputStream authorizedKeysBuffer = new ByteArrayOutputStream();
		int numberOfAuthorizedKeys = 0;
		boolean overallSuccess = true;
		for (final File sshkeyFileDirectory : new File(getClass().getClassLoader().getResource("sshkey").toURI()).listFiles()) {
			for (final File sshkeyFile : sshkeyFileDirectory.listFiles()) {
				final String filename = sshkeyFile.getName();
				try {
					if (endsWithIgnoreCase(filename, ".ppk")) {
						final String md5Hash = filename.substring(filename.indexOf("(") + 1, filename.indexOf(")"));
						try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							final SshKey sshKey;
							if (filename.toLowerCase().contains("_no_password_")) {
								sshKey = SshKeyReader.readKey(inputStream, null);
							} else {
								sshKey = SshKeyReader.readKey(inputStream, "pÄsswOrd".toCharArray());
							}
							Assert.assertEquals(filename, md5Hash.toUpperCase(), sshKey.getMd5Fingerprint().toUpperCase().replace(":", ""));

							final boolean keyCheckSuccess = CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic());
							if (!keyCheckSuccess) {
								System.out.println("Signature sign/verify test failed with file: " + filename + ": " + keyCheckSuccess);
							}
							overallSuccess &= keyCheckSuccess;
						}

						try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							final List<SshKey> publicSshKeys = SshKeyReader.readAllPublicKeys(inputStream);
							if (publicSshKeys != null && publicSshKeys.size() > 0) {
								Assert.assertEquals(filename, md5Hash.toUpperCase(), publicSshKeys.get(0).getMd5Fingerprint().toUpperCase().replace(":", ""));
							}
						}
					} else if (endsWithIgnoreCase(filename, ".pub")) {
						final String md5Hash = filename.substring(filename.indexOf("(") + 1, filename.indexOf(")"));
						try (final InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							final SshKey sshKey = SshKeyReader.readKey(inputStream, null);
							final String readMd5Fingerprint = sshKey.getMd5Fingerprint();
							Assert.assertEquals(filename, md5Hash.toUpperCase(), readMd5Fingerprint.toUpperCase().replace(":", ""));
						}

						try (final InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							authorizedKeysBuffer.write(("#" + filename + "\n").getBytes(StandardCharsets.UTF_8));
							copy(inputStream, authorizedKeysBuffer);
							authorizedKeysBuffer.write(("\n\n").getBytes(StandardCharsets.UTF_8));
							numberOfAuthorizedKeys++;
						}
					} else if (endsWithIgnoreCase(filename, ".pem") && filename.toLowerCase().contains("public")) {
						final String md5Hash = filename.substring(filename.indexOf("(") + 1, filename.indexOf(")"));
						try (final InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							final SshKey sshKey = SshKeyReader.readKey(inputStream, null);
							final String readMd5Fingerprint = sshKey.getMd5Fingerprint();
							Assert.assertEquals(filename, md5Hash.toUpperCase(), readMd5Fingerprint.toUpperCase().replace(":", ""));
						}
					} else if (endsWithIgnoreCase(filename, ".pem") && filename.toLowerCase().contains("private")) {
						final String md5Hash = filename.substring(filename.indexOf("(") + 1, filename.indexOf(")"));
						try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							final SshKey sshKey;
							if (filename.toLowerCase().contains("_no_password_")) {
								sshKey = SshKeyReader.readKey(inputStream, null);
							} else {
								sshKey = SshKeyReader.readKey(inputStream, "pÄsswOrd".toCharArray());
							}
							if (sshKey.getKeyPair().getPublic() != null) {
								Assert.assertEquals(filename, md5Hash.toUpperCase(), sshKey.getMd5Fingerprint().toUpperCase().replace(":", ""));

								final boolean keyCheckSuccess = CryptographicUtilities.checkPrivateKeyFitsPublicKey(sshKey.getKeyPair().getPrivate(), sshKey.getKeyPair().getPublic());
								if (!keyCheckSuccess) {
									System.out.println("Signature sign/verify test failed with file: " + filename + ": " + keyCheckSuccess);
								}
								overallSuccess &= keyCheckSuccess;
							}
						}

						try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sshkey/" + sshkeyFileDirectory.getName() + "/" + filename)) {
							final List<SshKey> publicSshKeys = SshKeyReader.readAllPublicKeys(inputStream);
							if (publicSshKeys != null && publicSshKeys.size() > 0) {
								Assert.assertEquals(filename, md5Hash.toUpperCase(), publicSshKeys.get(0).getMd5Fingerprint().toUpperCase().replace(":", ""));
							}
						}
					}
				} catch (final Exception e) {
					System.out.println("Signature sign/verify test failed with file: " + filename);
					e.printStackTrace();
					overallSuccess = false;
				}
			}
		}
		Assert.assertTrue("At least one keyfile test had errors", overallSuccess);

		final List<SshKey> publicKeys = SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(authorizedKeysBuffer.toByteArray()));
		Assert.assertEquals(numberOfAuthorizedKeys, publicKeys.size());
	}

	@Test
	public void testRsa() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);
		testKeyPair(keyPair);
	}

	@Test
	public void testDsa() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createDsaKeyPair(1024);
		testKeyPair(keyPair);
	}

	@Test
	public void testEc256() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");
		testKeyPair(keyPair);
	}

	@Test
	public void testSimpleEc256() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(256);
		testKeyPair(keyPair);
	}

	@Test
	public void testEc384() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");
		testKeyPair(keyPair);
	}

	@Test
	public void testSimpleEc384() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(384);
		testKeyPair(keyPair);
	}

	@Test
	public void testEc521() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp521");
		testKeyPair(keyPair);
	}

	@Test
	public void testSimpleEc521() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair(521);
		testKeyPair(keyPair);
	}

	@Test
	public void testEd25519() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();
		testKeyPair(keyPair);
	}

	@Test
	public void testEd448() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd448CurveKeyPair();
		testKeyPair(keyPair);
	}

	private void testKeyPair(final KeyPair keyPair) throws Exception {
		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] privateKeyPkcs8Data;
		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePKCS8Format(byteArrayOutStream, keyPair, TESTPASSWORD, null);
			byteArrayOutStream.flush();
			privateKeyPkcs8Data = byteArrayOutStream.toByteArray();
		}

		if (!new String(privateKeyPkcs8Data, StandardCharsets.UTF_8).contains("----BEGIN ")) {
			Assert.fail();
		}

		SshKey openSshKey1;
		try (InputStream inputStream = new ByteArrayInputStream(privateKeyPkcs8Data)) {
			openSshKey1 = SshKeyReader.readKey(inputStream, TESTPASSWORD);
		}
		if (openSshKey1.getKeyPair().getPublic() != null) {
			final String readsha256Fingerprint = openSshKey1.getSha256FingerprintBase64();
			Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		}

		final byte[] publicKeyPkcs1Data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePKCS1Format(byteArrayOutStream, keyPair.getPublic());
			byteArrayOutStream.flush();
			publicKeyPkcs1Data = byteArrayOutStream.toByteArray();
		}

		if (!new String(publicKeyPkcs1Data, StandardCharsets.UTF_8).contains("---- BEGIN SSH2 PUBLIC KEY ----")) {
			Assert.fail();
		}
		final SshKey openSshKey2;
		try (InputStream inputStream = new ByteArrayInputStream(publicKeyPkcs1Data)) {
			openSshKey2 = SshKeyReader.readKey(inputStream, TESTPASSWORD);
		}
		Assert.assertEquals(sha256Fingerprint, openSshKey2.getSha256FingerprintBase64());

		final byte[] keypairPkcs1Data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePKCS8Format(byteArrayOutStream, keyPair, null, null);
			SshKeyWriter.writePKCS1Format(byteArrayOutStream, keyPair.getPublic());
			byteArrayOutStream.flush();
			keypairPkcs1Data = byteArrayOutStream.toByteArray();
		}

		if (!new String(keypairPkcs1Data, StandardCharsets.UTF_8).contains("---- BEGIN SSH2 PUBLIC KEY ----")) {
			Assert.fail();
		}
		final SshKey openSshKey3;
		try (InputStream inputStream = new ByteArrayInputStream(keypairPkcs1Data)) {
			openSshKey3 = SshKeyReader.readKey(inputStream, TESTPASSWORD);
		}
		if (openSshKey3.getKeyPair().getPublic() != null) {
			Assert.assertEquals(sha256Fingerprint, openSshKey3.getSha256FingerprintBase64());
		}
	}

	@Test
	public void test_PuttyVersion2() throws Exception {
		final SshKey sshKey = new SshKey(SshKeyFormat.Putty2, "TestKey (ÄÖÜäöüß)", KeyPairUtilities.createRsaKeyPair(2048));

		final ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, sshKey, "passwörd".toCharArray());

		final SshKey sshKey2 = SshKeyReader.readKey(new ByteArrayInputStream(byteArrayOutStream.toByteArray()), "passwörd".toCharArray());

		final ByteArrayOutputStream outputNoPassword = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion2Key(outputNoPassword, sshKey, null);

		final SshKey sshKey3 = SshKeyReader.readKey(new ByteArrayInputStream(outputNoPassword.toByteArray()), null);

		if (sshKey.getMd5Fingerprint() == null || sshKey.getMd5Fingerprint().length() == 0
				|| !sshKey.getMd5Fingerprint().equals(sshKey2.getMd5Fingerprint())
				|| !sshKey.getMd5Fingerprint().equals(sshKey3.getMd5Fingerprint())) {
			Assert.fail();
		}

		final String authKey = sshKey2.encodePublicKeyForAuthorizedKeys();
		if (authKey == null || authKey.length() == 0) {
			Assert.fail();
		}

		final ByteArrayOutputStream output2 = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output2, sshKey2.getKeyPair(), null, null);
		if (output2.toByteArray() == null || output2.toByteArray().length == 0) {
			Assert.fail();
		}

		final String sha256Fingerprint = sshKey.getSha256FingerprintBase64();
		if (sha256Fingerprint == null || sha256Fingerprint.length() == 0) {
			Assert.fail();
		}

		final ByteArrayOutputStream output3 = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output3, sshKey.getKeyPair(), "DES-EDE3-CBC", "passwörd".toCharArray(), null);
		if (output3.toByteArray() == null || output3.toByteArray().length == 0) {
			Assert.fail();
		}
	}

	@Test
	public void test_Rsa_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Dsa_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createDsaKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
	}

	@Test
	public void test_Ec256_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec384_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec521_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp521");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ed25519_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ed448_PuttyVersion2() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd448CurveKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion2Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty2, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-2"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_PuttyVersion3() throws Exception {
		final SshKey sshKey = new SshKey(SshKeyFormat.Putty3, "TestKey (ÄÖÜäöüß)", KeyPairUtilities.createRsaKeyPair(2048));

		final ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, sshKey, "passwörd".toCharArray());

		final SshKey sshKey2 = SshKeyReader.readKey(new ByteArrayInputStream(byteArrayOutStream.toByteArray()), "passwörd".toCharArray());

		final ByteArrayOutputStream outputNoPassword = new ByteArrayOutputStream();
		SshKeyWriter.writePuttyVersion3Key(outputNoPassword, sshKey, null);

		final SshKey sshKey3 = SshKeyReader.readKey(new ByteArrayInputStream(outputNoPassword.toByteArray()), null);

		if (sshKey.getMd5Fingerprint() == null || sshKey.getMd5Fingerprint().length() == 0
				|| !sshKey.getMd5Fingerprint().equals(sshKey2.getMd5Fingerprint())
				|| !sshKey.getMd5Fingerprint().equals(sshKey3.getMd5Fingerprint())) {
			Assert.fail();
		}

		final String authKey = sshKey2.encodePublicKeyForAuthorizedKeys();
		if (authKey == null || authKey.length() == 0) {
			Assert.fail();
		}

		final ByteArrayOutputStream output2 = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output2, sshKey2.getKeyPair(), null, null);
		if (output2.toByteArray() == null || output2.toByteArray().length == 0) {
			Assert.fail();
		}

		final String sha256Fingerprint = sshKey.getSha256FingerprintBase64();
		if (sha256Fingerprint == null || sha256Fingerprint.length() == 0) {
			Assert.fail();
		}

		final ByteArrayOutputStream output3 = new ByteArrayOutputStream();
		SshKeyWriter.writePKCS8Format(output3, sshKey.getKeyPair(), "DES-EDE3-CBC", "passwörd".toCharArray(), null);
		if (output3.toByteArray() == null || output3.toByteArray().length == 0) {
			Assert.fail();
		}
	}

	@Test
	public void test_Rsa_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Dsa_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createDsaKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
	}

	@Test
	public void test_Ec256_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec384_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec521_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp521");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ed25519_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ed448_PuttyVersion3() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd448CurveKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writePuttyVersion3Key(byteArrayOutStream, new SshKey(SshKeyFormat.Putty3, TESTCOMMENT, keyPair), TESTPASSWORD);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("PuTTY-User-Key-File-3"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Rsa_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createRsaKeyPair(2048);

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Dsa_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createDsaKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec256_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp256");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec384_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp384");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ec521_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEllipticCurveKeyPair("nistp521");

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ed25519_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd25519CurveKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	@Test
	public void test_Ed448_OpenSshv1() throws Exception {
		final KeyPair keyPair = KeyPairUtilities.createEd448CurveKeyPair();

		final String sha256Fingerprint = KeyPairUtilities.getSha256FingerprintBase64(keyPair);

		final byte[] data;

		try (ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream()) {
			SshKeyWriter.writeOpenSshv1Key(byteArrayOutStream, new SshKey(SshKeyFormat.OpenSSHv1, TESTCOMMENT, keyPair), TESTPASSWORD, null);
			byteArrayOutStream.flush();
			data = byteArrayOutStream.toByteArray();
		}

		Assert.assertTrue(new String(data, StandardCharsets.UTF_8).contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		final SshKey readSshKey = SshKeyReader.readKey(new ByteArrayInputStream(data), TESTPASSWORD);
		final String readsha256Fingerprint = readSshKey.getSha256FingerprintBase64();
		Assert.assertEquals(sha256Fingerprint, readsha256Fingerprint);
		Assert.assertEquals(TESTCOMMENT, readSshKey.getComment());
		Assert.assertTrue(CryptographicUtilities.checkPrivateKeyFitsPublicKey(readSshKey.getKeyPair().getPrivate(), readSshKey.getKeyPair().getPublic()));
	}

	private static boolean endsWithIgnoreCase(final String data, final String suffix) {
		if (data == suffix) {
			// both null or same object
			return true;
		} else if (data == null) {
			// data is null but suffix is not
			return false;
		} else if (suffix == null) {
			// suffix is null but data is not
			return true;
		} else if (data.toLowerCase().endsWith(suffix.toLowerCase())) {
			// both are set, so ignore the case for standard endsWith-method
			return true;
		} else {
			// anything else
			return false;
		}
	}

	private static long copy(final InputStream inputStream, final OutputStream outputStream) throws IOException {
		final byte[] buffer = new byte[4096];
		int lengthRead = -1;
		long bytesCopied = 0;
		while ((lengthRead = inputStream.read(buffer)) > -1) {
			outputStream.write(buffer, 0, lengthRead);
			bytesCopied += lengthRead;
		}
		outputStream.flush();
		return bytesCopied;
	}
}
