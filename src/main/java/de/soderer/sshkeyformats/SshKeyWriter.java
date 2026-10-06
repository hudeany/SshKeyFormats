package de.soderer.sshkeyformats;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.Asn1Codec;
import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;
import de.soderer.sshkeyformats.data.BCryptPBKDF;
import de.soderer.sshkeyformats.data.CryptographicUtilities;
import de.soderer.sshkeyformats.data.KeyPairUtilities;
import de.soderer.sshkeyformats.data.OID;
import de.soderer.sshkeyformats.data.Password;

/**
 * Writer for SSH public and private keys with optional password protection<br />
 * <br />
 * Supported key formats:<br />
 * - OpenSSHv1 (proprietary format of OpenSSH, "-----BEGIN OPENSSH PRIVATE KEY-----")<br />
 * - OpenSSL, PKCS#8 ("-----BEGIN RSA/DSA/EC PRIVATE KEY-----", doesn't support EdDSA)<br />
 * - PuTTY key version 2 ("PuTTY-User-Key-File-2: ...")<br />
 * - PuTTY key version 3 ("PuTTY-User-Key-File-3: ...")<br />
 * - PKCS#1 ("---- BEGIN SSH2 PRIVATE KEY ----", no password encryption)<br />
 * <br />
 * Supported cipher algorithms:<br />
 * - RSA<br />
 * - DSA<br />
 * - EC / ECDSA (nistp256, nistp384, nistp521)<br />
 * - EdDSA (Ed25519, Ed448)<br />
 * <br />
 */
public class SshKeyWriter {
	/**
	 * Converts this keypair into protected OpenSSH format<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import<br />
	 * <br />
	 * passwordEncoding is used for encoding of password:<br />
	 *	- default is "UTF-8"<br />
	 *	- other value may be "ISO-8859-1"<br />
	 * <br />
	 * Watchout for PuTTY's key import can only use special characters in passwords, if the ISO-8859-1 encoding is used for passwordAndCommentEncoding.<br />
	 * But OpenSSH's default encoding is UTF-8<br />

	 * @param outputStream the stream receiving the encoded key
	 * @param sshKey the SSH key to write
	 * @param passwordChars the optional password used to encrypt the private key
	 * @param passwordAndCommentEncoding the character encoding for the password and comment, or {@code null} for UTF-8
	 * @throws Exception if the key cannot be encoded or written
	 */
	public static void writeOpenSshv1Key(final OutputStream outputStream, final SshKey sshKey, final char[] passwordChars, Charset passwordAndCommentEncoding) throws Exception {
		if (passwordAndCommentEncoding == null) {
			passwordAndCommentEncoding = StandardCharsets.UTF_8;
		}

		final byte[] publicKeyData = KeyPairUtilities.getPublicKeyBytes(sshKey.getKeyPair().getPublic());
		final byte[] privateKeyData = getOpenSshv1PrivateKeyBytes(sshKey, passwordAndCommentEncoding);

		final BlockDataWriter keyDataBuffer = new BlockDataWriter();
		// Storage format name
		keyDataBuffer.writeZeroLimitedData("openssh-key-v1".getBytes(StandardCharsets.UTF_8));

		final boolean encrypt = passwordChars != null && passwordChars.length > 0;
		byte[] kdfInitialVectorBytes = null;
		int kdfRounds = 0;
		if (!encrypt) {
			// EncryptionCipherName
			keyDataBuffer.writeData("none".getBytes(StandardCharsets.UTF_8));
			// kdf: key derivation function
			keyDataBuffer.writeData("none".getBytes(StandardCharsets.UTF_8));
			// kdf info
			keyDataBuffer.writeSimpleInt(0);
		} else {
			// EncryptionCipherName
			keyDataBuffer.writeData("aes256-ctr".getBytes(StandardCharsets.UTF_8));
			// kdf: key derivation function
			keyDataBuffer.writeData("bcrypt".getBytes(StandardCharsets.UTF_8));
			// kdf info
			kdfInitialVectorBytes = new byte[16];
			new SecureRandom().nextBytes(kdfInitialVectorBytes);
			kdfRounds = 16;
			final BlockDataWriter kdfInfoWriter = new BlockDataWriter();
			kdfInfoWriter.writeData(kdfInitialVectorBytes);
			kdfInfoWriter.writeSimpleInt(kdfRounds);
			keyDataBuffer.writeData(kdfInfoWriter.toByteArray());
		}

		// Amount of stored keys
		keyDataBuffer.writeSimpleInt(1);

		// Public key
		keyDataBuffer.writeData(publicKeyData);

		// Private key
		try (final Password password = new Password(copyPasswordForEncryption(passwordChars))) {
			if (password.hasPassword()) {
				// Encrypt private key data by bcrypt pbkdf
				// Putty uses "ISO-8859-1" for password encoding, even for those keys stored in OpenSSHv1 and OpenSSL format
				// "ssh-keygen" on Linx uses UTF-8 for password encoding
				final byte[] privateKeyDataBytesEncrypted;
				final byte[] passwordBytes = StandardCharsets.UTF_8.equals(passwordAndCommentEncoding) ? password.getPasswordBytesUtfEncoded() : password.getPasswordBytesIsoEncoded();
				byte[] derivedKeyBytes = null;
				try {
					derivedKeyBytes = new byte[48];
					new BCryptPBKDF().derivePassword(passwordBytes, kdfInitialVectorBytes, kdfRounds, derivedKeyBytes);
					final SecretKey secretKey = new SecretKeySpec(derivedKeyBytes, 0, 32, "AES");
					final AlgorithmParameterSpec iv = new IvParameterSpec(derivedKeyBytes, 32, 16);

					final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
					cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

					privateKeyDataBytesEncrypted = cipher.doFinal(privateKeyData);
				} finally {
					clear(derivedKeyBytes);
				}

				keyDataBuffer.writeData(privateKeyDataBytesEncrypted);
			} else {
				keyDataBuffer.writeData(privateKeyData);
			}
		}

		outputStream.write(("-----BEGIN OPENSSH PRIVATE KEY-----\n").getBytes(StandardCharsets.UTF_8));
		outputStream.write(toWrappedBase64(keyDataBuffer.toByteArray(), 64, "\n").getBytes(StandardCharsets.UTF_8));
		outputStream.write(("\n-----END OPENSSH PRIVATE KEY-----\n").getBytes(StandardCharsets.UTF_8));
	}

	private static byte[] getOpenSshv1PrivateKeyBytes(final SshKey sshKey, final Charset commentCharset) throws Exception {
		if (sshKey.getKeyPair().getPrivate() == null) {
			throw new Exception("Invalid empty privateKey parameter");
		} else {
			final BlockDataWriter privateKeyWriter = new BlockDataWriter();
			final int checkInt = new SecureRandom().nextInt();
			privateKeyWriter.writeSimpleInt(checkInt);
			privateKeyWriter.writeSimpleInt(checkInt);

			if (sshKey.getKeyPair().getPrivate() instanceof RSAPrivateCrtKey) {
				privateKeyWriter.writeData(Algorithm.RSA.getSshAlgorithmId().getBytes(StandardCharsets.UTF_8));
				final RSAPrivateCrtKey privateKeyRSA = (RSAPrivateCrtKey) sshKey.getKeyPair().getPrivate();
				privateKeyWriter.writeBigInt(privateKeyRSA.getModulus());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPublicExponent());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrivateExponent());
				privateKeyWriter.writeBigInt(privateKeyRSA.getCrtCoefficient());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeP());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeQ());
			} else if (sshKey.getKeyPair().getPrivate() instanceof DSAPrivateKey) {
				privateKeyWriter.writeData(Algorithm.DSA.getSshAlgorithmId().getBytes(StandardCharsets.UTF_8));
				final DSAPrivateKey privateKeyDSA = (DSAPrivateKey) sshKey.getKeyPair().getPrivate();
				final DSAPublicKey publicKeyDSA = (DSAPublicKey) sshKey.getKeyPair().getPublic();
				privateKeyWriter.writeBigInt(privateKeyDSA.getParams().getP());
				privateKeyWriter.writeBigInt(privateKeyDSA.getParams().getQ());
				privateKeyWriter.writeBigInt(privateKeyDSA.getParams().getG());
				privateKeyWriter.writeBigInt(publicKeyDSA.getY());
				privateKeyWriter.writeBigInt(privateKeyDSA.getX());
			} else if (sshKey.getKeyPair().getPrivate() instanceof ECPrivateKey) {
				final ECPrivateKey privateKeyEC = (ECPrivateKey) sshKey.getKeyPair().getPrivate();
				final ECPublicKey publicKeyEC = (ECPublicKey) sshKey.getKeyPair().getPublic();
				final String ecCurveName = CryptographicUtilities.getEcDsaEllipticCurveName(publicKeyEC);
				privateKeyWriter.writeData(("ecdsa-sha2-" + ecCurveName).getBytes(StandardCharsets.UTF_8));
				privateKeyWriter.writeData((ecCurveName).getBytes(StandardCharsets.UTF_8));
				final int coordinateLength = (publicKeyEC.getParams().getCurve().getField().getFieldSize() + 7) / 8;
				final byte[] eccKeyBlobBytes = new byte[1 + 2 * coordinateLength];
				eccKeyBlobBytes[0] = 0x04;
				final byte[] x = toFixedLength(publicKeyEC.getW().getAffineX(), coordinateLength);
				final byte[] y = toFixedLength(publicKeyEC.getW().getAffineY(), coordinateLength);
				System.arraycopy(x, 0, eccKeyBlobBytes, 1, coordinateLength);
				System.arraycopy(y, 0, eccKeyBlobBytes, 1 + coordinateLength, coordinateLength);
				privateKeyWriter.writeData(eccKeyBlobBytes);
				privateKeyWriter.writeBigInt(privateKeyEC.getS());
			} else if (sshKey.getKeyPair().getPrivate() instanceof EdECPrivateKey) {
				final EdECPrivateKey privateKeyEdEC = (EdECPrivateKey) sshKey.getKeyPair().getPrivate();
				final EdECPublicKey publicKeyEdEC = (EdECPublicKey) sshKey.getKeyPair().getPublic();
				if ("Ed25519".equalsIgnoreCase(publicKeyEdEC.getParams().getName())) {
					privateKeyWriter.writeData(Algorithm.ED25519.getSshAlgorithmId().getBytes(StandardCharsets.UTF_8));
				} else if ("Ed448".equalsIgnoreCase(publicKeyEdEC.getParams().getName())) {
					privateKeyWriter.writeData(Algorithm.ED448.getSshAlgorithmId().getBytes(StandardCharsets.UTF_8));
				} else {
					throw new Exception("Unknown EdDSA type: " + publicKeyEdEC.getParams().getName());
				}
				final byte[] publicKeyData = getEdDSAPublicKeyBytes(publicKeyEdEC);
				final byte[] privateKeyData = getEdDSAPrivateKeyBytes(privateKeyEdEC);
				privateKeyWriter.writeData(publicKeyData);
				final ByteArrayOutputStream keyDataBuffer = new ByteArrayOutputStream();
				keyDataBuffer.write(privateKeyData);
				keyDataBuffer.write(publicKeyData);
				privateKeyWriter.writeData(keyDataBuffer.toByteArray());
			} else {
				throw new IllegalArgumentException("Unsupported SSH cipher algorithm");
			}

			privateKeyWriter.writeData(sshKey.getComment() == null ? new byte[0] : sshKey.getComment().getBytes(commentCharset));

			// Padding
			final int paddingSize = 16 - (privateKeyWriter.toByteArray().length % 16);
			if (paddingSize < 16) {
				for (int i = 0; i < paddingSize; i++) {
					privateKeyWriter.writePaddingByte((byte) (i + 1));
				}
			}

			return privateKeyWriter.toByteArray();
		}
	}

	private static byte[] getEdDSAPrivateKeyBytes(final EdECPrivateKey privateKeyEdEC) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(privateKeyEdEC.getEncoded());
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());

		final BigInteger keyEncodingVersion = new BigInteger(derDataTags.get(0).getData());
		if (!BigInteger.ZERO.equals(keyEncodingVersion)) {
			throw new Exception("Invalid key data version found");
		}

		if (Asn1Codec.DER_TAG_SEQUENCE != derDataTags.get(1).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> sshAlgorithmDerTags = Asn1Codec.readDerTags(derDataTags.get(1).getData());
		final OID sshAlgorithmOid = new OID(sshAlgorithmDerTags.get(0).getData());
		if (OID.EDDSA25519_ALGORITHM.matches(sshAlgorithmOid.getByteArrayEncoding())
				|| OID.EDDSA448_ALGORITHM.matches(sshAlgorithmOid.getByteArrayEncoding())) {
			if (Asn1Codec.DER_TAG_OCTET_STRING != derDataTags.get(2).getTagId()) {
				throw new Exception("Invalid key data found");
			} else {
				final List<DerTag> privateKeyTags = Asn1Codec.readDerTags(derDataTags.get(2).getData());
				if (Asn1Codec.DER_TAG_OCTET_STRING != privateKeyTags.get(0).getTagId()) {
					throw new Exception("Invalid key data found");
				} else {
					return privateKeyTags.get(0).getData();
				}
			}
		} else {
			throw new Exception("Unknown ssh algorithm OID: " + sshAlgorithmOid.getStringEncoding());
		}
	}

	private static byte[] getEdDSAPublicKeyBytes(final EdECPublicKey publicKeyEdEC) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(publicKeyEdEC.getEncoded());
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());

		if (Asn1Codec.DER_TAG_SEQUENCE != derDataTags.get(0).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> sshAlgorithmDerTags = Asn1Codec.readDerTags(derDataTags.get(0).getData());
		final OID sshAlgorithmOid = new OID(sshAlgorithmDerTags.get(0).getData());
		if (OID.EDDSA25519_ALGORITHM.matches(sshAlgorithmOid.getByteArrayEncoding())
				|| OID.EDDSA448_ALGORITHM.matches(sshAlgorithmOid.getByteArrayEncoding())) {
			if (Asn1Codec.DER_TAG_BIT_STRING != derDataTags.get(1).getTagId()) {
				throw new Exception("Invalid key data found");
			} else {
				// Remove prefix "0"
				final byte[] dataWithLeadingZero = derDataTags.get(1).getData();
				return Arrays.copyOfRange(dataWithLeadingZero, 1, dataWithLeadingZero.length);
			}
		} else {
			throw new Exception("Unknown ssh algorithm OID: " + sshAlgorithmOid.getStringEncoding());
		}
	}

	private static class BlockDataWriter {
		private final ByteArrayOutputStream outputStream;
		private final DataOutput keyDataOutput;

		private BlockDataWriter() {
			outputStream = new ByteArrayOutputStream();
			keyDataOutput = new DataOutputStream(outputStream);
		}

		private byte[] toByteArray() {
			return outputStream.toByteArray();
		}

		private void writeSimpleInt(final int value) throws Exception {
			keyDataOutput.writeInt(value);
		}

		private void writeBigInt(final BigInteger value) throws Exception {
			writeData(value.toByteArray());
		}

		private void writeData(final byte[] value) throws Exception {
			keyDataOutput.writeInt(value.length);
			if (value.length > 0) {
				keyDataOutput.write(value);
			}
		}

		private void writeZeroLimitedData(final byte[] value) throws IOException, Exception {
			keyDataOutput.write(value);
			keyDataOutput.write(new byte[] { 0 });
		}

		private void writePaddingByte(final byte value) throws Exception {
			keyDataOutput.write(value);
		}
	}

	/**
	 * Converts this public key into unprotected PEM format (PKCS#1) for OpenSSH keys<br />
	 * This format includes public key data only and is NOT accepted by PuTTY's key import<br />

	 * @param outputStream the stream receiving the encoded key
	 * @param publicKey the public key to write
	 * @throws Exception if the key cannot be encoded or written
	 */
	public static void writePKCS1Format(final OutputStream outputStream, final PublicKey publicKey) throws Exception {
		final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(publicKey);

		final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, 64, "\r\n");

		final StringBuilder content = new StringBuilder();
		content.append("---- BEGIN SSH2 PUBLIC KEY ----").append("\r\n");
		content.append(publicKeyBase64).append("\r\n");
		content.append("---- END SSH2 PUBLIC KEY ----").append("\r\n");

		outputStream.write(content.toString().getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Converts this key into PEM format (PKCS#8) for OpenSSH keys<br />
	 * Using default encryption method "AES-128-CBC", when the optional password is set.<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import.<br />
	 * <br />
	 * Watchout for PuTTY's key import can only use special characters in passwords, if the ISO-8859-1 encoding is used for passwordEncoding.<br />
	 * But OpenSSH's default encoding is UTF-8<br />

	 * @param outputStream the stream receiving the encoded key
	 * @param keyPair the key pair to write
	 * @param passwordChars the optional password used to encrypt the private key
	 * @param passwordEncoding the character encoding for the password, or {@code null} for UTF-8
	 * @throws Exception if the key cannot be encoded or written
	 */
	public static void writePKCS8Format(final OutputStream outputStream, final KeyPair keyPair, final char[] passwordChars, final Charset passwordEncoding) throws Exception {
		writePKCS8Format(outputStream, keyPair, null, passwordChars, passwordEncoding);
	}

	/**
	 * Converts this keypair into protected PEM format (PKCS#8) for OpenSSL keys<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import<br />
	 * <br />
	 * keyEncryptionCipherName:<br />
	 *	- default is "AES-128-CBC"<br />
	 *	- other value may be "DES-EDE3-CBC"<br />
	 * <br />
	 * passwordEncoding is used for encoding of password:<br />
	 *	- default is "UTF-8"<br />
	 *	- other value may be "ISO-8859-1"<br />
	 * <br />
	 * Watchout for PuTTY's key import can only use special characters in passwords, if the ISO-8859-1 encoding is used for passwordEncoding.<br />
	 * But OpenSSH's default encoding is UTF-8<br />

	 * @param outputStream the stream receiving the encoded key
	 * @param keyPair the key pair to write
	 * @param keyEncryptionCipherName the encryption cipher name, or {@code null} for the default
	 * @param passwordChars the optional password used to encrypt the private key
	 * @param passwordEncoding the character encoding for the password, or {@code null} for UTF-8
	 * @throws Exception if the key cannot be encoded or written
	 */
	public static void writePKCS8Format(final OutputStream outputStream, final KeyPair keyPair, String keyEncryptionCipherName, final char[] passwordChars, final Charset passwordEncoding) throws Exception {
		String keyTypeName;
		byte[] keyData;
		final Algorithm algorithm = KeyPairUtilities.getAlgorithm(keyPair);
		if (Algorithm.RSA == algorithm) {
			keyTypeName = "RSA PRIVATE KEY";
			keyData = createRsaBinaryKey(keyPair);
		} else if (Algorithm.DSA == algorithm) {
			keyTypeName = "DSA PRIVATE KEY";
			keyData = createDsaBinaryKey(keyPair);
		} else if (Algorithm.NISTP256 == algorithm) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(keyPair, OID.ECDSA_CURVE_NISTP256);
		} else if (Algorithm.NISTP384 == algorithm) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(keyPair, OID.ECDSA_CURVE_NISTP384);
		} else if (Algorithm.NISTP521 == algorithm) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(keyPair, OID.ECDSA_CURVE_NISTP521);
		} else if (Algorithm.ED25519 == algorithm) {
			keyTypeName = "PRIVATE KEY";
			keyData = keyPair.getPrivate().getEncoded();
		} else if (Algorithm.ED448 == algorithm) {
			keyTypeName = "PRIVATE KEY";
			keyData = keyPair.getPrivate().getEncoded();
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithm.name());
		}

		final Map<String, String> headers = new LinkedHashMap<>();

		if (passwordChars != null && passwordChars.length > 0) {
			try (Password password = new Password(passwordChars.clone())) {
				final byte[] passwordBytes;
				if (passwordEncoding == null) {
					passwordBytes = password.getPasswordBytesUtfEncoded();
				} else if (StandardCharsets.UTF_8.equals(passwordEncoding)) {
					passwordBytes = password.getPasswordBytesUtfEncoded();
				} else if (StandardCharsets.ISO_8859_1.equals(passwordEncoding)) {
					passwordBytes = password.getPasswordBytesIsoEncoded();
				} else {
					throw new Exception("Unsupported passwordEncoding: " + passwordEncoding.name());
				}

				if (keyEncryptionCipherName == null || "".equals(keyEncryptionCipherName.trim())) {
					keyEncryptionCipherName = "AES-128-CBC";
				}

				final SecureRandom rnd = new SecureRandom();
				final String cipherName;
				final String keyAlgorithm;
				final int keySize;
				final int blockSize;
				switch (keyEncryptionCipherName.trim().toUpperCase()) {
					case "DES-EDE3-CBC":
						cipherName = "DESede/CBC/NoPadding";
						keyAlgorithm = "DESede";
						keySize = 24;
						blockSize = 8;
						break;
					case "AES-128-CBC":
						cipherName = "AES/CBC/NoPadding";
						keyAlgorithm = "AES";
						keySize = 16;
						blockSize = 16;
						break;
					case "AES-192-CBC":
						cipherName = "AES/CBC/NoPadding";
						keyAlgorithm = "AES";
						keySize = 24;
						blockSize = 16;
						break;
					case "AES-256-CBC":
						cipherName = "AES/CBC/NoPadding";
						keyAlgorithm = "AES";
						keySize = 32;
						blockSize = 16;
						break;
					default:
						throw new Exception("Unknown key encryption cipher: " + keyEncryptionCipherName);
				}
				final byte[] iv = new byte[blockSize];
				rnd.nextBytes(iv);
				final String ivString = toHexString(iv);
				final Cipher cipher = Cipher.getInstance(cipherName);
				final byte[] key = SshKeyReader.stretchPasswordForOpenSsl(passwordBytes, iv, 8, keySize);
				try {
					cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keyAlgorithm), new IvParameterSpec(iv));
				} finally {
					clear(key);
				}
				keyData = addLengthCodedPadding(keyData, blockSize);
				headers.put("Proc-Type", "4,ENCRYPTED");
				headers.put("DEK-Info", keyEncryptionCipherName.trim().toUpperCase() + "," + ivString);

				keyData = cipher.doFinal(keyData);
			}
		}

		outputStream.write(("-----BEGIN " + keyTypeName + "-----\n").getBytes(StandardCharsets.UTF_8));
		outputStream.write(getPemHeaderLines(headers).getBytes(StandardCharsets.UTF_8));
		outputStream.write(toWrappedBase64(keyData, 64, "\n").getBytes(StandardCharsets.UTF_8));
		outputStream.write(("\n-----END " + keyTypeName + "-----\n").getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Converts the supplied key pair into unprotected DER format (binary data).
	 * <p>Use with caution, because this key format is not protected by any password.</p>
	 * @param outputStream stream receiving the DER encoded key.
	 * @param keyPair key pair to encode.
	 * @throws Exception if the key cannot be converted or written.
	 */
	public static void writeDerFormat(final OutputStream outputStream, final KeyPair keyPair) throws Exception {
		final Algorithm algorithm = KeyPairUtilities.getAlgorithm(keyPair);
		if (Algorithm.RSA == algorithm) {
			outputStream.write(createRsaBinaryKey(keyPair));
		} else if (Algorithm.DSA == algorithm) {
			outputStream.write(createDsaBinaryKey(keyPair));
		} else if (Algorithm.NISTP256 == algorithm) {
			outputStream.write(createEcdsaBinaryKey(keyPair, OID.ECDSA_CURVE_NISTP256));
		} else if (Algorithm.NISTP384 == algorithm) {
			outputStream.write(createEcdsaBinaryKey(keyPair, OID.ECDSA_CURVE_NISTP384));
		} else if (Algorithm.NISTP521 == algorithm) {
			outputStream.write(createEcdsaBinaryKey(keyPair, OID.ECDSA_CURVE_NISTP521));
		} else if (Algorithm.ED25519 == algorithm || Algorithm.ED448 == algorithm) {
			// EdDSA keys have no traditional format, so PKCS#8 is used
			outputStream.write(keyPair.getPrivate().getEncoded());
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithm.name());
		}
	}

	private static String getPemHeaderLines(final Map<String, String> headers) {
		final StringBuilder headerBuilder = new StringBuilder();
		if (headers != null && !headers.isEmpty()) {
			for (final Entry<String, String> entry : headers.entrySet()) {
				headerBuilder.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
			}
			headerBuilder.append("\n");
		}
		return headerBuilder.toString();
	}

	private static byte[] createRsaBinaryKey(final KeyPair keyPair) throws Exception {
		final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) keyPair.getPrivate());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getModulus().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPublicExponent().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrivateExponent().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeExponentP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeExponentQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getCrtCoefficient().toByteArray())
				);
	}

	private static byte[] createDsaBinaryKey(final KeyPair keyPair) throws Exception {
		final DSAPublicKey publicKey = ((DSAPublicKey) keyPair.getPublic());
		final DSAPrivateKey privateKey = ((DSAPrivateKey) keyPair.getPrivate());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getG().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, publicKey.getY().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getX().toByteArray())
				);
	}

	private static byte[] createEcdsaBinaryKey(final KeyPair keyPair, final OID curveOid) throws Exception {
		final ECPrivateKey privateKey = ((ECPrivateKey) keyPair.getPrivate());
		final ECPublicKey publicKey = ((ECPublicKey) keyPair.getPublic());

		byte[] qBytes;
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(publicKey.getEncoded());
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());
		if (Asn1Codec.DER_TAG_SEQUENCE != derDataTags.get(0).getTagId()) {
			throw new Exception("Invalid key data found");
		}
		final List<DerTag> sshAlgorithmDerTags = Asn1Codec.readDerTags(derDataTags.get(0).getData());
		final OID ecDsaPublicKeyOid = new OID(sshAlgorithmDerTags.get(0).getData());
		if (OID.ECDSA_PUBLICKEY.matches(ecDsaPublicKeyOid.getByteArrayEncoding())) {
			final OID ecDsaCurveOid = new OID(sshAlgorithmDerTags.get(1).getData());
			if (OID.ECDSA_CURVE_NISTP256.matches(ecDsaCurveOid.getByteArrayEncoding())
					|| OID.ECDSA_CURVE_NISTP384.matches(ecDsaCurveOid.getByteArrayEncoding())
					|| OID.ECDSA_CURVE_NISTP521.matches(ecDsaCurveOid.getByteArrayEncoding())) {
				if (Asn1Codec.DER_TAG_BIT_STRING != derDataTags.get(1).getTagId()) {
					throw new Exception("Invalid key data found");
				} else {
					qBytes = derDataTags.get(1).getData();
				}
			} else {
				throw new Exception("Unknown SSH EcDSA curve OID: " + ecDsaCurveOid.getStringEncoding());
			}
		} else {
			throw new Exception("Unknown SSH EcDSA public key OID: " + ecDsaPublicKeyOid.getStringEncoding());
		}

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ONE.toByteArray()),
				// RFC 5915: the private key is an unsigned octet string of the fixed length ceiling(log2(n) / 8)
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OCTET_STRING, toFixedLengthUnsigned(privateKey.getS(), (privateKey.getParams().getOrder().bitLength() + 7) / 8)),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_0, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OBJECT, curveOid.getByteArrayEncoding())),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_1, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_BIT_STRING, qBytes))
				);
	}

	private static byte[] toFixedLengthUnsigned(final BigInteger value, final int length) throws Exception {
		final byte[] signedBytes = value.toByteArray();
		int start = 0;
		while (start < signedBytes.length - 1 && signedBytes[start] == 0) {
			start++;
		}
		final int significantLength = signedBytes.length - start;
		if (significantLength > length) {
			throw new Exception("Value is too large for fixed length " + length);
		}
		final byte[] result = new byte[length];
		System.arraycopy(signedBytes, start, result, length - significantLength, significantLength);
		return result;
	}

	private static byte[] addLengthCodedPadding(final byte[] data, final int paddingSize) {
		final byte[] dataPadded;
		if (data.length % paddingSize != 0) {
			dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
		} else {
			dataPadded = new byte[data.length + paddingSize];
		}
		for (int i = 0; i < data.length; i++) {
			dataPadded[i] = data[i];
		}
		final byte padValue = (byte) (dataPadded.length - data.length);
		for (int i = data.length; i < dataPadded.length; i++) {
			dataPadded[i] = padValue;
		}
		return dataPadded;
	}

/**
 * writePuttyVersion2Key operation.
 * @param outputStream the outputStream value.
 * @param sshKey the sshKey value.
 * @param passwordChars the passwordChars value.
 * @throws Exception if the operation cannot be completed.
 */
	public static void writePuttyVersion2Key(final OutputStream outputStream, final SshKey sshKey, final char[] passwordChars) throws Exception {
		final boolean encrypt = passwordChars != null && passwordChars.length > 0;
		try (final Password password = new Password(copyPasswordForEncryption(passwordChars))) {
			final Algorithm algorithm = sshKey.getAlgorithm();
			final String comment = getPuttyComment(sshKey);
			final String encryptionType = encrypt ? "aes256-cbc" : "none";

			final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(sshKey.getKeyPair().getPublic());
			byte[] privateKeyBytes = getPuttyVersion2PrivateKeyBytes(sshKey.getKeyPair().getPrivate());

			// padding up to multiple of 16 bytes for AES/CBC/NoPadding encryption
			privateKeyBytes = addRandomPadding(privateKeyBytes, 16);

			final byte[] passwordBytes = encrypt ? password.getPasswordBytesIsoEncoded() : null;
			final byte[] macKey = SshKeyReader.getPuttyMacKeyVersion2(passwordBytes);
			final String macHash;
			try {
				macHash = SshKeyReader.calculatePuttyMac(2, macKey, algorithm, encryptionType, comment.getBytes(StandardCharsets.ISO_8859_1), publicKeyBytes, privateKeyBytes);
			} finally {
				clear(macKey);
			}

			if (encrypt) {
				final byte[] puttyKeyEncryptionKey = SshKeyReader.getPuttyPrivateKeyEncryptionKeyVersion2(passwordBytes);
				try {
					final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
					cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(new byte[16])); // initial vector=0
					privateKeyBytes = cipher.doFinal(privateKeyBytes);
				} finally {
					clear(puttyKeyEncryptionKey);
				}
			}

			final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, 64, "\r\n");
			final String privateKeyBase64 = toWrappedBase64(privateKeyBytes, 64, "\r\n");

			final StringBuilder content = new StringBuilder();
			content.append("PuTTY-User-Key-File-2: ").append(algorithm.getSshAlgorithmId()).append("\r\n");
			content.append("Encryption: ").append(encryptionType).append("\r\n");
			content.append("Comment: ").append(comment).append("\r\n");
			content.append("Public-Lines: ").append(getLineCount(publicKeyBase64)).append("\r\n");
			content.append(publicKeyBase64).append("\r\n");
			content.append("Private-Lines: ").append(getLineCount(privateKeyBase64)).append("\r\n");
			content.append(privateKeyBase64).append("\r\n");
			content.append("Private-MAC: ").append(macHash).append("\r\n");

			outputStream.write(content.toString().getBytes(StandardCharsets.ISO_8859_1));
		}
	}

	/**
	 * PuTTY stores the comment as single header line, which is part of the MAC checksum.
	 */
	private static String getPuttyComment(final SshKey sshKey) {
		final String comment = sshKey.getComment() == null ? "" : sshKey.getComment();
		if (comment.indexOf('\r') >= 0 || comment.indexOf('\n') >= 0) {
			throw new IllegalArgumentException("Linebreaks are not allowed in PuTTY key comments");
		}
		return comment;
	}

	private static byte[] getPuttyVersion2PrivateKeyBytes(final PrivateKey privateKey) throws Exception {
		if (privateKey == null) {
			throw new Exception("Invalid empty privateKey parameter");
		} else {
			final BlockDataWriter privateKeyWriter = new BlockDataWriter();
			if (privateKey instanceof RSAPrivateCrtKey) {
				final RSAPrivateCrtKey privateKeyRSA = (RSAPrivateCrtKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrivateExponent());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeP());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeQ());
				privateKeyWriter.writeBigInt(privateKeyRSA.getCrtCoefficient());
			} else if (privateKey instanceof DSAPrivateKey) {
				final DSAPrivateKey privateKeyDSA = (DSAPrivateKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyDSA.getX());
			} else if (privateKey instanceof ECPrivateKey) {
				final ECPrivateKey privateKeyEC = (ECPrivateKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyEC.getS());
			} else if (privateKey instanceof EdECPrivateKey) {
				final EdECPrivateKey privateKeyEdEC = (EdECPrivateKey) privateKey;
				final byte[] privateKeyData = getEdDSAPrivateKeyBytes(privateKeyEdEC);
				privateKeyWriter.writeData(privateKeyData);
			} else {
				throw new IllegalArgumentException("Unsupported SSH cipher algorithm");
			}
			return privateKeyWriter.toByteArray();
		}
	}

/**
 * writePuttyVersion3Key operation.
 * @param outputStream the outputStream value.
 * @param sshKey the sshKey value.
 * @param passwordChars the passwordChars value.
 * @throws Exception if the operation cannot be completed.
 */
	public static void writePuttyVersion3Key(final OutputStream outputStream, final SshKey sshKey, final char[] passwordChars) throws Exception {
		final boolean encrypt = passwordChars != null && passwordChars.length > 0;
		try (final Password password = new Password(copyPasswordForEncryption(passwordChars))) {
			final Algorithm algorithm = sshKey.getAlgorithm();
			final String comment = getPuttyComment(sshKey);
			final byte[] commentBytes = comment.getBytes(StandardCharsets.ISO_8859_1);

			final byte[] publicKeyBytes = KeyPairUtilities.getPublicKeyBytes(sshKey.getKeyPair().getPublic());
			byte[] privateKeyBytes = getPuttyVersion3PrivateKeyBytes(sshKey.getKeyPair().getPrivate());

			// padding up to multiple of 16 bytes for AES/CBC/NoPadding encryption
			privateKeyBytes = addRandomPadding(privateKeyBytes, 16);

			final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, 64, "\r\n");

			final StringBuilder content = new StringBuilder();
			content.append("PuTTY-User-Key-File-3: ").append(algorithm.getSshAlgorithmId()).append("\r\n");
			content.append("Encryption: ").append(encrypt ? "aes256-cbc" : "none").append("\r\n");
			content.append("Comment: ").append(comment).append("\r\n");
			content.append("Public-Lines: ").append(getLineCount(publicKeyBase64)).append("\r\n");
			content.append(publicKeyBase64).append("\r\n");

			final String macHash;

			if (encrypt) {
				final String keyDerivation = "Argon2id";
				content.append("Key-Derivation: ").append(keyDerivation).append("\r\n");
				final int argon2Memory = 8192;
				content.append("Argon2-Memory: ").append(argon2Memory).append("\r\n");
				final int argon2Passes = 21;
				content.append("Argon2-Passes: ").append(argon2Passes).append("\r\n");
				final int argon2Parallelism = 1;
				content.append("Argon2-Parallelism: ").append(argon2Parallelism).append("\r\n");
				final byte[] argon2Salt = new byte[16];
				new SecureRandom().nextBytes(argon2Salt);
				content.append("Argon2-Salt: ").append(toHexString(argon2Salt)).append("\r\n");

				byte[] puttyKeyEncryptionKey = null;
				try {
					puttyKeyEncryptionKey = SshKeyReader.deriveArgon2Key(password.getPasswordBytesIsoEncoded(), keyDerivation, argon2Memory, argon2Passes, argon2Parallelism, argon2Salt);
					macHash = SshKeyReader.calculatePuttyMac(3, Arrays.copyOfRange(puttyKeyEncryptionKey, 48, 80), algorithm, "aes256-cbc", commentBytes, publicKeyBytes, privateKeyBytes);

					final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
					cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(puttyKeyEncryptionKey, 32, 16));

					privateKeyBytes = cipher.doFinal(privateKeyBytes);
				} finally {
					clear(puttyKeyEncryptionKey);
				}
			} else {
				macHash = SshKeyReader.calculatePuttyMac(3, new byte[0], algorithm, "none", commentBytes, publicKeyBytes, privateKeyBytes);
			}

			final String privateKeyBase64 = toWrappedBase64(privateKeyBytes, 64, "\r\n");

			content.append("Private-Lines: ").append(getLineCount(privateKeyBase64)).append("\r\n");
			content.append(privateKeyBase64).append("\r\n");
			content.append("Private-MAC: ").append(macHash).append("\r\n");

			outputStream.write(content.toString().getBytes(StandardCharsets.ISO_8859_1));
		}
	}

	private static byte[] getPuttyVersion3PrivateKeyBytes(final PrivateKey privateKey) throws Exception {
		if (privateKey == null) {
			throw new Exception("Invalid empty privateKey parameter");
		} else {
			final BlockDataWriter privateKeyWriter = new BlockDataWriter();
			if (privateKey instanceof RSAPrivateCrtKey) {
				final RSAPrivateCrtKey privateKeyRSA = (RSAPrivateCrtKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrivateExponent());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeP());
				privateKeyWriter.writeBigInt(privateKeyRSA.getPrimeQ());
				privateKeyWriter.writeBigInt(privateKeyRSA.getCrtCoefficient());
			} else if (privateKey instanceof DSAPrivateKey) {
				final DSAPrivateKey privateKeyDSA = (DSAPrivateKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyDSA.getX());
			} else if (privateKey instanceof ECPrivateKey) {
				final ECPrivateKey privateKeyEC = (ECPrivateKey) privateKey;
				privateKeyWriter.writeBigInt(privateKeyEC.getS());
			} else if (privateKey instanceof EdECPrivateKey) {
				final EdECPrivateKey privateKeyEdEC = (EdECPrivateKey) privateKey;
				final byte[] privateKeyData = getEdDSAPrivateKeyBytes(privateKeyEdEC);
				privateKeyWriter.writeData(privateKeyData);
			} else {
				throw new IllegalArgumentException("Unsupported SSH cipher algorithm");
			}
			return privateKeyWriter.toByteArray();
		}
	}

	private static byte[] addRandomPadding(final byte[] data, final int paddingSize) {
		if (data.length % paddingSize != 0) {
			final byte[] dataPadded;
			dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
			for (int i = 0; i < data.length; i++) {
				dataPadded[i] = data[i];
			}
			final byte[] randomPadding = new byte[dataPadded.length - data.length];
			new SecureRandom().nextBytes(randomPadding);
			for (int i = 0; i < randomPadding.length; i++) {
				dataPadded[data.length + i] = randomPadding[i];
			}
			return dataPadded;
		} else {
			return data;
		}
	}

	/**
	 * Converts byte array to base64 with linebreaks
	 */
	private static String toWrappedBase64(final byte[] byteArray, final int maxLineLength, final String lineBreak) {
		return Base64.getMimeEncoder(maxLineLength, lineBreak.getBytes(StandardCharsets.ISO_8859_1)).encodeToString(byteArray);
	}

	private static String toHexString(final byte[] data) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString();
	}

	private static int getLineCount(final String dataString) throws IOException {
		if (dataString == null) {
			return 0;
		} else if ("".equals(dataString)) {
			return 1;
		} else {
			try (LineNumberReader lineNumberReader = new LineNumberReader(new StringReader(dataString))) {
				while (lineNumberReader.readLine() != null) {
					// do nothing
				}
				return lineNumberReader.getLineNumber();
			}
		}
	}

	private static void clear(final byte[] array) {
		if (array != null) {
			Arrays.fill(array, (byte) 0);
		}
	}

	/**
	 * Returns a copy of the password, or null if no password (null or empty) is given, which means no encryption.
	 */
	private static char[] copyPasswordForEncryption(final char[] passwordChars) {
		if (passwordChars == null || passwordChars.length == 0) {
			return null;
		} else {
			return passwordChars.clone();
		}
	}
	private static byte[] toFixedLength(final BigInteger value, final int length) {
		final byte[] source = value.toByteArray();
		final byte[] result = new byte[length];
		final int sourceOffset = source.length > length ? source.length - length : 0;
		final int copyLength = Math.min(source.length, length);
		System.arraycopy(source, sourceOffset, result, length - copyLength, copyLength);
		return result;
	}

}
