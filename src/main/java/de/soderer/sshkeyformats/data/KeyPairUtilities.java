package de.soderer.sshkeyformats.data;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;

public class KeyPairUtilities {
	/**
	 * Create a RSA keypair of given strength
	 */
	public static KeyPair createRsaKeyPair(final int keyStrength) throws Exception {
		if (keyStrength < 512) {
			throw new Exception("Invalid RSA key strength: " + keyStrength);
		}
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keyStrength);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a DSA keypair of 1024 bit strength<br/>
	 * Watchout: OpenSSH only supports 1024 bit DSA key strength<br/>
	 */
	public static KeyPair createDsaKeyPair() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(1024);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a DSA keypair of given strength<br/>
	 * Watchout: OpenSSH only supports 1024 bit DSA key strength<br/>
	 */
	public static KeyPair createDsaKeyPair(final int keyStrength) throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(keyStrength);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Create a ECDSA keypair of eliptic curve name.
	 * Supported eliptic curve names are
	 *   nistp256 or secp256
	 *   nistp384 or secp384
	 *   nistp521 or secp521
	 */
	public static KeyPair createEllipticCurveKeyPair(final String ecdsaCurveName) throws Exception {
		if (ecdsaCurveName == null || "".equals(ecdsaCurveName.trim())) {
			throw new Exception("Missing ECDSA curve name parameter");
		}
		final String curveName = ecdsaCurveName.toLowerCase().trim().replace("nist", "sec");
		if (!"secp256".equals(curveName) && !"secp384".equals(curveName) && !"secp521".equals(curveName)) {
			throw new Exception("Unknown ECDSA curve name: " + ecdsaCurveName);
		}
		final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(curveName + "r1"));
		final ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
		return keyPairGenerator.generateKeyPair();
	}

	public static KeyPair createEllipticCurveKeyPair(final int curveId) throws Exception {
		if (256 != curveId && 384 != curveId && 521 != curveId) {
			throw new Exception("Invalid ECDSA curve id parameter");
		}
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(curveId);
		return keyPairGenerator.generateKeyPair();
	}

	public static KeyPair createEd25519CurveKeyPair() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
		return keyPairGenerator.generateKeyPair();
	}

	public static KeyPair createEd448CurveKeyPair() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed448");
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public static Algorithm getAlgorithm(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else if (keyPair.getPrivate() != null) {
			return getAlgorithm(keyPair.getPrivate());
		} else if (keyPair.getPublic() != null) {
			return getAlgorithm(keyPair.getPublic());
		} else {
			throw new Exception("KeyPair data is empty");
		}
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public static Algorithm getAlgorithm(final PublicKey publicKey) throws Exception {
		if (publicKey == null){
			throw new Exception("Invalid empty publicKey parameter");
		} else if ("RSA".equals(publicKey.getAlgorithm())) {
			return Algorithm.RSA;
		} else if ("DSA".equals(publicKey.getAlgorithm())) {
			return Algorithm.DSA;
		} else if ("EC".equals(publicKey.getAlgorithm()) || "ECDSA".equals(publicKey.getAlgorithm())) {
			final String nistCipher = CryptographicUtilities.getEcDsaEllipticCurveName((ECPublicKey) publicKey);
			if ("nistp256".equalsIgnoreCase(nistCipher)) {
				return Algorithm.NISTP256;
			} else if ("nistp384".equalsIgnoreCase(nistCipher)) {
				return Algorithm.NISTP384;
			} else if ("nistp521".equalsIgnoreCase(nistCipher)) {
				return Algorithm.NISTP521;
			} else {
				throw new IllegalArgumentException("Unknown NIST public key cipher: " + nistCipher);
			}
		} else if ("EdDSA".equals(publicKey.getAlgorithm())) {
			final String ecCipher = ((EdECPublicKey) publicKey).getParams().getName();
			if ("Ed25519".equals(ecCipher)) {
				return Algorithm.ED25519;
			} else if ("Ed448".equals(ecCipher)) {
				return Algorithm.ED448;
			} else {
				throw new Exception("Unsupported EdDSA algorithm name: " + ecCipher);
			}
		} else {
			throw new Exception("Unsupported ssh algorithm name: " + publicKey.getAlgorithm());
		}
	}

	/**
	 * Key type<br />
	 * "ssh-rsa" for RSA key<br />
	 * "ssh-dss" for DSA key<br />
	 * "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" for ECDSA key<br />
	 */
	public static Algorithm getAlgorithm(final PrivateKey privateKey) throws Exception {
		if (privateKey == null){
			throw new Exception("Invalid empty privateKey parameter");
		} else if (privateKey instanceof RSAPrivateCrtKey) {
			return Algorithm.RSA;
		} else if (privateKey instanceof DSAPrivateKey) {
			return Algorithm.DSA;
		} else if (privateKey instanceof ECPrivateKey) {
			final String nistCipher = CryptographicUtilities.getEcDsaEllipticCurveName((ECPrivateKey) privateKey);
			if ("nistp256".equalsIgnoreCase(nistCipher)) {
				return Algorithm.NISTP256;
			} else if ("nistp384".equalsIgnoreCase(nistCipher)) {
				return Algorithm.NISTP384;
			} else if ("nistp521".equalsIgnoreCase(nistCipher)) {
				return Algorithm.NISTP521;
			} else {
				throw new IllegalArgumentException("Unknown NIST private key cipher: " + nistCipher);
			}
		} else if (privateKey instanceof EdECPrivateKey) {
			final String ecCipher = ((EdECPrivateKey) privateKey).getParams().getName();
			if ("Ed25519".equalsIgnoreCase(ecCipher)) {
				return Algorithm.ED25519;
			} else if ("Ed448".equalsIgnoreCase(ecCipher)) {
				return Algorithm.ED448;
			} else {
				throw new Exception("Unknown EdDSA type: " + ecCipher);
			}
		} else {
			throw new IllegalArgumentException("Unknown private key cipher");
		}
	}

	public static int getKeyStrength(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getKeyStrength(keyPair.getPublic());
		}
	}

	public static int getKeyStrength(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			final Algorithm algorithm = getAlgorithm(publicKey);
			if (Algorithm.RSA == algorithm) {
				return ((RSAPublicKey) publicKey).getModulus().bitLength();
			} else if (Algorithm.DSA == algorithm) {
				return ((DSAPublicKey) publicKey).getY().bitLength();
			} else if (Algorithm.NISTP256 == algorithm) {
				return 256;
			} else if (Algorithm.NISTP384 == algorithm) {
				return 384;
			} else if (Algorithm.NISTP521 == algorithm) {
				return 521;
			} else {
				throw new Exception("Unsupported ssh algorithm name: " + algorithm.name());
			}
		}
	}

	public static byte[] getPublicKeyBytes(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			final Algorithm algorithm = getAlgorithm(publicKey);
			final BlockDataWriter publicKeyWriter = new BlockDataWriter();
			if (publicKey instanceof RSAPublicKey) {
				final RSAPublicKey publicKeyRSA = (RSAPublicKey) publicKey;
				publicKeyWriter.writeString(algorithm.getSshAlgorithmId());
				publicKeyWriter.writeBigInt(publicKeyRSA.getPublicExponent());
				publicKeyWriter.writeBigInt(publicKeyRSA.getModulus());
				return publicKeyWriter.toByteArray();
			} else if (publicKey instanceof DSAPublicKey) {
				final DSAPublicKey publicKeyDSA = (DSAPublicKey) publicKey;
				publicKeyWriter.writeString(algorithm.getSshAlgorithmId());
				publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getP());
				publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getQ());
				publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getG());
				publicKeyWriter.writeBigInt(publicKeyDSA.getY());
			} else if (publicKey instanceof ECPublicKey) {
				final ECPublicKey publicKeyEC = (ECPublicKey) publicKey;
				final String ecCurveName = CryptographicUtilities.getEcDsaEllipticCurveName(publicKeyEC);
				publicKeyWriter.writeString(algorithm.getSshAlgorithmId());
				publicKeyWriter.writeString(ecCurveName);

				final DerTag enclosingDerTag = Asn1Codec.readDerTag(publicKeyEC.getEncoded());
				if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
					throw new Exception("Invalid key data found");
				}
				final List<DerTag> derDataTags = Asn1Codec.readDerTags(enclosingDerTag.getData());
				if (Asn1Codec.DER_TAG_SEQUENCE != derDataTags.get(0).getTagId()) {
					throw new Exception("Invalid key data found");
				}
				final List<DerTag> sshAlgorithmDerTags = Asn1Codec.readDerTags(derDataTags.get(0).getData());
				final OID ecDsaPublicKeyOid = new OID(sshAlgorithmDerTags.get(0).getData());
				if (Arrays.equals(OID.ECDSA_PUBLICKEY_ARRAY, ecDsaPublicKeyOid.getByteArrayEncoding())) {
					final OID ecDsaCurveOid = new OID(sshAlgorithmDerTags.get(1).getData());
					if (Arrays.equals(OID.ECDSA_CURVE_NISTP256_ARRAY, ecDsaCurveOid.getByteArrayEncoding())
							|| Arrays.equals(OID.ECDSA_CURVE_NISTP384_ARRAY, ecDsaCurveOid.getByteArrayEncoding())
							|| Arrays.equals(OID.ECDSA_CURVE_NISTP521_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
						if (Asn1Codec.DER_TAG_BIT_STRING != derDataTags.get(1).getTagId()) {
							throw new Exception("Invalid key data found");
						} else {
							// remove first byte (odd sign)
							final byte[] dataWithLeadingZero = derDataTags.get(1).getData();
							final byte[] qBytes = Arrays.copyOfRange(dataWithLeadingZero, 1, dataWithLeadingZero.length);
							publicKeyWriter.writeData(qBytes);
						}
					} else {
						throw new Exception("Unknown SSH EcDSA curve OID: " + ecDsaCurveOid.getStringEncoding());
					}
				} else {
					throw new Exception("Unknown SSH EcDSA public key OID: " + ecDsaPublicKeyOid.getStringEncoding());
				}
			} else if (publicKey instanceof EdECPublicKey) {
				final EdECPublicKey publicKeyEdEC = (EdECPublicKey) publicKey;
				int publicKeyDataLength;
				if ("Ed25519".equalsIgnoreCase(publicKeyEdEC.getParams().getName())) {
					publicKeyWriter.writeString(algorithm.getSshAlgorithmId());
					publicKeyDataLength = 32;
				} else if ("Ed448".equalsIgnoreCase(publicKeyEdEC.getParams().getName())) {
					publicKeyWriter.writeString(algorithm.getSshAlgorithmId());
					publicKeyDataLength = 57;
				} else {
					throw new Exception("Unknown EdDSA type: " + publicKeyEdEC.getParams().getName());
				}

				final byte[] javaEncoding = publicKeyEdEC.getEncoded();
				final byte[] publicKeyData = new byte[publicKeyDataLength];
				System.arraycopy(javaEncoding, javaEncoding.length - publicKeyDataLength, publicKeyData, 0, publicKeyDataLength);
				publicKeyWriter.writeData(publicKeyData);
			} else {
				throw new Exception("Unsupported algorithm name: " + algorithm.name());
			}
			return publicKeyWriter.toByteArray();
		}
	}

	public static String getMd5Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getMd5Fingerprint(keyPair.getPublic());
		}
	}

	public static String getMd5Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(getPublicKeyBytes(publicKey));
				return BitUtilities.toHexString(md.digest(), ":").toUpperCase();
			} catch (final Exception e) {
				throw new Exception("Cannot create MD5 fingerprint", e);
			}
		}
	}

	public static String getSha1Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha1Fingerprint(keyPair.getPublic());
		}
	}

	public static String getSha1Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(getPublicKeyBytes(publicKey));
				return BitUtilities.toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA1 fingerprint", e);
			}
		}
	}

	public static String getSha1FingerprintBase64(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha1FingerprintBase64(keyPair.getPublic());
		}
	}

	public static String getSha1FingerprintBase64(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(getPublicKeyBytes(publicKey));
				return Base64.getEncoder().encodeToString(md.digest());
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA1 fingerprint", e);
			}
		}
	}

	public static String getSha256Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha256Fingerprint(keyPair.getPublic());
		}
	}

	public static String getSha256Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(getPublicKeyBytes(publicKey));
				return BitUtilities.toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA256 fingerprint", e);
			}
		}
	}

	public static String getSha256FingerprintBase64(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha256FingerprintBase64(keyPair.getPublic());
		}
	}

	public static String getSha256FingerprintBase64(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(getPublicKeyBytes(publicKey));
				return Base64.getEncoder().encodeToString(md.digest());
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA256 fingerprint", e);
			}
		}
	}

	public static String getSha384Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha384Fingerprint(keyPair.getPublic());
		}
	}

	public static String getSha384Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-384");
				md.update(getPublicKeyBytes(publicKey));
				return BitUtilities.toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA384 fingerprint", e);
			}
		}
	}

	public static String getSha384FingerprintBase64(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha384FingerprintBase64(keyPair.getPublic());
		}
	}

	public static String getSha384FingerprintBase64(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-384");
				md.update(getPublicKeyBytes(publicKey));
				return Base64.getEncoder().encodeToString(md.digest());
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA384 fingerprint", e);
			}
		}
	}

	public static String getSha512Fingerprint(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha512Fingerprint(keyPair.getPublic());
		}
	}

	public static String getSha512Fingerprint(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-512");
				md.update(getPublicKeyBytes(publicKey));
				return BitUtilities.toHexString(md.digest(), ":");
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA512 fingerprint", e);
			}
		}
	}

	public static String getSha512FingerprintBase64(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else {
			return getSha512FingerprintBase64(keyPair.getPublic());
		}
	}

	public static String getSha512FingerprintBase64(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			try {
				final MessageDigest md = MessageDigest.getInstance("SHA-512");
				md.update(getPublicKeyBytes(publicKey));
				return Base64.getEncoder().encodeToString(md.digest());
			} catch (final Exception e) {
				throw new Exception("Cannot create SHA512 fingerprint", e);
			}
		}
	}

	public static String encodePublicKeyForAuthorizedKeys(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else if (keyPair.getPublic() == null) {
			throw new Exception("Missing public key for AuthorizedKey string generation");
		} else {
			return encodePublicKeyForAuthorizedKeys(keyPair.getPublic());
		}
	}

	public static String encodePublicKeyForAuthorizedKeys(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			return getAlgorithm(publicKey).getSshAlgorithmId() + " " + new String(Base64.getEncoder().encode(getPublicKeyBytes(publicKey)));
		}
	}

	private static class BlockDataWriter {
		private final ByteArrayOutputStream outputStream;
		private final DataOutput keyDataOutput;

		private BlockDataWriter() {
			outputStream = new ByteArrayOutputStream();
			keyDataOutput = new DataOutputStream(outputStream);
		}

		private void writeBigInt(final BigInteger bigIntegerData) throws Exception {
			writeData(bigIntegerData.toByteArray());
		}

		private void writeString(final String stringData) throws Exception {
			writeData(stringData.getBytes(StandardCharsets.ISO_8859_1));
		}

		private void writeData(final byte[] data) throws IOException, Exception {
			try {
				if (data.length <= 0) {
					throw new Exception("Key blocksize error");
				}

				keyDataOutput.writeInt(data.length);
				keyDataOutput.write(data);
			} catch (final IOException e) {
				throw new Exception("Key block write error", e);
			}
		}

		private byte[] toByteArray() {
			return outputStream.toByteArray();
		}
	}
}
