package de.soderer.sshkeyformats.data;

import java.io.ByteArrayOutputStream;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Base64;
import java.util.Locale;

/**
 * Helper methods for creating key pairs, determining their SSH algorithm and key strength,
 * encoding public keys in SSH wire format (RFC 4253 / RFC 5656 / RFC 8709) and calculating key fingerprints.
 */
public class KeyPairUtilities {
	private KeyPairUtilities() {
		// Utility class, no instances
	}

	/**
	 * Creates a RSA key pair of the given strength.
	 *
	 * @param keyStrength the RSA key size in bits (at least 2048, recommended at least 3072)
	 * @return the generated RSA key pair
	 * @throws Exception if the key strength is below 2048 bits or RSA key pair generation fails
	 */
	public static KeyPair createRsaKeyPair(final int keyStrength) throws Exception {
		if (keyStrength < 2048) {
			// RSA keys below 2048 bit are considered insecure by current standards (NIST/BSI)
			throw new Exception("Invalid RSA key strength (minimum 2048 bit required): " + keyStrength);
		}
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keyStrength);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Creates a DSA key pair of 1024 bit strength.
	 * <p>
	 * Watch out: OpenSSH only supports 1024 bit DSA keys and has disabled DSA by default since version 7.0.
	 *
	 * @return the generated 1024 bit DSA key pair
	 * @throws Exception if DSA key pair generation fails
	 * @deprecated DSA-1024 is considered cryptographically weak by current standards (NIST/BSI).
	 *             Use only for compatibility with legacy systems, never for new keys.
	 */
	@Deprecated
	public static KeyPair createDsaKeyPair() throws Exception {
		return createDsaKeyPair(1024);
	}

	/**
	 * Creates a DSA key pair of the given strength.
	 * <p>
	 * Watch out: OpenSSH only supports 1024 bit DSA keys and has disabled DSA by default since version 7.0.
	 *
	 * @param keyStrength the DSA key size in bits (as supported by the JDK, e.g. 1024, 2048 or 3072)
	 * @return the generated DSA key pair
	 * @throws Exception if the key strength is not supported or DSA key pair generation fails
	 * @deprecated DSA is considered legacy and, at the 1024 bit strength required for OpenSSH, cryptographically weak (NIST/BSI).
	 *             Use only for compatibility with legacy systems, never for new keys.
	 */
	@Deprecated
	public static KeyPair createDsaKeyPair(final int keyStrength) throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(keyStrength);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Creates an ECDSA key pair for the given elliptic curve name.
	 * <p>
	 * Supported curve names (case insensitive):
	 * <ul>
	 * <li>"nistp256" or "secp256"</li>
	 * <li>"nistp384" or "secp384"</li>
	 * <li>"nistp521" or "secp521"</li>
	 * </ul>
	 *
	 * @param ecdsaCurveName the ECDSA curve name
	 * @return the generated elliptic curve key pair
	 * @throws Exception if the curve name is missing or unsupported or key generation fails
	 */
	public static KeyPair createEllipticCurveKeyPair(final String ecdsaCurveName) throws Exception {
		if (ecdsaCurveName == null || "".equals(ecdsaCurveName.trim())) {
			throw new Exception("Missing ECDSA curve name parameter");
		}
		final String curveName = ecdsaCurveName.toLowerCase(Locale.ROOT).trim().replace("nist", "sec");
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

	/**
	 * Creates an ECDSA key pair for the NIST curve of the given size.
	 *
	 * @param curveId the curve size in bits: 256 (nistp256), 384 (nistp384) or 521 (nistp521)
	 * @return the generated elliptic curve key pair
	 * @throws Exception if the curve size is not supported or key generation fails
	 */
	public static KeyPair createEllipticCurveKeyPair(final int curveId) throws Exception {
		if (256 != curveId && 384 != curveId && 521 != curveId) {
			throw new Exception("Invalid ECDSA curve id parameter: " + curveId);
		}
		return createEllipticCurveKeyPair("nistp" + curveId);
	}

	/**
	 * Creates an EdDSA key pair on curve Ed25519.
	 *
	 * @return the generated Ed25519 key pair
	 * @throws Exception if key generation fails
	 */
	public static KeyPair createEd25519CurveKeyPair() throws Exception {
		return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
	}

	/**
	 * Creates an EdDSA key pair on curve Ed448.
	 *
	 * @return the generated Ed448 key pair
	 * @throws Exception if key generation fails
	 */
	public static KeyPair createEd448CurveKeyPair() throws Exception {
		return KeyPairGenerator.getInstance("Ed448").generateKeyPair();
	}

	/**
	 * Determines the SSH algorithm of a key pair, preferably by its private key.
	 *
	 * @param keyPair the key pair to inspect
	 * @return the SSH algorithm represented by the key pair (e.g. {@link Algorithm#RSA} for "ssh-rsa")
	 * @throws Exception if the key pair is empty or the key type is unsupported
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
	 * Determines the SSH algorithm of a public key.
	 *
	 * @param publicKey the public key to inspect
	 * @return the SSH algorithm represented by the public key (e.g. {@link Algorithm#NISTP256} for "ecdsa-sha2-nistp256")
	 * @throws Exception if the key is {@code null} or its type or curve is unsupported
	 */
	public static Algorithm getAlgorithm(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else if (publicKey instanceof RSAPublicKey) {
			return Algorithm.RSA;
		} else if (publicKey instanceof DSAPublicKey) {
			return Algorithm.DSA;
		} else if (publicKey instanceof ECPublicKey) {
			return getEcAlgorithm(CryptographicUtilities.getEcDsaEllipticCurveName((ECPublicKey) publicKey));
		} else if (publicKey instanceof EdECPublicKey) {
			return getEdDsaAlgorithm(((EdECPublicKey) publicKey).getParams().getName());
		} else {
			throw new Exception("Unsupported ssh algorithm name: " + publicKey.getAlgorithm());
		}
	}

	/**
	 * Determines the SSH algorithm of a private key.
	 *
	 * @param privateKey the private key to inspect
	 * @return the SSH algorithm represented by the private key (e.g. {@link Algorithm#ED25519} for "ssh-ed25519")
	 * @throws Exception if the key is {@code null} or its type or curve is unsupported
	 */
	public static Algorithm getAlgorithm(final PrivateKey privateKey) throws Exception {
		if (privateKey == null) {
			throw new Exception("Invalid empty privateKey parameter");
		} else if (privateKey instanceof RSAPrivateKey) {
			return Algorithm.RSA;
		} else if (privateKey instanceof DSAPrivateKey) {
			return Algorithm.DSA;
		} else if (privateKey instanceof ECPrivateKey) {
			return getEcAlgorithm(CryptographicUtilities.getEcDsaEllipticCurveName((ECPrivateKey) privateKey));
		} else if (privateKey instanceof EdECPrivateKey) {
			return getEdDsaAlgorithm(((EdECPrivateKey) privateKey).getParams().getName());
		} else {
			throw new Exception("Unsupported private key algorithm: " + privateKey.getAlgorithm());
		}
	}

	private static Algorithm getEcAlgorithm(final String nistCurveName) throws Exception {
		if ("nistp256".equalsIgnoreCase(nistCurveName)) {
			return Algorithm.NISTP256;
		} else if ("nistp384".equalsIgnoreCase(nistCurveName)) {
			return Algorithm.NISTP384;
		} else if ("nistp521".equalsIgnoreCase(nistCurveName)) {
			return Algorithm.NISTP521;
		} else {
			throw new Exception("Unsupported ECDSA curve: " + nistCurveName);
		}
	}

	private static Algorithm getEdDsaAlgorithm(final String edDsaCurveName) throws Exception {
		if ("Ed25519".equalsIgnoreCase(edDsaCurveName)) {
			return Algorithm.ED25519;
		} else if ("Ed448".equalsIgnoreCase(edDsaCurveName)) {
			return Algorithm.ED448;
		} else {
			throw new Exception("Unsupported EdDSA algorithm name: " + edDsaCurveName);
		}
	}

	/**
	 * Returns the key strength in bits (RSA: modulus size, DSA: size of prime p, EC: curve size).
	 *
	 * @param keyPair the key pair to inspect, the public key is preferred if available
	 * @return the key strength in bits
	 * @throws Exception if the key pair is empty or the key type is unsupported
	 */
	public static int getKeyStrength(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else if (keyPair.getPublic() != null) {
			return getKeyStrength(keyPair.getPublic());
		} else if (keyPair.getPrivate() != null) {
			final PrivateKey privateKey = keyPair.getPrivate();
			final Algorithm algorithm = getAlgorithm(privateKey);
			if (Algorithm.RSA == algorithm) {
				return ((RSAPrivateKey) privateKey).getModulus().bitLength();
			} else if (Algorithm.DSA == algorithm) {
				return ((DSAPrivateKey) privateKey).getParams().getP().bitLength();
			} else {
				return getKeyStrength(algorithm);
			}
		} else {
			throw new Exception("KeyPair data is empty");
		}
	}

	/**
	 * Returns the key strength in bits (RSA: modulus size, DSA: size of prime p, EC: curve size).
	 *
	 * @param publicKey the public key to inspect
	 * @return the key strength in bits
	 * @throws Exception if the key is {@code null} or the key type is unsupported
	 */
	public static int getKeyStrength(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			final Algorithm algorithm = getAlgorithm(publicKey);
			if (Algorithm.RSA == algorithm) {
				return ((RSAPublicKey) publicKey).getModulus().bitLength();
			} else if (Algorithm.DSA == algorithm) {
				// The strength of a DSA key is the size of the prime p, the public value y may be shorter
				return ((DSAPublicKey) publicKey).getParams().getP().bitLength();
			} else {
				return getKeyStrength(algorithm);
			}
		}
	}

	private static int getKeyStrength(final Algorithm algorithm) throws Exception {
		if (Algorithm.NISTP256 == algorithm) {
			return 256;
		} else if (Algorithm.NISTP384 == algorithm) {
			return 384;
		} else if (Algorithm.NISTP521 == algorithm) {
			return 521;
		} else if (Algorithm.ED25519 == algorithm) {
			return 256;
		} else if (Algorithm.ED448 == algorithm) {
			return 448;
		} else {
			throw new Exception("Unsupported ssh algorithm name: " + algorithm.name());
		}
	}

	/**
	 * Encodes a public key in SSH wire format (RFC 4253 / RFC 5656 / RFC 8709),
	 * as used in authorized_keys files, RFC 4716 files and for fingerprints.
	 *
	 * @param publicKey the public key to encode
	 * @return the SSH wire format key blob
	 * @throws Exception if the key is {@code null} or its type is unsupported
	 */
	public static byte[] getPublicKeyBytes(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		}

		final Algorithm algorithm = getAlgorithm(publicKey);
		final BlockDataWriter publicKeyWriter = new BlockDataWriter();
		publicKeyWriter.writeString(algorithm.getSshAlgorithmId());
		if (publicKey instanceof RSAPublicKey) {
			final RSAPublicKey publicKeyRSA = (RSAPublicKey) publicKey;
			publicKeyWriter.writeBigInt(publicKeyRSA.getPublicExponent());
			publicKeyWriter.writeBigInt(publicKeyRSA.getModulus());
		} else if (publicKey instanceof DSAPublicKey) {
			final DSAPublicKey publicKeyDSA = (DSAPublicKey) publicKey;
			publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getP());
			publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getQ());
			publicKeyWriter.writeBigInt(publicKeyDSA.getParams().getG());
			publicKeyWriter.writeBigInt(publicKeyDSA.getY());
		} else if (publicKey instanceof ECPublicKey) {
			final ECPublicKey publicKeyEC = (ECPublicKey) publicKey;
			publicKeyWriter.writeString(CryptographicUtilities.getEcDsaEllipticCurveName(publicKeyEC));
			publicKeyWriter.writeData(getUncompressedEcPoint(publicKeyEC));
		} else if (publicKey instanceof EdECPublicKey) {
			final int publicKeyDataLength = Algorithm.ED25519 == algorithm ? 32 : 57;
			// The X.509 encoding ends with the raw public key (RFC 8410)
			final byte[] javaEncoding = publicKey.getEncoded();
			final byte[] publicKeyData = new byte[publicKeyDataLength];
			System.arraycopy(javaEncoding, javaEncoding.length - publicKeyDataLength, publicKeyData, 0, publicKeyDataLength);
			publicKeyWriter.writeData(publicKeyData);
		} else {
			throw new Exception("Unsupported algorithm name: " + algorithm.name());
		}
		return publicKeyWriter.toByteArray();
	}

	/**
	 * Returns the uncompressed point encoding (0x04 | X | Y, SEC1) of an EC public key with fixed length coordinates.
	 */
	private static byte[] getUncompressedEcPoint(final ECPublicKey publicKeyEC) {
		final int coordinateLength = (publicKeyEC.getParams().getCurve().getField().getFieldSize() + 7) / 8;
		final byte[] point = new byte[1 + 2 * coordinateLength];
		point[0] = 0x04;
		copyUnsignedFixedLength(publicKeyEC.getW().getAffineX(), point, 1, coordinateLength);
		copyUnsignedFixedLength(publicKeyEC.getW().getAffineY(), point, 1 + coordinateLength, coordinateLength);
		return point;
	}

	private static void copyUnsignedFixedLength(final BigInteger value, final byte[] target, final int targetOffset, final int length) {
		final byte[] source = value.toByteArray();
		// Skip the leading sign byte of BigInteger encoding
		final int copyLength = Math.min(source.length, length);
		System.arraycopy(source, source.length - copyLength, target, targetOffset + length - copyLength, copyLength);
	}

	/**
	 * Calculates the MD5 fingerprint of the public key of a key pair (as shown by "ssh-keygen -l -E md5", but in uppercase hex, e.g. "0A:1B:...").
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the uppercase colon separated hexadecimal MD5 fingerprint
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getMd5Fingerprint(final KeyPair keyPair) throws Exception {
		return getMd5Fingerprint(getPublicKey(keyPair));
	}

	/**
	 * Calculates the MD5 fingerprint of a public key (as shown by "ssh-keygen -l -E md5", but in uppercase hex, e.g. "0A:1B:...").
	 *
	 * @param publicKey the public key
	 * @return the uppercase colon separated hexadecimal MD5 fingerprint
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getMd5Fingerprint(final PublicKey publicKey) throws Exception {
		return BitUtilities.toHexString(getFingerprintBytes(publicKey, "MD5"), ":").toUpperCase(Locale.ROOT);
	}

	/**
	 * Calculates the SHA-1 fingerprint of the public key of a key pair as lowercase colon separated hexadecimal string.
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the lowercase colon separated hexadecimal SHA-1 fingerprint
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha1Fingerprint(final KeyPair keyPair) throws Exception {
		return getSha1Fingerprint(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-1 fingerprint of a public key as lowercase colon separated hexadecimal string.
	 *
	 * @param publicKey the public key
	 * @return the lowercase colon separated hexadecimal SHA-1 fingerprint
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha1Fingerprint(final PublicKey publicKey) throws Exception {
		return BitUtilities.toHexString(getFingerprintBytes(publicKey, "SHA-1"), ":");
	}

	/**
	 * Calculates the SHA-1 fingerprint of the public key of a key pair as unpadded Base64 string (as shown by "ssh-keygen -l -E sha1" without prefix "SHA1:").
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the Base64 encoded SHA-1 fingerprint without padding
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha1FingerprintBase64(final KeyPair keyPair) throws Exception {
		return getSha1FingerprintBase64(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-1 fingerprint of a public key as unpadded Base64 string (as shown by "ssh-keygen -l -E sha1" without prefix "SHA1:").
	 *
	 * @param publicKey the public key
	 * @return the Base64 encoded SHA-1 fingerprint without padding
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha1FingerprintBase64(final PublicKey publicKey) throws Exception {
		return Base64.getEncoder().withoutPadding().encodeToString(getFingerprintBytes(publicKey, "SHA-1"));
	}

	/**
	 * Calculates the SHA-256 fingerprint of the public key of a key pair as lowercase colon separated hexadecimal string.
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the lowercase colon separated hexadecimal SHA-256 fingerprint
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha256Fingerprint(final KeyPair keyPair) throws Exception {
		return getSha256Fingerprint(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-256 fingerprint of a public key as lowercase colon separated hexadecimal string.
	 *
	 * @param publicKey the public key
	 * @return the lowercase colon separated hexadecimal SHA-256 fingerprint
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha256Fingerprint(final PublicKey publicKey) throws Exception {
		return BitUtilities.toHexString(getFingerprintBytes(publicKey, "SHA-256"), ":");
	}

	/**
	 * Calculates the SHA-256 fingerprint of the public key of a key pair as unpadded Base64 string (as shown by "ssh-keygen -l" without prefix "SHA256:").
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the Base64 encoded SHA-256 fingerprint without padding
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha256FingerprintBase64(final KeyPair keyPair) throws Exception {
		return getSha256FingerprintBase64(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-256 fingerprint of a public key as unpadded Base64 string (as shown by "ssh-keygen -l" without prefix "SHA256:").
	 *
	 * @param publicKey the public key
	 * @return the Base64 encoded SHA-256 fingerprint without padding
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha256FingerprintBase64(final PublicKey publicKey) throws Exception {
		return Base64.getEncoder().withoutPadding().encodeToString(getFingerprintBytes(publicKey, "SHA-256"));
	}

	/**
	 * Calculates the SHA-384 fingerprint of the public key of a key pair as lowercase colon separated hexadecimal string.
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the lowercase colon separated hexadecimal SHA-384 fingerprint
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha384Fingerprint(final KeyPair keyPair) throws Exception {
		return getSha384Fingerprint(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-384 fingerprint of a public key as lowercase colon separated hexadecimal string.
	 *
	 * @param publicKey the public key
	 * @return the lowercase colon separated hexadecimal SHA-384 fingerprint
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha384Fingerprint(final PublicKey publicKey) throws Exception {
		return BitUtilities.toHexString(getFingerprintBytes(publicKey, "SHA-384"), ":");
	}

	/**
	 * Calculates the SHA-384 fingerprint of the public key of a key pair as unpadded Base64 string (as shown by "ssh-keygen -l -E sha384" without prefix "SHA384:").
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the Base64 encoded SHA-384 fingerprint without padding
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha384FingerprintBase64(final KeyPair keyPair) throws Exception {
		return getSha384FingerprintBase64(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-384 fingerprint of a public key as unpadded Base64 string (as shown by "ssh-keygen -l -E sha384" without prefix "SHA384:").
	 *
	 * @param publicKey the public key
	 * @return the Base64 encoded SHA-384 fingerprint without padding
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha384FingerprintBase64(final PublicKey publicKey) throws Exception {
		return Base64.getEncoder().withoutPadding().encodeToString(getFingerprintBytes(publicKey, "SHA-384"));
	}

	/**
	 * Calculates the SHA-512 fingerprint of the public key of a key pair as lowercase colon separated hexadecimal string.
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the lowercase colon separated hexadecimal SHA-512 fingerprint
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha512Fingerprint(final KeyPair keyPair) throws Exception {
		return getSha512Fingerprint(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-512 fingerprint of a public key as lowercase colon separated hexadecimal string.
	 *
	 * @param publicKey the public key
	 * @return the lowercase colon separated hexadecimal SHA-512 fingerprint
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha512Fingerprint(final PublicKey publicKey) throws Exception {
		return BitUtilities.toHexString(getFingerprintBytes(publicKey, "SHA-512"), ":");
	}

	/**
	 * Calculates the SHA-512 fingerprint of the public key of a key pair as unpadded Base64 string (as shown by "ssh-keygen -l -E sha512" without prefix "SHA512:").
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the Base64 encoded SHA-512 fingerprint without padding
	 * @throws Exception if the key pair or its public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha512FingerprintBase64(final KeyPair keyPair) throws Exception {
		return getSha512FingerprintBase64(getPublicKey(keyPair));
	}

	/**
	 * Calculates the SHA-512 fingerprint of a public key as unpadded Base64 string (as shown by "ssh-keygen -l -E sha512" without prefix "SHA512:").
	 *
	 * @param publicKey the public key
	 * @return the Base64 encoded SHA-512 fingerprint without padding
	 * @throws Exception if the public key is missing or the fingerprint cannot be calculated
	 */
	public static String getSha512FingerprintBase64(final PublicKey publicKey) throws Exception {
		return Base64.getEncoder().withoutPadding().encodeToString(getFingerprintBytes(publicKey, "SHA-512"));
	}

	private static PublicKey getPublicKey(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else if (keyPair.getPublic() == null) {
			throw new Exception("Missing public key in keyPair");
		} else {
			return keyPair.getPublic();
		}
	}

	private static byte[] getFingerprintBytes(final PublicKey publicKey, final String digestAlgorithm) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		}
		try {
			return MessageDigest.getInstance(digestAlgorithm).digest(getPublicKeyBytes(publicKey));
		} catch (final Exception e) {
			throw new Exception("Cannot create " + digestAlgorithm + " fingerprint", e);
		}
	}

	/**
	 * Encodes the public key of a key pair as authorized_keys entry without options and comment (e.g. "ssh-ed25519 AAAAC3...").
	 *
	 * @param keyPair the key pair, which must contain a public key
	 * @return the key type followed by a blank and the Base64 encoded SSH wire format public key
	 * @throws Exception if the key pair or its public key is missing or the key type is unsupported
	 */
	public static String encodePublicKeyForAuthorizedKeys(final KeyPair keyPair) throws Exception {
		if (keyPair == null) {
			throw new Exception("Invalid empty keyPair parameter");
		} else if (keyPair.getPublic() == null) {
			throw new Exception("Missing public key for AuthorizedKey string generation");
		} else {
			return encodePublicKeyForAuthorizedKeys(keyPair.getPublic());
		}
	}

	/**
	 * Encodes a public key as authorized_keys entry without options and comment (e.g. "ssh-ed25519 AAAAC3...").
	 *
	 * @param publicKey the public key
	 * @return the key type followed by a blank and the Base64 encoded SSH wire format public key
	 * @throws Exception if the key is missing or its type is unsupported
	 */
	public static String encodePublicKeyForAuthorizedKeys(final PublicKey publicKey) throws Exception {
		if (publicKey == null) {
			throw new Exception("Invalid empty publicKey parameter");
		} else {
			return getAlgorithm(publicKey).getSshAlgorithmId() + " " + Base64.getEncoder().encodeToString(getPublicKeyBytes(publicKey));
		}
	}

	/**
	 * Writer for SSH wire format data (RFC 4251: string, mpint).
	 */
	private static class BlockDataWriter {
		private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		private final DataOutputStream keyDataOutput = new DataOutputStream(outputStream);

		private void writeBigInt(final BigInteger bigIntegerData) throws Exception {
			writeData(bigIntegerData.toByteArray());
		}

		private void writeString(final String stringData) throws Exception {
			writeData(stringData.getBytes(StandardCharsets.ISO_8859_1));
		}

		private void writeData(final byte[] data) throws Exception {
			if (data.length == 0) {
				throw new Exception("Key blocksize error");
			}
			try {
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
