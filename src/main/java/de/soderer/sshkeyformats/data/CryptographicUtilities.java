package de.soderer.sshkeyformats.data;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;

/**
 * Small cryptographic helper methods used by the SSH key format implementation.
 *
 * <p>This class deliberately contains only functionality that is actually used
 * by the project. Provider-specific functionality is kept out of this class;
 * the JDK/JCA is used wherever it provides the required operation.</p>
 */
public final class CryptographicUtilities {

	private CryptographicUtilities() {
		// Utility class
	}

	/**
	 * Checks whether a private key belongs to the supplied public key by signing
	 * and verifying a random challenge.
	 *
	 * @param privateKey private key
	 * @param publicKey public key
	 * @return {@code true} if the signature created with the private key can be verified
	 *         with the public key; {@code false} otherwise
	 * @throws Exception if the keys are missing, the key algorithms are unsupported, or the signature operation fails
	 */
	public static boolean checkPrivateKeyFitsPublicKey(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		final Signature challengeSignature;
		if (privateKey == null) {
			throw new Exception("PrivateKey is missing");
		} else if (publicKey == null) {
			throw new Exception("PublicKey is missing");
		}

		final String algorithm = privateKey.getAlgorithm();
		if ("DSA".equalsIgnoreCase(algorithm)) {
			challengeSignature = Signature.getInstance("SHA512withDSA");
		} else if ("EC".equalsIgnoreCase(algorithm)) {
			// ECDSA is provided by the JDK; no BC provider is required.
			challengeSignature = Signature.getInstance("SHA512withECDSA");
		} else if ("EdDSA".equalsIgnoreCase(algorithm)) {
			if (!(publicKey instanceof EdECPublicKey)) {
				throw new Exception("PublicKey is not an EdDSA public key");
			}
			final EdECPublicKey publicEdDsaKey = (EdECPublicKey) publicKey;
			if ("Ed25519".equals(publicEdDsaKey.getParams().getName())) {
				challengeSignature = Signature.getInstance("Ed25519");
			} else if ("Ed448".equals(publicEdDsaKey.getParams().getName())) {
				challengeSignature = Signature.getInstance("Ed448");
			} else {
				throw new Exception("Unsupported EdDSA algorithm name: " + publicEdDsaKey.getParams().getName());
			}
		} else if ("Ed25519".equalsIgnoreCase(algorithm)) {
			challengeSignature = Signature.getInstance("Ed25519");
		} else if ("Ed448".equalsIgnoreCase(algorithm)) {
			challengeSignature = Signature.getInstance("Ed448");
		} else {
			challengeSignature = Signature.getInstance("SHA512withRSA");
		}

		final byte[] challenge = new byte[1024];
		ThreadLocalRandom.current().nextBytes(challenge);

		challengeSignature.initSign(privateKey);
		challengeSignature.update(challenge);
		final byte[] signature = challengeSignature.sign();

		challengeSignature.initVerify(publicKey);
		challengeSignature.update(challenge);

		return challengeSignature.verify(signature);
	}

	/**
	 * Returns the SSH curve name for an EC public key.
	 *
	 * <p>The curve is determined from the named-curve OID contained in the
	 * encoded X.509 public-key structure. No provider-specific EC API is used.</p>
	 *
	 * <p>The supported curves are {@code nistp256}, {@code nistp384} and
	 * {@code nistp521}.</p>
	 *
	 * @param publicKeyEC EC public key whose SSH curve name is requested
	 * @return the SSH curve name corresponding to the key, such as {@code nistp256}
	 * @throws Exception if the encoded key is invalid, does not contain an ECDSA
	 *         public-key OID, or uses an unsupported curve
	 */
	public static String getEcDsaEllipticCurveName(final ECPublicKey publicKeyEC) throws Exception {
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
		if (!OID.ECDSA_PUBLICKEY.matches(ecDsaPublicKeyOid.getByteArrayEncoding())) {
			throw new Exception("Unknown SSH EcDSA public key OID: " + ecDsaPublicKeyOid.getStringEncoding());
		}

		final OID ecDsaCurveOid = new OID(sshAlgorithmDerTags.get(1).getData());
		if (OID.ECDSA_CURVE_NISTP256.matches(ecDsaCurveOid.getByteArrayEncoding())) {
			return "nistp256";
		} else if (OID.ECDSA_CURVE_NISTP384.matches(ecDsaCurveOid.getByteArrayEncoding())) {
			return "nistp384";
		} else if (OID.ECDSA_CURVE_NISTP521.matches(ecDsaCurveOid.getByteArrayEncoding())) {
			return "nistp521";
		}
		throw new Exception("Unknown SSH EcDSA curve OID: " + ecDsaCurveOid.getStringEncoding());
	}

	/**
	 * Returns the SSH curve name for an EC private key.
	 *
	 * <p>The encoded PKCS#8/EC private-key structure is inspected to obtain the
	 * named-curve OID, so no provider-specific EC API is needed.</p>
	 *
	 * <p>The supported curves are {@code nistp256}, {@code nistp384} and
	 * {@code nistp521}.</p>
	 *
	 * @param ecPrivateKey EC private key whose SSH curve name is requested
	 * @return the SSH curve name corresponding to the key, such as {@code nistp256}
	 * @throws Exception if the encoded key is invalid, has an unsupported version,
	 *         does not contain an ECDSA public-key OID, or uses an unsupported curve
	 */
	public static String getEcDsaEllipticCurveName(final ECPrivateKey ecPrivateKey) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(ecPrivateKey.getEncoded());
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
		final OID ecDsaPublicKeyOid = new OID(sshAlgorithmDerTags.get(0).getData());
		if (!OID.ECDSA_PUBLICKEY.matches(ecDsaPublicKeyOid.getByteArrayEncoding())) {
			throw new Exception("Unknown SSH EcDSA public key OID: " + ecDsaPublicKeyOid.getStringEncoding());
		}

		final OID ecDsaCurveOid = new OID(sshAlgorithmDerTags.get(1).getData());
		if (OID.ECDSA_CURVE_NISTP256.matches(ecDsaCurveOid.getByteArrayEncoding())) {
			return "nistp256";
		} else if (OID.ECDSA_CURVE_NISTP384.matches(ecDsaCurveOid.getByteArrayEncoding())) {
			return "nistp384";
		} else if (OID.ECDSA_CURVE_NISTP521.matches(ecDsaCurveOid.getByteArrayEncoding())) {
			return "nistp521";
		}
		throw new Exception("Unknown SSH EcDSA curve OID: " + ecDsaCurveOid.getStringEncoding());
	}
}
