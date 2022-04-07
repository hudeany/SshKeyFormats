package de.soderer.sshkeyformats.data;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.spec.ECParameterSpec;

import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;

public class CryptographicUtilities {
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
		if (Arrays.equals(OID.ECDSA_PUBLICKEY_ARRAY, ecDsaPublicKeyOid.getByteArrayEncoding())) {
			final OID ecDsaCurveOid = new OID(sshAlgorithmDerTags.get(1).getData());
			if (Arrays.equals(OID.ECDSA_CURVE_NISTP256_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
				return "nistp256";
			} else if (Arrays.equals(OID.ECDSA_CURVE_NISTP384_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
				return "nistp384";
			} else if (Arrays.equals(OID.ECDSA_CURVE_NISTP521_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
				return "nistp521";
			} else {
				throw new Exception("Unknown SSH EcDSA curve OID: " + ecDsaCurveOid.getStringEncoding());
			}
		} else {
			throw new Exception("Unknown SSH EcDSA public key OID: " + ecDsaPublicKeyOid.getStringEncoding());
		}
	}

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
		if (Arrays.equals(OID.ECDSA_PUBLICKEY_ARRAY, ecDsaPublicKeyOid.getByteArrayEncoding())) {
			final OID ecDsaCurveOid = new OID(sshAlgorithmDerTags.get(1).getData());
			if (Arrays.equals(OID.ECDSA_CURVE_NISTP256_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
				return "nistp256";
			} else if (Arrays.equals(OID.ECDSA_CURVE_NISTP384_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
				return "nistp384";
			} else if (Arrays.equals(OID.ECDSA_CURVE_NISTP521_ARRAY, ecDsaCurveOid.getByteArrayEncoding())) {
				return "nistp521";
			} else {
				throw new Exception("Unknown SSH EcDSA curve OID: " + ecDsaCurveOid.getStringEncoding());
			}
		} else {
			throw new Exception("Unknown SSH EcDSA public key OID: " + ecDsaPublicKeyOid.getStringEncoding());
		}
	}

	public static final String getEllipticCurveName(final PublicKey publicKey) throws Exception{
		if (publicKey instanceof ECPublicKey){
			final ECPublicKey pk = (ECPublicKey) publicKey;
			final java.security.spec.ECParameterSpec params = pk.getParams();
			return getEllipticCurveName(EC5Util.convertSpec(params));
		} else if(publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey){
			final org.bouncycastle.jce.interfaces.ECPublicKey pk = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
			return getEllipticCurveName(pk.getParameters());
		} else {
			throw new IllegalArgumentException("This public key is no elliptic curve public key");
		}
	}

	public static final String getEllipticCurveName(final PrivateKey privateKey) throws Exception{
		if (privateKey instanceof ECPrivateKey){
			final ECPrivateKey pk = (ECPrivateKey) privateKey;
			final java.security.spec.ECParameterSpec params = pk.getParams();
			return getEllipticCurveName(EC5Util.convertSpec(params));
		} else if(privateKey instanceof org.bouncycastle.jce.interfaces.ECPrivateKey){
			final org.bouncycastle.jce.interfaces.ECPrivateKey pk = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
			return getEllipticCurveName(pk.getParameters());
		} else {
			throw new IllegalArgumentException("This private key is no elliptic curve private key");
		}
	}

	public static final String getEllipticCurveName(final ECParameterSpec ecParameterSpec) throws Exception{
		for (final String name : Collections.list((Enumeration<String>) org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames())){
			final X9ECParameters params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);
			if (params.getN().equals(ecParameterSpec.getN())
					&& params.getH().equals(ecParameterSpec.getH())
					&& params.getCurve().equals(ecParameterSpec.getCurve())
					&& params.getG().equals(ecParameterSpec.getG())){
				return name;
			}
		}
		throw new Exception("Could not find elliptic curve name");
	}
}
