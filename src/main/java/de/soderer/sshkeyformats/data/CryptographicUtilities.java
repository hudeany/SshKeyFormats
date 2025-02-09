package de.soderer.sshkeyformats.data;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ThreadLocalRandom;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;
import jdk.security.jarsigner.JarSigner;

public class CryptographicUtilities {
	public static final String[] SYMMETRIC_CIPHERS = {
			// Block chiffre
			"AES", "AESWrap", "Blowfish	", "Camellia", "CamelliaWrap", "CAST5", "CAST6", "DES", "DESede", "TripleDES", "3DES", "DESedeWrap", "GOST28147", "IDEA", "Noekeon", "RC2", "RC5", "RC5-64", "RC6", "Rijndael",
			"SEED", "SEEDWrap", "Serpent", "Skipjack", "TEA", "Twofish", "XTEA",

			// Stream chiffre
			"RC4", "HC128", "HC256", "Salsa20", "VMPC", "Grainv1", "Grain128" };

	public static final String DEFAULT_SYMMETRIC_ENCRYPTION_METHOD = "AES/CBC/PKCS7Padding";
	public static final String[] KNOWN_SYMMETRIC_ENCRYPTION_METHODS = new String[] {
			"AES/CBC/PKCS7Padding", "DES/CBC/PKCS5Padding", "DES/CBC/X9.23Padding", "DES/OFB8/NoPadding",
			"DES/ECB/WithCTS", "IDEA/CBC/ISO10126Padding", "IDEA/CBC/ISO7816-4Padding", "SKIPJACK/ECB/PKCS7Padding" };

	public static final String DEFAULT_SIGNATURE_METHOD_RSA = "SHA256WithRSA";
	public static final String[] KNOWN_SIGNATURE_METHODS_RSA = new String[] { "MD2withRSA", "MD5withRSA", "SHA1withRSA",
			"RIPEMD128withRSA", "RIPEMD160withRSA", "RIPEMD256withRSA", "SHA256withRSA", "SHA224withRSA", "SHA384withRSA",
			"SHA512withRSA", "SHA1withRSAandMGF1", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1" };

	public static final String DEFAULT_SIGNATURE_METHOD_DSA = "SHA256withDSA";
	public static final String[] KNOWN_SIGNATURE_METHODS_DSA = new String[] { "SHA256withDSA", "SHA1withDSA",
			"SHA384withDSA", "SHA512withDSA", "NONEwithDSA" };

	public static final String DEFAULT_SIGNATURE_METHOD_EC = "SHA256withECDSA";
	public static final String[] KNOWN_SIGNATURE_METHODS_EC = new String[] { "RIPEMD160withECDSA", "SHA1withECDSA",
			"NONEwithECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA1withECNR",
			"SHA224withECNR", "SHA256withECNR", "SHA384withECNR", "SHA512withECNR" };

	public static final String[] KNOWN_SIGNATURE_METHODS_OTHERS = new String[] { "DSTU4145", "GOST3411withGOST3410", "GOST3411withGOST3410-94", "GOST3411withECGOST3410",
	"GOST3411withGOST3410-2001" };

	public static final String[] ASYMMETRIC_CIPHERS = new String[] { "RSA", "EC", "ElGamal", "Ed25519", "Ed448" };

	public static final String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_RSA = "RSA/ECB/PKCS1Padding";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_RSA = new String[] {
			"RSA/NONE/PKCS1Padding",
			"RSA/NONE/OAEPPadding",
			"RSA/NONE/NoPadding",
			"RSA/NONE/PKCS1Padding",
			"RSA/NONE/OAEPWithMD5AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA1AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA224AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA256AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA384AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA512AndMGF1Padding",
			"RSA/NONE/ISO9796-1Padding"
	};

	public static final String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_EC = "ECIES";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_EC = new String[] {
			"ECIES"
	};

	public static final String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_ELGAMAL = "ELGAMAL/NONE/PKCS1PADDING";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_ELGAMAL = new String[] {
			"ELGAMAL/NONE/NoPadding",
			"ELGAMAL/NONE/PKCS1PADDING",
	};

	public static final String DEFAULT_ELLIPTIC_CURVE_NAME = "secp256k1";
	public static final String[] KNOWN_ELLIPTIC_CURVE_NAMES = new String[] {
			"secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
			"secp192r1", //= prime192v1
			"prime192v1", //= secp192r1
			"secp224k1", "secp224r1",
			"secp256k1", //= Bitcoin
			"secp256r1", //= prime256v1
			"prime256v1", //= secp256r1
			"secp384r1", "secp521r1",
			"sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1", "sect163r2", "sect193r1",
			"sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
			"sect571k1", "sect571r1"
	};

	public static final String ENCRYPTION_METHOD_ED25519 = "ED25519";
	public static final String ENCRYPTION_METHOD_ED448 = "ED448";

	public static KeyPair generateRsaKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateDsaKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateDhKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateEcKeyPair(final String ecCurveName) throws Exception {
		if (ecCurveName == null || "".equals(ecCurveName.trim())) {
			throw new Exception("Missing EC curve name parameter");
		}

		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecCurveName);
			keyGen.initialize(ecGenParameterSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create EC keypair", e);
		}
	}

	public static KeyPair generateElGamalKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateEd25519KeyPair() throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ED25519", BouncyCastleProvider.PROVIDER_NAME);
			final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("ED25519");
			keyGen.initialize(ecGenParameterSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create EC keypair", e);
		}
	}

	public static KeyPair generateEd448KeyPair() throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ED448", BouncyCastleProvider.PROVIDER_NAME);
			final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("ED448");
			keyGen.initialize(ecGenParameterSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create EC keypair", e);
		}
	}

	public static String getStringFromX509Certificate(final X509Certificate certificate) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final StringWriter stringWriter = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(certificate);
		} catch (final Exception e) {
			throw new Exception("Cannot create certificate string: " + e.getMessage(), e);
		}
		return stringWriter.toString();
	}

	public static String getStringFromKeyPair(final AsymmetricCipherKeyPair keyPair, final char[] password) throws Exception {
		final PublicKey publicKey = getPublicKeyFromAsymmetricCipherKeyPair(keyPair);
		final PrivateKey privateKey = getPrivateKeyFromAsymmetricCipherKeyPair(keyPair);

		return getStringFromKeyPair(privateKey, password, publicKey);
	}

	public static String getStringFromKeyPair(final KeyPair keyPair, final char[] password) throws Exception {
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		return getStringFromKeyPair(privateKey, password, publicKey);
	}

	public static String getStringFromKeyPair(final PrivateKey privateKey, final char[] password, final PublicKey publicKey) throws Exception {
		final StringBuilder result = new StringBuilder();
		result.append(getStringFromKey(privateKey, password));
		result.append(getStringFromKey(publicKey));
		return result.toString();
	}

	public static String getStringFromKey(final PublicKey publicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final StringWriter stringWriter = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(publicKey);
		} catch (final Exception e) {
			throw new Exception("Cannot create public key string: " + e.getMessage(), e);
		}
		return stringWriter.toString();
	}

	public static String getStringFromKey(final PrivateKey privateKey, final char[] password) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		if (password == null || password.length == 0) {
			final StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				pemWriter.writeObject(privateKey);
			} catch (final Exception e) {
				throw new Exception("Cannot create private key string: " + e.getMessage(), e);
			}
			return stringWriter.toString();
		} else {
			final StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				final OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
						.setProvider(BouncyCastleProvider.PROVIDER_NAME)
						.setRandom(new SecureRandom())
						.setPassword(password).build();
				pemWriter.writeObject(new JcaPKCS8Generator(privateKey, encryptor));
			} catch (final Exception e) {
				throw new Exception("Cannot create private key string: " + e.getMessage(), e);
			}
			return stringWriter.toString();
		}
	}

	/**
	 * not tested yet
	 */
	public static KeyPair getKeyPairFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair asymmetricCipherKeyPair) throws Exception {
		final byte[] pkcs8Encoded = PrivateKeyInfoFactory.createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate()).getEncoded();
		final PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8Encoded);
		final byte[] spkiEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic()).getEncoded();
		final X509EncodedKeySpec spkiKeySpec = new X509EncodedKeySpec(spkiEncoded);
		final KeyFactory keyFac = KeyFactory.getInstance("RSA");
		return new KeyPair(keyFac.generatePublic(spkiKeySpec), keyFac.generatePrivate(pkcs8KeySpec));
	}

	public static AsymmetricCipherKeyPair getAsymmetricCipherKeyPair(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(getStringFromKeyPair(privateKey, null, publicKey));
		final AsymmetricKeyParameter privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		final AsymmetricKeyParameter publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());

		return new AsymmetricCipherKeyPair(privateAsymmetricKeyParameter, publicAsymmetricKeyParameter);
	}

	public static PublicKey getPublicKeyFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
	}

	public static PublicKey getPublicKeyFromKeyPair(final KeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
	}

	public static PrivateKey getPrivateKeyFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
		final BigInteger exponent = ((RSAPrivateCrtKeyParameters) keyPair.getPrivate()).getExponent();
		//		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		//		BigInteger exponent = publicKey.getExponent();
		return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(privateKey.getModulus(), exponent, privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
				privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
	}

	/**
	 * Generates Private Key from BASE64 encoded string
	 */
	public static PEMKeyPair getPEMKeyPairFromString(final String keyString) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (PEMParser pemReader = new PEMParser(new StringReader(keyString))) {
			final Object readObject = pemReader.readObject();
			pemReader.close();
			//			if (readObject instanceof PEMEncryptedKeyPair) {
			//                PEMEncryptedKeyPair pemEncryptedKeyPairKeyPair = (PEMEncryptedKeyPair) readObject;
			//                JcePEMDecryptorProviderBuilder jcePEMDecryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();
			//                PEMKeyPair pemKeyPair = pemEncryptedKeyPairKeyPair.decryptKeyPair(jcePEMDecryptorProviderBuilder.build(keyPassword.toCharArray()));
			//            } else
			if (readObject instanceof PEMKeyPair) {
				final PEMKeyPair keyPair = (PEMKeyPair) readObject;
				return keyPair;
			} else if (readObject instanceof PrivateKeyInfo) {
				final PEMKeyPair keyPair = new PEMKeyPair(null, (PrivateKeyInfo) readObject);
				return keyPair;
			} else {
				return null;
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read private key", e);
		}
	}

	/**
	 * Generates X509Certificate from BASE64 encoded string
	 */
	public static List<X509Certificate> getCertificatesFromString(final String certificateString) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (PEMParser pemReader = new PEMParser(new StringReader(certificateString))) {
			final List<X509Certificate> returnList = new ArrayList<>();
			Object readObject;
			while ((readObject = pemReader.readObject()) != null) {
				if (readObject instanceof X509Certificate) {
					returnList.add((X509Certificate) readObject);
				} else if (readObject instanceof X509CertificateHolder) {
					returnList.add(new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) readObject));
				}
			}
			return returnList;
		} catch (final Exception e) {
			throw new Exception("Cannot read certificate", e);
		}
	}

	public static byte[] stretchPassword(final char[] password, final int keyLength, final byte[] salt) {
		Security.addProvider(new BouncyCastleProvider());

		final PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
		generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, 1000);
		final KeyParameter params = (KeyParameter) generator.generateDerivedParameters(keyLength);
		return params.getKey();
	}

	/**
	 * Check if jar file has a signature and has only signed class and resource files
	 *
	 * @param jarFile
	 * @return
	 * @throws Exception
	 */
	public static boolean checkJarIsCompletlySigned(final File jarFile) throws Exception {
		try (JarFile jar = new JarFile(jarFile)) {
			final Manifest manifest = jar.getManifest();
			if (manifest == null) {
				// Has no MANIFEST.MF file
				return false;
			}

			final byte[] buffer = new byte[4096];
			final Enumeration<JarEntry> jarEntriesEnumerator = jar.entries();

			while (jarEntriesEnumerator.hasMoreElements()) {
				final JarEntry jarEntry = jarEntriesEnumerator.nextElement();

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry)) {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// just read it
					}
				}

				if (!jarEntry.isDirectory()) {
					// Every file must be signed, except for files in META-INF
					final Certificate[] certificates = jarEntry.getCertificates();
					if ((certificates == null) || (certificates.length == 0)) {
						if (!jarEntry.getName().startsWith("META-INF")) {
							// Contains unsigned files
							return false;
						}
					} else {
						for (final Certificate cert : certificates) {
							if (!(cert instanceof X509Certificate)) {
								// Unknown type of certificate
								return false;
							}
						}
					}
				}
			}

			return true;
		}
	}

	public static boolean verifyJarSignature(final File jarFile, final Collection<? extends Certificate> trustedCertificates) {
		if (trustedCertificates == null || trustedCertificates.size() == 0) {
			return false;
		}

		try (JarFile jar = new JarFile(jarFile)) {
			final Manifest manifest = jar.getManifest();
			if (manifest == null) {
				throw new SecurityException("The jar file has no manifest, which contains the file signatures");
			}

			final byte[] buffer = new byte[4096];
			final Enumeration<JarEntry> jarEntriesEnumerator = jar.entries();

			while (jarEntriesEnumerator.hasMoreElements()) {
				final JarEntry jarEntry = jarEntriesEnumerator.nextElement();

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry)) {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// just read it
					}
				}

				if (!jarEntry.isDirectory()) {
					// Every file must be signed, except for files in META-INF
					final Certificate[] certificates = jarEntry.getCertificates();
					if ((certificates == null) || (certificates.length == 0)) {
						if (!jarEntry.getName().startsWith("META-INF")) {
							throw new SecurityException("The jar file contains unsigned files.");
						}
					} else {
						boolean isSignedByTrustedCert = false;

						for (final Certificate chainRootCertificate : certificates) {
							if (chainRootCertificate instanceof X509Certificate && verifyChainOfTrust((X509Certificate) chainRootCertificate, trustedCertificates)) {
								// TODO: check certificate validity period: ((X509Certificate) chainRootCertificate).checkValidity();
								isSignedByTrustedCert = true;
								break;
							}
						}

						if (!isSignedByTrustedCert) {
							throw new SecurityException("The jar file contains untrusted signed files");
						}
					}
				}
			}

			return true;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	public static void createJarSignature(final File unsignedJarFile, final PrivateKey privateKey, final CertPath certPath, final File signedJarFile) throws Exception {
		final JarSigner signer = new JarSigner.Builder(privateKey, certPath).build();
		try (ZipFile in = new ZipFile(unsignedJarFile);
				FileOutputStream out = new FileOutputStream(signedJarFile)) {
			signer.sign(in, out);
		}
	}

	public static CertPath createX509CertPath(final Certificate[] certs) throws Exception {
		return CertificateFactory.getInstance("X509").generateCertPath(Arrays.asList(certs));
	}

	public static CertPath createX509CertPath(final List<X509Certificate> certs) throws Exception {
		return CertificateFactory.getInstance("X509").generateCertPath(certs);
	}

	public static CertPath createX509CertPath(final X509Certificate cert) throws Exception {
		final List<Certificate> certs = new ArrayList<>();
		certs.add(cert);
		return CertificateFactory.getInstance("X509").generateCertPath(certs);
	}

	/**
	 * Check if "certificate" was certified by "trustedCertificates"
	 *
	 * @param certificate
	 * @param trustedCertificates
	 * @return
	 * @throws Exception
	 */
	public static boolean verifyChainOfTrust(final X509Certificate certificate, final Collection<? extends Certificate> trustedCertificates) throws Exception {
		final X509CertSelector targetConstraints = new X509CertSelector();
		targetConstraints.setCertificate(certificate);

		final Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (final Certificate trustedRootCert : trustedCertificates) {
			trustAnchors.add(new TrustAnchor((X509Certificate) trustedRootCert, null));
		}

		final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetConstraints);
		params.setRevocationEnabled(false);
		try {
			final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
			return result != null;
		} catch (@SuppressWarnings("unused") final Exception cpbe) {
			return false;
		}
	}

	/**
	 * Check if "certificate" was certified by "trustedCertificates"
	 *
	 * @param certificate
	 * @param trustedCertificates
	 * @return
	 * @throws Exception
	 */
	public static boolean verifyChainOfTrust(final X509Certificate certificate, final Certificate... trustedCertificates) throws Exception {
		final X509CertSelector targetConstraints = new X509CertSelector();
		targetConstraints.setCertificate(certificate);

		final Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (final Certificate trustedRootCert : trustedCertificates) {
			trustAnchors.add(new TrustAnchor((X509Certificate) trustedRootCert, null));
		}

		final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetConstraints);
		params.setRevocationEnabled(false);
		try {
			final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
			return result != null;
		} catch (@SuppressWarnings("unused") final Exception cpbe) {
			return false;
		}
	}

	public static X509Certificate[] getChainRootCertificates(final Certificate[] certificates) {
		final Vector<X509Certificate> result = new Vector<>();
		for (int i = 0; i < certificates.length - 1; i++) {
			if (!((X509Certificate) certificates[i + 1]).getSubjectX500Principal().equals(((X509Certificate) certificates[i]).getIssuerX500Principal())) {
				result.addElement((X509Certificate) certificates[i]);
			}
		}
		// The final entry in the certificates array is always a root certificate
		result.addElement((X509Certificate) certificates[certificates.length - 1]);
		final X509Certificate[] returnValue = new X509Certificate[result.size()];
		result.copyInto(returnValue);
		return returnValue;
	}

	public static Collection<? extends X509Certificate> loadCertificatesFromPemStream(final InputStream pemInputStream) throws Exception {
		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		@SuppressWarnings("unchecked")
		final Collection<? extends X509Certificate> certificates = (Collection<? extends X509Certificate>) certificateFactory.generateCertificates(pemInputStream);
		return certificates;
	}

	public static boolean checkForCaCertificate(final X509Certificate certificate) {
		return certificate.getBasicConstraints() >= 0;
	}

	public static String getMd5FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha1FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha256FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha384FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-384");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha512FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-512");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getMd5FingerPrint(final Key key, final String byteSeparator) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest(), byteSeparator);
	}

	public static String getMd5FingerPrintBase64(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(md.digest());
	}

	public static String getSha1FingerPrint(final Key key, final String byteSeparator) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest(), byteSeparator);
	}

	public static String getSha1FingerPrintBase64(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(md.digest());
	}

	public static String getSha256FingerPrint(final Key key, final String byteSeparator) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest(), byteSeparator);
	}

	public static String getSha256FingerPrintBase64(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(md.digest());
	}

	public static String getSha384FingerPrint(final Key key, final String byteSeparator) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-384");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest(), byteSeparator);
	}

	public static String getSha384FingerPrintBase64(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-384");
		md.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(md.digest());
	}

	public static String getSha512FingerPrint(final Key key, final String byteSeparator) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-512");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest(), byteSeparator);
	}

	public static String getSha512FingerPrintBase64(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-512");
		md.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(md.digest());
	}

	public static KeyPair convertPEMKeyPairToKeyPair(final PEMKeyPair keyPair) throws PEMException {
		try {
			String algorithm = keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm().getAlgorithm().getId();
			if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm)) {
				algorithm = "ECDSA";
			}

			final KeyFactory keyFactory = new DefaultJcaJceHelper().createKeyFactory(algorithm);

			return new KeyPair(
					keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublicKeyInfo().getEncoded())),
					keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivateKeyInfo().getEncoded())));
		} catch (final Exception e) {
			throw new PEMException("Unable to convert key pair: " + e.getMessage(), e);
		}
	}

	public static PublicKey getPublicKeyFromString(final String keyDataString) throws Exception {
		try {
			Security.addProvider(new BouncyCastleProvider());

			try (final PEMParser pemParser = new PEMParser(new StringReader(keyDataString))) {
				Object object;
				while ((object = pemParser.readObject()) != null) {
					if (object instanceof PEMKeyPair) {
						final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
						final KeyPair keyPair = converter.getKeyPair((PEMKeyPair) object);
						return keyPair.getPublic();
					} else if (object instanceof SubjectPublicKeyInfo) {
						final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
						return converter.getPublicKey((SubjectPublicKeyInfo) object);
					}
				}
				throw new Exception("No public key object found in data");
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read public key: " + e.getMessage(), e);
		}
	}

	public static String getKeyInfo(final Key key) {
		String dataOutput = "";
		dataOutput += "Algorithm: " + key.getAlgorithm();
		dataOutput += "\n";

		if (key instanceof PrivateKey) {
			dataOutput += "Keytype: PrivateKey";
			dataOutput += "\n";
		} else if (key instanceof PublicKey) {
			dataOutput += "Keytype: PublicKey";
			dataOutput += "\n";
		}

		if (key instanceof RSAKey) {
			dataOutput += "Key length: " + ((RSAKey) key).getModulus().bitLength();
			dataOutput += "\n";
		} else if (key instanceof ECKey) {
			try {
				if (key instanceof PrivateKey) {
					dataOutput += "Elliptic Curve Name: " + getEllipticCurveName((PrivateKey) key);
					dataOutput += "\n";
				} else if (key instanceof PublicKey) {
					dataOutput += "Elliptic Curve Name: " + getEllipticCurveName((PublicKey) key);
					dataOutput += "\n";
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				dataOutput += "Elliptic Curve Name: Unknown";
				dataOutput += "\n";
			}
		}

		try {
			dataOutput += "MD5 fingerprint: " + CryptographicUtilities.getMd5FingerPrint(key, null);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "MD5 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA1 fingerprint: " + CryptographicUtilities.getSha1FingerPrint(key, null);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA1 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA256 fingerprint: " + CryptographicUtilities.getSha256FingerPrint(key, null);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA256 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA384 fingerprint: " + CryptographicUtilities.getSha384FingerPrint(key, null);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA384 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA512 fingerprint: " + CryptographicUtilities.getSha512FingerPrint(key, null);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA512 fingerprint: Unknown";
		}
		dataOutput += "\n";

		return dataOutput;
	}

	public static boolean checkPrivateKeyFitsPublicKey(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		final Signature challengeSignature;
		if (privateKey == null) {
			throw new Exception("PrivateKey is missing");
		} else if (publicKey == null) {
			throw new Exception("PublicKey is missing");
		} else if (privateKey.getAlgorithm().toLowerCase().equals("dsa")) {
			challengeSignature = Signature.getInstance("SHA512withDSA");
		} else if (privateKey.getAlgorithm().toLowerCase().equals("ec")) {
			Security.addProvider(new BouncyCastleProvider());
			challengeSignature = Signature.getInstance("SHA512withECDSA", BouncyCastleProvider.PROVIDER_NAME);
		} else if (privateKey.getAlgorithm().toLowerCase().equals("eddsa")) {
			final EdECPublicKey publicEdDsaKey = (EdECPublicKey) publicKey;
			if ("Ed25519".equals(publicEdDsaKey.getParams().getName())) {
				challengeSignature = Signature.getInstance("Ed25519");
			} else if ("Ed448".equals(publicEdDsaKey.getParams().getName())) {
				challengeSignature = Signature.getInstance("Ed448");
			} else {
				throw new Exception("Unsupported EdDSA algorithm name: " + publicEdDsaKey.getParams().getName());
			}
		} else if (privateKey.getAlgorithm().toLowerCase().equals("ed25519")) {
			challengeSignature = Signature.getInstance("Ed25519");
		} else if (privateKey.getAlgorithm().toLowerCase().equals("ed448")) {
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

	public static String checkSignatureMethodName(final String signatureMethodName) {
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_RSA) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_DSA) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_EC) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_OTHERS) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		return null;
	}

	public static ASN1ObjectIdentifier getASN1ObjectIdentifierByEncryptionMethodName(final String encryptionMethodName) {
		try {
			for (final Field field : CMSAlgorithm.class.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) && field.getName().replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(encryptionMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
					return (ASN1ObjectIdentifier) field.get(encryptionMethodName);
				}
			}
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static String checkEncryptionMethodName(final String encryptionMethodName) {
		try {
			for (final Field field : CMSAlgorithm.class.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) && field.getName().replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(encryptionMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
					return encryptionMethodName;
				}
			}
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static String getStringFromCertificationRequest(final PKCS10CertificationRequest certificationRequest) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final StringWriter writer = new StringWriter();
		try (final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(writer)) {
			jcaPEMWriter.writeObject(certificationRequest);
		} catch (final Exception e) {
			throw new Exception("Cannot create certification signing request string: " + e.getMessage(), e);
		}
		return writer.toString();
	}

	public static PKCS10CertificationRequest getCertificationRequestFromString(final String encodedCertificationRequest) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		PKCS10CertificationRequest certificationRequest;
		try (final PEMParser pemParser = new PEMParser(new StringReader(encodedCertificationRequest))) {
			certificationRequest = (PKCS10CertificationRequest) pemParser.readObject();
		} catch (final IOException e) {
			throw new Exception("Error in reading the certificate signing request: " + e.getMessage(), e);
		}
		return certificationRequest;
	}

	public static boolean isKeyStoreFile(final File potentialKeyStoreFile) {
		if (potentialKeyStoreFile != null && potentialKeyStoreFile.exists()) {
			try (InputStream keyStoreInputStream = new FileInputStream(potentialKeyStoreFile)) {
				final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				keyStore.load(keyStoreInputStream, null);
				return true;
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static boolean isJavaKeyStoreFile(final File potentialJavaKeyStoreFile) {
		if (potentialJavaKeyStoreFile != null && potentialJavaKeyStoreFile.exists()) {
			final byte[] firstBytes = new byte[4];
			try (InputStream keyStoreInputStream = new FileInputStream(potentialJavaKeyStoreFile)) {
				if (keyStoreInputStream.read(firstBytes) == 4) {
					// Magic file numbers "FE ED FE ED"
					return firstBytes[0] == -2 && firstBytes[1] == -19 && firstBytes[2] == -2 && firstBytes[3] == -19;
				} else {
					return false;
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static PublicKey getPublicKeyFromPrivateKey(final PrivateKey privateKey) throws Exception {
		if (privateKey == null) {
			throw new Exception("Cannot extract PublicKey from empty PrivateKey");
		} else if (privateKey instanceof RSAPrivateCrtKey) {
			final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(((RSAPrivateCrtKey) privateKey).getModulus(), ((RSAPrivateCrtKey) privateKey).getPublicExponent());
			final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(publicKeySpec);
		} else if (privateKey instanceof org.bouncycastle.jce.interfaces.ECPrivateKey) {
			final org.bouncycastle.jce.interfaces.ECPrivateKey ecPrivateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
			final String name = getEllipticCurveName(ecPrivateKey);
			final KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
			final ECPoint q = ecSpec.getG().multiply(ecPrivateKey.getD());
			final byte[] publicDerBytes = q.getEncoded(false);
			final ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
			final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
			return keyFactory.generatePublic(pubSpec);
		} else if (privateKey instanceof ECPrivateKey) {
			final ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
			final String name = getEllipticCurveName(ecPrivateKey);
			final KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
			final ECPoint q = ecSpec.getG().multiply(ecPrivateKey.getS());
			final byte[] publicDerBytes = q.getEncoded(false);
			final ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
			final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
			return keyFactory.generatePublic(pubSpec);
		} else if (privateKey instanceof DSAPrivateKey) {
			throw new Exception("Cannot extract PublicKey from " + privateKey.getClass().getSimpleName());
		} else {
			throw new Exception("Cannot extract PublicKey from " + privateKey.getClass().getSimpleName());
		}
	}

	public static List<String> getKeyAliasesFromJavaKeyStore(final KeyStore keyStore) throws KeyStoreException {
		final List<String> keyAliases = new ArrayList<>();
		for (final String alias : Collections.list(keyStore.aliases())) {
			try {
				if (keyStore.entryInstanceOf(alias, SecretKeyEntry.class)) {
					keyAliases.add(alias);
				} else if (keyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
					keyAliases.add(alias);
				}
			} catch (@SuppressWarnings("unused") final KeyStoreException e) {
				// Do not list this alias
			}
		}
		return keyAliases;
	}

	public static List<X509Certificate> getCertificatesFromJavaKeyStore(final KeyStore keyStore) throws Exception {
		final List<X509Certificate> certificates = new ArrayList<>();
		for (final String alias : Collections.list(keyStore.aliases())) {
			try {
				if (keyStore.entryInstanceOf(alias, TrustedCertificateEntry.class)) {
					final TrustedCertificateEntry entry = (TrustedCertificateEntry) keyStore.getEntry(alias, null);
					certificates.add((X509Certificate) entry.getTrustedCertificate());
				} else if (keyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
					final Certificate certificate = keyStore.getCertificate(alias);
					if (certificate != null && certificate instanceof X509Certificate) {
						certificates.add((X509Certificate) certificate);
					}
				}
			} catch (@SuppressWarnings("unused") final KeyStoreException e) {
				// Do not list this alias
			}
		}
		return certificates;
	}

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
		if (publicKey instanceof ECPublicKey) {
			final ECPublicKey pk = (ECPublicKey) publicKey;
			final java.security.spec.ECParameterSpec params = pk.getParams();
			return getEllipticCurveName(EC5Util.convertSpec(params));
		} else if(publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
			final org.bouncycastle.jce.interfaces.ECPublicKey pk = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
			return getEllipticCurveName(pk.getParameters());
		} else {
			throw new IllegalArgumentException("This public key is no elliptic curve public key");
		}
	}

	public static final String getEllipticCurveName(final PrivateKey privateKey) throws Exception{
		if (privateKey instanceof ECPrivateKey) {
			final ECPrivateKey pk = (ECPrivateKey) privateKey;
			final java.security.spec.ECParameterSpec params = pk.getParams();
			return getEllipticCurveName(EC5Util.convertSpec(params));
		} else if(privateKey instanceof org.bouncycastle.jce.interfaces.ECPrivateKey) {
			final org.bouncycastle.jce.interfaces.ECPrivateKey pk = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
			return getEllipticCurveName(pk.getParameters());
		} else {
			throw new IllegalArgumentException("This private key is no elliptic curve private key");
		}
	}

	public static final String getEllipticCurveName(final ECParameterSpec ecParameterSpec) throws Exception{
		final Enumeration<String> curveNamesEnumeration = org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames();

		for (final String name : Collections.list(curveNamesEnumeration)) {
			final X9ECParameters params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);
			if (params.getN().equals(ecParameterSpec.getN())
					&& params.getH().equals(ecParameterSpec.getH())
					&& params.getCurve().equals(ecParameterSpec.getCurve())
					&& params.getG().equals(ecParameterSpec.getG())) {
				return name;
			}
		}
		throw new Exception("Could not find elliptic curve name");
	}
}
