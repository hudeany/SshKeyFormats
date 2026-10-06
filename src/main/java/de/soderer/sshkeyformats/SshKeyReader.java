package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import de.soderer.sshkeyformats.SshKey.SshKeyFormat;
import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.Asn1Codec;
import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;
import de.soderer.sshkeyformats.data.AuthorizedKeyLineParser;
import de.soderer.sshkeyformats.data.BCryptPBKDF;
import de.soderer.sshkeyformats.data.KeyPairUtilities;
import de.soderer.sshkeyformats.data.OID;
import de.soderer.sshkeyformats.data.Password;
import de.soderer.sshkeyformats.data.WrongPasswordException;

/**
 * Reader for SSH public and private keys with optional password protection<br />
 * <br />
 * Supported key formats:<br />
 * - OpenSSHv1 (proprietary format of OpenSSH, "-----BEGIN OPENSSH PRIVATE KEY-----")<br />
 * - OpenSSL traditional ("-----BEGIN RSA/DSA/EC PRIVATE KEY-----", optionally encrypted by "Proc-Type: 4,ENCRYPTED")<br />
 * - PKCS#8 ("-----BEGIN PRIVATE KEY-----" and "-----BEGIN ENCRYPTED PRIVATE KEY-----" with PBES2/PBKDF2)<br />
 * - X.509 SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") and PKCS#1 ("-----BEGIN RSA PUBLIC KEY-----")<br />
 * - PuTTY key version 2 ("PuTTY-User-Key-File-2: ...")<br />
 * - PuTTY key version 3 ("PuTTY-User-Key-File-3: ...")<br />
 * - RFC 4716 ("---- BEGIN SSH2 PUBLIC KEY ----")<br />
 * - OpenSSH public keys and authorized_keys lines<br />
 * <br />
 * Supported cipher algorithms:<br />
 * - RSA<br />
 * - DSA<br />
 * - EC / ECDSA (nistp256, nistp384, nistp521)<br />
 * - EdDSA (Ed25519, Ed448)<br />
 * <br />
 */
public class SshKeyReader {
	/** Maximum encoded key data accepted in a PEM/RFC4716 block. */
	private static final int MAX_BASE64_ENCODED_DATA_LENGTH = 24 * 1024 * 1024; // 24 MB
	/** Maximum length of a single input line in characters (an authorized_keys line of a RSA-16384 key has about 3 KB). */
	static final int MAX_LINE_LENGTH = 1024 * 1024;
	/** Maximum number of header lines accepted in a PEM, RFC 4716 or PuTTY key. */
	static final int MAX_HEADER_COUNT = 64;
	/** Maximum length of a single header value including all continuation lines. */
	static final int MAX_HEADER_VALUE_LENGTH = 64 * 1024;
	/** Maximum number of PuTTY data lines accepted for one Public-Lines/Private-Lines section. */
	private static final int MAX_PUTTY_DATA_LINES = 1024 * 1024;
	/**
	 * Sanity upper bound for the bcrypt KDF round count of encrypted OpenSSH v1 private keys, to
	 * protect against maliciously crafted or corrupted key files that could otherwise force a
	 * practically unbounded CPU-bound loop during key derivation (Denial of Service protection),
	 * which happens before the password can even be validated. One round takes roughly 15 ms, so this
	 * limit allows about 2.5 minutes per derivation, while ssh-keygen defaults to 16 rounds.
	 */
	static final int MAX_BCRYPT_KDF_ROUNDS = 10_000;

	/** Sanity upper bound for PBKDF2 iterations of encrypted PKCS#8 keys (OpenSSL default is 2048). */
	static final int MAX_PBKDF2_ITERATIONS = 10_000_000;

	/** Sanity upper bound for the Argon2 memory of PuTTY v3 keys in KiB (PuTTY default is 8192 KiB). */
	static final int MAX_ARGON2_MEMORY_KB = 1024 * 1024;

	/** Sanity upper bound for the Argon2 passes of PuTTY v3 keys. */
	static final int MAX_ARGON2_PASSES = 1000;

	/** Sanity upper bound for the product of Argon2 memory and passes of PuTTY v3 keys (64 GiB processed in total). */
	static final long MAX_ARGON2_MEMORY_TIMES_PASSES_KB = 64L * 1024 * 1024;

	/** Sanity upper bound for the Argon2 parallelism of PuTTY v3 keys. */
	static final int MAX_ARGON2_PARALLELISM = 64;

	/** BouncyCastle provider instance, used directly without registering it globally in the JVM. */
	static final Provider BC_PROVIDER = new BouncyCastleProvider();

	private static final String PEM_BEGIN_PREFIX = "-----BEGIN ";
	private static final String PEM_SUFFIX = "-----";
	private static final String SSH2_BEGIN_PREFIX = "---- BEGIN SSH2 ";
	private static final String SSH2_SUFFIX = " KEY ----";

	private static final OID OID_PBES2 = oid("1.2.840.113549.1.5.13");
	private static final OID OID_PBKDF2 = oid("1.2.840.113549.1.5.12");
	private static final OID OID_SCRYPT = oid("1.3.6.1.4.1.11591.4.11");
	private static final OID OID_HMAC_SHA1 = oid("1.2.840.113549.2.7");
	private static final OID OID_HMAC_SHA224 = oid("1.2.840.113549.2.8");
	private static final OID OID_HMAC_SHA256 = oid("1.2.840.113549.2.9");
	private static final OID OID_HMAC_SHA384 = oid("1.2.840.113549.2.10");
	private static final OID OID_HMAC_SHA512 = oid("1.2.840.113549.2.11");
	private static final OID OID_AES128_CBC = oid("2.16.840.1.101.3.4.1.2");
	private static final OID OID_AES192_CBC = oid("2.16.840.1.101.3.4.1.22");
	private static final OID OID_AES256_CBC = oid("2.16.840.1.101.3.4.1.42");
	private static final OID OID_DES_EDE3_CBC = oid("1.2.840.113549.3.7");

	private static OID oid(final String oidString) {
		try {
			return new OID(oidString);
		} catch (final Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Reads all public key data and ignores private key parts.
	 * <p>
	 * This is useful when only the public keys are needed and the password of an
	 * encrypted private key is not available. Unencrypted private keys contribute their public key.
	 * Encrypted private keys, which do not contain unencrypted public key data, are skipped.
	 *
	 * @param inputStream the input stream containing one or more SSH public keys
	 * @return the public keys found in the input stream
	 * @throws Exception if the input cannot be parsed
	 */
	public static List<SshKey> readAllPublicKeys(final InputStream inputStream) throws Exception {
		try (final LimitedLineReader dataReader = new LimitedLineReader(new InputStreamReader(inputStream, StandardCharsets.ISO_8859_1), MAX_LINE_LENGTH)) {
			final List<SshKey> keyList = new ArrayList<>();
			SshKey nextKey;
			while ((nextKey = readNextKey(dataReader, null, true)) != null) {
				keyList.add(nextKey);
			}
			return keyList;
		}
	}

	/**
	 * Reads public and private key data, as far as it is available.
	 * <p>
	 * A password is optional and should be {@code null} for unencrypted private keys.
	 * When multiple keys are stored in the input, only the first key is read.
	 *
	 * @param inputStream the input stream containing the SSH key
	 * @param passwordChars the password for an encrypted private key, or {@code null} for an unencrypted key
	 * @return the first SSH key found in the input stream, or {@code null} if the input contains no key
	 * @throws Exception if the input cannot be parsed or the password is incorrect
	 */
	public static SshKey readKey(final InputStream inputStream, final char[] passwordChars) throws Exception {
		try (final LimitedLineReader dataReader = new LimitedLineReader(new InputStreamReader(inputStream, StandardCharsets.ISO_8859_1), MAX_LINE_LENGTH)) {
			return readNextKey(dataReader, passwordChars, false);
		}
	}

	/**
	 * Reads the next key of the input.
	 * <p>
	 * The stream is read internally with ISO-8859-1 charset, because PuTTY keys use it and their comments are part of the MAC checksum.
	 *
	 * @return the next key or {@code null} at the end of the input
	 */
	private static SshKey readNextKey(final LimitedLineReader dataReader, final char[] passwordChars, final boolean publicKeyOnly) throws Exception {
		try (final Password password = new Password(passwordChars == null ? null : passwordChars.clone())) {
			while (true) {
				final String nextLine = readNextContentLine(dataReader);
				if (nextLine == null) {
					return null;
				}

				final SshKey sshKey;
				if (nextLine.startsWith(PEM_BEGIN_PREFIX) && nextLine.endsWith(PEM_SUFFIX) && nextLine.length() > PEM_BEGIN_PREFIX.length() + PEM_SUFFIX.length()) {
					final String pemTypeName = nextLine.substring(PEM_BEGIN_PREFIX.length(), nextLine.length() - PEM_SUFFIX.length()).trim();
					final TextBlock pemBlock = readPemBlock(dataReader, "-----END " + pemTypeName + "-----");
					sshKey = readPemKey(pemTypeName, pemBlock, password, publicKeyOnly);
				} else if (nextLine.startsWith(SSH2_BEGIN_PREFIX) && nextLine.endsWith(SSH2_SUFFIX)) {
					final TextBlock ssh2Block = readRfc4716Block(dataReader, nextLine.replace("BEGIN ", "END "));
					if (nextLine.toLowerCase().contains("public")) {
						sshKey = new SshKey(SshKeyFormat.OpenSSL, ssh2Block.getHeader("Comment"), new KeyPair(parsePublicKeyBytes(ssh2Block.getData()), null));
					} else if (nextLine.toLowerCase().contains("private")) {
						sshKey = readTraditionalPrivateKey("RSA", ssh2Block, password, publicKeyOnly, SshKeyFormat.OpenSSL);
					} else {
						throw new Exception("Unknown key identifier found: " + nextLine);
					}
				} else if (nextLine.startsWith("PuTTY-User-Key-File-2:") || nextLine.startsWith("PuTTY-User-Key-File-3:")) {
					final int puttyVersion = nextLine.startsWith("PuTTY-User-Key-File-2:") ? 2 : 3;
					final Map<String, String> keyProperties = readPuttyKeyProperties(dataReader);
					keyProperties.put("PuTTY-User-Key-File", nextLine.substring(nextLine.indexOf(':') + 1).trim());
					sshKey = readPuttyKey(puttyVersion, keyProperties, password, publicKeyOnly);
				} else if (isBase64(nextLine)) {
					sshKey = new SshKey(SshKeyFormat.OpenSSL, null, new KeyPair(parsePublicKeyBytes(Base64.getDecoder().decode(nextLine)), null));
				} else {
					// Everything else must be an authorized_keys line (OpenSSH public key with optional options and comment).
					// Parse errors are reported with the detailed message of the parser.
					final AuthorizedKey authorizedKey = AuthorizedKeyLineParser.parseAuthorizedKeyLine(nextLine);
					authorizedKey.setKeyPair(new KeyPair(parsePublicKeyBytes(Base64.getDecoder().decode(authorizedKey.getKeyString())), null));
					if (authorizedKey.getKeyType() != authorizedKey.getAlgorithm()) {
						throw new Exception("AuthorizedKey keytype mismatch for authorizedKey line \"" + nextLine + "\". Public keys keytype is " + authorizedKey.getAlgorithm());
					}
					sshKey = authorizedKey;
				}

				if (sshKey != null) {
					return sshKey;
				}
				// Key was skipped (encrypted private key without public key data in public key only mode), continue with the next one
			}
		}
	}

	private static String readNextContentLine(final LimitedLineReader dataReader) throws IOException {
		String nextLine;
		while ((nextLine = dataReader.readLine()) != null) {
			nextLine = nextLine.trim();
			// Skip empty lines and comment lines (#), especially for public key files
			if (!nextLine.isEmpty() && !nextLine.startsWith("#")) {
				return nextLine;
			}
		}
		return null;
	}

	private static boolean isBase64(final String value) {
		try {
			Base64.getDecoder().decode(value);
			return true;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	// ---------------------------------------------------------------------------------------------
	// PEM (OpenSSL / PKCS#8 / X.509 / OpenSSH v1)
	// ---------------------------------------------------------------------------------------------

	private static SshKey readPemKey(final String pemTypeName, final TextBlock pemBlock, final Password password, final boolean publicKeyOnly) throws Exception {
		switch (pemTypeName) {
			case "OPENSSH PRIVATE KEY":
				return readOpenSshv1Key(pemBlock.getData(), password, publicKeyOnly);
			case "RSA PRIVATE KEY":
				return readTraditionalPrivateKey("RSA", pemBlock, password, publicKeyOnly, SshKeyFormat.OpenSSL);
			case "DSA PRIVATE KEY":
				return readTraditionalPrivateKey("DSA", pemBlock, password, publicKeyOnly, SshKeyFormat.OpenSSL);
			case "EC PRIVATE KEY":
				return readTraditionalPrivateKey("EC", pemBlock, password, publicKeyOnly, SshKeyFormat.OpenSSL);
			case "PRIVATE KEY":
				// PKCS#8, optionally encrypted by legacy PEM encryption headers
				return readTraditionalPrivateKey("PKCS8", pemBlock, password, publicKeyOnly, SshKeyFormat.OpenSSL);
			case "ENCRYPTED PRIVATE KEY":
				if (publicKeyOnly) {
					return null;
				} else {
					return new SshKey(SshKeyFormat.OpenSSL, null, decryptPkcs8PrivateKey(pemBlock.getData(), password));
				}
			case "PUBLIC KEY":
				return new SshKey(SshKeyFormat.OpenSSL, null, new KeyPair(parseX509PublicKey(pemBlock.getData()), null));
			case "RSA PUBLIC KEY":
				return new SshKey(SshKeyFormat.PKCS1, null, new KeyPair(parsePkcs1RsaPublicKey(pemBlock.getData()), null));
			default:
				throw new Exception("Unknown key identifier found: " + pemTypeName);
		}
	}

	/**
	 * Reads unencrypted or legacy encrypted ("Proc-Type: 4,ENCRYPTED") private keys.
	 *
	 * @param keyType "RSA", "DSA", "EC" (traditional OpenSSL formats) or "PKCS8"
	 * @return the key, or {@code null} if an encrypted key was skipped in public key only mode
	 */
	private static SshKey readTraditionalPrivateKey(final String keyType, final TextBlock pemBlock, final Password password, final boolean publicKeyOnly, final SshKeyFormat keyFormat) throws Exception {
		final boolean encrypted = "4,ENCRYPTED".equals(pemBlock.getHeader("Proc-Type"));
		if (!encrypted) {
			final KeyPair keyPair = parsePrivateKeyDer(keyType, pemBlock.getData());
			return new SshKey(keyFormat, null, publicKeyOnly ? new KeyPair(keyPair.getPublic(), null) : keyPair);
		} else if (publicKeyOnly) {
			return null;
		} else if (!password.hasPassword()) {
			throw new WrongPasswordException("Key is encrypted, but no password was given");
		} else {
			// Putty uses "ISO-8859-1" for password encoding, even for those keys stored in OpenSSHv1 and OpenSSL format
			// "ssh-keygen" on Linux uses UTF-8 for password encoding
			Exception lastException = null;
			for (final byte[] passwordBytes : getPasswordByteVariants(password, true)) {
				final byte[] decryptedData;
				try {
					decryptedData = decryptOpenSslKeyData(pemBlock.getData(), pemBlock.getHeader("DEK-Info"), passwordBytes);
				} catch (final WrongPasswordException e) {
					lastException = e;
					continue;
				}
				try {
					return new SshKey(keyFormat, null, parsePrivateKeyDer(keyType, decryptedData));
				} catch (final Exception e) {
					// Padding was valid by chance, but the decrypted data is garbage
					lastException = e;
				}
			}
			throw new WrongPasswordException("Missing or wrong password", lastException);
		}
	}

	private static KeyPair parsePrivateKeyDer(final String keyType, final byte[] derData) throws Exception {
		switch (keyType) {
			case "RSA":
				return parsePkcs1RsaPrivateKey(derData);
			case "DSA":
				return parseTraditionalDsaPrivateKey(derData);
			case "EC":
				return parseSec1EcPrivateKey(derData, null);
			case "PKCS8":
				return parsePkcs8PrivateKey(derData);
			default:
				throw new Exception("Unknown key type: " + keyType);
		}
	}

	private static byte[] decryptOpenSslKeyData(final byte[] keyData, final String dekInfo, final byte[] passwordBytes) throws Exception {
		if (dekInfo == null) {
			throw new Exception("Missing key encryption info (DEK-Info)");
		}
		final String[] dekInfoParts = dekInfo.split(",");
		if (dekInfoParts.length != 2) {
			throw new Exception("Invalid key encryption info (DEK-Info): " + dekInfo);
		}
		final String keyEncryptionCipherName = dekInfoParts[0].trim().toUpperCase();
		final byte[] iv = fromHexString(dekInfoParts[1].trim());

		final String cipherName;
		final String keyAlgorithm;
		final int keySize;
		final int blockSize;
		switch (keyEncryptionCipherName) {
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
		if (iv.length != blockSize) {
			throw new Exception("Invalid initialization vector length " + iv.length + " for key encryption cipher " + keyEncryptionCipherName);
		} else if (keyData.length == 0 || keyData.length % blockSize != 0) {
			throw new Exception("Invalid encrypted key data length " + keyData.length + " for key encryption cipher " + keyEncryptionCipherName);
		}

		final byte[] key = stretchPasswordForOpenSsl(passwordBytes, iv, 8, keySize);
		try {
			final Cipher cipher = Cipher.getInstance(cipherName);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlgorithm), new IvParameterSpec(iv));
			return removePkcs7Padding(cipher.doFinal(keyData), blockSize);
		} finally {
			Arrays.fill(key, (byte) 0);
		}
	}

	/**
	 * Removes and validates PKCS#5/#7 padding. An invalid padding indicates a wrong password.
	 */
	private static byte[] removePkcs7Padding(final byte[] data, final int blockSize) throws WrongPasswordException {
		if (data.length == 0) {
			throw new WrongPasswordException("Missing or wrong password (invalid padding)");
		}
		final int paddingSize = data[data.length - 1] & 0xFF;
		if (paddingSize < 1 || paddingSize > blockSize || paddingSize > data.length) {
			throw new WrongPasswordException("Missing or wrong password (invalid padding)");
		}
		for (int i = data.length - paddingSize; i < data.length; i++) {
			if ((data[i] & 0xFF) != paddingSize) {
				throw new WrongPasswordException("Missing or wrong password (invalid padding)");
			}
		}
		return Arrays.copyOfRange(data, 0, data.length - paddingSize);
	}

	/**
	 * <b>Security note:</b> This implements the legacy OpenSSL "EVP_BytesToKey" key derivation
	 * (single MD5 round, no configurable work factor), as mandated by the classic "Proc-Type:
	 * 4,ENCRYPTED" PEM format for backward compatibility. This scheme is inherently weak against
	 * brute-force attacks by modern standards and has been deprecated by OpenSSL itself in favor of
	 * encrypted PKCS#8. It cannot be strengthened here without breaking compatibility with existing
	 * files in this legacy format; prefer PKCS#8 or OpenSSH v1 encrypted key formats where possible.
	 */
	static byte[] stretchPasswordForOpenSsl(final byte[] passwordBytes, final byte[] iv, final int usingIvSize, final int keySize) throws Exception {
		final MessageDigest hash = MessageDigest.getInstance("MD5");
		final byte[] key = new byte[keySize];
		int keyIndex = 0;
		byte[] previous = null;
		while (keyIndex < keySize) {
			if (previous != null) {
				hash.update(previous);
			}
			hash.update(passwordBytes);
			hash.update(iv, 0, usingIvSize);
			previous = hash.digest();
			final int bytesToCopy = Math.min(previous.length, keySize - keyIndex);
			System.arraycopy(previous, 0, key, keyIndex, bytesToCopy);
			keyIndex += bytesToCopy;
		}
		Arrays.fill(previous, (byte) 0);
		return key;
	}

	/**
	 * Reads a PKCS#8 "EncryptedPrivateKeyInfo" encrypted with PBES2 (PBKDF2 + AES-CBC or DES-EDE3-CBC).
	 * <p>
	 * The JDK implementation of PBES2 only accepts ASCII passwords, so it is implemented here directly on the password bytes.
	 */
	private static KeyPair decryptPkcs8PrivateKey(final byte[] derData, final Password password) throws Exception {
		if (!password.hasPassword()) {
			throw new WrongPasswordException("Key is encrypted, but no password was given");
		}

		final List<DerTag> encryptedPrivateKeyInfoTags = readDerSequence(derData);
		final List<DerTag> encryptionAlgorithmTags = Asn1Codec.readDerTags(getTag(encryptedPrivateKeyInfoTags, 0, Asn1Codec.DER_TAG_SEQUENCE));
		final byte[] encryptedData = getTag(encryptedPrivateKeyInfoTags, 1, Asn1Codec.DER_TAG_OCTET_STRING);

		final OID encryptionAlgorithmOid = new OID(getTag(encryptionAlgorithmTags, 0, Asn1Codec.DER_TAG_OBJECT));
		if (!OID_PBES2.equals(encryptionAlgorithmOid)) {
			throw new Exception("Unsupported PKCS#8 encryption algorithm (only PBES2 is supported): " + encryptionAlgorithmOid);
		}
		final List<DerTag> pbes2ParameterTags = Asn1Codec.readDerTags(getTag(encryptionAlgorithmTags, 1, Asn1Codec.DER_TAG_SEQUENCE));
		final List<DerTag> keyDerivationTags = Asn1Codec.readDerTags(getTag(pbes2ParameterTags, 0, Asn1Codec.DER_TAG_SEQUENCE));
		final List<DerTag> encryptionSchemeTags = Asn1Codec.readDerTags(getTag(pbes2ParameterTags, 1, Asn1Codec.DER_TAG_SEQUENCE));

		final OID keyDerivationOid = new OID(getTag(keyDerivationTags, 0, Asn1Codec.DER_TAG_OBJECT));
		if (OID_SCRYPT.equals(keyDerivationOid)) {
			throw new Exception("Unsupported PKCS#8 key derivation function scrypt (only PBKDF2 is supported)");
		} else if (!OID_PBKDF2.equals(keyDerivationOid)) {
			throw new Exception("Unsupported PKCS#8 key derivation function (only PBKDF2 is supported): " + keyDerivationOid);
		}
		final List<DerTag> pbkdf2ParameterTags = Asn1Codec.readDerTags(getTag(keyDerivationTags, 1, Asn1Codec.DER_TAG_SEQUENCE));
		final byte[] salt = getTag(pbkdf2ParameterTags, 0, Asn1Codec.DER_TAG_OCTET_STRING);
		final BigInteger iterationCount = new BigInteger(1, getTag(pbkdf2ParameterTags, 1, Asn1Codec.DER_TAG_INTEGER));
		if (iterationCount.signum() <= 0 || iterationCount.compareTo(BigInteger.valueOf(MAX_PBKDF2_ITERATIONS)) > 0) {
			throw new Exception("Invalid or too large PBKDF2 iteration count " + iterationCount + " (maximum is " + MAX_PBKDF2_ITERATIONS + "). Maybe the key data is corrupted or malicious");
		}
		String hmacName = "HmacSHA1";
		for (int i = 2; i < pbkdf2ParameterTags.size(); i++) {
			// Optional keyLength (INTEGER) and prf (AlgorithmIdentifier)
			if (pbkdf2ParameterTags.get(i).getTagId() == Asn1Codec.DER_TAG_SEQUENCE) {
				final OID prfOid = new OID(getTag(Asn1Codec.readDerTags(pbkdf2ParameterTags.get(i).getData()), 0, Asn1Codec.DER_TAG_OBJECT));
				if (OID_HMAC_SHA1.equals(prfOid)) {
					hmacName = "HmacSHA1";
				} else if (OID_HMAC_SHA224.equals(prfOid)) {
					hmacName = "HmacSHA224";
				} else if (OID_HMAC_SHA256.equals(prfOid)) {
					hmacName = "HmacSHA256";
				} else if (OID_HMAC_SHA384.equals(prfOid)) {
					hmacName = "HmacSHA384";
				} else if (OID_HMAC_SHA512.equals(prfOid)) {
					hmacName = "HmacSHA512";
				} else {
					throw new Exception("Unsupported PBKDF2 pseudo random function: " + prfOid);
				}
			}
		}

		final OID encryptionSchemeOid = new OID(getTag(encryptionSchemeTags, 0, Asn1Codec.DER_TAG_OBJECT));
		final byte[] iv = getTag(encryptionSchemeTags, 1, Asn1Codec.DER_TAG_OCTET_STRING);
		final String cipherName;
		final String keyAlgorithm;
		final int keySize;
		if (OID_AES128_CBC.equals(encryptionSchemeOid)) {
			cipherName = "AES/CBC/NoPadding";
			keyAlgorithm = "AES";
			keySize = 16;
		} else if (OID_AES192_CBC.equals(encryptionSchemeOid)) {
			cipherName = "AES/CBC/NoPadding";
			keyAlgorithm = "AES";
			keySize = 24;
		} else if (OID_AES256_CBC.equals(encryptionSchemeOid)) {
			cipherName = "AES/CBC/NoPadding";
			keyAlgorithm = "AES";
			keySize = 32;
		} else if (OID_DES_EDE3_CBC.equals(encryptionSchemeOid)) {
			cipherName = "DESede/CBC/NoPadding";
			keyAlgorithm = "DESede";
			keySize = 24;
		} else {
			throw new Exception("Unsupported PKCS#8 encryption scheme: " + encryptionSchemeOid);
		}
		final int blockSize = "AES".equals(keyAlgorithm) ? 16 : 8;
		if (iv.length != blockSize || encryptedData.length == 0 || encryptedData.length % blockSize != 0) {
			throw new Exception("Invalid PKCS#8 encrypted data");
		}

		Exception lastException = null;
		for (final byte[] passwordBytes : getPasswordByteVariants(password, true)) {
			final byte[] key = pbkdf2(hmacName, passwordBytes, salt, iterationCount.intValue(), keySize);
			try {
				final Cipher cipher = Cipher.getInstance(cipherName);
				cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlgorithm), new IvParameterSpec(iv));
				final byte[] privateKeyInfo = removePkcs7Padding(cipher.doFinal(encryptedData), blockSize);
				return parsePkcs8PrivateKey(privateKeyInfo);
			} catch (final Exception e) {
				lastException = e;
			} finally {
				Arrays.fill(key, (byte) 0);
			}
		}
		throw new WrongPasswordException("Missing or wrong password", lastException);
	}

	private static byte[] pbkdf2(final String hmacName, final byte[] passwordBytes, final byte[] salt, final int iterations, final int keyLength) throws Exception {
		final Mac mac = Mac.getInstance(hmacName);
		// HMAC keys may be empty in PBKDF2, but SecretKeySpec does not allow empty keys
		// HMAC pads keys with zeros, so an empty key equals a single zero byte key, which SecretKeySpec accepts
		mac.init(new SecretKeySpec(passwordBytes.length == 0 ? new byte[1] : passwordBytes, hmacName));
		final int hashLength = mac.getMacLength();
		final byte[] result = new byte[keyLength];
		final byte[] block = new byte[hashLength];
		for (int blockIndex = 1, offset = 0; offset < keyLength; blockIndex++, offset += hashLength) {
			mac.update(salt);
			mac.update(new byte[] { (byte) (blockIndex >>> 24), (byte) (blockIndex >>> 16), (byte) (blockIndex >>> 8), (byte) blockIndex });
			byte[] u = mac.doFinal();
			System.arraycopy(u, 0, block, 0, hashLength);
			for (int i = 1; i < iterations; i++) {
				u = mac.doFinal(u);
				for (int j = 0; j < hashLength; j++) {
					block[j] ^= u[j];
				}
			}
			System.arraycopy(block, 0, result, offset, Math.min(hashLength, keyLength - offset));
		}
		Arrays.fill(block, (byte) 0);
		return result;
	}

	/**
	 * Parses a PKCS#8 "PrivateKeyInfo" / "OneAsymmetricKey" structure and derives the public key.
	 */
	private static KeyPair parsePkcs8PrivateKey(final byte[] derData) throws Exception {
		final List<DerTag> privateKeyInfoTags = readDerSequence(derData);
		final BigInteger version = new BigInteger(getTag(privateKeyInfoTags, 0, Asn1Codec.DER_TAG_INTEGER));
		if (!BigInteger.ZERO.equals(version) && !BigInteger.ONE.equals(version)) {
			throw new Exception("Invalid PKCS#8 key data version found: " + version);
		}
		final List<DerTag> algorithmTags = Asn1Codec.readDerTags(getTag(privateKeyInfoTags, 1, Asn1Codec.DER_TAG_SEQUENCE));
		final OID algorithmOid = new OID(getTag(algorithmTags, 0, Asn1Codec.DER_TAG_OBJECT));
		final byte[] privateKeyData = getTag(privateKeyInfoTags, 2, Asn1Codec.DER_TAG_OCTET_STRING);

		if (OID.RSA_ALGORITHM.equals(algorithmOid)) {
			return parsePkcs1RsaPrivateKey(privateKeyData);
		} else if (OID.DSA_ALGORITHM.equals(algorithmOid)) {
			final List<DerTag> dsaParameterTags = Asn1Codec.readDerTags(getTag(algorithmTags, 1, Asn1Codec.DER_TAG_SEQUENCE));
			final BigInteger p = new BigInteger(1, getTag(dsaParameterTags, 0, Asn1Codec.DER_TAG_INTEGER));
			final BigInteger q = new BigInteger(1, getTag(dsaParameterTags, 1, Asn1Codec.DER_TAG_INTEGER));
			final BigInteger g = new BigInteger(1, getTag(dsaParameterTags, 2, Asn1Codec.DER_TAG_INTEGER));
			final BigInteger x = new BigInteger(1, getTag(Asn1Codec.readDerTags(privateKeyData), 0, Asn1Codec.DER_TAG_INTEGER));
			return createDsaKeyPair(p, q, g, g.modPow(x, p), x);
		} else if (OID.ECDSA_PUBLICKEY.equals(algorithmOid)) {
			final OID curveOid = new OID(getTag(algorithmTags, 1, Asn1Codec.DER_TAG_OBJECT));
			return parseSec1EcPrivateKey(privateKeyData, getNistCurveName(curveOid));
		} else if (OID.EDDSA25519_ALGORITHM.equals(algorithmOid) || OID.EDDSA448_ALGORITHM.equals(algorithmOid)) {
			final String curveName = OID.EDDSA25519_ALGORITHM.equals(algorithmOid) ? "Ed25519" : "Ed448";
			final byte[] seed = getTag(Asn1Codec.readDerTags(privateKeyData), 0, Asn1Codec.DER_TAG_OCTET_STRING);
			final PrivateKey privateKey = createEdDsaPrivateKey(seed, curveName);
			final PublicKey publicKey = createEdDsaPublicKey(deriveEdDsaPublicKeyBytes(seed, curveName), curveName);
			return new KeyPair(publicKey, privateKey);
		} else {
			throw new Exception("Unknown ssh algorithm OID: " + algorithmOid);
		}
	}

	/**
	 * Parses a PKCS#1 "RSAPrivateKey" structure (traditional "RSA PRIVATE KEY").
	 */
	private static KeyPair parsePkcs1RsaPrivateKey(final byte[] derData) throws Exception {
		final List<DerTag> derDataTags = readDerSequence(derData);
		final BigInteger keyEncodingVersion = new BigInteger(getTag(derDataTags, 0, Asn1Codec.DER_TAG_INTEGER));
		if (!BigInteger.ZERO.equals(keyEncodingVersion)) {
			throw new Exception("Invalid or unsupported (multi prime) RSA key data version found: " + keyEncodingVersion);
		}
		final BigInteger modulus = new BigInteger(1, getTag(derDataTags, 1, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger publicExponent = new BigInteger(1, getTag(derDataTags, 2, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger privateExponent = new BigInteger(1, getTag(derDataTags, 3, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger primeP = new BigInteger(1, getTag(derDataTags, 4, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger primeQ = new BigInteger(1, getTag(derDataTags, 5, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger primeExponentP = new BigInteger(1, getTag(derDataTags, 6, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger primeExponentQ = new BigInteger(1, getTag(derDataTags, 7, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger crtCoefficient = new BigInteger(1, getTag(derDataTags, 8, Asn1Codec.DER_TAG_INTEGER));

		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		final PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		final PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient));
		return new KeyPair(publicKey, privateKey);
	}

	/**
	 * Parses the traditional OpenSSL "DSA PRIVATE KEY" structure.
	 */
	private static KeyPair parseTraditionalDsaPrivateKey(final byte[] derData) throws Exception {
		final List<DerTag> derDataTags = readDerSequence(derData);
		final BigInteger keyEncodingVersion = new BigInteger(getTag(derDataTags, 0, Asn1Codec.DER_TAG_INTEGER));
		if (!BigInteger.ZERO.equals(keyEncodingVersion)) {
			throw new Exception("Invalid key data version found");
		}
		final BigInteger p = new BigInteger(1, getTag(derDataTags, 1, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger q = new BigInteger(1, getTag(derDataTags, 2, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger g = new BigInteger(1, getTag(derDataTags, 3, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger y = new BigInteger(1, getTag(derDataTags, 4, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger x = new BigInteger(1, getTag(derDataTags, 5, Asn1Codec.DER_TAG_INTEGER));
		return createDsaKeyPair(p, q, g, y, x);
	}

	private static KeyPair createDsaKeyPair(final BigInteger p, final BigInteger q, final BigInteger g, final BigInteger y, final BigInteger x) throws Exception {
		final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		final PublicKey publicKey = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
		final PrivateKey privateKey = keyFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
		return new KeyPair(publicKey, privateKey);
	}

	/**
	 * Parses a SEC1 / RFC 5915 "ECPrivateKey" structure.
	 *
	 * @param outerCurveName curve name from an enclosing PKCS#8 structure, or {@code null} if the curve must be defined in the structure itself
	 */
	private static KeyPair parseSec1EcPrivateKey(final byte[] derData, final String outerCurveName) throws Exception {
		final List<DerTag> derDataTags = readDerSequence(derData);
		final BigInteger keyEncodingVersion = new BigInteger(getTag(derDataTags, 0, Asn1Codec.DER_TAG_INTEGER));
		if (!BigInteger.ONE.equals(keyEncodingVersion)) {
			throw new Exception("Invalid key data version found");
		}
		// The private key is an unsigned big-endian octet string
		final BigInteger s = new BigInteger(1, getTag(derDataTags, 1, Asn1Codec.DER_TAG_OCTET_STRING));

		String curveName = outerCurveName;
		byte[] publicKeyBytes = null;
		for (int i = 2; i < derDataTags.size(); i++) {
			if (derDataTags.get(i).getTagId() == Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_0) {
				final DerTag oidTag = Asn1Codec.readDerTag(derDataTags.get(i).getData());
				if (Asn1Codec.DER_TAG_OBJECT != oidTag.getTagId()) {
					throw new Exception("Unsupported explicit ec curve parameters found");
				}
				final String innerCurveName = getNistCurveName(new OID(oidTag.getData()));
				if (curveName != null && !curveName.equals(innerCurveName)) {
					throw new Exception("Inconsistent ec curve definitions found");
				}
				curveName = innerCurveName;
			} else if (derDataTags.get(i).getTagId() == Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_1) {
				final DerTag publicKeyTag = Asn1Codec.readDerTag(derDataTags.get(i).getData());
				final byte[] bitStringData = publicKeyTag.getData();
				if (Asn1Codec.DER_TAG_BIT_STRING != publicKeyTag.getTagId() || bitStringData.length < 2 || bitStringData[0] != 0) {
					throw new Exception("Invalid ec public key data found");
				}
				// Remove the "unused bits" prefix byte of the bit string
				publicKeyBytes = Arrays.copyOfRange(bitStringData, 1, bitStringData.length);
			}
		}
		if (curveName == null) {
			throw new Exception("Missing ec curve definition");
		}

		final PrivateKey privateKey = createEcPrivateKey(s, curveName);
		final PublicKey publicKey;
		if (publicKeyBytes != null) {
			publicKey = createEcPublicKey(publicKeyBytes, curveName);
		} else {
			publicKey = deriveEcPublicKey(s, curveName);
		}
		return new KeyPair(publicKey, privateKey);
	}

	private static PublicKey parseX509PublicKey(final byte[] derData) throws Exception {
		final List<DerTag> subjectPublicKeyInfoTags = readDerSequence(derData);
		final List<DerTag> algorithmTags = Asn1Codec.readDerTags(getTag(subjectPublicKeyInfoTags, 0, Asn1Codec.DER_TAG_SEQUENCE));
		final OID algorithmOid = new OID(getTag(algorithmTags, 0, Asn1Codec.DER_TAG_OBJECT));
		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derData);
		if (OID.RSA_ALGORITHM.equals(algorithmOid)) {
			return KeyFactory.getInstance("RSA").generatePublic(keySpec);
		} else if (OID.DSA_ALGORITHM.equals(algorithmOid)) {
			return KeyFactory.getInstance("DSA").generatePublic(keySpec);
		} else if (OID.ECDSA_PUBLICKEY.equals(algorithmOid)) {
			// Check for supported curve
			getNistCurveName(new OID(getTag(algorithmTags, 1, Asn1Codec.DER_TAG_OBJECT)));
			return KeyFactory.getInstance("EC", BC_PROVIDER).generatePublic(keySpec);
		} else if (OID.EDDSA25519_ALGORITHM.equals(algorithmOid)) {
			return KeyFactory.getInstance("Ed25519").generatePublic(keySpec);
		} else if (OID.EDDSA448_ALGORITHM.equals(algorithmOid)) {
			return KeyFactory.getInstance("Ed448").generatePublic(keySpec);
		} else {
			throw new Exception("Unknown ssh algorithm OID: " + algorithmOid);
		}
	}

	private static PublicKey parsePkcs1RsaPublicKey(final byte[] derData) throws Exception {
		final List<DerTag> derDataTags = readDerSequence(derData);
		final BigInteger modulus = new BigInteger(1, getTag(derDataTags, 0, Asn1Codec.DER_TAG_INTEGER));
		final BigInteger publicExponent = new BigInteger(1, getTag(derDataTags, 1, Asn1Codec.DER_TAG_INTEGER));
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
	}

	private static List<DerTag> readDerSequence(final byte[] derData) throws Exception {
		final DerTag enclosingDerTag = Asn1Codec.readDerTag(derData);
		if (Asn1Codec.DER_TAG_SEQUENCE != enclosingDerTag.getTagId()) {
			throw new Exception("Invalid key data found: Missing enclosing sequence");
		}
		return Asn1Codec.readDerTags(enclosingDerTag.getData());
	}

	private static byte[] getTag(final List<DerTag> derTags, final int index, final int expectedTagId) throws Exception {
		if (derTags.size() <= index) {
			throw new Exception("Invalid key data found: Missing data element " + index);
		} else if (derTags.get(index).getTagId() != expectedTagId) {
			throw new Exception("Invalid key data found: Unexpected data element type " + derTags.get(index).getTagId() + " at index " + index + " (expected " + expectedTagId + ")");
		} else {
			return derTags.get(index).getData();
		}
	}

	private static String getNistCurveName(final OID curveOid) throws Exception {
		if (OID.ECDSA_CURVE_NISTP256.equals(curveOid)) {
			return "nistp256";
		} else if (OID.ECDSA_CURVE_NISTP384.equals(curveOid)) {
			return "nistp384";
		} else if (OID.ECDSA_CURVE_NISTP521.equals(curveOid)) {
			return "nistp521";
		} else {
			throw new Exception("Unsupported ec curve oid found: " + curveOid);
		}
	}

	/**
	 * Reads the content of a PEM block up to the given end line.
	 * Headers (RFC 1421, continuation lines start with whitespace) are only allowed before the base64 data.
	 */
	private static TextBlock readPemBlock(final LimitedLineReader dataReader, final String endLine) throws Exception {
		final TextBlock textBlock = new TextBlock();
		final StringBuilder base64Data = new StringBuilder();
		String lastHeaderName = null;
		String nextLine;
		while ((nextLine = dataReader.readLine()) != null) {
			if (endLine.equals(nextLine.trim())) {
				if (base64Data.length() == 0) {
					throw new Exception("Corrupt key data found: Missing key data");
				}
				textBlock.setData(Base64.getMimeDecoder().decode(base64Data.toString()));
				return textBlock;
			} else if (base64Data.length() == 0 && lastHeaderName != null && !nextLine.isEmpty() && Character.isWhitespace(nextLine.charAt(0))) {
				textBlock.appendToHeader(lastHeaderName, nextLine.trim());
			} else if (nextLine.indexOf(':') > 0) {
				if (base64Data.length() > 0) {
					throw new Exception("Corrupt key data found: Headers found after keydata start");
				}
				lastHeaderName = nextLine.substring(0, nextLine.indexOf(':')).trim();
				textBlock.setHeader(lastHeaderName, nextLine.substring(nextLine.indexOf(':') + 1).trim());
			} else {
				final String dataLine = nextLine.trim();
				if ((long) base64Data.length() + dataLine.length() > MAX_BASE64_ENCODED_DATA_LENGTH) {
					throw new Exception("Corrupt key data found: Base64 key data exceeds maximum allowed size of " + MAX_BASE64_ENCODED_DATA_LENGTH + " characters");
				}
				base64Data.append(dataLine);
			}
		}
		throw new Exception("Corrupt key data found: End line is missing: '" + endLine + "'");
	}

	/**
	 * Reads the content of a RFC 4716 block up to the given end line.
	 * Header continuation lines end with a backslash, header values may be enclosed in double quotes.
	 */
	private static TextBlock readRfc4716Block(final LimitedLineReader dataReader, final String endLine) throws Exception {
		final TextBlock textBlock = new TextBlock();
		final StringBuilder base64Data = new StringBuilder();
		String nextLine;
		while ((nextLine = dataReader.readLine()) != null) {
			nextLine = nextLine.trim();
			if (endLine.equals(nextLine)) {
				if (base64Data.length() == 0) {
					throw new Exception("Corrupt key data found: Missing key data");
				}
				textBlock.setData(Base64.getMimeDecoder().decode(base64Data.toString()));
				return textBlock;
			} else if (nextLine.indexOf(':') > 0 && base64Data.length() == 0) {
				final String headerName = nextLine.substring(0, nextLine.indexOf(':')).trim();
				final StringBuilder headerValue = new StringBuilder(nextLine.substring(nextLine.indexOf(':') + 1).trim());
				while (headerValue.length() > 0 && headerValue.charAt(headerValue.length() - 1) == '\\') {
					headerValue.setLength(headerValue.length() - 1);
					final String continuationLine = dataReader.readLine();
					if (continuationLine == null) {
						throw new Exception("Corrupt key data found: Missing header continuation line");
					}
					final String continuationValue = continuationLine.trim();
					checkHeaderValueLength(headerName, (long) headerValue.length() + continuationValue.length());
					headerValue.append(continuationValue);
				}
				String value = headerValue.toString();
				if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
					value = value.substring(1, value.length() - 1);
				}
				textBlock.setHeader(headerName, value);
			} else if (nextLine.indexOf(':') > 0) {
				throw new Exception("Corrupt key data found: Headers found after keydata start");
			} else {
				if ((long) base64Data.length() + nextLine.length() > MAX_BASE64_ENCODED_DATA_LENGTH) {
					throw new Exception("Corrupt key data found: Base64 key data exceeds maximum allowed size of " + MAX_BASE64_ENCODED_DATA_LENGTH + " characters");
				}
				base64Data.append(nextLine);
			}
		}
		throw new Exception("Corrupt key data found: End line is missing: '" + endLine + "'");
	}

	/**
	 * Header and data content of a PEM or RFC 4716 block.
	 * The number of headers and the length of header values are limited (Denial of Service protection).
	 */
	private static class TextBlock {
		private final Map<String, StringBuilder> headers = new LinkedHashMap<>();
		private int headerCount = 0;
		private byte[] data;

		private void setHeader(final String name, final String value) throws Exception {
			if (++headerCount > MAX_HEADER_COUNT) {
				throw new Exception("Corrupt key data found: More than " + MAX_HEADER_COUNT + " headers");
			}
			checkHeaderValueLength(name, value.length());
			headers.put(name.toLowerCase(), new StringBuilder(value));
		}

		private void appendToHeader(final String name, final String value) throws Exception {
			final StringBuilder headerValue = headers.get(name.toLowerCase());
			checkHeaderValueLength(name, (long) headerValue.length() + value.length());
			headerValue.append(value);
		}

		private String getHeader(final String name) {
			final StringBuilder headerValue = headers.get(name.toLowerCase());
			return headerValue == null ? null : headerValue.toString();
		}

		private byte[] getData() {
			return data;
		}

		private void setData(final byte[] data) {
			this.data = data;
		}
	}

	private static void checkHeaderValueLength(final String headerName, final long length) throws Exception {
		if (length > MAX_HEADER_VALUE_LENGTH) {
			throw new Exception("Corrupt key data found: Value of header '" + headerName + "' exceeds maximum allowed length of " + MAX_HEADER_VALUE_LENGTH + " characters");
		}
	}

	// ---------------------------------------------------------------------------------------------
	// OpenSSH v1
	// ---------------------------------------------------------------------------------------------

	private static SshKey readOpenSshv1Key(final byte[] data, final Password password, final boolean publicKeyOnly) throws Exception {
		final BlockDataReader dataReader = new BlockDataReader(data);
		// Storage format name
		final String keyFormatString = new String(dataReader.readZeroLimitedData(32), StandardCharsets.UTF_8);
		if (!"openssh-key-v1".equals(keyFormatString)) {
			throw new Exception("Invalid keyFormat name '" + keyFormatString + "' found. Expected 'openssh-key-v1'");
		}

		final String encryptionCipherName = dataReader.readString();
		final String kdfName = dataReader.readString();
		final byte[] kdfInfoBytes = dataReader.readData();

		// Amount of stored keys
		final int amountOfKeys = dataReader.readSimpleInt();
		if (amountOfKeys != 1) {
			throw new Exception("Invalid amountOfKeys " + amountOfKeys + " found. Expected 1");
		}

		// Public key
		final PublicKey publicKey = parsePublicKeyBytes(dataReader.readData());
		if (publicKeyOnly) {
			return new SshKey(SshKeyFormat.OpenSSHv1, null, new KeyPair(publicKey, null));
		}

		// Private key
		byte[] privateKeyDataBytes = dataReader.readData();
		if (dataReader.isMoreDataAvailable()) {
			throw new Exception("Invalid key data: unexpected trailing data found");
		}

		if (!"none".equals(encryptionCipherName)) {
			final OpenSshCipher openSshCipher = OpenSshCipher.getByName(encryptionCipherName);
			if (!"bcrypt".equals(kdfName)) {
				throw new Exception("Invalid key derivation function method (Only 'bcrypt' allowed) '" + kdfName + "'");
			}
			final BlockDataReader kdfInfoReader = new BlockDataReader(kdfInfoBytes);
			final byte[] kdfSalt = kdfInfoReader.readData();
			final int kdfRounds = kdfInfoReader.readSimpleInt();
			if (kdfSalt.length == 0) {
				throw new Exception("Invalid key derivation function info 'kdfSalt' for key derivation function '" + kdfName + "'");
			} else if (kdfRounds <= 0) {
				throw new Exception("Invalid key derivation function info 'kdfRounds = " + kdfRounds + "' for key derivation function '" + kdfName + "'");
			} else if (kdfRounds > MAX_BCRYPT_KDF_ROUNDS) {
				throw new Exception("Key derivation function info 'kdfRounds = " + kdfRounds + "' exceeds maximum allowed value of " + MAX_BCRYPT_KDF_ROUNDS + " for key derivation function '" + kdfName + "'. Maybe the key data is corrupted or malicious");
			} else if (privateKeyDataBytes.length < 8 || privateKeyDataBytes.length % openSshCipher.blockSize != 0) {
				throw new Exception("Invalid encrypted private key data length " + privateKeyDataBytes.length);
			} else if (!password.hasPassword()) {
				throw new WrongPasswordException("Key is encrypted, but no password was given");
			}

			// Putty uses "ISO-8859-1" for password encoding, even for those keys stored in OpenSSHv1 and OpenSSL format
			// "ssh-keygen" on Linux uses UTF-8 for password encoding
			byte[] decryptedPrivateKeyDataBytes = null;
			for (final byte[] passwordBytes : getPasswordByteVariants(password, true)) {
				final byte[] derivedKeyBytes = new byte[openSshCipher.keySize + 16];
				try {
					new BCryptPBKDF().derivePassword(passwordBytes, kdfSalt, kdfRounds, derivedKeyBytes);
					final Cipher cipher = Cipher.getInstance(openSshCipher.javaCipherName);
					cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivedKeyBytes, 0, openSshCipher.keySize, "AES"), new IvParameterSpec(derivedKeyBytes, openSshCipher.keySize, 16));
					final byte[] candidate = cipher.doFinal(privateKeyDataBytes);
					if (checkIntsMatch(candidate)) {
						decryptedPrivateKeyDataBytes = candidate;
						break;
					}
				} finally {
					Arrays.fill(derivedKeyBytes, (byte) 0);
				}
			}
			if (decryptedPrivateKeyDataBytes == null) {
				throw new WrongPasswordException();
			}
			privateKeyDataBytes = decryptedPrivateKeyDataBytes;
		} else if (!"none".equals(kdfName)) {
			throw new Exception("Invalid key derivation function '" + kdfName + "' for unencrypted key");
		}

		final SshKey sshKey = readOpenSshv1PrivateKey(privateKeyDataBytes);
		if (!Arrays.equals(publicKey.getEncoded(), sshKey.getKeyPair().getPublic().getEncoded())) {
			throw new Exception("Invalid key data: public key and public key data of the private key section do not match");
		}
		return sshKey;
	}

	private static boolean checkIntsMatch(final byte[] privateKeyData) {
		return privateKeyData.length >= 8
				&& privateKeyData[0] == privateKeyData[4]
				&& privateKeyData[1] == privateKeyData[5]
				&& privateKeyData[2] == privateKeyData[6]
				&& privateKeyData[3] == privateKeyData[7];
	}

	private enum OpenSshCipher {
		AES128_CTR("aes128-ctr", "AES/CTR/NoPadding", 16),
		AES192_CTR("aes192-ctr", "AES/CTR/NoPadding", 24),
		AES256_CTR("aes256-ctr", "AES/CTR/NoPadding", 32),
		AES128_CBC("aes128-cbc", "AES/CBC/NoPadding", 16),
		AES192_CBC("aes192-cbc", "AES/CBC/NoPadding", 24),
		AES256_CBC("aes256-cbc", "AES/CBC/NoPadding", 32);

		private final String sshName;
		private final String javaCipherName;
		private final int keySize;
		private final int blockSize = 16;

		OpenSshCipher(final String sshName, final String javaCipherName, final int keySize) {
			this.sshName = sshName;
			this.javaCipherName = javaCipherName;
			this.keySize = keySize;
		}

		private static OpenSshCipher getByName(final String name) throws Exception {
			for (final OpenSshCipher openSshCipher : values()) {
				if (openSshCipher.sshName.equals(name)) {
					return openSshCipher;
				}
			}
			throw new Exception("Unsupported key encryption cipher '" + name + "' (supported: aes128/192/256-ctr, aes128/192/256-cbc)");
		}
	}

	private static SshKey readOpenSshv1PrivateKey(final byte[] privateKeyData) throws Exception {
		final BlockDataReader privateKeyDataReader = new BlockDataReader(privateKeyData);
		// Quick decryption validity check. Both checkInts must match.
		final int checkInt1 = privateKeyDataReader.readSimpleInt();
		final int checkInt2 = privateKeyDataReader.readSimpleInt();
		if (checkInt1 != checkInt2) {
			throw new WrongPasswordException();
		}

		final Algorithm algorithm = Algorithm.getForSshAlgorithmId(privateKeyDataReader.readString());
		final KeyPair keyPair;
		if (Algorithm.RSA == algorithm) {
			final BigInteger modulus = privateKeyDataReader.readBigInt();
			final BigInteger publicExponent = privateKeyDataReader.readBigInt();
			final BigInteger privateExponent = privateKeyDataReader.readBigInt();
			final BigInteger crtCoefficient = privateKeyDataReader.readBigInt();
			final BigInteger primeP = privateKeyDataReader.readBigInt();
			final BigInteger primeQ = privateKeyDataReader.readBigInt();
			keyPair = createRsaKeyPair(modulus, publicExponent, privateExponent, primeP, primeQ, crtCoefficient);
		} else if (Algorithm.DSA == algorithm) {
			final BigInteger p = privateKeyDataReader.readBigInt();
			final BigInteger q = privateKeyDataReader.readBigInt();
			final BigInteger g = privateKeyDataReader.readBigInt();
			final BigInteger y = privateKeyDataReader.readBigInt();
			final BigInteger x = privateKeyDataReader.readBigInt();
			keyPair = createDsaKeyPair(p, q, g, y, x);
		} else if (Algorithm.NISTP256 == algorithm || Algorithm.NISTP384 == algorithm || Algorithm.NISTP521 == algorithm) {
			final String ecdsaCurveName = privateKeyDataReader.readString();
			checkCurveNameMatchesAlgorithm(ecdsaCurveName, algorithm);
			final PublicKey publicKey = createEcPublicKey(privateKeyDataReader.readData(), ecdsaCurveName);
			final PrivateKey privateKey = createEcPrivateKey(privateKeyDataReader.readBigInt(), ecdsaCurveName);
			keyPair = new KeyPair(publicKey, privateKey);
		} else if (Algorithm.ED25519 == algorithm || Algorithm.ED448 == algorithm) {
			final String curveName = Algorithm.ED25519 == algorithm ? "Ed25519" : "Ed448";
			final int keyLength = Algorithm.ED25519 == algorithm ? 32 : 57;
			final byte[] publicKeyBytes = privateKeyDataReader.readData();
			final byte[] secretKeyBytes = privateKeyDataReader.readData();
			if (publicKeyBytes.length != keyLength || secretKeyBytes.length != 2 * keyLength) {
				throw new Exception("Invalid " + curveName + " key data length");
			}
			if (!Arrays.equals(publicKeyBytes, Arrays.copyOfRange(secretKeyBytes, keyLength, 2 * keyLength))) {
				throw new Exception("Invalid " + curveName + " key data: inconsistent public key data");
			}
			final PrivateKey privateKey = createEdDsaPrivateKey(Arrays.copyOfRange(secretKeyBytes, 0, keyLength), curveName);
			Arrays.fill(secretKeyBytes, (byte) 0);
			keyPair = new KeyPair(createEdDsaPublicKey(publicKeyBytes, curveName), privateKey);
		} else {
			throw new Exception("Unexpected key type '" + algorithm.name() + "'");
		}

		final String keyComment = decodeComment(privateKeyDataReader.readData());

		final byte[] paddingBytes = privateKeyDataReader.readLeftoverData();
		for (int i = 0; i < paddingBytes.length; i++) {
			if (paddingBytes[i] != (byte) (i + 1)) {
				throw new Exception("Invalid private key padding found");
			}
		}

		return new SshKey(SshKeyFormat.OpenSSHv1, keyComment, keyPair);
	}

	// ---------------------------------------------------------------------------------------------
	// SSH wire format public keys
	// ---------------------------------------------------------------------------------------------

	/**
	 * Parses a public key in SSH wire format (RFC 4253 / RFC 5656 / RFC 8709) as used in OpenSSH public keys, authorized_keys, RFC 4716 and PuTTY keys.
	 */
	static PublicKey parsePublicKeyBytes(final byte[] data) throws Exception {
		final BlockDataReader publicKeyReader = new BlockDataReader(data);
		final Algorithm algorithm = Algorithm.getForSshAlgorithmId(publicKeyReader.readString());
		final PublicKey publicKey;
		if (Algorithm.RSA == algorithm) {
			final BigInteger publicExponent = publicKeyReader.readBigInt();
			final BigInteger modulus = publicKeyReader.readBigInt();
			publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		} else if (Algorithm.DSA == algorithm) {
			final BigInteger p = publicKeyReader.readBigInt();
			final BigInteger q = publicKeyReader.readBigInt();
			final BigInteger g = publicKeyReader.readBigInt();
			final BigInteger y = publicKeyReader.readBigInt();
			publicKey = KeyFactory.getInstance("DSA").generatePublic(new DSAPublicKeySpec(y, p, q, g));
		} else if (Algorithm.NISTP256 == algorithm || Algorithm.NISTP384 == algorithm || Algorithm.NISTP521 == algorithm) {
			final String ecdsaCurveName = publicKeyReader.readString();
			checkCurveNameMatchesAlgorithm(ecdsaCurveName, algorithm);
			publicKey = createEcPublicKey(publicKeyReader.readData(), ecdsaCurveName);
		} else if (Algorithm.ED25519 == algorithm) {
			publicKey = createEdDsaPublicKey(publicKeyReader.readData(), "Ed25519");
		} else if (Algorithm.ED448 == algorithm) {
			publicKey = createEdDsaPublicKey(publicKeyReader.readData(), "Ed448");
		} else {
			throw new IllegalArgumentException("Invalid public key algorithm (only supports RSA / DSA / ECDSA / EdDSA): " + algorithm.name());
		}
		if (publicKeyReader.isMoreDataAvailable()) {
			throw new Exception("Invalid public key data: unexpected trailing data found");
		}
		return publicKey;
	}

	private static void checkCurveNameMatchesAlgorithm(final String ecdsaCurveName, final Algorithm algorithm) throws Exception {
		if (!algorithm.getSshAlgorithmId().equals("ecdsa-sha2-" + ecdsaCurveName)) {
			throw new Exception("Unsupported or mismatching ECDSA curveName '" + ecdsaCurveName + "' for algorithm " + algorithm.getSshAlgorithmId());
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Key creation helpers
	// ---------------------------------------------------------------------------------------------

	private static KeyPair createRsaKeyPair(final BigInteger modulus, final BigInteger publicExponent, final BigInteger privateExponent, final BigInteger primeP, final BigInteger primeQ, final BigInteger crtCoefficient) throws Exception {
		if (modulus.signum() <= 0 || publicExponent.signum() <= 0 || privateExponent.signum() <= 0 || primeP.signum() <= 0 || primeQ.signum() <= 0 || crtCoefficient.signum() <= 0) {
			throw new Exception("Invalid RSA key data");
		}
		final BigInteger primeExponentP = privateExponent.mod(primeP.subtract(BigInteger.ONE)); // d mod (p-1)
		final BigInteger primeExponentQ = privateExponent.mod(primeQ.subtract(BigInteger.ONE)); // d mod (q-1)
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		final PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		final PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient));
		return new KeyPair(publicKey, privateKey);
	}

	private static ECNamedCurveParameterSpec getEcCurveSpec(final String nistCurveName) throws Exception {
		if (!"nistp256".equals(nistCurveName) && !"nistp384".equals(nistCurveName) && !"nistp521".equals(nistCurveName)) {
			throw new Exception("Unsupported ECDSA curveName: " + nistCurveName);
		}
		return ECNamedCurveTable.getParameterSpec(nistCurveName.replace("nist", "sec") + "r1");
	}

	private static ECParameterSpec getJdkEcCurveSpec(final String nistCurveName) throws Exception {
		if (!"nistp256".equals(nistCurveName) && !"nistp384".equals(nistCurveName) && !"nistp521".equals(nistCurveName)) {
			throw new Exception("Unsupported ECDSA curveName: " + nistCurveName);
		}
		final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(nistCurveName.replace("nist", "sec") + "r1"));
		return parameters.getParameterSpec(ECParameterSpec.class);
	}

	/**
	 * Creates an EC public key from the SSH uncompressed point encoding using the JDK EC implementation.
	 */
	static PublicKey createEcPublicKey(final byte[] pointEncoding, final String nistCurveName) throws Exception {
		final ECParameterSpec ecSpec = getJdkEcCurveSpec(nistCurveName);
		if (pointEncoding == null || pointEncoding.length < 3 || pointEncoding[0] != 0x04) {
			throw new Exception("Unsupported or invalid EC point encoding");
		}
		final int coordinateLength = (ecSpec.getCurve().getField().getFieldSize() + 7) / 8;
		if (pointEncoding.length != 1 + 2 * coordinateLength) {
			throw new Exception("Invalid EC point length");
		}
		final byte[] xBytes = Arrays.copyOfRange(pointEncoding, 1, 1 + coordinateLength);
		final byte[] yBytes = Arrays.copyOfRange(pointEncoding, 1 + coordinateLength, pointEncoding.length);
		final ECPoint point = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
		return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, ecSpec));
	}

	static PrivateKey createEcPrivateKey(final BigInteger s, final String nistCurveName) throws Exception {
		final ECParameterSpec ecSpec = getJdkEcCurveSpec(nistCurveName);
		if (s.signum() <= 0 || s.compareTo(ecSpec.getOrder()) >= 0) {
			throw new Exception("Invalid EC private key value (not in interval [1, n - 1])");
		}
		return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(s, ecSpec));
	}

	private static PublicKey deriveEcPublicKey(final BigInteger s, final String nistCurveName) throws Exception {
		final ECNamedCurveParameterSpec ecSpec = getEcCurveSpec(nistCurveName);
		final org.bouncycastle.math.ec.ECPoint point = ecSpec.getG().multiply(s).normalize();
		return KeyFactory.getInstance("EC", BC_PROVIDER).generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec));
	}

	/**
	 * Creates an EdDSA public key from its raw encoding (RFC 8032: little-endian y with the sign bit of x in the most significant bit).
	 */
	static PublicKey createEdDsaPublicKey(final byte[] rawPublicKey, final String curveName) throws Exception {
		final int expectedLength = "Ed25519".equals(curveName) ? 32 : 57;
		if (rawPublicKey == null || rawPublicKey.length != expectedLength) {
			throw new Exception("Invalid " + curveName + " public key length: " + (rawPublicKey == null ? 0 : rawPublicKey.length) + " (expected " + expectedLength + ")");
		}
		final byte[] data = rawPublicKey.clone();
		final boolean xOdd = (data[data.length - 1] & 0x80) != 0;
		data[data.length - 1] &= (byte) 0x7F;
		reverseArray(data);
		final EdECPoint edECPoint = new EdECPoint(xOdd, new BigInteger(1, data));
		return KeyFactory.getInstance(curveName).generatePublic(new EdECPublicKeySpec(new NamedParameterSpec(curveName), edECPoint));
	}

	static PrivateKey createEdDsaPrivateKey(final byte[] seed, final String curveName) throws Exception {
		final int expectedLength = "Ed25519".equals(curveName) ? 32 : 57;
		if (seed == null || seed.length != expectedLength) {
			throw new Exception("Invalid " + curveName + " private key length: " + (seed == null ? 0 : seed.length) + " (expected " + expectedLength + ")");
		}
		return KeyFactory.getInstance(curveName).generatePrivate(new EdECPrivateKeySpec(new NamedParameterSpec(curveName), seed));
	}

	private static byte[] deriveEdDsaPublicKeyBytes(final byte[] seed, final String curveName) {
		if ("Ed25519".equals(curveName)) {
			return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
		} else {
			return new Ed448PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
		}
	}

	// ---------------------------------------------------------------------------------------------
	// PuTTY
	// ---------------------------------------------------------------------------------------------

	private static Map<String, String> readPuttyKeyProperties(final LimitedLineReader dataReader) throws Exception {
		final Map<String, String> keyProperties = new LinkedHashMap<>();
		int headerCount = 0;
		String nextLine;
		while ((nextLine = dataReader.readLine()) != null) {
			final int indexOfHeaderSeparator = nextLine.indexOf(": ");
			if (indexOfHeaderSeparator > 0) {
				if (++headerCount > MAX_HEADER_COUNT) {
					throw new Exception("Corrupt key data found: More than " + MAX_HEADER_COUNT + " headers");
				}
				final String headerName = nextLine.substring(0, indexOfHeaderSeparator).trim();
				if ("Public-Lines".equals(headerName) || "Private-Lines".equals(headerName)) {
					final int numberOfLines;
					try {
						numberOfLines = Integer.parseInt(nextLine.substring(indexOfHeaderSeparator + 2).trim());
					} catch (final NumberFormatException e) {
						throw new Exception("Corrupt key data found: Invalid value for '" + headerName + "'", e);
					}
					if (numberOfLines < 0 || numberOfLines > MAX_PUTTY_DATA_LINES) {
						throw new Exception("Corrupt key data found: Invalid value for '" + headerName + "' (maximum " + MAX_PUTTY_DATA_LINES + " lines)");
					}
					final StringBuilder value = new StringBuilder();
					for (int i = 0; i < numberOfLines; i++) {
						if ((nextLine = dataReader.readLine()) != null) {
							final String dataLine = nextLine.trim();
							if ((long) value.length() + dataLine.length() > MAX_BASE64_ENCODED_DATA_LENGTH) {
								throw new Exception("Corrupt key data found: " + headerName + " exceeds maximum allowed size of " + MAX_BASE64_ENCODED_DATA_LENGTH + " characters");
							}
							value.append(dataLine);
						} else {
							throw new Exception("Corrupt key data found: Missing some lines for '" + headerName + "'");
						}
					}
					keyProperties.put(headerName, value.toString());
				} else {
					// Watchout for Comment values correct encoding, because it is part of the MAC checksum
					keyProperties.put(headerName, nextLine.substring(indexOfHeaderSeparator + 2));
					if ("Private-MAC".equals(headerName)) {
						// End of this PuTTY key. Following data may contain further keys.
						return keyProperties;
					}
				}
			} else if (isNotBlank(nextLine)) {
				throw new Exception("Corrupt key data found: Unexpected line: '" + nextLine + "'");
			}
		}
		throw new Exception("Corrupt key data found: Missing 'Private-MAC'");
	}

	private static SshKey readPuttyKey(final int puttyVersion, final Map<String, String> keyProperties, final Password password, final boolean publicKeyOnly) throws Exception {
		final SshKeyFormat keyFormat = puttyVersion == 2 ? SshKeyFormat.Putty2 : SshKeyFormat.Putty3;
		final Algorithm algorithm = Algorithm.getForSshAlgorithmId(keyProperties.get("PuTTY-User-Key-File"));
		final String encryptionMethod = getRequiredProperty(keyProperties, "Encryption");
		final String rawComment = keyProperties.get("Comment");
		final String comment = rawComment == null ? null : decodeComment(rawComment.getBytes(StandardCharsets.ISO_8859_1));

		final byte[] publicKeyData = Base64.getDecoder().decode(getRequiredProperty(keyProperties, "Public-Lines"));
		final PublicKey publicKey = parsePublicKeyBytes(publicKeyData);
		if (KeyPairUtilities.getAlgorithm(publicKey) != algorithm) {
			throw new Exception("PuTTY key type mismatch: header says " + algorithm.getSshAlgorithmId() + ", public key data is " + KeyPairUtilities.getAlgorithm(publicKey).getSshAlgorithmId());
		}
		if (publicKeyOnly) {
			return new SshKey(keyFormat, comment, new KeyPair(publicKey, null));
		}

		final byte[] encryptedPrivateKeyData = Base64.getDecoder().decode(getRequiredProperty(keyProperties, "Private-Lines"));
		final byte[] foundMacChecksum = getRequiredProperty(keyProperties, "Private-MAC").trim().toLowerCase().getBytes(StandardCharsets.ISO_8859_1);
		// The comment is part of the MAC exactly in the bytes of the file
		final byte[] commentBytes = rawComment == null ? new byte[0] : rawComment.getBytes(StandardCharsets.ISO_8859_1);

		if ("none".equals(encryptionMethod)) {
			final byte[] macKey;
			if (puttyVersion == 2) {
				macKey = getPuttyMacKeyVersion2(null);
			} else {
				macKey = new byte[0];
			}
			final String calculatedMac = calculatePuttyMac(puttyVersion, macKey, algorithm, encryptionMethod, commentBytes, publicKeyData, encryptedPrivateKeyData);
			if (!MessageDigest.isEqual(foundMacChecksum, calculatedMac.getBytes(StandardCharsets.ISO_8859_1))) {
				throw new Exception("Invalid PuTTY key data: MAC checksum mismatch");
			}
			return new SshKey(keyFormat, comment, readPuttyPrivateKeyData(encryptedPrivateKeyData, publicKey, algorithm));
		} else if ("aes256-cbc".equals(encryptionMethod)) {
			if (!password.hasPassword()) {
				throw new WrongPasswordException("Key is encrypted, but no password was given");
			} else if (encryptedPrivateKeyData.length == 0 || encryptedPrivateKeyData.length % 16 != 0) {
				throw new Exception("Invalid PuTTY key data: Invalid encrypted data length");
			}

			// PuTTY on Windows uses the system codepage (mostly compatible to ISO-8859-1), newer versions on Linux use UTF-8
			for (final byte[] passwordBytes : getPasswordByteVariants(password, false)) {
				byte[] puttyKeyEncryptionKey = null;
				byte[] privateKeyData = null;
				try {
					final byte[] macKey;
					final AlgorithmParameterSpec iv;
					if (puttyVersion == 2) {
						puttyKeyEncryptionKey = getPuttyPrivateKeyEncryptionKeyVersion2(passwordBytes);
						macKey = getPuttyMacKeyVersion2(passwordBytes);
						iv = new IvParameterSpec(new byte[16]);
					} else {
						puttyKeyEncryptionKey = getPuttyPrivateKeyEncryptionKeyVersion3Argon2(passwordBytes, keyProperties);
						macKey = Arrays.copyOfRange(puttyKeyEncryptionKey, 48, 80);
						iv = new IvParameterSpec(puttyKeyEncryptionKey, 32, 16);
					}
					final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
					cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), iv);
					privateKeyData = cipher.doFinal(encryptedPrivateKeyData);

					final String calculatedMac = calculatePuttyMac(puttyVersion, macKey, algorithm, encryptionMethod, commentBytes, publicKeyData, privateKeyData);
					Arrays.fill(macKey, (byte) 0);
					if (MessageDigest.isEqual(foundMacChecksum, calculatedMac.getBytes(StandardCharsets.ISO_8859_1))) {
						return new SshKey(keyFormat, comment, readPuttyPrivateKeyData(privateKeyData, publicKey, algorithm));
					}
				} finally {
					clear(puttyKeyEncryptionKey);
					clear(privateKeyData);
				}
			}
			throw new WrongPasswordException();
		} else {
			throw new Exception("Unsupported key encryption method: " + encryptionMethod);
		}
	}

	private static String getRequiredProperty(final Map<String, String> keyProperties, final String propertyName) throws Exception {
		final String value = keyProperties.get(propertyName);
		if (value == null) {
			throw new Exception("Corrupt key data found: Missing '" + propertyName + "'");
		}
		return value;
	}

	static byte[] getPuttyPrivateKeyEncryptionKeyVersion2(final byte[] passwordByteArray) throws Exception {
		final byte[] puttyKeyEncryptionKey = new byte[32];
		final MessageDigest digest = MessageDigest.getInstance("SHA-1");

		digest.update(new byte[] { 0, 0, 0, 0 });
		digest.update(passwordByteArray);
		final byte[] key1 = digest.digest();

		digest.update(new byte[] { 0, 0, 0, 1 });
		digest.update(passwordByteArray);
		final byte[] key2 = digest.digest();

		System.arraycopy(key1, 0, puttyKeyEncryptionKey, 0, 20);
		System.arraycopy(key2, 0, puttyKeyEncryptionKey, 20, 12);
		Arrays.fill(key1, (byte) 0);
		Arrays.fill(key2, (byte) 0);
		return puttyKeyEncryptionKey;
	}

	static byte[] getPuttyMacKeyVersion2(final byte[] passwordBytes) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.update("putty-private-key-file-mac-key".getBytes(StandardCharsets.US_ASCII));
		if (passwordBytes != null) {
			digest.update(passwordBytes);
		}
		return digest.digest();
	}

	private static byte[] getPuttyPrivateKeyEncryptionKeyVersion3Argon2(final byte[] passwordBytes, final Map<String, String> keyProperties) throws Exception {
		final String argon2Type = getRequiredProperty(keyProperties, "Key-Derivation");
		final int argon2Memory = parsePuttyIntProperty(keyProperties, "Argon2-Memory");
		final int argon2Passes = parsePuttyIntProperty(keyProperties, "Argon2-Passes");
		final int argon2Parallelism = parsePuttyIntProperty(keyProperties, "Argon2-Parallelism");
		final byte[] argon2Salt = fromHexString(getRequiredProperty(keyProperties, "Argon2-Salt"));

		if (argon2Memory < 8 || argon2Memory > MAX_ARGON2_MEMORY_KB) {
			throw new Exception("Invalid Argon2-Memory value " + argon2Memory + " (allowed: 8 - " + MAX_ARGON2_MEMORY_KB + " KiB). Maybe the key data is corrupted or malicious");
		} else if (argon2Passes < 1 || argon2Passes > MAX_ARGON2_PASSES) {
			throw new Exception("Invalid Argon2-Passes value " + argon2Passes + " (allowed: 1 - " + MAX_ARGON2_PASSES + "). Maybe the key data is corrupted or malicious");
		} else if ((long) argon2Memory * argon2Passes > MAX_ARGON2_MEMORY_TIMES_PASSES_KB) {
			throw new Exception("Invalid Argon2 parameters: Argon2-Memory * Argon2-Passes exceeds " + MAX_ARGON2_MEMORY_TIMES_PASSES_KB + ". Maybe the key data is corrupted or malicious");
		} else if (argon2Parallelism < 1 || argon2Parallelism > MAX_ARGON2_PARALLELISM || argon2Memory < 8 * argon2Parallelism) {
			throw new Exception("Invalid Argon2-Parallelism value " + argon2Parallelism + ". Maybe the key data is corrupted or malicious");
		} else if (argon2Salt.length == 0) {
			throw new Exception("Invalid empty Argon2-Salt");
		}
		return deriveArgon2Key(passwordBytes, argon2Type, argon2Memory, argon2Passes, argon2Parallelism, argon2Salt);
	}

	static byte[] deriveArgon2Key(final byte[] passwordBytes, final String argon2Type, final int argon2Memory, final int argon2Passes, final int argon2Parallelism, final byte[] argon2Salt) throws Exception {
		final int argon2TypeInt;
		if ("Argon2i".equalsIgnoreCase(argon2Type)) {
			argon2TypeInt = Argon2Parameters.ARGON2_i;
		} else if ("Argon2d".equalsIgnoreCase(argon2Type)) {
			argon2TypeInt = Argon2Parameters.ARGON2_d;
		} else if ("Argon2id".equalsIgnoreCase(argon2Type)) {
			argon2TypeInt = Argon2Parameters.ARGON2_id;
		} else {
			throw new Exception("Unsupported Key-Derivation (Only \"Argon2i\", \"Argon2d\", \"Argon2id\" are supported): " + argon2Type);
		}
		final Argon2Parameters.Builder builder = new Argon2Parameters.Builder(argon2TypeInt)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withIterations(argon2Passes)
				.withMemoryAsKB(argon2Memory)
				.withParallelism(argon2Parallelism)
				.withSalt(argon2Salt);
		final Argon2BytesGenerator argon2BytesGenerator = new Argon2BytesGenerator();
		argon2BytesGenerator.init(builder.build());
		final byte[] puttyKeyEncryptionKey = new byte[80];
		argon2BytesGenerator.generateBytes(passwordBytes, puttyKeyEncryptionKey);
		return puttyKeyEncryptionKey;
	}

	private static int parsePuttyIntProperty(final Map<String, String> keyProperties, final String propertyName) throws Exception {
		try {
			return Integer.parseInt(getRequiredProperty(keyProperties, propertyName).trim());
		} catch (final NumberFormatException e) {
			throw new Exception("Corrupt key data found: Invalid value for '" + propertyName + "'", e);
		}
	}

	/**
	 * Calculates the PuTTY MAC (v2: HMAC-SHA-1, v3: HMAC-SHA-256) as lowercase hex string.
	 */
	static String calculatePuttyMac(final int puttyVersion, final byte[] macKey, final Algorithm algorithm, final String encryptionType, final byte[] commentBytes, final byte[] publicKey, final byte[] privateKey) throws Exception {
		final Mac mac = Mac.getInstance(puttyVersion == 2 ? "HmacSHA1" : "HmacSHA256");
		// PuTTY v3 uses an empty MAC key for unencrypted keys, which SecretKeySpec does not allow, but HMAC defines it to be equal to a zero byte key
		mac.init(new SecretKeySpec(macKey.length == 0 ? new byte[1] : macKey, mac.getAlgorithm()));

		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final DataOutputStream data = new DataOutputStream(out);

		final byte[] keyTypeBytes = algorithm.getSshAlgorithmId().getBytes(StandardCharsets.ISO_8859_1);
		data.writeInt(keyTypeBytes.length);
		data.write(keyTypeBytes);

		final byte[] encryptionTypeBytes = encryptionType.getBytes(StandardCharsets.ISO_8859_1);
		data.writeInt(encryptionTypeBytes.length);
		data.write(encryptionTypeBytes);

		data.writeInt(commentBytes.length);
		data.write(commentBytes);

		data.writeInt(publicKey.length);
		data.write(publicKey);

		data.writeInt(privateKey.length);
		data.write(privateKey);

		return toHexString(mac.doFinal(out.toByteArray())).toLowerCase();
	}

	private static KeyPair readPuttyPrivateKeyData(final byte[] privateKeyData, final PublicKey publicKey, final Algorithm algorithm) throws Exception {
		try {
			final BlockDataReader privateKeyReader = new BlockDataReader(privateKeyData);
			if (Algorithm.RSA == algorithm) {
				final java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
				final BigInteger privateExponent = privateKeyReader.readBigInt();
				final BigInteger p = privateKeyReader.readBigInt(); // secret prime factor (= PrimeP)
				final BigInteger q = privateKeyReader.readBigInt(); // secret prime factor (= PrimeQ)
				final BigInteger iqmp = privateKeyReader.readBigInt(); // q^-1 mod p (= CrtCoefficient)
				return createRsaKeyPair(rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent(), privateExponent, p, q, iqmp);
			} else if (Algorithm.DSA == algorithm) {
				final java.security.interfaces.DSAPublicKey dsaPublicKey = (java.security.interfaces.DSAPublicKey) publicKey;
				final BigInteger x = privateKeyReader.readBigInt();
				return createDsaKeyPair(dsaPublicKey.getParams().getP(), dsaPublicKey.getParams().getQ(), dsaPublicKey.getParams().getG(), dsaPublicKey.getY(), x);
			} else if (Algorithm.NISTP256 == algorithm || Algorithm.NISTP384 == algorithm || Algorithm.NISTP521 == algorithm) {
				final String ecdsaCurveName = algorithm.getSshAlgorithmId().substring("ecdsa-sha2-".length());
				return new KeyPair(publicKey, createEcPrivateKey(privateKeyReader.readBigInt(), ecdsaCurveName));
			} else if (Algorithm.ED25519 == algorithm) {
				return new KeyPair(publicKey, createEdDsaPrivateKey(privateKeyReader.readData(), "Ed25519"));
			} else if (Algorithm.ED448 == algorithm) {
				return new KeyPair(publicKey, createEdDsaPrivateKey(privateKeyReader.readData(), "Ed448"));
			} else {
				throw new IllegalArgumentException("Invalid public key algorithm for PuTTY key (only supports RSA / DSA / ECDSA / EdDSA): " + algorithm.name());
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read key data", e);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Common helpers
	// ---------------------------------------------------------------------------------------------

	/**
	 * Password byte variants to try: Putty uses "ISO-8859-1" (or the Windows codepage) for password encoding, "ssh-keygen" and OpenSSL on Linux use UTF-8.
	 */
	private static List<byte[]> getPasswordByteVariants(final Password password, final boolean utf8First) {
		final List<byte[]> variants = new ArrayList<>();
		final byte[] utf8Bytes = password.getPasswordBytesUtfEncoded();
		final byte[] isoBytes = password.getPasswordBytesIsoEncoded();
		variants.add(utf8First ? utf8Bytes : isoBytes);
		if (!Arrays.equals(utf8Bytes, isoBytes)) {
			variants.add(utf8First ? isoBytes : utf8Bytes);
		}
		return variants;
	}

	/**
	 * Decodes key comment bytes.
	 * Comments are expected in UTF-8 (OpenSSH), but older tools write ISO-8859-1. Invalid UTF-8 data is therefore decoded as ISO-8859-1.
	 */
	static String decodeComment(final byte[] commentBytes) {
		if (commentBytes == null || commentBytes.length == 0) {
			return null;
		}
		final String comment = decodeStrict(commentBytes, StandardCharsets.UTF_8);
		if (comment == null) {
			return new String(commentBytes, StandardCharsets.ISO_8859_1);
		}
		// Fix comments, which were encoded twice in UTF-8 (e.g. "Ã¤" instead of "ä")
		boolean onlyLatin1 = true;
		boolean containsUtf8LeadingByteCharacter = false;
		for (final char nextChar : comment.toCharArray()) {
			if (nextChar > 0xFF) {
				onlyLatin1 = false;
				break;
			} else if (nextChar == 0xC3 || nextChar == 0xC2) {
				containsUtf8LeadingByteCharacter = true;
			}
		}
		if (onlyLatin1 && containsUtf8LeadingByteCharacter) {
			final String fixedComment = decodeStrict(comment.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
			if (fixedComment != null) {
				return fixedComment;
			}
		}
		return comment;
	}

	private static String decodeStrict(final byte[] data, final Charset charset) {
		try {
			return charset.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(data)).toString();
		} catch (@SuppressWarnings("unused") final CharacterCodingException e) {
			return null;
		}
	}

	static byte[] fromHexString(final String value) throws Exception {
		if (value == null || value.length() % 2 != 0) {
			throw new Exception("Invalid hex string");
		}
		final byte[] data = new byte[value.length() / 2];
		for (int i = 0; i < value.length(); i += 2) {
			final int high = Character.digit(value.charAt(i), 16);
			final int low = Character.digit(value.charAt(i + 1), 16);
			if (high < 0 || low < 0) {
				throw new Exception("Invalid hex string");
			}
			data[i / 2] = (byte) ((high << 4) + low);
		}
		return data;
	}

	static String toHexString(final byte[] data) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString();
	}

	private static byte[] reverseArray(final byte[] arrayData) {
		for (int i = 0; i < arrayData.length / 2; i++) {
			final int j = arrayData.length - 1 - i;
			final byte tmp = arrayData[i];
			arrayData[i] = arrayData[j];
			arrayData[j] = tmp;
		}
		return arrayData;
	}

	private static void clear(final byte[] array) {
		if (array != null) {
			Arrays.fill(array, (byte) 0);
		}
	}

	private static boolean isNotBlank(final String value) {
		return value != null && value.trim().length() > 0;
	}

	/**
	 * Reader for SSH wire format data (RFC 4251: uint32, string, mpint).
	 */
	private static class BlockDataReader {
		/**
		 * Sanity upper bound for a single length-prefixed data block, to protect against maliciously
		 * crafted or corrupted key files that could otherwise force a huge memory allocation before
		 * any validation of the key data has taken place (Denial of Service protection).
		 */
		private static final int MAX_BLOCK_SIZE = 16 * 1024 * 1024; // 16 MB

		private final ByteArrayInputStream inputStream;
		private final DataInputStream keyDataInput;

		private BlockDataReader(final byte[] data) {
			inputStream = new ByteArrayInputStream(data);
			keyDataInput = new DataInputStream(inputStream);
		}

		private boolean isMoreDataAvailable() {
			return inputStream.available() > 0;
		}

		private int readSimpleInt() throws Exception {
			try {
				return keyDataInput.readInt();
			} catch (final IOException e) {
				throw new Exception("Key block read error", e);
			}
		}

		private BigInteger readBigInt() throws Exception {
			final byte[] data = readData();
			// An empty mpint represents zero
			return data.length == 0 ? BigInteger.ZERO : new BigInteger(data);
		}

		private String readString() throws Exception {
			return new String(readData(), StandardCharsets.UTF_8);
		}

		private byte[] readData() throws Exception {
			try {
				final int nextBlockSize = keyDataInput.readInt();
				if (nextBlockSize < 0) {
					throw new Exception("Key blocksize error. Maybe the key encryption password was wrong");
				} else if (nextBlockSize > MAX_BLOCK_SIZE || nextBlockSize > inputStream.available()) {
					throw new Exception("Key blocksize " + nextBlockSize + " exceeds available data. Maybe the key encryption password was wrong or the key data is corrupted");
				} else {
					final byte[] nextBlock = new byte[nextBlockSize];
					keyDataInput.readFully(nextBlock);
					return nextBlock;
				}
			} catch (final IOException e) {
				throw new Exception("Key block read error", e);
			}
		}

		private byte[] readZeroLimitedData(final int maxLength) throws Exception {
			try {
				final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
				int nextByte;
				while ((nextByte = keyDataInput.readUnsignedByte()) != 0) {
					if (buffer.size() >= maxLength) {
						throw new Exception("Key block read error: Missing zero terminator");
					}
					buffer.write(nextByte);
				}
				return buffer.toByteArray();
			} catch (final IOException e) {
				throw new Exception("Key block read error", e);
			}
		}

		private byte[] readLeftoverData() throws Exception {
			try {
				final byte[] nextBlock = new byte[inputStream.available()];
				keyDataInput.readFully(nextBlock);
				return nextBlock;
			} catch (final IOException e) {
				throw new Exception("Key block read error", e);
			}
		}
	}
}
