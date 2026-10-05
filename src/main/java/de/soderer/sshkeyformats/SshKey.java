package de.soderer.sshkeyformats;

import java.security.KeyPair;

import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.KeyPairUtilities;

/**
 * Container for OpenSsh key data
 */
public class SshKey {
/**
 * SshKeyFormat API.
 */
	public enum SshKeyFormat {
		/** Undefined or unknown key format. */
		Undefined(""),
		/** OpenSSL PEM/PKCS#8 key format. */
		OpenSSL("OpenSSL / PKCS#8"),
		/** OpenSSH version 1 key format. */
		OpenSSHv1("OpenSSH Version 1"),
		/** PuTTY version 2 key format. */
		Putty2("PuTTY Version 2"),
		/** PuTTY version 3 key format. */
		Putty3("PuTTY Version 3"),
		/** PKCS#1 key format. */
		PKCS1("PKCS#1");

		private final String displayText;

/**
 * getDisplayText operation.
 * @return the resulting value.
 */
		public String getDisplayText() {
			return displayText;
		}

		SshKeyFormat(final String displayText) {
			this.displayText = displayText;
		}
	}

	private SshKeyFormat format;
	private String comment;
	private KeyPair keyPair;

	/**
	 * Creates an SSH key with the specified format, comment and key pair.
	 *
	 * @param format the key format; {@link SshKeyFormat#Undefined} is used when {@code null}
	 * @param comment the optional key comment
	 * @param keyPair the key pair, or {@code null} when no key pair is available
	 * @throws Exception if the supplied key pair uses an unsupported algorithm
	 */
	public SshKey(final SshKeyFormat format, final String comment, final KeyPair keyPair) throws Exception {
		this.format = format == null ? SshKeyFormat.Undefined : format;
		this.comment = comment;

		if (keyPair != null) {
			setKeyPair(keyPair);
		}
	}

	/**
	 * Sets the key pair represented by this SSH key.
	 * @param keyPair the key pair to set.
	 */
	protected void setKeyPair(final KeyPair keyPair) {
		if (keyPair == null) {
			this.keyPair = null;
		} else {
			String algorithm = null;
			if (keyPair.getPublic() != null) {
				algorithm = keyPair.getPublic().getAlgorithm();
			}
			if (keyPair.getPrivate() != null) {
				if (algorithm != null && !algorithm.equals(keyPair.getPrivate().getAlgorithm())) {
					throw new IllegalArgumentException("SSH cipher algorithm of public key ('" + algorithm + "') and private key ('" + keyPair.getPrivate().getAlgorithm() + "') do not match");
				} else {
					algorithm = keyPair.getPrivate().getAlgorithm();
				}
			}

			if ("RSA".equals(algorithm)
					|| "DSA".equals(algorithm)
					|| "EC".equals(algorithm)
					|| "EdDSA".equals(algorithm)) {
				this.keyPair = keyPair;
			} else {
				throw new IllegalArgumentException("Unsupported SSH cipher algorithm for SSH key (only supports RSA / DSA / EC (ECDSA) / EdDSA): " + algorithm);
			}
		}
	}

/**
 * getAlgorithm operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public Algorithm getAlgorithm() throws Exception {
		return KeyPairUtilities.getAlgorithm(keyPair);
	}

/**
 * getKeyStrength operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public int getKeyStrength() throws Exception {
		return KeyPairUtilities.getKeyStrength(keyPair);
	}

/**
 * getFormat operation.
 * @return the resulting value.
 */
	public SshKeyFormat getFormat() {
		return format;
	}

/**
 * setFormat operation.
 * @param format the format value.
 */
	public void setFormat(final SshKeyFormat format) {
		this.format = format == null ? SshKeyFormat.Undefined : format;
	}

/**
 * withFormat operation.
 * @param newFormat the newFormat value.
 * @return the resulting value.
 */
	public SshKey withFormat(final SshKeyFormat newFormat) {
		setFormat(newFormat);
		return this;
	}

/**
 * getComment operation.
 * @return the resulting value.
 */
	public String getComment() {
		return comment;
	}

/**
 * setComment operation.
 * @param comment the comment value.
 */
	public void setComment(final String comment) {
		this.comment = comment;
	}

/**
 * withComment operation.
 * @param newComment the newComment value.
 * @return the resulting value.
 */
	public SshKey withComment(final String newComment) {
		setComment(newComment);
		return this;
	}

/**
 * getMd5Fingerprint operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getMd5Fingerprint() throws Exception {
		return KeyPairUtilities.getMd5Fingerprint(keyPair);
	}

/**
 * getSha256Fingerprint operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getSha256Fingerprint() throws Exception {
		return KeyPairUtilities.getSha256Fingerprint(keyPair);
	}

/**
 * getSha256FingerprintBase64 operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getSha256FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha256FingerprintBase64(keyPair);
	}

/**
 * getSha384Fingerprint operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getSha384Fingerprint() throws Exception {
		return KeyPairUtilities.getSha384Fingerprint(keyPair);
	}

/**
 * getSha384FingerprintBase64 operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getSha384FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha384FingerprintBase64(keyPair);
	}

/**
 * getSha512Fingerprint operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getSha512Fingerprint() throws Exception {
		return KeyPairUtilities.getSha512Fingerprint(keyPair);
	}

/**
 * getSha512FingerprintBase64 operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String getSha512FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha512FingerprintBase64(keyPair);
	}

/**
 * getKeyPair operation.
 * @return the resulting value.
 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

/**
 * encodePublicKeyForAuthorizedKeys operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public String encodePublicKeyForAuthorizedKeys() throws Exception {
		return KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair);
	}
}
