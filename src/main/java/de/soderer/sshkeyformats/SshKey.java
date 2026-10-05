package de.soderer.sshkeyformats;

import java.security.KeyPair;

import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.KeyPairUtilities;

/**
 * Container for OpenSsh key data
 */
public class SshKey {
	/**
	 * Defines the supported ssh key format values.
	 */
	public enum SshKeyFormat {
		Undefined(""),
		OpenSSL("OpenSSL / PKCS#8"),
		OpenSSHv1("OpenSSH Version 1"),
		Putty2("PuTTY Version 2"),
		Putty3("PuTTY Version 3"),
		PKCS1("PKCS#1");

		private final String displayText;

		/**
		 * Returns the display text.
		 * @return the resulting value
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
	 * Create a SSH key with given keypair
	 */
	public SshKey(final SshKeyFormat format, final String comment, final KeyPair keyPair) throws Exception {
		this.format = format == null ? SshKeyFormat.Undefined : format;
		this.comment = comment;

		if (keyPair != null) {
			setKeyPair(keyPair);
		}
	}

	/**
	 * Sets  key pair.
	 * @param keyPair the key pair
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
	 * Returns the algorithm.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public Algorithm getAlgorithm() throws Exception {
		return KeyPairUtilities.getAlgorithm(keyPair);
	}

	/**
	 * Returns the key strength.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public int getKeyStrength() throws Exception {
		return KeyPairUtilities.getKeyStrength(keyPair);
	}

	/**
	 * Returns the format.
	 * @return the resulting value
	 */
	public SshKeyFormat getFormat() {
		return format;
	}

	/**
	 * Sets  format.
	 * @param format the format
	 */
	public void setFormat(final SshKeyFormat format) {
		this.format = format == null ? SshKeyFormat.Undefined : format;
	}

	/**
	 * Returns this object with  format set to the supplied value.
	 * @param newFormat the new format
	 * @return the resulting value
	 */
	public SshKey withFormat(final SshKeyFormat newFormat) {
		setFormat(newFormat);
		return this;
	}

	/**
	 * Returns the comment.
	 * @return the resulting value
	 */
	public String getComment() {
		return comment;
	}

	/**
	 * Sets  comment.
	 * @param comment the comment
	 */
	public void setComment(final String comment) {
		this.comment = comment;
	}

	/**
	 * Returns this object with  comment set to the supplied value.
	 * @param newComment the new comment
	 * @return the resulting value
	 */
	public SshKey withComment(final String newComment) {
		setComment(newComment);
		return this;
	}

	/**
	 * Returns the md5 fingerprint.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getMd5Fingerprint() throws Exception {
		return KeyPairUtilities.getMd5Fingerprint(keyPair);
	}

	/**
	 * Returns the sha256 fingerprint.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getSha256Fingerprint() throws Exception {
		return KeyPairUtilities.getSha256Fingerprint(keyPair);
	}

	/**
	 * Returns the sha256 fingerprint base64.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getSha256FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha256FingerprintBase64(keyPair);
	}

	/**
	 * Returns the sha384 fingerprint.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getSha384Fingerprint() throws Exception {
		return KeyPairUtilities.getSha384Fingerprint(keyPair);
	}

	/**
	 * Returns the sha384 fingerprint base64.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getSha384FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha384FingerprintBase64(keyPair);
	}

	/**
	 * Returns the sha512 fingerprint.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getSha512Fingerprint() throws Exception {
		return KeyPairUtilities.getSha512Fingerprint(keyPair);
	}

	/**
	 * Returns the sha512 fingerprint base64.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String getSha512FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha512FingerprintBase64(keyPair);
	}

	/**
	 * Returns the key pair.
	 * @return the resulting value
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

	/**
	 * Encodes  public key for authorized keys.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public String encodePublicKeyForAuthorizedKeys() throws Exception {
		return KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair);
	}
}
