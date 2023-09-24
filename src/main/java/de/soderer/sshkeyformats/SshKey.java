package de.soderer.sshkeyformats;

import java.security.KeyPair;

import de.soderer.sshkeyformats.data.KeyPairUtilities;

/**
 * Container for OpenSsh key data
 */
public class SshKey {
	public enum SshKeyFormat {
		Undefined(""),
		OpenSSL("OpenSSL / PKCS#8"),
		OpenSSHv1("OpenSSH Version 1"),
		Putty2("PuTTY Version 2"),
		Putty3("PuTTY Version 3"),
		PKCS1("PKCS#1");

		private final String displayText;

		public String getDisplayText() {
			return displayText;
		}

		SshKeyFormat(final String displayText) {
			this.displayText = displayText;
		}
	}

	private SshKeyFormat format;
	private String comment;
	private final KeyPair keyPair;

	/**
	 * Create a SSH key with given keypair
	 */
	public SshKey(final SshKeyFormat format, final String comment, final KeyPair keyPair) throws Exception {
		this.format = format == null ? SshKeyFormat.Undefined : format;
		this.comment = comment;

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

	public String getAlgorithm() throws Exception {
		return KeyPairUtilities.getAlgorithm(keyPair);
	}

	public int getKeyStrength() throws Exception {
		return KeyPairUtilities.getKeyStrength(keyPair);
	}

	public SshKeyFormat getFormat() {
		return format;
	}

	public void setFormat(final SshKeyFormat format) {
		this.format = format == null ? SshKeyFormat.Undefined : format;
	}

	public String getComment() {
		return comment;
	}

	public void setComment(final String comment) {
		this.comment = comment;
	}

	public String getMd5Fingerprint() throws Exception {
		return KeyPairUtilities.getMd5Fingerprint(keyPair);
	}

	public String getSha256Fingerprint() throws Exception {
		return KeyPairUtilities.getSha256Fingerprint(keyPair);
	}

	public String getSha256FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha256FingerprintBase64(keyPair);
	}

	public String getSha384Fingerprint() throws Exception {
		return KeyPairUtilities.getSha384Fingerprint(keyPair);
	}

	public String getSha384FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha384FingerprintBase64(keyPair);
	}

	public String getSha512Fingerprint() throws Exception {
		return KeyPairUtilities.getSha512Fingerprint(keyPair);
	}

	public String getSha512FingerprintBase64() throws Exception {
		return KeyPairUtilities.getSha512FingerprintBase64(keyPair);
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}

	public String encodePublicKeyForAuthorizedKeys() throws Exception {
		return KeyPairUtilities.encodePublicKeyForAuthorizedKeys(keyPair);
	}
}
