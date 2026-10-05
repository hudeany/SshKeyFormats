package de.soderer.sshkeyformats.data;

/**
 * Algorithm API.
 */
public enum Algorithm {
	/** DSA (Digital Signature Algorithm). */
	DSA("ssh-dss"),
	/** RSA public key algorithm. */
	RSA("ssh-rsa"),
	/** NIST P-256 elliptic curve. */
	NISTP256("ecdsa-sha2-nistp256"),
	/** NIST P-384 elliptic curve. */
	NISTP384("ecdsa-sha2-nistp384"),
	/** NIST P-521 elliptic curve. */
	NISTP521("ecdsa-sha2-nistp521"),
	/** Ed25519 Edwards-curve signature algorithm. */
	ED25519("ssh-ed25519"),
	/** Ed448 Edwards-curve signature algorithm. */
	ED448("ssh-ed448");

	private final String sshAlgorithmId;

	Algorithm(final String sshAlgorithmId) {
		this.sshAlgorithmId = sshAlgorithmId;
	}

/**
 * getSshAlgorithmId operation.
 * @return the resulting value.
 */
	public String getSshAlgorithmId() {
		return sshAlgorithmId;
	}

/**
 * getForSshAlgorithmId operation.
 * @param text the text value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static Algorithm getForSshAlgorithmId(final String text) throws Exception {
		for (final Algorithm type : Algorithm.values()) {
			if (type.getSshAlgorithmId().equalsIgnoreCase(text)) {
				return type;
			}
		}
		throw new Exception("Unknown AuthorizedKeyType: " + text);
	}
}
