package de.soderer.sshkeyformats.data;

public enum Algorithm {
	DSA("ssh-dss"),
	RSA("ssh-rsa"),
	NISTP256("ecdsa-sha2-nistp256"),
	NISTP384("ecdsa-sha2-nistp384"),
	NISTP521("ecdsa-sha2-nistp521"),
	ED25519("ssh-ed25519"),
	ED448("ssh-ed448");

	private final String sshAlgorithmId;

	Algorithm(final String sshAlgorithmId) {
		this.sshAlgorithmId = sshAlgorithmId;
	}

	public String getSshAlgorithmId() {
		return sshAlgorithmId;
	}

	public static Algorithm getForSshAlgorithmId(final String text) throws Exception {
		for (final Algorithm type : Algorithm.values()) {
			if (type.getSshAlgorithmId().equalsIgnoreCase(text)) {
				return type;
			}
		}
		throw new Exception("Unknown AuthorizedKeyType: " + text);
	}
}
