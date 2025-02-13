package de.soderer.sshkeyformats.data;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.soderer.sshkeyformats.SshKey;
import de.soderer.sshkeyformats.SshKeyReader;

public class AuthorizedKey extends SshKey {
	public enum AuthorizedKeyType {
		DSA("ssh-dss"),
		RSA("ssh-rsa"),
		NISTP256("ecdsa-sha2-nistp256"),
		NISTP384("ecdsa-sha2-nistp384"),
		NISTP521("ecdsa-sha2-nistp521"),
		ED25519("ssh-ed25519"),
		ED448("ssh-ed448");

		private final String text;

		AuthorizedKeyType(final String text) {
			this.text = text;
		}

		public String getText() {
			return text;
		}

		public static AuthorizedKeyType getTypeFromText(final String text) throws Exception {
			for (final AuthorizedKeyType type : AuthorizedKeyType.values()) {
				if (type.getText().equalsIgnoreCase(text)) {
					return type;
				}
			}
			throw new Exception("Unknown AuthorizedKeyType: " + text);
		}
	}

	private Map<String, String> environment;
	private AuthorizedKeyType keyType;
	private String keyString;

	private transient String hash = null;

	public AuthorizedKey(final AuthorizedKeyType type, final String keyString) throws Exception {
		super(SshKeyFormat.OpenSSL, null, null);

		environment = new HashMap<>();
		keyType = type;
		this.keyString = keyString;
	}

	public AuthorizedKey(final AuthorizedKeyType type, final String keyString, final String comment) throws Exception {
		super(SshKeyFormat.OpenSSL, comment, null);

		environment = new HashMap<>();
		keyType = type;
		this.keyString = keyString;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @param environment
	 * @param type
	 * @param key
	 * @param comment
	 * @throws Exception
	 */
	public AuthorizedKey(final Map<String, String> environment, final AuthorizedKeyType type, final String keyString, final String comment) throws Exception {
		super(SshKeyFormat.OpenSSL, comment, null);

		this.environment = environment;
		keyType = type;
		this.keyString = keyString;
	}

	public Map<String, String> getEnvironment() {
		return environment;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @param environment
	 * @return
	 */
	public AuthorizedKey setEnvironment(final Map<String, String> environment) {
		this.environment = environment;
		return this;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @param environmentKeyName
	 * @param environmentValue
	 * @return
	 */
	public AuthorizedKey setEnvironmentValue(final String environmentKeyName, final String environmentValue) {
		environment.put(environmentKeyName, environmentValue);
		return this;
	}

	public AuthorizedKeyType getKeyType() {
		return keyType;
	}

	public AuthorizedKey setKeyType(final AuthorizedKeyType keyType) {
		this.keyType = keyType;
		return this;
	}

	public String getKeyString() {
		return keyString;
	}

	public AuthorizedKey setKeyString(final String keyString) {
		this.keyString = keyString;
		return this;
	}

	@Override
	public String toString() {
		if (getComment() != null) {
			return keyType.getText() + " " + keyString + " " + getComment();
		} else {
			return keyType.getText() + " " + keyString;
		}
	}

	public String getHash() throws Exception {
		if (hash == null) {
			try (InputStream inputStream = new ByteArrayInputStream((AuthorizedKeyType.RSA.getText() + " " + keyString + " noComment").getBytes(StandardCharsets.UTF_8))) {
				final List<SshKey> sshKeys = SshKeyReader.readAllPublicKeys(inputStream);
				hash = sshKeys.get(0).getMd5Fingerprint().replace(":", "");
			}
		}
		return hash;
	}
}
