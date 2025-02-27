package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import de.soderer.sshkeyformats.data.Algorithm;

public class AuthorizedKey extends SshKey {
	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 */
	private Map<String, String> environment = null;
	private String command;
	private boolean certAuthority;
	private String fromList;
	private boolean noAgentForwarding;
	private boolean noPortForwarding;
	private boolean noPty;
	private boolean noUserRc;
	private boolean noX11Forwarding;
	private String permitOpen;
	private String principals;
	private String tunnel;

	private final Algorithm keyType;
	private final String keyString;

	private transient String hash = null;

	public AuthorizedKey(final Algorithm type, final String keyString) throws Exception {
		super(SshKeyFormat.OpenSSL, null, null);

		keyType = type;
		this.keyString = keyString;
	}

	public AuthorizedKey(final Algorithm type, final String keyString, final String comment) throws Exception {
		super(SshKeyFormat.OpenSSL, comment, null);

		keyType = type;
		this.keyString = keyString;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @return
	 */
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

	public Algorithm getKeyType() {
		return keyType;
	}

	public String getKeyString() {
		return keyString;
	}

	@Override
	public String toString() {
		if (getComment() != null) {
			return keyType.getSshAlgorithmId() + " " + keyString + " " + getComment();
		} else {
			return keyType.getSshAlgorithmId() + " " + keyString;
		}
	}

	public String getHash() throws Exception {
		if (hash == null) {
			if (getKeyPair() == null) {
				try (InputStream inputStream = new ByteArrayInputStream(keyString.getBytes(StandardCharsets.UTF_8))) {
					final List<SshKey> sshKeys = SshKeyReader.readAllPublicKeys(inputStream);
					setKeyPair(sshKeys.get(0).getKeyPair());
				}
			}
			hash = getMd5Fingerprint().replace(":", "");
		}
		return hash;
	}

	public String getCommand() {
		return command;
	}

	public void setCommand(final String command) {
		this.command = command;
	}

	public boolean isCertAuthority() {
		return certAuthority;
	}

	public void setCertAuthority(final boolean certAuthority) {
		this.certAuthority = certAuthority;
	}

	public String getFromList() {
		return fromList;
	}

	public void setFromList(final String fromList) {
		this.fromList = fromList;
	}

	public boolean isNoAgentForwarding() {
		return noAgentForwarding;
	}

	public void setNoAgentForwarding(final boolean noAgentForwarding) {
		this.noAgentForwarding = noAgentForwarding;
	}

	public boolean isNoPortForwarding() {
		return noPortForwarding;
	}

	public void setNoPortForwarding(final boolean noPortForwarding) {
		this.noPortForwarding = noPortForwarding;
	}

	public boolean isNoPty() {
		return noPty;
	}

	public void setNoPty(final boolean noPty) {
		this.noPty = noPty;
	}

	public boolean isNoUserRc() {
		return noUserRc;
	}

	public void setNoUserRc(final boolean noUserRc) {
		this.noUserRc = noUserRc;
	}

	public boolean isNoX11Forwarding() {
		return noX11Forwarding;
	}

	public void setNoX11Forwarding(final boolean noX11Forwarding) {
		this.noX11Forwarding = noX11Forwarding;
	}

	public String getPermitOpen() {
		return permitOpen;
	}

	public void setPermitOpen(final String permitOpen) {
		this.permitOpen = permitOpen;
	}

	public String getPrincipals() {
		return principals;
	}

	public void setPrincipals(final String principals) {
		this.principals = principals;
	}

	public String getTunnel() {
		return tunnel;
	}

	public void setTunnel(final String tunnel) {
		this.tunnel = tunnel;
	}
}
