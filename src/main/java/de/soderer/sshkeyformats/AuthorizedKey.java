package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import de.soderer.sshkeyformats.data.Algorithm;

/**
 * AuthorizedKey API.
 */
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

/**
 * AuthorizedKey operation.
 * @param type the type value.
 * @param keyString the keyString value.
 * @throws Exception if the operation cannot be completed.
 */
	public AuthorizedKey(final Algorithm type, final String keyString) throws Exception {
		super(SshKeyFormat.OpenSSL, null, null);

		keyType = type;
		this.keyString = keyString;
	}

/**
 * AuthorizedKey operation.
 * @param type the type value.
 * @param keyString the keyString value.
 * @param comment the comment value.
 * @throws Exception if the operation cannot be completed.
 */
	public AuthorizedKey(final Algorithm type, final String keyString, final String comment) throws Exception {
		super(SshKeyFormat.OpenSSL, comment, null);

		keyType = type;
		this.keyString = keyString;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @return the environment variable names and values associated with this key
	 */
	public Map<String, String> getEnvironment() {
		return environment;
	}

	/**
	 * Sets the environment settings associated with this authorized key.
	 * <p>
	 * The SSH server must have the {@code PermitUserEnvironment} option enabled
	 * in {@code /etc/ssh/sshd_config} for these settings to take effect.
	 *
	 * @param environment the environment variable names and values
	 */
	public void setEnvironment(final Map<String, String> environment) {
		this.environment = environment;
	}

/**
 * withEnvironment operation.
 * @param newEnvironment the newEnvironment value.
 * @return the resulting value.
 */
	public AuthorizedKey withEnvironment(final Map<String, String> newEnvironment) {
		setEnvironment(newEnvironment);
		return this;
	}

	/**
	 * Sets one environment variable associated with this authorized key.
	 * <p>
	 * The SSH server must have the {@code PermitUserEnvironment} option enabled
	 * in {@code /etc/ssh/sshd_config} for this setting to take effect.
	 *
	 * @param environmentKeyName the environment variable name
	 * @param environmentValue the environment variable value
	 */
	public void setEnvironmentValue(final String environmentKeyName, final String environmentValue) {
		environment.put(environmentKeyName, environmentValue);
	}

/**
 * withEnvironmentValue operation.
 * @param newEnvironmentKeyName the newEnvironmentKeyName value.
 * @param newEnvironmentValue the newEnvironmentValue value.
 * @return the resulting value.
 */
	public AuthorizedKey withEnvironmentValue(final String newEnvironmentKeyName, final String newEnvironmentValue) {
		setEnvironmentValue(newEnvironmentKeyName, newEnvironmentValue);
		return this;
	}

/**
 * getKeyType operation.
 * @return the resulting value.
 */
	public Algorithm getKeyType() {
		return keyType;
	}

/**
 * getKeyString operation.
 * @return the resulting value.
 */
	public String getKeyString() {
		return keyString;
	}

	@Override
/**
 * toString operation.
 * @return the resulting value.
 */
	public String toString() {
		if (getComment() != null) {
			return keyType.getSshAlgorithmId() + " " + keyString + " " + getComment();
		} else {
			return keyType.getSshAlgorithmId() + " " + keyString;
		}
	}

/**
 * getHash operation.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
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

/**
 * getCommand operation.
 * @return the resulting value.
 */
	public String getCommand() {
		return command;
	}

/**
 * setCommand operation.
 * @param command the command value.
 */
	public void setCommand(final String command) {
		this.command = command;
	}

/**
 * withCommand operation.
 * @param newCommand the newCommand value.
 * @return the resulting value.
 */
	public AuthorizedKey withCommand(final String newCommand) {
		setCommand(newCommand);
		return this;
	}

/**
 * isCertAuthority operation.
 * @return the resulting value.
 */
	public boolean isCertAuthority() {
		return certAuthority;
	}

/**
 * setCertAuthority operation.
 * @param certAuthority the certAuthority value.
 */
	public void setCertAuthority(final boolean certAuthority) {
		this.certAuthority = certAuthority;
	}

/**
 * withCertAuthority operation.
 * @param newCertAuthority the newCertAuthority value.
 * @return the resulting value.
 */
	public AuthorizedKey withCertAuthority(final boolean newCertAuthority) {
		setCertAuthority(newCertAuthority);
		return this;
	}

/**
 * getFromList operation.
 * @return the resulting value.
 */
	public String getFromList() {
		return fromList;
	}

/**
 * setFromList operation.
 * @param fromList the fromList value.
 */
	public void setFromList(final String fromList) {
		this.fromList = fromList;
	}

/**
 * withFromList operation.
 * @param newFromList the newFromList value.
 * @return the resulting value.
 */
	public AuthorizedKey withFromList(final String newFromList) {
		setFromList(newFromList);
		return this;
	}

/**
 * isNoAgentForwarding operation.
 * @return the resulting value.
 */
	public boolean isNoAgentForwarding() {
		return noAgentForwarding;
	}

/**
 * setNoAgentForwarding operation.
 * @param noAgentForwarding the noAgentForwarding value.
 */
	public void setNoAgentForwarding(final boolean noAgentForwarding) {
		this.noAgentForwarding = noAgentForwarding;
	}

/**
 * withNoAgentForwarding operation.
 * @param newNoAgentForwarding the newNoAgentForwarding value.
 * @return the resulting value.
 */
	public AuthorizedKey withNoAgentForwarding(final boolean newNoAgentForwarding) {
		setNoAgentForwarding(newNoAgentForwarding);
		return this;
	}

/**
 * isNoPortForwarding operation.
 * @return the resulting value.
 */
	public boolean isNoPortForwarding() {
		return noPortForwarding;
	}

/**
 * setNoPortForwarding operation.
 * @param noPortForwarding the noPortForwarding value.
 */
	public void setNoPortForwarding(final boolean noPortForwarding) {
		this.noPortForwarding = noPortForwarding;
	}

/**
 * withNoPortForwarding operation.
 * @param newNoPortForwarding the newNoPortForwarding value.
 * @return the resulting value.
 */
	public AuthorizedKey withNoPortForwarding(final boolean newNoPortForwarding) {
		setNoPortForwarding(newNoPortForwarding);
		return this;
	}

/**
 * isNoPty operation.
 * @return the resulting value.
 */
	public boolean isNoPty() {
		return noPty;
	}

/**
 * setNoPty operation.
 * @param noPty the noPty value.
 */
	public void setNoPty(final boolean noPty) {
		this.noPty = noPty;
	}

/**
 * withNoPty operation.
 * @param newNoPty the newNoPty value.
 * @return the resulting value.
 */
	public AuthorizedKey withNoPty(final boolean newNoPty) {
		setNoPty(newNoPty);
		return this;
	}

/**
 * isNoUserRc operation.
 * @return the resulting value.
 */
	public boolean isNoUserRc() {
		return noUserRc;
	}

/**
 * setNoUserRc operation.
 * @param noUserRc the noUserRc value.
 */
	public void setNoUserRc(final boolean noUserRc) {
		this.noUserRc = noUserRc;
	}

/**
 * withNoUserRc operation.
 * @param newNoUserRc the newNoUserRc value.
 * @return the resulting value.
 */
	public AuthorizedKey withNoUserRc(final boolean newNoUserRc) {
		setNoUserRc(newNoUserRc);
		return this;
	}

/**
 * isNoX11Forwarding operation.
 * @return the resulting value.
 */
	public boolean isNoX11Forwarding() {
		return noX11Forwarding;
	}

/**
 * setNoX11Forwarding operation.
 * @param noX11Forwarding the noX11Forwarding value.
 */
	public void setNoX11Forwarding(final boolean noX11Forwarding) {
		this.noX11Forwarding = noX11Forwarding;
	}

/**
 * withNoX11Forwarding operation.
 * @param newNoX11Forwarding the newNoX11Forwarding value.
 * @return the resulting value.
 */
	public AuthorizedKey withNoX11Forwarding(final boolean newNoX11Forwarding) {
		setNoX11Forwarding(newNoX11Forwarding);
		return this;
	}

/**
 * getPermitOpen operation.
 * @return the resulting value.
 */
	public String getPermitOpen() {
		return permitOpen;
	}

/**
 * setPermitOpen operation.
 * @param permitOpen the permitOpen value.
 */
	public void setPermitOpen(final String permitOpen) {
		this.permitOpen = permitOpen;
	}

/**
 * withPermitOpen operation.
 * @param newPermitOpen the newPermitOpen value.
 * @return the resulting value.
 */
	public AuthorizedKey withPermitOpen(final String newPermitOpen) {
		setPermitOpen(newPermitOpen);
		return this;
	}

/**
 * getPrincipals operation.
 * @return the resulting value.
 */
	public String getPrincipals() {
		return principals;
	}

/**
 * setPrincipals operation.
 * @param principals the principals value.
 */
	public void setPrincipals(final String principals) {
		this.principals = principals;
	}

/**
 * withPrincipals operation.
 * @param newPrincipals the newPrincipals value.
 * @return the resulting value.
 */
	public AuthorizedKey withPrincipals(final String newPrincipals) {
		setPrincipals(newPrincipals);
		return this;
	}

/**
 * getTunnel operation.
 * @return the resulting value.
 */
	public String getTunnel() {
		return tunnel;
	}

/**
 * setTunnel operation.
 * @param tunnel the tunnel value.
 */
	public void setTunnel(final String tunnel) {
		this.tunnel = tunnel;
	}

/**
 * withTunnel operation.
 * @param newTunnel the newTunnel value.
 * @return the resulting value.
 */
	public AuthorizedKey withTunnel(final String newTunnel) {
		setTunnel(newTunnel);
		return this;
	}
}
