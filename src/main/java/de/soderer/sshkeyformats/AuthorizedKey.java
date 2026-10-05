package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import de.soderer.sshkeyformats.data.Algorithm;

/**
 * Provides functionality for authorized key.
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
	 * Creates an authorized-key representation for the supplied key type and encoded key data.
	 * @param type the type
	 * @param keyString the key string
	 * @throws Exception if the operation cannot be completed
	 */
	public AuthorizedKey(final Algorithm type, final String keyString) throws Exception {
		super(SshKeyFormat.OpenSSL, null, null);

		keyType = type;
		this.keyString = keyString;
	}

	/**
	 * Creates an authorized-key representation with the supplied comment.
	 * @param type the type
	 * @param keyString the key string
	 * @param comment the comment
	 * @throws Exception if the operation cannot be completed
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
	 * @return the environment map
	 */
	public Map<String, String> getEnvironment() {
		return environment;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @param environment
	 * @return this key with the supplied environment settings
	 */
	public void setEnvironment(final Map<String, String> environment) {
		this.environment = environment;
	}

	/**
	 * Returns this object with  environment set to the supplied value.
	 * @param newEnvironment the new environment
	 * @return the resulting value
	 */
	public AuthorizedKey withEnvironment(final Map<String, String> newEnvironment) {
		setEnvironment(newEnvironment);
		return this;
	}

	/**
	 * <b>Watchout:</b>
	 * "environment" settings need activated "PermitUserEnvironment" option in "/etc/ssh/sshd_config" file to take effect
	 *
	 * @param environmentKeyName
	 * @param environmentValue
	 * @return this key with the supplied environment value
	 */
	public void setEnvironmentValue(final String environmentKeyName, final String environmentValue) {
		environment.put(environmentKeyName, environmentValue);
	}

	/**
	 * Returns this object with  environment value set to the supplied value.
	 * @param newEnvironmentKeyName the new environment key name
	 * @param newEnvironmentValue the new environment value
	 * @return the resulting value
	 */
	public AuthorizedKey withEnvironmentValue(final String newEnvironmentKeyName, final String newEnvironmentValue) {
		setEnvironmentValue(newEnvironmentKeyName, newEnvironmentValue);
		return this;
	}

	/**
	 * Returns the key type.
	 * @return the resulting value
	 */
	public Algorithm getKeyType() {
		return keyType;
	}

	/**
	 * Returns the key string.
	 * @return the resulting value
	 */
	public String getKeyString() {
		return keyString;
	}

	@Override
	/**
	 * Converts the value to  string.
	 * @return the resulting value
	 */
	public String toString() {
		if (getComment() != null) {
			return keyType.getSshAlgorithmId() + " " + keyString + " " + getComment();
		} else {
			return keyType.getSshAlgorithmId() + " " + keyString;
		}
	}

	/**
	 * Returns the hash.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
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
	 * Returns the command.
	 * @return the resulting value
	 */
	public String getCommand() {
		return command;
	}

	/**
	 * Sets  command.
	 * @param command the command
	 */
	public void setCommand(final String command) {
		this.command = command;
	}

	/**
	 * Returns this object with  command set to the supplied value.
	 * @param newCommand the new command
	 * @return the resulting value
	 */
	public AuthorizedKey withCommand(final String newCommand) {
		setCommand(newCommand);
		return this;
	}

	/**
	 * Returns whether  cert authority.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isCertAuthority() {
		return certAuthority;
	}

	/**
	 * Sets  cert authority.
	 * @param certAuthority the cert authority
	 */
	public void setCertAuthority(final boolean certAuthority) {
		this.certAuthority = certAuthority;
	}

	/**
	 * Returns this object with  cert authority set to the supplied value.
	 * @param newCertAuthority the new cert authority
	 * @return the resulting value
	 */
	public AuthorizedKey withCertAuthority(final boolean newCertAuthority) {
		setCertAuthority(newCertAuthority);
		return this;
	}

	/**
	 * Returns the from list.
	 * @return the resulting value
	 */
	public String getFromList() {
		return fromList;
	}

	/**
	 * Sets  from list.
	 * @param fromList the from list
	 */
	public void setFromList(final String fromList) {
		this.fromList = fromList;
	}

	/**
	 * Returns this object with  from list set to the supplied value.
	 * @param newFromList the new from list
	 * @return the resulting value
	 */
	public AuthorizedKey withFromList(final String newFromList) {
		setFromList(newFromList);
		return this;
	}

	/**
	 * Returns whether  no agent forwarding.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isNoAgentForwarding() {
		return noAgentForwarding;
	}

	/**
	 * Sets  no agent forwarding.
	 * @param noAgentForwarding the no agent forwarding
	 */
	public void setNoAgentForwarding(final boolean noAgentForwarding) {
		this.noAgentForwarding = noAgentForwarding;
	}

	/**
	 * Returns this object with  no agent forwarding set to the supplied value.
	 * @param newNoAgentForwarding the new no agent forwarding
	 * @return the resulting value
	 */
	public AuthorizedKey withNoAgentForwarding(final boolean newNoAgentForwarding) {
		setNoAgentForwarding(newNoAgentForwarding);
		return this;
	}

	/**
	 * Returns whether  no port forwarding.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isNoPortForwarding() {
		return noPortForwarding;
	}

	/**
	 * Sets  no port forwarding.
	 * @param noPortForwarding the no port forwarding
	 */
	public void setNoPortForwarding(final boolean noPortForwarding) {
		this.noPortForwarding = noPortForwarding;
	}

	/**
	 * Returns this object with  no port forwarding set to the supplied value.
	 * @param newNoPortForwarding the new no port forwarding
	 * @return the resulting value
	 */
	public AuthorizedKey withNoPortForwarding(final boolean newNoPortForwarding) {
		setNoPortForwarding(newNoPortForwarding);
		return this;
	}

	/**
	 * Returns whether  no pty.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isNoPty() {
		return noPty;
	}

	/**
	 * Sets  no pty.
	 * @param noPty the no pty
	 */
	public void setNoPty(final boolean noPty) {
		this.noPty = noPty;
	}

	/**
	 * Returns this object with  no pty set to the supplied value.
	 * @param newNoPty the new no pty
	 * @return the resulting value
	 */
	public AuthorizedKey withNoPty(final boolean newNoPty) {
		setNoPty(newNoPty);
		return this;
	}

	/**
	 * Returns whether  no user rc.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isNoUserRc() {
		return noUserRc;
	}

	/**
	 * Sets  no user rc.
	 * @param noUserRc the no user rc
	 */
	public void setNoUserRc(final boolean noUserRc) {
		this.noUserRc = noUserRc;
	}

	/**
	 * Returns this object with  no user rc set to the supplied value.
	 * @param newNoUserRc the new no user rc
	 * @return the resulting value
	 */
	public AuthorizedKey withNoUserRc(final boolean newNoUserRc) {
		setNoUserRc(newNoUserRc);
		return this;
	}

	/**
	 * Returns whether  no x11 forwarding.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isNoX11Forwarding() {
		return noX11Forwarding;
	}

	/**
	 * Sets  no x11 forwarding.
	 * @param noX11Forwarding the no x11 forwarding
	 */
	public void setNoX11Forwarding(final boolean noX11Forwarding) {
		this.noX11Forwarding = noX11Forwarding;
	}

	/**
	 * Returns this object with  no x11 forwarding set to the supplied value.
	 * @param newNoX11Forwarding the new no x11 forwarding
	 * @return the resulting value
	 */
	public AuthorizedKey withNoX11Forwarding(final boolean newNoX11Forwarding) {
		setNoX11Forwarding(newNoX11Forwarding);
		return this;
	}

	/**
	 * Returns the permit open.
	 * @return the resulting value
	 */
	public String getPermitOpen() {
		return permitOpen;
	}

	/**
	 * Sets  permit open.
	 * @param permitOpen the permit open
	 */
	public void setPermitOpen(final String permitOpen) {
		this.permitOpen = permitOpen;
	}

	/**
	 * Returns this object with  permit open set to the supplied value.
	 * @param newPermitOpen the new permit open
	 * @return the resulting value
	 */
	public AuthorizedKey withPermitOpen(final String newPermitOpen) {
		setPermitOpen(newPermitOpen);
		return this;
	}

	/**
	 * Returns the principals.
	 * @return the resulting value
	 */
	public String getPrincipals() {
		return principals;
	}

	/**
	 * Sets  principals.
	 * @param principals the principals
	 */
	public void setPrincipals(final String principals) {
		this.principals = principals;
	}

	/**
	 * Returns this object with  principals set to the supplied value.
	 * @param newPrincipals the new principals
	 * @return the resulting value
	 */
	public AuthorizedKey withPrincipals(final String newPrincipals) {
		setPrincipals(newPrincipals);
		return this;
	}

	/**
	 * Returns the tunnel.
	 * @return the resulting value
	 */
	public String getTunnel() {
		return tunnel;
	}

	/**
	 * Sets  tunnel.
	 * @param tunnel the tunnel
	 */
	public void setTunnel(final String tunnel) {
		this.tunnel = tunnel;
	}

	/**
	 * Returns this object with  tunnel set to the supplied value.
	 * @param newTunnel the new tunnel
	 * @return the resulting value
	 */
	public AuthorizedKey withTunnel(final String newTunnel) {
		setTunnel(newTunnel);
		return this;
	}
}
