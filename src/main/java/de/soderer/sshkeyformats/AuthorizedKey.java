package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

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
	private String permitListen;
	private String principals;
	private String tunnel;
	private String expiryTime;
	private boolean restrict;
	private boolean agentForwarding;
	private boolean portForwarding;
	private boolean pty;
	private boolean userRc;
	private boolean x11Forwarding;
	private boolean noTouchRequired;
	private boolean verifyRequired;

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
		if (environment == null) {
			environment = new LinkedHashMap<>();
		}
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
					if (sshKeys.isEmpty()) {
						throw new Exception("No public key data found in key string");
					}
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

	/**
	 * Creates the complete authorized_keys line in OpenSSH syntax including all options, key type, key data and comment.
	 * <p>
	 * In contrast to {@link #toString()} this keeps all restrictions (command, from, no-pty, ...) of this key.
	 *
	 * @return the authorized_keys line
	 */
	public String toAuthorizedKeysLine() {
		final List<String> options = new ArrayList<>();
		if (restrict) {
			options.add("restrict");
		}
		if (certAuthority) {
			options.add("cert-authority");
		}
		if (command != null) {
			options.add("command=" + quoteOptionValue(command));
		}
		if (environment != null) {
			for (final Entry<String, String> entry : environment.entrySet()) {
				options.add("environment=" + quoteOptionValue(entry.getKey() + "=" + (entry.getValue() == null ? "" : entry.getValue())));
			}
		}
		if (expiryTime != null) {
			options.add("expiry-time=" + quoteOptionValue(expiryTime));
		}
		if (fromList != null) {
			options.add("from=" + quoteOptionValue(fromList));
		}
		if (principals != null) {
			options.add("principals=" + quoteOptionValue(principals));
		}
		if (tunnel != null) {
			options.add("tunnel=" + quoteOptionValue(tunnel));
		}
		addMultiValueOption(options, "permitopen", permitOpen);
		addMultiValueOption(options, "permitlisten", permitListen);
		addFlag(options, noAgentForwarding, "no-agent-forwarding");
		addFlag(options, agentForwarding, "agent-forwarding");
		addFlag(options, noPortForwarding, "no-port-forwarding");
		addFlag(options, portForwarding, "port-forwarding");
		addFlag(options, noPty, "no-pty");
		addFlag(options, pty, "pty");
		addFlag(options, noUserRc, "no-user-rc");
		addFlag(options, userRc, "user-rc");
		addFlag(options, noX11Forwarding, "no-x11-forwarding");
		addFlag(options, x11Forwarding, "x11-forwarding");
		addFlag(options, noTouchRequired, "no-touch-required");
		addFlag(options, verifyRequired, "verify-required");

		final StringBuilder line = new StringBuilder();
		if (!options.isEmpty()) {
			line.append(String.join(",", options)).append(" ");
		}
		line.append(keyType.getSshAlgorithmId()).append(" ").append(keyString);
		if (getComment() != null && getComment().trim().length() > 0) {
			line.append(" ").append(getComment().trim());
		}
		return line.toString();
	}

	private static void addFlag(final List<String> options, final boolean flag, final String optionName) {
		if (flag) {
			options.add(optionName);
		}
	}

	private static void addMultiValueOption(final List<String> options, final String optionName, final String commaSeparatedValues) {
		if (commaSeparatedValues != null) {
			for (final String value : commaSeparatedValues.split(",")) {
				if (value.trim().length() > 0) {
					options.add(optionName + "=" + quoteOptionValue(value.trim()));
				}
			}
		}
	}

	private static String quoteOptionValue(final String value) {
		if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
			throw new IllegalArgumentException("Linebreaks are not allowed in authorized_keys option values");
		}
		return "\"" + value.replace("\"", "\\\"") + "\"";
	}

	/**
	 * Gets the allowed remote port forwarding listen addresses (option "permitlisten"), comma separated if multiple.
	 * @return the current value
	 */
	public String getPermitListen() {
		return permitListen;
	}

	/**
	 * Sets the value of PermitListen.
	 * @param permitListen the new value
	 */
	public void setPermitListen(final String permitListen) {
		this.permitListen = permitListen;
	}

	/**
	 * Sets the value of PermitListen and returns this object for chaining.
	 * @param newPermitListen the new value
	 * @return this object
	 */
	public AuthorizedKey withPermitListen(final String newPermitListen) {
		setPermitListen(newPermitListen);
		return this;
	}

	/**
	 * Gets the expiry time of this key (option "expiry-time", format YYYYMMDD[HHMM[SS]][Z]).
	 * @return the current value
	 */
	public String getExpiryTime() {
		return expiryTime;
	}

	/**
	 * Sets the value of ExpiryTime.
	 * @param expiryTime the new value
	 */
	public void setExpiryTime(final String expiryTime) {
		this.expiryTime = expiryTime;
	}

	/**
	 * Sets the value of ExpiryTime and returns this object for chaining.
	 * @param newExpiryTime the new value
	 * @return this object
	 */
	public AuthorizedKey withExpiryTime(final String newExpiryTime) {
		setExpiryTime(newExpiryTime);
		return this;
	}

	/**
	 * Gets whether all optional features are disabled (option "restrict").
	 * @return the current value
	 */
	public boolean isRestrict() {
		return restrict;
	}

	/**
	 * Sets the value of Restrict.
	 * @param restrict the new value
	 */
	public void setRestrict(final boolean restrict) {
		this.restrict = restrict;
	}

	/**
	 * Sets the value of Restrict and returns this object for chaining.
	 * @param newRestrict the new value
	 * @return this object
	 */
	public AuthorizedKey withRestrict(final boolean newRestrict) {
		setRestrict(newRestrict);
		return this;
	}

	/**
	 * Gets whether agent forwarding is explicitly enabled after "restrict" (option "agent-forwarding").
	 * @return the current value
	 */
	public boolean isAgentForwarding() {
		return agentForwarding;
	}

	/**
	 * Sets the value of AgentForwarding.
	 * @param agentForwarding the new value
	 */
	public void setAgentForwarding(final boolean agentForwarding) {
		this.agentForwarding = agentForwarding;
	}

	/**
	 * Sets the value of AgentForwarding and returns this object for chaining.
	 * @param newAgentForwarding the new value
	 * @return this object
	 */
	public AuthorizedKey withAgentForwarding(final boolean newAgentForwarding) {
		setAgentForwarding(newAgentForwarding);
		return this;
	}

	/**
	 * Gets whether port forwarding is explicitly enabled after "restrict" (option "port-forwarding").
	 * @return the current value
	 */
	public boolean isPortForwarding() {
		return portForwarding;
	}

	/**
	 * Sets the value of PortForwarding.
	 * @param portForwarding the new value
	 */
	public void setPortForwarding(final boolean portForwarding) {
		this.portForwarding = portForwarding;
	}

	/**
	 * Sets the value of PortForwarding and returns this object for chaining.
	 * @param newPortForwarding the new value
	 * @return this object
	 */
	public AuthorizedKey withPortForwarding(final boolean newPortForwarding) {
		setPortForwarding(newPortForwarding);
		return this;
	}

	/**
	 * Gets whether pty allocation is explicitly enabled after "restrict" (option "pty").
	 * @return the current value
	 */
	public boolean isPty() {
		return pty;
	}

	/**
	 * Sets the value of Pty.
	 * @param pty the new value
	 */
	public void setPty(final boolean pty) {
		this.pty = pty;
	}

	/**
	 * Sets the value of Pty and returns this object for chaining.
	 * @param newPty the new value
	 * @return this object
	 */
	public AuthorizedKey withPty(final boolean newPty) {
		setPty(newPty);
		return this;
	}

	/**
	 * Gets whether execution of ~/.ssh/rc is explicitly enabled after "restrict" (option "user-rc").
	 * @return the current value
	 */
	public boolean isUserRc() {
		return userRc;
	}

	/**
	 * Sets the value of UserRc.
	 * @param userRc the new value
	 */
	public void setUserRc(final boolean userRc) {
		this.userRc = userRc;
	}

	/**
	 * Sets the value of UserRc and returns this object for chaining.
	 * @param newUserRc the new value
	 * @return this object
	 */
	public AuthorizedKey withUserRc(final boolean newUserRc) {
		setUserRc(newUserRc);
		return this;
	}

	/**
	 * Gets whether X11 forwarding is explicitly enabled after "restrict" (option "x11-forwarding").
	 * @return the current value
	 */
	public boolean isX11Forwarding() {
		return x11Forwarding;
	}

	/**
	 * Sets the value of X11Forwarding.
	 * @param x11Forwarding the new value
	 */
	public void setX11Forwarding(final boolean x11Forwarding) {
		this.x11Forwarding = x11Forwarding;
	}

	/**
	 * Sets the value of X11Forwarding and returns this object for chaining.
	 * @param newX11Forwarding the new value
	 * @return this object
	 */
	public AuthorizedKey withX11Forwarding(final boolean newX11Forwarding) {
		setX11Forwarding(newX11Forwarding);
		return this;
	}

	/**
	 * Gets whether FIDO keys may be used without user presence (option "no-touch-required").
	 * @return the current value
	 */
	public boolean isNoTouchRequired() {
		return noTouchRequired;
	}

	/**
	 * Sets the value of NoTouchRequired.
	 * @param noTouchRequired the new value
	 */
	public void setNoTouchRequired(final boolean noTouchRequired) {
		this.noTouchRequired = noTouchRequired;
	}

	/**
	 * Sets the value of NoTouchRequired and returns this object for chaining.
	 * @param newNoTouchRequired the new value
	 * @return this object
	 */
	public AuthorizedKey withNoTouchRequired(final boolean newNoTouchRequired) {
		setNoTouchRequired(newNoTouchRequired);
		return this;
	}

	/**
	 * Gets whether FIDO keys require user verification (option "verify-required").
	 * @return the current value
	 */
	public boolean isVerifyRequired() {
		return verifyRequired;
	}

	/**
	 * Sets the value of VerifyRequired.
	 * @param verifyRequired the new value
	 */
	public void setVerifyRequired(final boolean verifyRequired) {
		this.verifyRequired = verifyRequired;
	}

	/**
	 * Sets the value of VerifyRequired and returns this object for chaining.
	 * @param newVerifyRequired the new value
	 * @return this object
	 */
	public AuthorizedKey withVerifyRequired(final boolean newVerifyRequired) {
		setVerifyRequired(newVerifyRequired);
		return this;
	}
}
