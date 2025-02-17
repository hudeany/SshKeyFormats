package de.soderer.sshkeyformats.data;

import java.util.Base64;
import java.util.Map;

import de.soderer.sshkeyformats.AuthorizedKey;

public class AuthorizedKeyLineParser {
	private static String COMMAND_PREFIX = "command=";
	private static String ENVIRONMENT_PREFIX = "environment=";
	private static String CERT_AUTHORITY_TOKEN = "cert-authority";
	private static String FROM_PREFIX = "from=";
	private static String NO_AGENT_FORWARDING_TOKEN = "no-agent-forwarding";
	private static String NO_PORT_FORWARDING_TOKEN = "no-port-forwarding";
	private static String NO_PTY_TOKEN = "no-pty";
	private static String NO_USER_RC_TOKEN = "no-user-rc";
	private static String NO_X11_FORWARDING_TOKEN = "no-x11-forwarding";
	private static String PERMITOPEN_PREFIX = "permitopen=";
	private static String PRINCIPALS_PREFIX = "principals=";
	private static String TUNNEL_PREFIX = "tunnel=";

	private char[] currentLineTextArray;
	private int currentLineReadIndex;

	public AuthorizedKey parseAuthorizedKeyLine(final String authorizedKeyLine) throws Exception {
		try {
			currentLineTextArray = authorizedKeyLine.trim().toCharArray();
			currentLineReadIndex = 0;

			String command = null;
			String fromList = null;
			String permitOpen = null;
			String principals = null;
			String tunnel = null;

			boolean certAuthority = false;
			boolean noAgentForwarding = false;
			boolean noPortForwarding = false;
			boolean noPty = false;
			boolean noUserRc = false;
			boolean noX11Forwarding = false;

			Map<String, String> environment = null;

			while (true) {
				// Skip whitespace characters
				while (currentLineReadIndex < currentLineTextArray.length && Character.isWhitespace(currentLineTextArray[currentLineReadIndex])) {
					currentLineReadIndex++;
				}

				if (authorizedKeyLine.startsWith(COMMAND_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += COMMAND_PREFIX.length();
					command = getNextStringBlock();
				} else if (authorizedKeyLine.startsWith(ENVIRONMENT_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += ENVIRONMENT_PREFIX.length();
					final String environmentBlock = getNextStringBlock();
					Map<String, String> nextEnvironment = MapStringReader.readMap(environmentBlock);
					if (nextEnvironment.size() == 0) {
						nextEnvironment = null;
					} else {
						if (environment == null) {
							environment = nextEnvironment;
						} else {
							environment.putAll(nextEnvironment);
						}
					}
				} else if (authorizedKeyLine.startsWith(FROM_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += FROM_PREFIX.length();
					fromList = getNextStringBlock();
				} else if (authorizedKeyLine.startsWith(PERMITOPEN_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += PERMITOPEN_PREFIX.length();
					permitOpen = getNextStringBlock();
				} else if (authorizedKeyLine.startsWith(PRINCIPALS_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += PRINCIPALS_PREFIX.length();
					principals = getNextStringBlock();
				} else if (authorizedKeyLine.startsWith(TUNNEL_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += TUNNEL_PREFIX.length();
					tunnel = getNextStringBlock();
				} else if (authorizedKeyLine.startsWith(CERT_AUTHORITY_TOKEN, currentLineReadIndex)) {
					currentLineReadIndex += CERT_AUTHORITY_TOKEN.length();
					certAuthority = true;
				} else if (authorizedKeyLine.startsWith(NO_AGENT_FORWARDING_TOKEN, currentLineReadIndex)) {
					currentLineReadIndex += NO_AGENT_FORWARDING_TOKEN.length();
					noAgentForwarding = true;
				} else if (authorizedKeyLine.startsWith(NO_PORT_FORWARDING_TOKEN, currentLineReadIndex)) {
					currentLineReadIndex += NO_PORT_FORWARDING_TOKEN.length();
					noPortForwarding = true;
				} else if (authorizedKeyLine.startsWith(NO_PTY_TOKEN, currentLineReadIndex)) {
					currentLineReadIndex += NO_PTY_TOKEN.length();
					noPty = true;
				} else if (authorizedKeyLine.startsWith(NO_USER_RC_TOKEN, currentLineReadIndex)) {
					currentLineReadIndex += NO_USER_RC_TOKEN.length();
					noUserRc = true;
				} else if (authorizedKeyLine.startsWith(NO_X11_FORWARDING_TOKEN, currentLineReadIndex)) {
					currentLineReadIndex += NO_X11_FORWARDING_TOKEN.length();
					noX11Forwarding = true;
				} else {
					break;
				}
			}

			final String keyTypeString = getNextStringBlock();
			final Algorithm keyType = Algorithm.getForSshAlgorithmId(keyTypeString);

			final String key = getNextStringBlock();
			try {
				Base64.getDecoder().decode(key);
			} catch (final Exception e) {
				throw new AuthorizedKeyException("Invalid key data (not base64) in line '" + authorizedKeyLine + "'", e);
			}

			String comment = authorizedKeyLine.substring(currentLineReadIndex).trim();
			if (isBlank(comment)) {
				comment = null;
			}

			final AuthorizedKey authorizedKey = new AuthorizedKey(keyType, key, comment);
			authorizedKey.setCommand(command);
			authorizedKey.setEnvironment(environment);
			authorizedKey.setFromList(fromList);
			authorizedKey.setPermitOpen(permitOpen);
			authorizedKey.setPrincipals(principals);
			authorizedKey.setTunnel(tunnel);

			authorizedKey.setCertAuthority(certAuthority);
			authorizedKey.setNoAgentForwarding(noAgentForwarding);
			authorizedKey.setNoPortForwarding(noPortForwarding);
			authorizedKey.setNoPty(noPty);
			authorizedKey.setNoUserRc(noUserRc);
			authorizedKey.setNoX11Forwarding(noX11Forwarding);

			return authorizedKey;
		} catch (final AuthorizedKeyException e) {
			throw e;
		} catch (final Exception e) {
			throw new AuthorizedKeyException("Unsupported authorized key format in line '" + authorizedKeyLine + "'", e);
		}
	}

	private String getNextStringBlock() throws Exception {
		// Skip whitespace characters
		while (currentLineReadIndex < currentLineTextArray.length && Character.isWhitespace(currentLineTextArray[currentLineReadIndex])) {
			currentLineReadIndex++;
		}

		if (currentLineTextArray.length <= currentLineReadIndex) {
			return "";
		} else {
			final StringBuilder block = new StringBuilder();
			if (currentLineTextArray[currentLineReadIndex] == '"') {
				currentLineReadIndex++;
				while (currentLineReadIndex < currentLineTextArray.length) {
					final char nextChar = currentLineTextArray[currentLineReadIndex];
					currentLineReadIndex++;
					if (nextChar == '"' && block.charAt(block.length() - 1) != '\\') {
						if (currentLineTextArray[currentLineReadIndex] == ' ') {
							currentLineReadIndex++;
						}
						return block.toString().replace("\\\"", "\"");
					} else {
						block.append(nextChar);
					}
				}
				throw new Exception("Missing closing quote character (\")");
			} else if (currentLineTextArray[currentLineReadIndex] == '\'') {
				currentLineReadIndex++;
				while (currentLineReadIndex < currentLineTextArray.length) {
					final char nextChar = currentLineTextArray[currentLineReadIndex];
					currentLineReadIndex++;
					if (nextChar == '\'' && block.charAt(block.length() - 1) != '\\') {
						if (currentLineTextArray[currentLineReadIndex] == ' ') {
							currentLineReadIndex++;
						}
						return block.toString().replace("\\'", "'");
					} else {
						block.append(nextChar);
					}
				}
				throw new Exception("Missing closing quote character (')");
			} else {
				while (currentLineReadIndex < currentLineTextArray.length) {
					final char nextChar = currentLineTextArray[currentLineReadIndex];
					currentLineReadIndex++;
					if (nextChar == ' ') {
						break;
					} else {
						block.append(nextChar);
					}
				}
				return block.toString().replace("\\'", "'").replace("\\\"", "\"");
			}
		}
	}

	private static boolean isBlank(final String value) {
		return value == null || value.length() == 0 || value.trim().length() == 0;
	}
}
