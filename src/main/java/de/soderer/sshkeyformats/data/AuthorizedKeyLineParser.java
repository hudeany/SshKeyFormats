package de.soderer.sshkeyformats.data;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import de.soderer.sshkeyformats.AuthorizedKey;

/**
 * Parser for single lines of an OpenSSH "authorized_keys" file.
 * <p>
 * Syntax as specified in sshd(8), section "AUTHORIZED_KEYS FILE FORMAT":
 * <pre>[options] keytype base64-key [comment]</pre>
 * Options are comma separated without any whitespace except within double quotes.
 * Within double quotes a double quote character may be escaped by a backslash.
 * Option names are case insensitive. Unknown options are rejected, like sshd does.
 */
public class AuthorizedKeyLineParser {
	private static final String OPTION_AGENT_FORWARDING = "agent-forwarding";
	private static final String OPTION_CERT_AUTHORITY = "cert-authority";
	private static final String OPTION_COMMAND = "command";
	private static final String OPTION_ENVIRONMENT = "environment";
	private static final String OPTION_EXPIRY_TIME = "expiry-time";
	private static final String OPTION_FROM = "from";
	private static final String OPTION_NO_AGENT_FORWARDING = "no-agent-forwarding";
	private static final String OPTION_NO_PORT_FORWARDING = "no-port-forwarding";
	private static final String OPTION_NO_PTY = "no-pty";
	private static final String OPTION_NO_TOUCH_REQUIRED = "no-touch-required";
	private static final String OPTION_NO_USER_RC = "no-user-rc";
	private static final String OPTION_NO_X11_FORWARDING = "no-x11-forwarding";
	private static final String OPTION_PERMITLISTEN = "permitlisten";
	private static final String OPTION_PERMITOPEN = "permitopen";
	private static final String OPTION_PORT_FORWARDING = "port-forwarding";
	private static final String OPTION_PRINCIPALS = "principals";
	private static final String OPTION_PTY = "pty";
	private static final String OPTION_RESTRICT = "restrict";
	private static final String OPTION_TUNNEL = "tunnel";
	private static final String OPTION_USER_RC = "user-rc";
	private static final String OPTION_VERIFY_REQUIRED = "verify-required";
	private static final String OPTION_X11_FORWARDING = "x11-forwarding";

	private AuthorizedKeyLineParser() {
		// do nothing
	}

	/**
	 * Parses a single authorized_keys line.
	 *
	 * @param authorizedKeyLine the line to parse
	 * @return the parsed authorized key
	 * @throws AuthorizedKeyException if the line is not a valid authorized_keys line
	 */
	public static AuthorizedKey parseAuthorizedKeyLine(final String authorizedKeyLine) throws AuthorizedKeyException {
		if (authorizedKeyLine == null) {
			throw new AuthorizedKeyException("Invalid empty authorized key line", null);
		}
		try {
			final String line = authorizedKeyLine.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				throw new Exception("Line contains no key data");
			}

			int index = 0;
			String optionsString = null;
			String firstToken = readUnquotedToken(line, index);
			if (!isKnownKeyType(firstToken)) {
				// The first field contains the options, which may contain whitespace within double quotes
				final int optionsEnd = findOptionsEnd(line);
				optionsString = line.substring(0, optionsEnd);
				index = skipWhitespace(line, optionsEnd);
				firstToken = readUnquotedToken(line, index);
			}

			final Algorithm keyType;
			try {
				keyType = Algorithm.getForSshAlgorithmId(firstToken);
			} catch (final Exception e) {
				throw new Exception("Unknown or unsupported key type '" + firstToken + "'", e);
			}
			index = skipWhitespace(line, index + firstToken.length());

			final String key = readUnquotedToken(line, index);
			if (key.isEmpty()) {
				throw new Exception("Missing key data");
			}
			try {
				Base64.getDecoder().decode(key);
			} catch (final Exception e) {
				throw new AuthorizedKeyException("Invalid key data (not base64) in line '" + authorizedKeyLine + "'", e);
			}
			index = skipWhitespace(line, index + key.length());

			String comment = line.substring(index).trim();
			if (comment.isEmpty()) {
				comment = null;
			}

			final AuthorizedKey authorizedKey = new AuthorizedKey(keyType, key, comment);
			if (optionsString != null) {
				applyOptions(authorizedKey, optionsString);
			}
			return authorizedKey;
		} catch (final AuthorizedKeyException e) {
			throw e;
		} catch (final Exception e) {
			throw new AuthorizedKeyException("Unsupported authorized key format in line '" + authorizedKeyLine + "': " + e.getMessage(), e);
		}
	}

	private static void applyOptions(final AuthorizedKey authorizedKey, final String optionsString) throws Exception {
		Map<String, String> environment = null;
		final List<String> permitOpenValues = new ArrayList<>();
		final List<String> permitListenValues = new ArrayList<>();

		for (final String option : splitOptions(optionsString)) {
			final int equalsIndex = option.indexOf('=');
			final String optionName = (equalsIndex < 0 ? option : option.substring(0, equalsIndex)).toLowerCase(Locale.ROOT);
			final String optionValue = equalsIndex < 0 ? null : dequote(option.substring(equalsIndex + 1), optionName);

			switch (optionName) {
				case OPTION_RESTRICT:
					requireNoValue(optionName, optionValue);
					authorizedKey.setRestrict(true);
					break;
				case OPTION_CERT_AUTHORITY:
					requireNoValue(optionName, optionValue);
					authorizedKey.setCertAuthority(true);
					break;
				case OPTION_NO_AGENT_FORWARDING:
					requireNoValue(optionName, optionValue);
					authorizedKey.setNoAgentForwarding(true);
					break;
				case OPTION_AGENT_FORWARDING:
					requireNoValue(optionName, optionValue);
					authorizedKey.setAgentForwarding(true);
					break;
				case OPTION_NO_PORT_FORWARDING:
					requireNoValue(optionName, optionValue);
					authorizedKey.setNoPortForwarding(true);
					break;
				case OPTION_PORT_FORWARDING:
					requireNoValue(optionName, optionValue);
					authorizedKey.setPortForwarding(true);
					break;
				case OPTION_NO_PTY:
					requireNoValue(optionName, optionValue);
					authorizedKey.setNoPty(true);
					break;
				case OPTION_PTY:
					requireNoValue(optionName, optionValue);
					authorizedKey.setPty(true);
					break;
				case OPTION_NO_USER_RC:
					requireNoValue(optionName, optionValue);
					authorizedKey.setNoUserRc(true);
					break;
				case OPTION_USER_RC:
					requireNoValue(optionName, optionValue);
					authorizedKey.setUserRc(true);
					break;
				case OPTION_NO_X11_FORWARDING:
					requireNoValue(optionName, optionValue);
					authorizedKey.setNoX11Forwarding(true);
					break;
				case OPTION_X11_FORWARDING:
					requireNoValue(optionName, optionValue);
					authorizedKey.setX11Forwarding(true);
					break;
				case OPTION_NO_TOUCH_REQUIRED:
					requireNoValue(optionName, optionValue);
					authorizedKey.setNoTouchRequired(true);
					break;
				case OPTION_VERIFY_REQUIRED:
					requireNoValue(optionName, optionValue);
					authorizedKey.setVerifyRequired(true);
					break;
				case OPTION_COMMAND:
					requireSingleValue(optionName, optionValue, authorizedKey.getCommand());
					authorizedKey.setCommand(optionValue);
					break;
				case OPTION_FROM:
					requireSingleValue(optionName, optionValue, authorizedKey.getFromList());
					authorizedKey.setFromList(optionValue);
					break;
				case OPTION_PRINCIPALS:
					requireSingleValue(optionName, optionValue, authorizedKey.getPrincipals());
					authorizedKey.setPrincipals(optionValue);
					break;
				case OPTION_TUNNEL:
					requireSingleValue(optionName, optionValue, authorizedKey.getTunnel());
					authorizedKey.setTunnel(optionValue);
					break;
				case OPTION_EXPIRY_TIME:
					requireSingleValue(optionName, optionValue, authorizedKey.getExpiryTime());
					authorizedKey.setExpiryTime(optionValue);
					break;
				case OPTION_PERMITOPEN:
					requireValue(optionName, optionValue);
					permitOpenValues.add(optionValue);
					break;
				case OPTION_PERMITLISTEN:
					requireValue(optionName, optionValue);
					permitListenValues.add(optionValue);
					break;
				case OPTION_ENVIRONMENT:
					final String environmentValue = requireValue(optionName, optionValue);
					final int nameEnd = environmentValue.indexOf('=');
					if (nameEnd <= 0) {
						throw new Exception("Invalid environment option value '" + environmentValue + "' (expected NAME=value)");
					}
					final String name = environmentValue.substring(0, nameEnd);
					for (final char nameChar : name.toCharArray()) {
						if (!Character.isLetterOrDigit(nameChar) && nameChar != '_') {
							throw new Exception("Invalid environment variable name '" + name + "'");
						}
					}
					if (environment == null) {
						environment = new LinkedHashMap<>();
					}
					// Like sshd: only the first value of a variable is used
					environment.putIfAbsent(name, environmentValue.substring(nameEnd + 1));
					break;
				default:
					throw new Exception("Unknown authorized_keys option '" + optionName + "'");
			}
		}

		authorizedKey.setEnvironment(environment);
		if (!permitOpenValues.isEmpty()) {
			authorizedKey.setPermitOpen(String.join(",", permitOpenValues));
		}
		if (!permitListenValues.isEmpty()) {
			authorizedKey.setPermitListen(String.join(",", permitListenValues));
		}
	}

	private static void requireNoValue(final String optionName, final String optionValue) throws Exception {
		if (optionValue != null) {
			throw new Exception("Option '" + optionName + "' does not take a value");
		}
	}

	private static String requireValue(final String optionName, final String optionValue) throws Exception {
		if (optionValue == null) {
			throw new Exception("Option '" + optionName + "' requires a value");
		}
		return optionValue;
	}

	private static void requireSingleValue(final String optionName, final String optionValue, final String existingValue) throws Exception {
		requireValue(optionName, optionValue);
		if (existingValue != null) {
			throw new Exception("Option '" + optionName + "' is set multiple times");
		}
	}

	/**
	 * Splits the options field at commas outside of double quotes.
	 */
	private static List<String> splitOptions(final String optionsString) throws Exception {
		final List<String> options = new ArrayList<>();
		final StringBuilder current = new StringBuilder();
		boolean inQuotes = false;
		for (int i = 0; i < optionsString.length(); i++) {
			final char nextChar = optionsString.charAt(i);
			if (inQuotes && nextChar == '\\' && i + 1 < optionsString.length() && optionsString.charAt(i + 1) == '"') {
				current.append(nextChar).append('"');
				i++;
			} else if (nextChar == '"') {
				inQuotes = !inQuotes;
				current.append(nextChar);
			} else if (nextChar == ',' && !inQuotes) {
				if (current.length() == 0) {
					throw new Exception("Empty option found");
				}
				options.add(current.toString());
				current.setLength(0);
			} else {
				current.append(nextChar);
			}
		}
		if (inQuotes) {
			throw new Exception("Missing closing quote character (\")");
		} else if (current.length() == 0) {
			throw new Exception("Empty option found");
		}
		options.add(current.toString());
		return options;
	}

	/**
	 * Removes the enclosing double quotes of an option value and resolves escaped double quotes.
	 */
	private static String dequote(final String quotedValue, final String optionName) throws Exception {
		if (quotedValue.length() < 2 || quotedValue.charAt(0) != '"' || quotedValue.charAt(quotedValue.length() - 1) != '"') {
			throw new Exception("Value of option '" + optionName + "' must be enclosed in double quotes");
		}
		final String innerValue = quotedValue.substring(1, quotedValue.length() - 1);
		final StringBuilder value = new StringBuilder();
		for (int i = 0; i < innerValue.length(); i++) {
			final char nextChar = innerValue.charAt(i);
			if (nextChar == '\\' && i + 1 < innerValue.length() && innerValue.charAt(i + 1) == '"') {
				value.append('"');
				i++;
			} else if (nextChar == '"') {
				throw new Exception("Unescaped quote character within value of option '" + optionName + "'");
			} else {
				value.append(nextChar);
			}
		}
		return value.toString();
	}

	/**
	 * Finds the end of the options field, which is the first whitespace outside of double quotes.
	 */
	private static int findOptionsEnd(final String line) throws Exception {
		boolean inQuotes = false;
		for (int i = 0; i < line.length(); i++) {
			final char nextChar = line.charAt(i);
			if (inQuotes && nextChar == '\\' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
				i++;
			} else if (nextChar == '"') {
				inQuotes = !inQuotes;
			} else if (!inQuotes && Character.isWhitespace(nextChar)) {
				return i;
			}
		}
		if (inQuotes) {
			throw new Exception("Missing closing quote character (\")");
		}
		throw new Exception("Missing key data after options");
	}

	private static String readUnquotedToken(final String line, final int startIndex) {
		int endIndex = startIndex;
		while (endIndex < line.length() && !Character.isWhitespace(line.charAt(endIndex))) {
			endIndex++;
		}
		return line.substring(startIndex, endIndex);
	}

	private static int skipWhitespace(final String line, int index) {
		while (index < line.length() && Character.isWhitespace(line.charAt(index))) {
			index++;
		}
		return index;
	}

	private static boolean isKnownKeyType(final String token) {
		for (final Algorithm algorithm : Algorithm.values()) {
			if (algorithm.getSshAlgorithmId().equals(token)) {
				return true;
			}
		}
		return false;
	}
}
