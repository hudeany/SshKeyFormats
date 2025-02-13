package de.soderer.sshkeyformats.data;

import java.util.Base64;
import java.util.Map;

import de.soderer.sshkeyformats.data.AuthorizedKey.AuthorizedKeyType;

public class AuthorizedKeyLineParser {
	private static String COMMAND_PREFIX = "command=";
	private static String ENVIRONMENT_PREFIX = "environment=";

	private char[] currentLineTextArray;
	private int currentLineReadIndex;

	public AuthorizedKey parseAuthorizedKeyLine(final String authorizedKeyLine) throws Exception {
		try {
			currentLineTextArray = authorizedKeyLine.trim().toCharArray();
			currentLineReadIndex = 0;

			@SuppressWarnings("unused")
			String commandBlock = null;

			Map<String, String> environment = null;

			while (true) {
				if (authorizedKeyLine.startsWith(COMMAND_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += COMMAND_PREFIX.length();
					commandBlock = getNextStringBlock();
				} else if (authorizedKeyLine.startsWith(ENVIRONMENT_PREFIX, currentLineReadIndex)) {
					currentLineReadIndex += ENVIRONMENT_PREFIX.length();
					final String environmentBlock = getNextStringBlock();
					environment = MapStringReader.readMap(environmentBlock);
					if (environment.size() == 0) {
						environment = null;
					}
				} else {
					break;
				}
			}

			final String keyTypeString = getNextStringBlock();
			final AuthorizedKeyType keyType = AuthorizedKeyType.getTypeFromText(keyTypeString);

			final String key = getNextStringBlock();
			try {
				Base64.getDecoder().decode(key);
			} catch (final Exception e) {
				throw new AuthorizedKeyException("Invalid key data (not base64) in line '" + authorizedKeyLine + "'", e);
			}

			String comment = authorizedKeyLine.substring(currentLineReadIndex);
			if (isBlank(comment)) {
				comment = null;
			}

			return new AuthorizedKey(environment, keyType, key, comment);
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
