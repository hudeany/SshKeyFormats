package de.soderer.sshkeyformats.data;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Provides functionality for map string reader.
 */
public class MapStringReader extends BasicReader {
	private boolean useBlankAsSeparator = false;

	/**
	 * Creates a map reader using the default character encoding.
	 * @param inputStream the input stream
	 * @throws Exception if the operation cannot be completed
	 */
	public MapStringReader(final InputStream inputStream) throws Exception {
		super(inputStream, null);
	}

	/**
	 * Creates a map reader using the supplied character encoding.
	 * @param inputStream the input stream
	 * @param encodingCharset the encoding charset
	 * @throws Exception if the operation cannot be completed
	 */
	public MapStringReader(final InputStream inputStream, final Charset encodingCharset) throws Exception {
		super(inputStream, encodingCharset);
	}

	/**
	 * Returns whether  use blank as separator.
	 * @return true if the condition is met; otherwise false
	 */
	public boolean isUseBlankAsSeparator() {
		return useBlankAsSeparator;
	}

	/**
	 * Sets  use blank as separator.
	 * @param useBlankAsSeparator the use blank as separator
	 */
	public void setUseBlankAsSeparator(final boolean useBlankAsSeparator) {
		this.useBlankAsSeparator = useBlankAsSeparator;
	}

	/**
	 * Reads  map.
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public Map<String, String> readMap() throws Exception {
		final Map<String, String> returnMap = new LinkedHashMap<>();

		boolean inValue = false;

		StringBuilder nextKey = new StringBuilder();
		boolean keyWasQuoted = false;
		StringBuilder nextValue = new StringBuilder();
		boolean valueWasQuoted = false;

		Character currentChar = readNextNonWhitespace();
		while (currentChar != null) {
			switch (currentChar) {
				case ' ':
					if (useBlankAsSeparator) {
						if (nextKey.length() > 0 || nextValue.length() > 0) {
							returnMap.put(nextKey.toString(), nextValue.toString());
							inValue = false;
							nextKey = new StringBuilder();
							keyWasQuoted = false;
							nextValue = new StringBuilder();
							valueWasQuoted = false;
						}
						currentChar = readNextNonWhitespace();
						break;
					} else {
						// Item content, maybe quoted
						if (inValue) {
							if (!valueWasQuoted) {
								nextValue.append(currentChar);
							}
						} else {
							if (!keyWasQuoted) {
								nextKey.append(currentChar);
							}
						}
						currentChar = readNextCharacter();
						break;
					}
				case ',':
				case ';':
				case '\n':
				case '\r':
				case '\t':
					if (nextKey.length() > 0 || nextValue.length() > 0) {
						returnMap.put(keyWasQuoted ? nextKey.toString() : nextKey.toString().trim(),
								valueWasQuoted ? nextValue.toString() : nextValue.toString().trim());
						inValue = false;
						nextKey = new StringBuilder();
						keyWasQuoted = false;
						nextValue = new StringBuilder();
						valueWasQuoted = false;
					}
					currentChar = readNextNonWhitespace();
					break;
				case '\'':
				case '"':
					// Start quoted value
					final String quotedText = readQuotedText(currentChar, '\\');
					if (inValue) {
						nextValue = new StringBuilder(quotedText);
						valueWasQuoted = true;
					} else {
						nextKey = new StringBuilder(quotedText);
						keyWasQuoted = true;
					}
					currentChar = readNextCharacter();
					break;
				case '=':
					// Key value separator
					if (!inValue) {
						inValue = true;
					} else {
						nextValue.append(currentChar);
					}
					currentChar = readNextNonWhitespace();
					break;
				default:
					// Item content, maybe quoted
					if (inValue) {
						nextValue.append(currentChar);
					} else {
						nextKey.append(currentChar);
					}
					currentChar = readNextCharacter();
					break;
			}
		}

		if (inValue || nextKey.length() > 0) {
			returnMap.put(keyWasQuoted ? nextKey.toString() : nextKey.toString().trim(),
					valueWasQuoted ? nextValue.toString() : nextValue.toString().trim());
			inValue = false;
			nextKey = new StringBuilder();
			keyWasQuoted = false;
			nextValue = new StringBuilder();
			valueWasQuoted = false;
		}

		return returnMap;
	}

	/**
	 * Reads  map.
	 * @param mapString the map string
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public static Map<String, String> readMap(final String mapString) throws Exception {
		try (MapStringReader mapStringReader = new MapStringReader(new ByteArrayInputStream(mapString.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)) {
			return mapStringReader.readMap();
		}
	}

	/**
	 * Reads  map with blank as separator.
	 * @param mapString the map string
	 * @return the resulting value
	 * @throws Exception if the operation cannot be completed
	 */
	public static Map<String, String> readMapWithBlankAsSeparator(final String mapString) throws Exception {
		try (MapStringReader mapStringReader = new MapStringReader(new ByteArrayInputStream(mapString.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)) {
			mapStringReader.setUseBlankAsSeparator(true);
			return mapStringReader.readMap();
		}
	}
}
