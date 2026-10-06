package de.soderer.sshkeyformats;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.Reader;

/**
 * Line reader with a maximum line length, to protect against unbounded memory usage by input without line breaks
 * (Denial of Service protection).
 * <p>
 * Line breaks are LF, CR or CRLF like in {@link BufferedReader#readLine()}.
 */
final class LimitedLineReader implements Closeable {
	private final BufferedReader reader;
	private final int maxLineLength;
	private boolean skipNextLineFeed = false;

	/**
	 * Creates a line reader.
	 *
	 * @param reader the underlying reader
	 * @param maxLineLength the maximum number of characters per line (without line break)
	 */
	LimitedLineReader(final Reader reader, final int maxLineLength) {
		this.reader = new BufferedReader(reader);
		this.maxLineLength = maxLineLength;
	}

	/**
	 * Reads the next line.
	 *
	 * @return the next line without line break, or {@code null} at the end of the input
	 * @throws IOException if the line exceeds the maximum length or the input cannot be read
	 */
	String readLine() throws IOException {
		final StringBuilder line = new StringBuilder();
		boolean anyCharacterRead = false;
		int nextChar;
		while ((nextChar = reader.read()) != -1) {
			if (skipNextLineFeed) {
				skipNextLineFeed = false;
				if (nextChar == '\n') {
					// LF of a CRLF line break
					continue;
				}
			}
			anyCharacterRead = true;
			if (nextChar == '\n') {
				return line.toString();
			} else if (nextChar == '\r') {
				skipNextLineFeed = true;
				return line.toString();
			} else if (line.length() >= maxLineLength) {
				throw new IOException("Line exceeds maximum allowed length of " + maxLineLength + " characters");
			}
			line.append((char) nextChar);
		}
		return anyCharacterRead ? line.toString() : null;
	}

	@Override
	public void close() throws IOException {
		reader.close();
	}
}
