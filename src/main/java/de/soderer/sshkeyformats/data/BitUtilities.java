package de.soderer.sshkeyformats.data;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Helper methods for bit, byte and hexadecimal conversions as well as XOR and padding operations on byte arrays.
 * <p>
 * Hexadecimal input is only accepted with the ASCII digits 0-9, a-f and A-F. Other Unicode digits (like fullwidth
 * or Arabic-Indic digits) are rejected.
 * </p>
 */
public class BitUtilities {
	private static final Pattern BITSTRINGPATTERN_BYTE = Pattern.compile("^[10]{1,8}$");
	private static final Pattern BITSTRINGPATTERN_INTEGER = Pattern.compile("^[10]{1,32}$");
	private static final char[] HEX_CHARS_UPPERCASE = "0123456789ABCDEF".toCharArray();

	/** Prefix "0x" not directly following a hex digit, so a separator like 'x' in "10x20" is not taken as prefix. */
	private static final Pattern HEX_PREFIX_PATTERN = Pattern.compile("(?<![0-9a-fA-F])0[xX]");

	/** All characters which are no ASCII hex digits. */
	private static final Pattern NON_HEX_CHARACTER_PATTERN = Pattern.compile("[^0-9a-fA-F]");

	/** Shared random source, SecureRandom is thread safe and creating new instances is expensive. */
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private BitUtilities() {
		// Utility class, no instances
	}

	/**
	 * Returns values from 0 to 255 (value range of byte)
	 *
	 * @param value the signed byte value to interpret as unsigned
	 * @return the value in the range 0 to 255
	 */
	public static int getUnsignedValue(final byte value) {
		return value & 0xFF;
	}

	/**
	 * Returns values from 0 to 255 (value range of byte)
	 *
	 * @param value the signed byte values to interpret as unsigned
	 * @return an array containing the corresponding values in the range 0 to 255
	 */
	public static int[] getUnsignedValue(final byte[] value) {
		final int[] returnValue = new int[value.length];
		for (int i = 0; i < value.length; i++) {
			returnValue[i] = getUnsignedValue(value[i]);
		}
		return returnValue;
	}

	/**
	 * Returns the value as a Byte which contains only signed values in Java
	 *
	 * @param value the unsigned value in the range 0 to 255
	 * @return the corresponding Java byte value
	 * @throws IllegalArgumentException if the value is outside the range 0 to 255
	 */
	public static byte getUnsignedAsByte(final int value) {
		if (value < 0 || value > 255) {
			throw new IllegalArgumentException("Unsigned value out of range for byte: " + value);
		} else {
			return (byte) value;
		}
	}

	/**
	 * Returns the 8 character bit representation of a byte, most significant bit first (e.g. "00001010").
	 *
	 * @param byteItem the byte to convert
	 * @return the bit string with exactly 8 characters
	 */
	public static String getBitString(final byte byteItem) {
		final StringBuilder result = new StringBuilder(8);
		appendBits(result, byteItem);
		return result.toString();
	}

	/**
	 * Returns the 32 character bit representation of an int, most significant bit first.
	 *
	 * @param intItem the int to convert
	 * @return the bit string with exactly 32 characters
	 */
	public static String getBitString(final int intItem) {
		final StringBuilder result = new StringBuilder(32);
		for (int i = 31; i >= 0; i--) {
			result.append((intItem >>> i) & 0x01);
		}
		return result.toString();
	}

	/**
	 * Returns the bit representation of a byte array, each byte as 8 characters separated by a blank.
	 *
	 * @param byteArray the bytes to convert
	 * @return the bit string, empty for an empty array
	 */
	public static String getBitString(final byte[] byteArray) {
		return getBitString(byteArray, " ");
	}

	/**
	 * Returns the bit representation of a byte array, each byte as 8 characters separated by the given separator.
	 *
	 * @param byteArray the bytes to convert
	 * @param byteSeparator the separator inserted between bytes, or {@code null} for no separator
	 * @return the bit string, empty for an empty array
	 */
	public static String getBitString(final byte[] byteArray, final String byteSeparator) {
		final StringBuilder result = new StringBuilder();
		for (int i = 0; i < byteArray.length; i++) {
			if (i > 0 && byteSeparator != null) {
				result.append(byteSeparator);
			}
			appendBits(result, byteArray[i]);
		}
		return result.toString();
	}

	private static void appendBits(final StringBuilder result, final byte byteItem) {
		for (int i = 7; i >= 0; i--) {
			result.append((byteItem >>> i) & 0x01);
		}
	}

	/**
	 * Parses a bit string of 1 to 8 characters ('0' and '1', surrounding whitespace is ignored) into a byte.
	 *
	 * @param bitString the bit string, most significant bit first
	 * @return the byte value (bit strings with a leading 1 in the 8th bit result in negative values)
	 * @throws Exception if the bit string is empty or contains invalid characters or more than 8 bits
	 */
	public static byte getByteFromBitString(final String bitString) throws Exception {
		if (isEmpty(bitString) || !BITSTRINGPATTERN_BYTE.matcher(bitString.trim()).matches()) {
			throw new Exception("Invalid bitstring for byte");
		}
		return (byte) Integer.parseInt(bitString.trim(), 2);
	}

	/**
	 * Parses a bit string of 1 to 32 characters ('0' and '1', surrounding whitespace is ignored) into an int.
	 *
	 * @param bitString the bit string, most significant bit first
	 * @return the int value (bit strings with a leading 1 in the 32nd bit result in negative values)
	 * @throws Exception if the bit string is empty or contains invalid characters or more than 32 bits
	 */
	public static int getIntegerFromBitString(final String bitString) throws Exception {
		if (isEmpty(bitString) || !BITSTRINGPATTERN_INTEGER.matcher(bitString.trim()).matches()) {
			throw new Exception("Invalid bitstring for integer");
		}
		return Integer.parseUnsignedInt(bitString.trim(), 2);
	}

	/**
	 * Decodes a hexadecimal string (case insensitive, optional prefix "0x") into a byte array.
	 *
	 * @param value the hexadecimal string with an even number of ASCII hex digits
	 * @return the decoded bytes, or {@code null} if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the string contains non hexadecimal characters or has an odd number of digits
	 */
	public static byte[] fromHexString(final String value) {
		if (value == null) {
			return null;
		} else {
			String decodeValue = value;
			if (decodeValue.startsWith("0x") || decodeValue.startsWith("0X")) {
				decodeValue = decodeValue.substring(2);
			}
			if (decodeValue.length() % 2 != 0) {
				throw new IllegalArgumentException("Hexadecimal string has an odd number of digits: " + value);
			}
			final byte[] data = new byte[decodeValue.length() / 2];
			for (int i = 0; i < decodeValue.length(); i += 2) {
				final int high = hexDigitValue(decodeValue.charAt(i));
				final int low = hexDigitValue(decodeValue.charAt(i + 1));
				if (high < 0 || low < 0) {
					throw new IllegalArgumentException("String contains non hexadecimal character: " + value);
				}
				data[i / 2] = (byte) ((high << 4) | low);
			}
			return data;
		}
	}

	/**
	 * Decodes a hexadecimal string into a byte array, optionally ignoring all non hexadecimal characters
	 * (like separators, blanks or linebreaks, e.g. "0A:1B:2C" or "0x0A, 0x1B, 0x2C").
	 * <p>
	 * Each byte must be written with two hex digits, because single digit bytes cannot be told apart after the
	 * separators are removed: "1:2" is decoded as the single byte 0x12, not as the two bytes 0x01 and 0x02.
	 * </p>
	 *
	 * @param value the hexadecimal string
	 * @param ignoreNonHexCharacters {@code true} to remove all "0x" prefixes and all non hexadecimal characters before
	 *            decoding
	 * @return the decoded bytes, or {@code null} if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the remaining string contains non hexadecimal characters or has an odd number of digits
	 */
	public static byte[] fromHexString(final String value, final boolean ignoreNonHexCharacters) {
		if (value == null) {
			return null;
		} else if (ignoreNonHexCharacters) {
			// Remove the prefixes first, otherwise their "0" would remain as hex digit
			final String withoutPrefixes = HEX_PREFIX_PATTERN.matcher(value).replaceAll("");
			return fromHexString(NON_HEX_CHARACTER_PATTERN.matcher(withoutPrefixes).replaceAll(""));
		} else {
			return fromHexString(value);
		}
	}

	/**
	 * Returns an uppercase hexadecimal representation of byte array data.
	 *
	 * @param data the byte array to convert
	 * @return the hexadecimal representation, or {@code null} if {@code data} is {@code null}
	 */
	public static String toHexString(final byte[] data) {
		if (data == null) {
			return null;
		} else {
			final char[] hexChars = new char[data.length * 2];
			for (int j = 0; j < data.length; j++) {
				final int v = data[j] & 0xFF;
				hexChars[j * 2] = HEX_CHARS_UPPERCASE[v >>> 4];
				hexChars[j * 2 + 1] = HEX_CHARS_UPPERCASE[v & 0x0F];
			}
			return new String(hexChars);
		}
	}

	/**
	 * Returns a <b>lowercase</b> hexadecimal representation of byte array data with an optional separator (e.g. "0a:1b:2c").
	 *
	 * @param data the byte array to convert
	 * @param separator the separator inserted between bytes, or {@code null} for no separator
	 * @return the hexadecimal representation, or {@code null} if {@code data} is {@code null}
	 */
	public static String toHexString(final byte[] data, final String separator) {
		if (data == null) {
			return null;
		}
		final StringBuilder returnString = new StringBuilder();
		for (int i = 0; i < data.length; i++) {
			if (i > 0 && separator != null) {
				returnString.append(separator);
			}
			final int v = data[i] & 0xFF;
			returnString.append(Character.forDigit(v >>> 4, 16)).append(Character.forDigit(v & 0x0F, 16));
		}
		return returnString.toString();
	}

	/**
	 * Returns a hex dump of the given data (uppercase hex digits).
	 *
	 * @param data the bytes to dump
	 * @param separator the separator inserted between bytes within one line, or {@code null} for no separator
	 * @param bytesBeforeLinebreak number of bytes per line, or 0 (or less) for a single line
	 * @param insertHexLineNumber {@code true} to prefix each line with its hexadecimal byte offset (e.g. "00000010h: ")
	 * @param insertAsciiText {@code true} to append the printable ASCII representation of each line (non printable bytes are shown as '.')
	 * @return the hex dump, an empty string for empty data, or {@code null} if {@code data} is {@code null}
	 */
	public static String getHexString(final byte[] data, final String separator, final int bytesBeforeLinebreak, final boolean insertHexLineNumber, final boolean insertAsciiText) {
		if (data == null) {
			return null;
		} else if (data.length == 0) {
			// No line number without any line content
			return "";
		}

		final StringBuilder returnString = new StringBuilder();
		int byteCount = 0;
		StringBuilder asciiTextLine = new StringBuilder();
		for (final byte dataByte : data) {
			if (byteCount > 0) {
				if (bytesBeforeLinebreak > 0 && byteCount % bytesBeforeLinebreak == 0) {
					if (insertAsciiText) {
						returnString.append(" ; ");
						returnString.append(asciiTextLine);
						asciiTextLine = new StringBuilder();
					}
					returnString.append('\n');
					if (insertHexLineNumber) {
						returnString.append(String.format("%08Xh: ", byteCount));
					}
				} else if (separator != null) {
					returnString.append(separator);
				}
			}
			returnString.append(HEX_CHARS_UPPERCASE[(dataByte >>> 4) & 0x0F]).append(HEX_CHARS_UPPERCASE[dataByte & 0x0F]);
			// Only printable 7-bit ASCII characters are shown, everything else (control characters, DEL, bytes >= 0x80) as '.'
			if (dataByte >= 32 && dataByte < 127) {
				asciiTextLine.append((char) dataByte);
			} else {
				asciiTextLine.append('.');
			}
			byteCount++;
		}

		if (insertAsciiText && asciiTextLine.length() > 0) {
			if (bytesBeforeLinebreak > 0) {
				final int bytesInLastLine = byteCount % bytesBeforeLinebreak;
				if (bytesInLastLine > 0) {
					final int separatorLength = separator == null ? 0 : separator.length();
					returnString.append(repeatString(" ", (bytesBeforeLinebreak - bytesInLastLine) * (2 + separatorLength)));
				}
			}
			returnString.append(" ; ");
			returnString.append(asciiTextLine);
		}

		if (insertHexLineNumber) {
			return String.format("%08Xh: ", 0) + returnString.toString();
		} else {
			return returnString.toString();
		}
	}

	/**
	 * Decodes a hexadecimal string (case insensitive, optional prefix "0x", no separators) into a byte array.
	 * Unlike {@link #fromHexString(String)} a {@code null} value is rejected.
	 *
	 * @param value the hexadecimal string with an even number of ASCII hex digits
	 * @return the decoded bytes
	 * @throws IllegalArgumentException if the value is {@code null}, contains non hexadecimal characters or has an odd number of digits
	 */
	public static byte[] getByteArrayFromHexString(final String value) {
		if (value == null) {
			throw new IllegalArgumentException("Invalid empty hexadecimal string");
		}
		return fromHexString(value);
	}

	/**
	 * XORs the supplied byte arrays.
	 *
	 * @param byteArrays the byte arrays to combine, all of the same length
	 * @return the XOR result
	 * @throws IllegalArgumentException if no arrays are given, an array is {@code null} or the arrays differ in length
	 */
	public static byte[] xor(final byte[]... byteArrays) {
		if (byteArrays == null) {
			throw new IllegalArgumentException("Missing byte arrays for xor");
		}
		return xor(Arrays.asList(byteArrays));
	}

	/**
	 * XORs the supplied byte arrays.
	 *
	 * @param byteArrays the byte arrays to combine, all of the same length
	 * @return the XOR result
	 * @throws IllegalArgumentException if no arrays are given, an array is {@code null} or the arrays differ in length
	 */
	public static byte[] xor(final List<byte[]> byteArrays) {
		if (byteArrays == null || byteArrays.isEmpty()) {
			throw new IllegalArgumentException("Missing byte arrays for xor");
		}
		for (final byte[] byteArray : byteArrays) {
			if (byteArray == null) {
				throw new IllegalArgumentException("Byte arrays for xor contain a null array");
			}
		}

		final byte[] returnArray = new byte[byteArrays.get(0).length];
		for (final byte[] byteArray : byteArrays) {
			if (byteArray.length != returnArray.length) {
				throw new IllegalArgumentException("Byte arrays for xor must have the same length");
			}
			for (int j = 0; j < returnArray.length; j++) {
				returnArray[j] ^= byteArray[j];
			}
		}
		return returnArray;
	}

	/**
	 * XORs all given bytes.
	 * <p>
	 * A call without arguments ({@code xor()}) or with {@code null} is ambiguous with {@link #xor(byte[]...)} and does
	 * not compile. To XOR no bytes, pass an empty array: {@code xor(new byte[0])}.
	 * </p>
	 *
	 * @param keyData the bytes to combine
	 * @return the XOR of all bytes, 0 for an empty array
	 */
	public static byte xor(final byte... keyData) {
		byte resultItem = 0;
		for (final byte key : keyData) {
			resultItem ^= key;
		}
		return resultItem;
	}

	/**
	 * Concatenates the given byte arrays in the given order.
	 *
	 * @param arrays the byte arrays to join
	 * @return a new array containing all bytes
	 * @throws IllegalArgumentException if the arrays or one of the arrays is {@code null}
	 */
	public static byte[] joinByteArrays(final byte[]... arrays) {
		if (arrays == null) {
			throw new IllegalArgumentException("Invalid null arrays for join");
		}
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (final byte[] array : arrays) {
			if (array == null) {
				throw new IllegalArgumentException("Invalid null array for join");
			}
			out.writeBytes(array);
		}
		return out.toByteArray();
	}

	/**
	 * Adds length-coded padding (PKCS#5/#7) that can be removed after decryption by
	 * {@link #removeLengthCodedPadding(byte[], int)}. Data, whose length is already a multiple of the padding size, gets
	 * a full block of padding.
	 *
	 * @param data the data to pad
	 * @param paddingSize the padding block size (1 - 255)
	 * @return the padded data
	 * @throws IllegalArgumentException if the padding size is not in the range 1 - 255
	 */
	public static byte[] addLengthCodedPadding(final byte[] data, final int paddingSize) {
		if (paddingSize < 1 || paddingSize > 255) {
			throw new IllegalArgumentException("Invalid padding size: " + paddingSize);
		}
		final int padLength = paddingSize - (data.length % paddingSize);
		final byte[] dataPadded = Arrays.copyOf(data, data.length + padLength);
		Arrays.fill(dataPadded, data.length, dataPadded.length, (byte) padLength);
		return dataPadded;
	}

	/**
	 * Removes length-coded padding (PKCS#5/#7) added by {@link #addLengthCodedPadding(byte[], int)}.
	 * <p>
	 * All padding bytes are checked without early exit, so the check takes the same time wherever the padding is
	 * broken. Note that distinguishable error messages after decryption can still allow a padding oracle attack, so
	 * callers decrypting untrusted data should report all decryption errors the same way.
	 * </p>
	 *
	 * @param data the padded data, its length must be a positive multiple of the padding size
	 * @param paddingSize the padding block size (1 - 255)
	 * @return the data without padding
	 * @throws IllegalArgumentException if the padding size is not in the range 1 - 255, the data length is invalid or
	 *             the padding is invalid
	 */
	public static byte[] removeLengthCodedPadding(final byte[] data, final int paddingSize) {
		if (paddingSize < 1 || paddingSize > 255) {
			throw new IllegalArgumentException("Invalid padding size: " + paddingSize);
		} else if (data == null || data.length == 0 || data.length % paddingSize != 0) {
			throw new IllegalArgumentException("Invalid padded data length");
		}

		final int padLength = data[data.length - 1] & 0xFF;
		boolean invalid = padLength < 1 || padLength > paddingSize;
		// Check the maximum possible padding area completely, so the duration does not depend on the padding content
		for (int i = 1; i <= paddingSize; i++) {
			final boolean isPaddingByte = i <= padLength;
			invalid |= isPaddingByte & (data[data.length - i] & 0xFF) != padLength;
		}
		if (invalid) {
			throw new IllegalArgumentException("Invalid padding");
		}
		return Arrays.copyOf(data, data.length - padLength);
	}

	/**
	 * Adds random padding that cannot be removed without knowing the resulting length.
	 *
	 * @param data the data to pad
	 * @param paddingSize the padding block size (must be positive)
	 * @return the padded data, or a copy of the data if its length is already a multiple of the padding size
	 * @throws IllegalArgumentException if the padding size is not positive
	 */
	public static byte[] addRandomPadding(final byte[] data, final int paddingSize) {
		if (paddingSize < 1) {
			throw new IllegalArgumentException("Invalid padding size: " + paddingSize);
		}
		if (data.length % paddingSize != 0) {
			final byte[] dataPadded = Arrays.copyOf(data, ((data.length / paddingSize) + 1) * paddingSize);
			final byte[] randomPadding = new byte[dataPadded.length - data.length];
			SECURE_RANDOM.nextBytes(randomPadding);
			System.arraycopy(randomPadding, 0, dataPadded, data.length, randomPadding.length);
			return dataPadded;
		} else {
			return data.clone();
		}
	}

	/**
	 * Decodes the first two hexadecimal characters of a string into a byte. Further characters are ignored.
	 *
	 * @param data the string starting with two ASCII hexadecimal digits
	 * @return the decoded byte
	 * @throws IllegalArgumentException if the string is shorter than two characters or contains non hexadecimal characters
	 */
	public static byte hexToByte(final String data) {
		if (data == null || data.length() < 2) {
			throw new IllegalArgumentException("Invalid hexadecimal byte: " + data);
		}
		return BitUtilities.hexToByte(data.charAt(0), data.charAt(1));
	}

	/**
	 * Decodes two hexadecimal characters into a byte.
	 *
	 * @param char1 the high nibble ASCII hex digit
	 * @param char2 the low nibble ASCII hex digit
	 * @return the decoded byte
	 * @throws IllegalArgumentException if one of the characters is not an ASCII hexadecimal digit
	 */
	public static byte hexToByte(final char char1, final char char2) {
		final int high = hexDigitValue(char1);
		final int low = hexDigitValue(char2);
		if (high < 0 || low < 0) {
			throw new IllegalArgumentException("Invalid hexadecimal byte: " + char1 + char2);
		}
		return (byte) ((high << 4) | low);
	}

	/**
	 * Returns the two digit uppercase hexadecimal representation of a byte.
	 *
	 * @param data the byte to convert
	 * @return the hexadecimal representation (e.g. "0A")
	 */
	public static String byteToHex(final byte data) {
		return new String(new char[] { HEX_CHARS_UPPERCASE[(data >>> 4) & 0x0F], HEX_CHARS_UPPERCASE[data & 0x0F] });
	}

	/**
	 * Returns the value of an ASCII hexadecimal digit (0-9, a-f, A-F). Unlike {@link Character#digit(char, int)} this
	 * does not accept non ASCII digits like fullwidth or Arabic-Indic digits.
	 *
	 * @param character the character to convert
	 * @return the value 0 to 15, or -1 if the character is no ASCII hexadecimal digit
	 */
	private static int hexDigitValue(final char character) {
		if (character >= '0' && character <= '9') {
			return character - '0';
		} else if (character >= 'a' && character <= 'f') {
			return character - 'a' + 10;
		} else if (character >= 'A' && character <= 'F') {
			return character - 'A' + 10;
		} else {
			return -1;
		}
	}

	private static String repeatString(final String itemString, final int repeatTimes) {
		final StringBuilder returnStringBuilder = new StringBuilder();
		for (int i = 0; i < repeatTimes; i++) {
			returnStringBuilder.append(itemString);
		}
		return returnStringBuilder.toString();
	}

	private static boolean isEmpty(final String value) {
		return value == null || value.length() == 0;
	}
}
