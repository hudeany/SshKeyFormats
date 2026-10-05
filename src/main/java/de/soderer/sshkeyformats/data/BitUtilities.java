package de.soderer.sshkeyformats.data;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * BitUtilities API.
 */
public class BitUtilities {
	private static Pattern BITSTRINGPATTERN_BYTE = Pattern.compile("^[10]{1,8}$");
	private static Pattern BITSTRINGPATTERN_INTEGER = Pattern.compile("^[10]{1,32}$");
	private static Pattern HEXADECIMAL_PATTERN = Pattern.compile("\\p{XDigit}+");

	/**
	 * Returns values from 0 to 255 (value range of byte)
	 *
	 * @param value the signed byte value to interpret as unsigned
	 * @return the value in the range 0 to 255
	 */
	public static int getUnsignedValue(final byte value) {
		if (value < 0) {
			return (value) + 256;
		} else {
			return value;
		}
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
	 * @throws Exception if the value is outside the range 0 to 255
	 */
	public static byte getUnsignedAsByte(final int value) throws Exception {
		if (value < 0 || value > 255) {
			throw new Exception("Unsigned value out of range for byte");
		} else if (value > 127) {
			return (byte) (value - 256);
		} else {
			return (byte) value;
		}
	}

/**
 * getBitString operation.
 * @param byteItem the byteItem value.
 * @return the resulting value.
 */
	public static String getBitString(final byte byteItem) {
		final StringBuilder result = new StringBuilder();
		for (int i = 7; i >= 0; i--) {
			result.append((byte) ((byteItem >>> i) & 0x01));
		}
		return result.toString();
	}

/**
 * getBitString operation.
 * @param intItem the intItem value.
 * @return the resulting value.
 */
	public static String getBitString(final int intItem) {
		final StringBuilder result = new StringBuilder();
		for (int i = 31; i >= 0; i--) {
			result.append((byte) ((intItem >>> i) & 0x01));
		}
		return result.toString();
	}

/**
 * getBitString operation.
 * @param byteArray the byteArray value.
 * @return the resulting value.
 */
	public static String getBitString(final byte[] byteArray) {
		return getBitString(byteArray, " ");
	}

/**
 * getBitString operation.
 * @param byteArray the byteArray value.
 * @param byteSeparator the byteSeparator value.
 * @return the resulting value.
 */
	public static String getBitString(final byte[] byteArray, final String byteSeparator) {
		final StringBuilder result = new StringBuilder();
		for (final byte byteItem : byteArray) {
			if (result.length() > 0) {
				result.append(byteSeparator);
			}

			for (int i = 7; i >= 0; i--) {
				result.append((byte) ((byteItem >>> i) & 0x01));
			}
		}
		return result.toString();
	}

/**
 * getByteFromBitString operation.
 * @param bitString the bitString value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static byte getByteFromBitString(String bitString) throws Exception {
		if (isEmpty(bitString)) {
			throw new Exception("Invalid bitstring for byte");
		}

		bitString = bitString.trim();

		if (!BITSTRINGPATTERN_BYTE.matcher(bitString).matches()) {
			throw new Exception("Invalid bitstring for byte");
		}

		byte result = 0;
		int posValue = 1;
		final char[] characters = bitString.toCharArray();
		for (int i = characters.length - 1; i >= 0; i--) {
			if (characters[i] == '1') {
				result += posValue;
			}
			posValue *= 2;
		}
		return result;
	}

/**
 * getIntegerFromBitString operation.
 * @param bitString the bitString value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static int getIntegerFromBitString(String bitString) throws Exception {
		if (isEmpty(bitString)) {
			throw new Exception("Invalid bitstring for integer");
		}

		bitString = bitString.trim();

		if (!BITSTRINGPATTERN_INTEGER.matcher(bitString).matches()) {
			throw new Exception("Invalid bitstring for integer");
		}

		int result = 0;
		int posValue = 1;
		final char[] characters = bitString.toCharArray();
		for (int i = characters.length - 1; i >= 0; i--) {
			if (characters[i] == '1') {
				result += posValue;
			}
			posValue *= 2;
		}
		return result;
	}

/**
 * fromHexString operation.
 * @param value the value value.
 * @return the resulting value.
 */
	public static byte[] fromHexString(final String value) {
		if (value == null) {
			return null;
		} else {
			String decodeValue = value;
			if (value.toLowerCase().startsWith("0x")) {
				decodeValue = decodeValue.substring(2);
			}
			if (!HEXADECIMAL_PATTERN.matcher(decodeValue).matches()) {
				throw new RuntimeException("String contains non hexadecimal character: " + value);
			}
			final int length = decodeValue.length();
			final byte[] data = new byte[length / 2];
			for (int i = 0; i < length; i += 2) {
				data[i / 2] = (byte) ((Character.digit(decodeValue.charAt(i), 16) << 4) + Character.digit(decodeValue.charAt(i + 1), 16));
			}
			return data;
		}
	}

/**
 * fromHexString operation.
 * @param value the value value.
 * @param ignoreNonHexCharacters the ignoreNonHexCharacters value.
 * @return the resulting value.
 */
	public static byte[] fromHexString(final String value, final boolean ignoreNonHexCharacters) {
		if (value == null) {
			return null;
		} else if (ignoreNonHexCharacters) {
			return fromHexString(value.toLowerCase().replaceAll("[^abcdef0-9]", ""));
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
			final char[] hexArray = "0123456789ABCDEF".toCharArray();

			final char[] hexChars = new char[data.length * 2];
			for (int j = 0; j < data.length; j++) {
				final int v = data[j] & 0xFF;
				hexChars[j * 2] = hexArray[v >>> 4];
				hexChars[j * 2 + 1] = hexArray[v & 0x0F];
			}
			return new String(hexChars);
		}
	}

	/**
	 * Returns an uppercase hexadecimal representation of byte array data with an optional separator.
	 *
	 * @param data the byte array to convert
	 * @param separator the separator inserted between bytes, or {@code null} for no separator
	 * @return the hexadecimal representation
	 */
	public static String toHexString(final byte[] data, final String separator) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			if (returnString.length() > 0 && separator != null) {
				returnString.append(separator);
			}
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString().toLowerCase();
	}

/**
 * getHexString operation.
 * @param data the data value.
 * @param separator the separator value.
 * @param bytesBeforeLinebreak the bytesBeforeLinebreak value.
 * @param insertHexLineNumber the insertHexLineNumber value.
 * @param insertAsciiText the insertAsciiText value.
 * @return the resulting value.
 */
	public static String getHexString(final byte[] data, final String separator, final int bytesBeforeLinebreak, final boolean insertHexLineNumber, final boolean insertAsciiText) {
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
				} else {
					returnString.append(separator);
				}
			}
			returnString.append(String.format("%02X", dataByte));
			if (dataByte >= 0 && dataByte < 32) {
				asciiTextLine.append('.');
			} else {
				asciiTextLine.append(new String(new byte[] { dataByte }));
			}
			byteCount++;
		}

		if (insertAsciiText && asciiTextLine.length() > 0) {
			final int bytesInLastLine = byteCount % bytesBeforeLinebreak;
			if (bytesInLastLine > 0) {
				returnString.append(repeatString("   ", bytesBeforeLinebreak - bytesInLastLine));
			}
			returnString.append(" ; ");
			returnString.append(asciiTextLine.toString());
		}

		if (insertHexLineNumber) {
			return String.format("%08Xh: ", 0) + returnString.toString();
		} else {
			return returnString.toString();
		}
	}

/**
 * getByteArrayFromHexString operation.
 * @param value the value value.
 * @return the resulting value.
 */
	public static byte[] getByteArrayFromHexString(final String value) {
		final int length = value.length();
		final byte[] data = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(value.charAt(i), 16) << 4) + Character.digit(value.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * XORs the supplied byte arrays.
	 *
	 * @param byteArrays the byte arrays to combine
	 * @return the XOR result
	 */
	public static byte[] xor(final byte[]... byteArrays) {
		return xor(Arrays.asList(byteArrays));
	}

	/**
	 * XORs the supplied byte arrays.
	 *
	 * @param byteArrays the byte arrays to combine
	 * @return the XOR result
	 */
	public static byte[] xor(final List<byte[]> byteArrays) {
		final byte[] returnArray = new byte[byteArrays.get(0).length];

		for (int i = 0; i < byteArrays.size(); i++) {
			for (int j = 0; j < returnArray.length; j++) {
				returnArray[j] = xor(returnArray[j], byteArrays.get(i)[j]);
			}
		}

		return returnArray;
	}

/**
 * xor operation.
 * @param keyData the keyData value.
 * @return the resulting value.
 */
	public static byte xor(final byte... keyData) {
		byte resultItem = 0;

		for (final byte key : keyData) {
			resultItem = (byte) (resultItem ^ key);
		}

		return resultItem;
	}

/**
 * joinByteArrays operation.
 * @param arrays the arrays value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static byte[] joinByteArrays(final byte[]... arrays) throws Exception {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (final byte[] array : arrays) {
			out.write(array);
		}
		return out.toByteArray();
	}

	/**
	 * Adds length-coded padding that can be removed after encryption.
	 *
	 * @param data the data to pad
	 * @param paddingSize the padding block size
	 * @return the padded data
	 */
	public static byte[] addLengthCodedPadding(final byte[] data, final int paddingSize) {
		final byte[] dataPadded;
		if (data.length % paddingSize != 0) {
			dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
		} else {
			dataPadded = new byte[data.length + paddingSize];
		}
		for (int i = 0; i < data.length; i++) {
			dataPadded[i] = data[i];
		}
		final byte padValue = (byte) (dataPadded.length - data.length);
		for (int i = data.length; i < dataPadded.length; i++) {
			dataPadded[i] = padValue;
		}
		return dataPadded;
	}

	/**
	 * Adds random padding that cannot be removed without knowing the resulting length.
	 *
	 * @param data the data to pad
	 * @param paddingSize the padding block size
	 * @return the padded data
	 */
	public static byte[] addRandomPadding(final byte[] data, final int paddingSize) {
		if (data.length % paddingSize != 0) {
			final byte[] dataPadded;
			dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
			for (int i = 0; i < data.length; i++) {
				dataPadded[i] = data[i];
			}
			final byte[] randomPadding = new byte[dataPadded.length - data.length];
			new SecureRandom().nextBytes(randomPadding);
			for (int i = 0; i < randomPadding.length; i++) {
				dataPadded[data.length + i] = randomPadding[i];
			}
			return dataPadded;
		} else {
			return data;
		}
	}

/**
 * hexToByte operation.
 * @param data the data value.
 * @return the resulting value.
 */
	public static byte hexToByte(final String data) {
		return BitUtilities.hexToByte(data.charAt(0), data.charAt(1));
	}

/**
 * hexToByte operation.
 * @param char1 the char1 value.
 * @param char2 the char2 value.
 * @return the resulting value.
 */
	public static byte hexToByte(final char char1, final char char2) {
		return (byte) ((Character.digit(char1, 16) << 4) + Character.digit(char2, 16));
	}

/**
 * byteToHex operation.
 * @param data the data value.
 * @return the resulting value.
 */
	public static String byteToHex(final byte data) {
		return String.format("%02X", data);
	}

	private static String repeatString(final String itemString, final int repeatTimes) {
		return repeatString(itemString, repeatTimes, null);
	}

	private static String repeatString(final String itemString, final int repeatTimes, final String separatorString) {
		final StringBuilder returnStringBuilder = new StringBuilder();
		for (int i = 0; i < repeatTimes; i++) {
			if (separatorString != null && returnStringBuilder.length() > 0) {
				returnStringBuilder.append(separatorString);
			}
			returnStringBuilder.append(itemString);
		}
		return returnStringBuilder.toString();
	}

	private static boolean isEmpty(final String value) {
		return value == null || value.length() == 0;
	}
}
