package de.soderer.sshkeyformats.data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Encoder / Decoder for the ASN.1 DER format.
 * <p>
 * The decoding methods are strict: only definite length encodings in their shortest (canonical)
 * DER form are accepted, and the data size of a single element is limited to protect against
 * maliciously crafted or corrupted data (e.g. data decrypted with a wrong password).
 */
public class Asn1Codec {
	/**
	 * ASN.1 "INTEGER" (0x02 = 2)
	 */
	public static final int DER_TAG_INTEGER = 0x02;

	/**
	 * ASN.1 "BIT STRING" (0x03 = 3)
	 */
	public static final int DER_TAG_BIT_STRING = 0x03;

	/**
	 * ASN.1 "OCTET STRING" (0x04 = 4)
	 */
	public static final int DER_TAG_OCTET_STRING = 0x04;

	/**
	 * ASN.1 "OBJECT" (0x06 = 6)
	 */
	public static final int DER_TAG_OBJECT = 0x06;

	/**
	 * ASN.1 "SEQUENCE" (0x30 = 48)
	 */
	public static final int DER_TAG_SEQUENCE = 0x30;

	/**
	 * ASN.1 CONTEXT SPECIFIC "cont [ 0 ]" (0xA0 = -96 = unsigned 160)
	 */
	public static final int DER_TAG_CONTEXT_SPECIFIC_0 = 0xA0;

	/**
	 * ASN.1 CONTEXT SPECIFIC "cont [ 1 ]" (0xA1 = -95 = unsigned 161)
	 */
	public static final int DER_TAG_CONTEXT_SPECIFIC_1 = 0xA1;

	/**
	 * Sanity upper bound for a single DER element's data, to protect against maliciously crafted or
	 * corrupted data that could otherwise force a huge memory allocation before any validation
	 * of the data has taken place (Denial of Service protection).
	 */
	private static final int MAX_DER_TAG_DATA_LENGTH = 16 * 1024 * 1024; // 16 MB

	private Asn1Codec() {
		// Utility class with static methods only
	}

	/**
	 * Encodes a non-negative value in the DER length format: values below 128 as a single byte
	 * (short form), larger values as 0x80 combined with the number of value bytes, followed by
	 * the value bytes in big endian order (long form).
	 * <p>
	 * Note: Despite its name this method produces a DER <i>length</i> encoding, not the content
	 * of an ASN.1 INTEGER element.
	 *
	 * @param value value to encode, must not be negative
	 * @return encoded bytes
	 * @throws Exception if the value is negative
	 */
	public static byte[] getAsnEncodedInteger(final long value) throws Exception {
		if (value < 0) {
			throw new Exception("Minimum ASN.1 encoded Integer underrun");
		} else if (value < 0x80) {
			return new byte[] { (byte) value };
		} else {
			byte[] data = BigInteger.valueOf(value).toByteArray();
			if (data[0] == 0) {
				// Remove the leading sign byte, which is not part of a DER length encoding
				data = Arrays.copyOfRange(data, 1, data.length);
			}
			final byte[] result = new byte[data.length + 1];
			result[0] = (byte) (0x80 | data.length);
			System.arraycopy(data, 0, result, 1, data.length);
			return result;
		}
	}

	/**
	 * Parses a length-prefixed ASN.1 INTEGER content. "offset" points to the DER length bytes
	 * (short or long form), which are directly followed by the integer's value bytes in two's
	 * complement big endian order (as within an ASN.1 INTEGER element after its tag byte).
	 * <p>
	 * Note: This is <b>not</b> the inverse of {@link #getAsnEncodedInteger(long)}, which only
	 * produces a DER length encoding.
	 *
	 * @param data data containing the encoded integer
	 * @param offset index of the first length byte within the data
	 * @return the decoded (signed) value
	 * @throws Exception if the offset is invalid, the length encoding is invalid or the data is truncated
	 */
	public static BigInteger parseAsnEncodedInteger(final byte[] data, final int offset) throws Exception {
		if (data == null || offset < 0 || offset >= data.length) {
			throw new Exception("Invalid data or offset for ASN.1 integer parsing");
		}

		int position = offset;
		final int lengthIndicatingValue = data[position++] & 0xFF;
		final long length;
		if (lengthIndicatingValue < 0x80) {
			length = lengthIndicatingValue;
		} else {
			final int lengthBytesCount = lengthIndicatingValue & 0x7F;
			if (lengthBytesCount == 0) {
				throw new Exception("Unsupported ASN.1 indefinite length encoding");
			} else if (lengthBytesCount > 4) {
				throw new Exception("Unsupported ASN.1 length encoding with " + lengthBytesCount + " length bytes");
			} else if (position + lengthBytesCount > data.length) {
				throw new Exception("Truncated ASN.1 length encoding");
			}
			long longLength = 0;
			for (int i = 0; i < lengthBytesCount; i++) {
				longLength = (longLength << 8) | (data[position++] & 0xFF);
			}
			length = longLength;
		}

		if (length == 0) {
			throw new Exception("Invalid ASN.1 integer with empty content");
		} else if (position + length > data.length) {
			// long arithmetic, so manipulated lengths cannot overflow
			throw new Exception("Invalid or truncated ASN.1 integer length: " + length);
		}
		return new BigInteger(Arrays.copyOfRange(data, position, position + (int) length));
	}

	/**
	 * Creates a DER encoded element from a tag id and its content, with the length encoded in
	 * short or long form as needed.
	 *
	 * @param derTagId tag id, e.g. {@link #DER_TAG_SEQUENCE}
	 * @param derDataItems content parts, written one after the other as the element's content
	 * @return encoded element (tag, length and content)
	 * @throws IOException if a content part is null or the content is too large
	 */
	public static byte[] createDerTagData(final int derTagId, final byte[]... derDataItems) throws IOException {
		if (derTagId < 0 || derTagId > 0xFF) {
			throw new IOException("Invalid DER tag id: " + derTagId);
		}

		long dataItemsLength = 0;
		if (derDataItems != null) {
			for (final byte[] dataItem : derDataItems) {
				if (dataItem == null) {
					throw new IOException("Invalid null DER data item");
				}
				dataItemsLength += dataItem.length;
			}
		}
		if (dataItemsLength > Integer.MAX_VALUE - 6) {
			throw new IOException("DER data too large: " + dataItemsLength + " bytes");
		}
		final int contentLength = (int) dataItemsLength;

		final ByteArrayOutputStream out = new ByteArrayOutputStream(contentLength + 6);
		out.write(derTagId);
		if (contentLength < 0x80) {
			out.write(contentLength);
		} else {
			final int lengthBytesCount = getByteEncodedLength(contentLength);
			out.write(0x80 | lengthBytesCount);
			for (int i = lengthBytesCount - 1; i >= 0; i--) {
				out.write((contentLength >> (8 * i)) & 0xFF);
			}
		}
		if (derDataItems != null) {
			for (final byte[] dataItem : derDataItems) {
				out.write(dataItem);
			}
		}
		return out.toByteArray();
	}

	private static int getByteEncodedLength(int value) {
		int lengthInBytes = 0;
		while (value > 0) {
			lengthInBytes++;
			value = value >> 8;
		}
		return lengthInBytes;
	}

	/**
	 * Reads the first DER element of the data. Any data following the first element is ignored.
	 *
	 * @param data DER encoded data
	 * @return the element with its tag id and content
	 * @throws Exception if the data is empty, truncated or its length encoding is invalid
	 */
	public static DerTag readDerTag(final byte[] data) throws Exception {
		if (data == null) {
			throw new Exception("Invalid empty DER data");
		}
		final DerTag derTag = readNextDerTag(new ByteArrayInputStream(data));
		if (derTag == null) {
			throw new Exception("Unexpected end of data while reading DER tag");
		}
		return derTag;
	}

	/**
	 * Reads all consecutive DER elements of the data.
	 *
	 * @param data DER encoded data, e.g. the content of a sequence
	 * @return the elements in the order of the data
	 * @throws Exception if the data is truncated or a length encoding is invalid
	 */
	public static List<DerTag> readDerTags(final byte[] data) throws Exception {
		if (data == null) {
			throw new Exception("Invalid empty DER data");
		}
		final ByteArrayInputStream input = new ByteArrayInputStream(data);
		final List<DerTag> returnList = new ArrayList<>();
		DerTag nextDerTag;
		while ((nextDerTag = readNextDerTag(input)) != null) {
			returnList.add(nextDerTag);
		}
		return returnList;
	}

	/**
	 * Reads the next DER element from the input.
	 *
	 * @return the next element, or {@code null} if the input is exhausted
	 */
	private static DerTag readNextDerTag(final ByteArrayInputStream input) throws Exception {
		final int tagId = input.read();
		if (tagId < 0) {
			return null;
		}

		final int lengthIndicatingValue = input.read();
		final int tagLength;
		if (lengthIndicatingValue < 0) {
			throw new Exception("Unexpected end of data while reading DER tag length");
		} else if (lengthIndicatingValue < 0x80) {
			tagLength = lengthIndicatingValue;
		} else {
			final int tagLengthBytesCount = lengthIndicatingValue & 0x7F;
			if (tagLengthBytesCount == 0) {
				throw new Exception("Unsupported DER indefinite length encoding");
			} else if (tagLengthBytesCount > 4) {
				throw new Exception("Invalid DER tag length encoding with " + tagLengthBytesCount + " length bytes");
			}
			long longTagLength = 0;
			for (int i = 0; i < tagLengthBytesCount; i++) {
				final int nextByte = input.read();
				if (nextByte < 0) {
					throw new Exception("Unexpected end of data while reading DER tag length");
				} else if (i == 0 && nextByte == 0) {
					throw new Exception("Invalid DER tag length encoding with leading zero");
				}
				longTagLength = (longTagLength << 8) | nextByte;
			}
			if (longTagLength < 0x80) {
				throw new Exception("Invalid DER tag length encoding: long form used for length " + longTagLength);
			} else if (longTagLength > MAX_DER_TAG_DATA_LENGTH) {
				throw new Exception("DER tag length " + longTagLength + " exceeds maximum allowed size of " + MAX_DER_TAG_DATA_LENGTH + " bytes");
			}
			tagLength = (int) longTagLength;
		}

		// The length might be invalid because of a wrong decryption password, so check the available data before allocating memory
		if (tagLength > input.available()) {
			throw new Exception("Block length read error. Available data: " + input.available() + " Tagsize: " + tagLength);
		}
		final byte[] dataBlock = new byte[tagLength];
		if (tagLength > 0 && input.read(dataBlock, 0, tagLength) != tagLength) {
			throw new Exception("Unexpected end of data while reading DER tag data of length " + tagLength);
		}
		// The freshly allocated array is not shared, so no defensive copy is needed here
		return new DerTag(tagId, dataBlock, false);
	}

	/**
	 * DER encoded element, consisting of its tag id and its content bytes.
	 * The content bytes are copied on input and output, so the element cannot be modified
	 * through shared array references.
	 */
	public static class DerTag {
		private int tagId;
		private byte[] data;

		/**
		 * Creates an element.
		 *
		 * @param tagId tag id, e.g. {@link Asn1Codec#DER_TAG_INTEGER}
		 * @param data content bytes (copied)
		 */
		public DerTag(final int tagId, final byte[] data) {
			this(tagId, data, true);
		}

		private DerTag(final int tagId, final byte[] data, final boolean copyData) {
			this.tagId = tagId;
			this.data = (copyData && data != null) ? data.clone() : data;
		}

		/**
		 * Returns the tag id.
		 *
		 * @return tag id
		 */
		public int getTagId() {
			return tagId;
		}

		/**
		 * Sets the tag id.
		 *
		 * @param tagId tag id
		 */
		public void setTagId(final int tagId) {
			this.tagId = tagId;
		}

		/**
		 * Returns a copy of the content bytes.
		 *
		 * @return content bytes, or {@code null} if not set
		 */
		public byte[] getData() {
			return data == null ? null : data.clone();
		}

		/**
		 * Sets the content bytes.
		 *
		 * @param data content bytes (copied)
		 */
		public void setData(final byte[] data) {
			this.data = data == null ? null : data.clone();
		}

		@Override
		public String toString() {
			if (data == null) {
				return tagId + " (no data)";
			} else {
				return tagId + " (length " + data.length + "): " + Arrays.toString(data);
			}
		}
	}
}
