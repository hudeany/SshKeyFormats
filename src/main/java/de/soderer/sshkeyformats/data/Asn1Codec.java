package de.soderer.sshkeyformats.data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Encoder / Decoder for the ASN.1 format
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
 * createDerTagData operation.
 * @param derTagId the derTagId value.
 * @param derDataItems the derDataItems value.
 * @return the resulting value.
 * @throws IOException if the operation cannot be completed.
 */
	public static byte[] createDerTagData(final int derTagId, final byte[]... derDataItems) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(derTagId);
		int dataItemsLength = 0;
		for (final byte[] dataItem : derDataItems) {
			dataItemsLength += dataItem.length;
		}
		if (dataItemsLength < 0x80) {
			out.write(dataItemsLength);
		} else {
			final int bytes = getByteEncodedLength(dataItemsLength);
			out.write(0x80 | bytes);
			for (int i = bytes - 1; i >= 0; i--) {
				out.write((dataItemsLength >> (8 * i)) & 0xFF);
			}
		}
		for (final byte[] dataItem : derDataItems) {
			out.write(dataItem);
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
	 * Sanity upper bound for a single DER tag's data, to protect against maliciously crafted or
	 * corrupted key data that could otherwise force a huge memory allocation before any validation
	 * of the data has taken place (Denial of Service protection).
	 */
	private static final int MAX_DER_TAG_DATA_LENGTH = 16 * 1024 * 1024; // 16 MB

	/**
	 * Reads the first DER tag of the given data. Any data following the first tag is ignored.
	 *
	 * @param data the DER encoded data
	 * @return the first DER tag
	 * @throws Exception if the data is not a valid DER tag
	 */
	public static DerTag readDerTag(final byte[] data) throws Exception {
		if (data == null) {
			throw new Exception("Invalid empty DER data");
		}
		final ByteArrayInputStream input = new ByteArrayInputStream(data);
		final DerTag derTag = readNextDerTag(input);
		if (derTag == null) {
			throw new Exception("Unexpected end of data while reading DER tag");
		}
		return derTag;
	}

	/**
	 * Reads all consecutive DER tags of the given data.
	 *
	 * @param data the DER encoded data
	 * @return the DER tags in order of appearance
	 * @throws Exception if the data is not a valid sequence of DER tags
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
	 * Reads the next DER tag from the input.
	 *
	 * @return the next DER tag, or {@code null} if the input is exhausted
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
				}
				longTagLength = (longTagLength << 8) + nextByte;
			}
			if (longTagLength > MAX_DER_TAG_DATA_LENGTH) {
				throw new Exception("DER tag length " + longTagLength + " exceeds maximum allowed size of " + MAX_DER_TAG_DATA_LENGTH + " bytes");
			}
			tagLength = (int) longTagLength;
		}

		// The length might be invalid because of a wrong decryption password, so check the available data before allocating memory
		if (tagLength > input.available()) {
			throw new Exception("Block length read error. Available data: " + input.available() + " Tagsize: " + tagLength);
		}
		final byte[] dataBlock = new byte[tagLength];
		if (input.read(dataBlock, 0, tagLength) != tagLength && tagLength > 0) {
			throw new Exception("Unexpected end of data while reading DER tag data of length " + tagLength);
		}
		return new DerTag(tagId, dataBlock);
	}

/**
 * DerTag API.
 */
	public static class DerTag {
		int tagId;
		byte[] data;

/**
 * DerTag operation.
 * @param tagId the tagId value.
 * @param data the data value.
 */
		public DerTag(final int tagId, final byte[] data) {
			this.tagId = tagId;
			this.data = data;
		}

/**
 * getTagId operation.
 * @return the resulting value.
 */
		public int getTagId() {
			return tagId;
		}

/**
 * setTagId operation.
 * @param tagId the tagId value.
 */
		public void setTagId(final int tagId) {
			this.tagId = tagId;
		}

/**
 * getData operation.
 * @return the resulting value.
 */
		public byte[] getData() {
			return data;
		}

/**
 * setData operation.
 * @param data the data value.
 */
		public void setData(final byte[] data) {
			this.data = data;
		}

		@Override
/**
 * toString operation.
 * @return the resulting value.
 */
		public String toString() {
			return tagId + " (length " + data.length + "): " + Arrays.toString(data);
		}
	}
}
