package de.soderer.sshkeyformats.data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
 * getAsnEncodedInteger operation.
 * @param value the value value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static byte[] getAsnEncodedInteger(final long value) throws Exception {
		if (value < 0) {
			throw new Exception("Minimum ASN.1 encoded Integer underrun");
		} else if (value < 0x80) {
			return new byte[] { (byte) value };
		} else {
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] data = BigInteger.valueOf(value).toByteArray();
			if (data[0] == 0) {
				// Removed the obsolete sign bit, which caused an additional byte
				final byte[] tmp = new byte[data.length - 1];
				System.arraycopy(data, 1, tmp, 0, tmp.length);
				data = tmp;
			}
			if (data.length >= 0x80) {
				throw new Exception("Maximum ASN.1 encoded Integer exceeded");
			}
			out.write(0x80 | data.length);
			out.write(data);
			return out.toByteArray();
		}
	}

/**
 * parseAsnEncodedInteger operation.
 * @param data the data value.
 * @param offset the offset value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static BigInteger parseAsnEncodedInteger(final byte[] data, final int offset) throws Exception {
		try {
			final DataInput blockDataInput = new DataInputStream(new ByteArrayInputStream(data));
			blockDataInput.skipBytes(offset - 1);

			final int nextBlockSize = blockDataInput.readInt();
			if (nextBlockSize <= 0 || nextBlockSize > 513) {
				throw new Exception("Blocksize error");
			}
			final byte[] nextBlock = new byte[nextBlockSize];
			blockDataInput.readFully(nextBlock);
			return new BigInteger(nextBlock);
		} catch (final IOException e) {
			throw new Exception("Block read error", e);
		}
	}

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
 * readDerTag operation.
 * @param data the data value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static DerTag readDerTag(final byte[] data) throws Exception {
		try {
			final ByteArrayInputStream input = new ByteArrayInputStream(data);

			final int tagId = input.read();

			int tagLength;
			final int lengthIndicatingValue = input.read();
			if (lengthIndicatingValue < 0) {
				throw new Exception("Unexpected end of data while reading DER tag length");
			} else if (lengthIndicatingValue < 0x80) {
				tagLength = lengthIndicatingValue;
			} else {
				final int tagLengthBytesCount = lengthIndicatingValue - 0x80;
				tagLength = 0;
				for (int i = 0; i < tagLengthBytesCount; i++) {
					final int nextValue = input.read();
					if (nextValue < 0) {
						throw new Exception("Unexpected end of data while reading DER tag length");
					}
					tagLength = (tagLength << 8) + nextValue;
				}
			}

			if (tagLength > MAX_DER_TAG_DATA_LENGTH) {
				throw new Exception("DER tag length " + tagLength + " exceeds maximum allowed size of " + MAX_DER_TAG_DATA_LENGTH + " bytes");
			}

			// This tagLength might be invalid encoded, because of invalid decryption.
			// So to prevent out of memory exception, read from input up to tagLength and stop if input hits EOF.
			final ByteArrayOutputStream tagData = new ByteArrayOutputStream();
			final byte[] buffer = new byte[8192];
			int bytesRead = 0;
			int tagLengthLeftToRead = tagLength;
			while ((bytesRead = input.read(buffer, 0, tagLengthLeftToRead)) > 0) {
				tagData.write(buffer, 0, bytesRead);
				tagLengthLeftToRead = tagLengthLeftToRead - bytesRead;
			}
			final byte[] blockData = tagData.toByteArray();

			if (blockData.length != tagLength) {
				throw new Exception("Block length read error. Blocksize: " + data.length + " Tagsize: " + tagLength);
			} else {
				return new DerTag(tagId, tagData.toByteArray());
			}
		} catch (final IOException e) {
			throw new Exception("Block read error", e);
		}
	}

	/**
	 * Sanity upper bound for a single DER tag's data, to protect against maliciously crafted or
	 * corrupted key data that could otherwise force a huge memory allocation before any validation
	 * of the data has taken place (Denial of Service protection).
	 */
	private static final int MAX_DER_TAG_DATA_LENGTH = 16 * 1024 * 1024; // 16 MB

/**
 * readDerTags operation.
 * @param data the data value.
 * @return the resulting value.
 * @throws Exception if the operation cannot be completed.
 */
	public static List<DerTag> readDerTags(final byte[] data) throws Exception {
		try {
			final ByteArrayInputStream input = new ByteArrayInputStream(data);
			final List<DerTag> returnList = new ArrayList<>();
			while (input.available() > 0) {
				final int tagId = input.read();

				int tagLength;
				final int lengthIndicatingValue = input.read();
				if (lengthIndicatingValue < 0) {
					throw new Exception("Unexpected end of data while reading DER tag length");
				} else if (lengthIndicatingValue < 0x80) {
					tagLength = lengthIndicatingValue;
				} else {
					final int tagLengthBytesCount = lengthIndicatingValue & 0x7F;
					tagLength = 0;
					for (int i = 0; i < tagLengthBytesCount; i++) {
						final int nextByte = input.read();
						if (nextByte < 0) {
							throw new Exception("Unexpected end of data while reading DER tag length");
						}
						tagLength = (tagLength << 8) + nextByte;
					}
				}

				if (tagLength < 0) {
					throw new Exception("Invalid negative DER tag length: " + tagLength);
				} else if (tagLength > MAX_DER_TAG_DATA_LENGTH) {
					throw new Exception("DER tag length " + tagLength + " exceeds maximum allowed size of " + MAX_DER_TAG_DATA_LENGTH + " bytes");
				}

				final byte[] dataBlock = new byte[tagLength];
				int totalBytesRead = 0;
				while (totalBytesRead < dataBlock.length) {
					final int bytesRead = input.read(dataBlock, totalBytesRead, dataBlock.length - totalBytesRead);
					if (bytesRead < 0) {
						throw new Exception("Unexpected end of data while reading DER tag data of length " + tagLength);
					}
					totalBytesRead += bytesRead;
				}

				returnList.add(new DerTag(tagId, dataBlock));
			}
			return returnList;
		} catch (final IOException e) {
			throw new Exception("Block read error", e);
		}
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
