package de.soderer.sshkeyformats;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import de.soderer.sshkeyformats.data.Asn1Codec;
import de.soderer.sshkeyformats.data.OID;

/**
 * Builders for DER, PEM and SSH wire format data, used to create manipulated key files in tests.
 */
final class TestKeyData {
	private TestKeyData() {
		// Utility class
	}

	// DER

	static byte[] derSequence(final byte[]... items) throws IOException {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE, items);
	}

	static byte[] derInteger(final long value) throws IOException {
		return derInteger(BigInteger.valueOf(value));
	}

	static byte[] derInteger(final BigInteger value) throws IOException {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, value.toByteArray());
	}

	static byte[] derOctetString(final byte[] data) throws IOException {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OCTET_STRING, data);
	}

	static byte[] derBitString(final byte[] dataWithUnusedBitsPrefix) throws IOException {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_BIT_STRING, dataWithUnusedBitsPrefix);
	}

	static byte[] derOid(final String oid) throws Exception {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OBJECT, new OID(oid).getByteArrayEncoding());
	}

	static byte[] derNull() throws IOException {
		return Asn1Codec.createDerTagData(0x05);
	}

	static byte[] derContext0(final byte[] content) throws IOException {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_0, content);
	}

	static byte[] derContext1(final byte[] content) throws IOException {
		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_1, content);
	}

	// PEM

	/**
	 * Creates a PEM block, headers are given as "Name: value" lines.
	 */
	static byte[] pem(final String typeName, final byte[] data, final String... headerLines) {
		final StringBuilder pem = new StringBuilder();
		pem.append("-----BEGIN ").append(typeName).append("-----\n");
		for (final String headerLine : headerLines) {
			pem.append(headerLine).append("\n");
		}
		if (headerLines.length > 0) {
			pem.append("\n");
		}
		pem.append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(data)).append("\n");
		pem.append("-----END ").append(typeName).append("-----\n");
		return pem.toString().getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Decodes the base64 data of a PEM block without headers.
	 */
	static byte[] decodePem(final String pemText) {
		return Base64.getMimeDecoder().decode(pemText.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
	}

	// SSH wire format

	/**
	 * Writer for SSH wire format data (uint32, string, mpint).
	 */
	static final class WireWriter {
		private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		private final DataOutputStream output = new DataOutputStream(buffer);

		WireWriter writeInt(final int value) throws IOException {
			output.writeInt(value);
			return this;
		}

		WireWriter writeData(final byte[] data) throws IOException {
			output.writeInt(data.length);
			output.write(data);
			return this;
		}

		WireWriter writeString(final String value) throws IOException {
			return writeData(value.getBytes(StandardCharsets.UTF_8));
		}

		WireWriter writeBigInt(final BigInteger value) throws IOException {
			return writeData(value.toByteArray());
		}

		WireWriter writeRaw(final byte[] data) throws IOException {
			output.write(data);
			return this;
		}

		byte[] toByteArray() {
			return buffer.toByteArray();
		}
	}

	/**
	 * Parts of an OpenSSH v1 private key file ("openssh-key-v1"), which can be changed and composed again.
	 */
	static final class OpenSshv1Parts {
		String magic;
		String cipherName;
		String kdfName;
		byte[] kdfOptions;
		int numberOfKeys;
		byte[] publicKey;
		byte[] privateKeyBlock;
		byte[] trailingData = new byte[0];

		static OpenSshv1Parts parse(final String pemText) throws IOException {
			final DataInputStream input = new DataInputStream(new ByteArrayInputStream(decodePem(pemText)));
			final OpenSshv1Parts parts = new OpenSshv1Parts();
			final ByteArrayOutputStream magicBuffer = new ByteArrayOutputStream();
			int nextByte;
			while ((nextByte = input.readUnsignedByte()) != 0) {
				magicBuffer.write(nextByte);
			}
			parts.magic = magicBuffer.toString(StandardCharsets.UTF_8);
			parts.cipherName = new String(readData(input), StandardCharsets.UTF_8);
			parts.kdfName = new String(readData(input), StandardCharsets.UTF_8);
			parts.kdfOptions = readData(input);
			parts.numberOfKeys = input.readInt();
			parts.publicKey = readData(input);
			parts.privateKeyBlock = readData(input);
			return parts;
		}

		byte[] toPem() throws IOException {
			final WireWriter writer = new WireWriter();
			writer.writeRaw(magic.getBytes(StandardCharsets.UTF_8)).writeRaw(new byte[] { 0 });
			writer.writeString(cipherName).writeString(kdfName).writeData(kdfOptions);
			writer.writeInt(numberOfKeys).writeData(publicKey).writeData(privateKeyBlock);
			writer.writeRaw(trailingData);
			return pem("OPENSSH PRIVATE KEY", writer.toByteArray());
		}
	}

	private static byte[] readData(final DataInputStream input) throws IOException {
		final byte[] data = new byte[input.readInt()];
		input.readFully(data);
		return data;
	}

	/**
	 * Splits a text into lines (without line breaks).
	 */
	static List<String> lines(final String text) {
		final List<String> lines = new ArrayList<>();
		for (final String line : text.split("\r?\n")) {
			lines.add(line);
		}
		return lines;
	}
}
