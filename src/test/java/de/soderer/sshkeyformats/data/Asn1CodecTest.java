package de.soderer.sshkeyformats.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.data.Asn1Codec.DerTag;

@SuppressWarnings("static-method")
public class Asn1CodecTest {
	@Test
	public void testAsnEncodedLength() throws Exception {
		assertArrayEquals(new byte[] { 0x00 }, Asn1Codec.getAsnEncodedInteger(0));
		assertArrayEquals(new byte[] { 0x7F }, Asn1Codec.getAsnEncodedInteger(127));
		// Long form: 0x80 combined with the number of length bytes, without leading zero byte
		assertArrayEquals(new byte[] { (byte) 0x81, (byte) 0x80 }, Asn1Codec.getAsnEncodedInteger(128));
		assertArrayEquals(new byte[] { (byte) 0x81, (byte) 0xFF }, Asn1Codec.getAsnEncodedInteger(255));
		assertArrayEquals(new byte[] { (byte) 0x82, 0x01, 0x00 }, Asn1Codec.getAsnEncodedInteger(256));
		assertArrayEquals(new byte[] { (byte) 0x83, 0x01, 0x00, 0x00 }, Asn1Codec.getAsnEncodedInteger(65536));
		assertThrows(Exception.class, () -> Asn1Codec.getAsnEncodedInteger(-1));
	}

	@Test
	public void testParseAsnEncodedInteger() throws Exception {
		// Short form length
		assertEquals(BigInteger.valueOf(5), Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x01, 0x05 }, 0));
		// Two's complement value
		assertEquals(BigInteger.valueOf(-1), Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x01, (byte) 0xFF }, 0));
		assertEquals(BigInteger.valueOf(255), Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x02, 0x00, (byte) 0xFF }, 0));
		// Offset within the data and trailing data
		assertEquals(BigInteger.valueOf(0x0102), Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x02, 0x02, 0x01, 0x02, 0x7F }, 1));

		// Long form length
		final byte[] longFormData = new byte[3 + 200];
		longFormData[0] = (byte) 0x82;
		longFormData[1] = 0x00;
		longFormData[2] = (byte) 200;
		longFormData[3 + 199] = 0x01;
		assertEquals(BigInteger.ONE, Asn1Codec.parseAsnEncodedInteger(longFormData, 0));
	}

	@Test
	public void testParseAsnEncodedIntegerErrors() {
		assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(null, 0));
		assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x01, 0x05 }, -1));
		assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x01, 0x05 }, 2));
		// Indefinite length
		assertTrue(assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { (byte) 0x80, 0x05 }, 0)).getMessage().contains("indefinite"));
		// Too many length bytes
		assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { (byte) 0x85, 1, 1, 1, 1, 1, 1 }, 0));
		// Truncated length bytes
		assertTrue(assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { (byte) 0x82, 0x01 }, 0)).getMessage().contains("Truncated"));
		// Empty content
		assertTrue(assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x00 }, 0)).getMessage().contains("empty content"));
		// Truncated content
		assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { 0x03, 0x01 }, 0));
		assertThrows(Exception.class, () -> Asn1Codec.parseAsnEncodedInteger(new byte[] { (byte) 0x84, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x01 }, 0));
	}

	@Test
	public void testCreateAndReadDerTag() throws Exception {
		final byte[] integerTag = Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, new byte[] { 0x05 });
		assertArrayEquals(new byte[] { 0x02, 0x01, 0x05 }, integerTag);

		final byte[] sequence = Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE, integerTag, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OCTET_STRING, new byte[200]));
		final DerTag sequenceTag = Asn1Codec.readDerTag(sequence);
		assertEquals(Asn1Codec.DER_TAG_SEQUENCE, sequenceTag.getTagId());

		final List<DerTag> innerTags = Asn1Codec.readDerTags(sequenceTag.getData());
		assertEquals(2, innerTags.size());
		assertEquals(Asn1Codec.DER_TAG_INTEGER, innerTags.get(0).getTagId());
		assertArrayEquals(new byte[] { 0x05 }, innerTags.get(0).getData());
		assertEquals(Asn1Codec.DER_TAG_OCTET_STRING, innerTags.get(1).getTagId());
		assertEquals(200, innerTags.get(1).getData().length);
	}

	@Test
	public void testCreateDerTagWithoutContent() throws Exception {
		assertArrayEquals(new byte[] { 0x05, 0x00 }, Asn1Codec.createDerTagData(0x05));
		assertArrayEquals(new byte[] { 0x05, 0x00 }, Asn1Codec.createDerTagData(0x05, (byte[][]) null));
		final DerTag emptyTag = Asn1Codec.readDerTag(new byte[] { 0x05, 0x00 });
		assertEquals(0, emptyTag.getData().length);
		assertTrue(Asn1Codec.readDerTags(new byte[0]).isEmpty());
	}

	@Test
	public void testCreateDerTagErrors() {
		assertThrows(IOException.class, () -> Asn1Codec.createDerTagData(-1, new byte[1]));
		assertThrows(IOException.class, () -> Asn1Codec.createDerTagData(0x100, new byte[1]));
		assertThrows(IOException.class, () -> Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE, new byte[1], null));
	}

	@Test
	public void testReadDerTagErrors() {
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(null));
		assertThrows(Exception.class, () -> Asn1Codec.readDerTags(null));
		// No tag at all
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[0]));
		// Missing length
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x02 }));
		// Indefinite length
		assertTrue(assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x30, (byte) 0x80 })).getMessage().contains("indefinite"));
		// Truncated long form length
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x04, (byte) 0x82, 0x01 }));
		// Length above the allowed maximum of 16 MB
		assertTrue(assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x04, (byte) 0x84, 0x02, 0x00, 0x00, 0x00 })).getMessage().contains("exceeds maximum"));
		// Content shorter than the length
		assertThrows(Exception.class, () -> Asn1Codec.readDerTag(new byte[] { 0x04, 0x05, 0x01 }));
	}

	@Test
	public void testDerTagAccessors() {
		final byte[] data = new byte[] { 1, 2 };
		final DerTag derTag = new DerTag(Asn1Codec.DER_TAG_OCTET_STRING, data);
		assertEquals("4 (length 2): [1, 2]", derTag.toString());

		derTag.setTagId(Asn1Codec.DER_TAG_BIT_STRING);
		assertEquals(Asn1Codec.DER_TAG_BIT_STRING, derTag.getTagId());

		final byte[] newData = new byte[] { 3 };
		derTag.setData(newData);
		// The data is copied
		newData[0] = 9;
		assertArrayEquals(new byte[] { 3 }, derTag.getData());

		derTag.setData(null);
		assertNull(derTag.getData());
		assertEquals("3 (no data)", derTag.toString());

		assertNull(new DerTag(Asn1Codec.DER_TAG_INTEGER, null).getData());
	}
}
