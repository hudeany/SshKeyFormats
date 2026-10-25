package de.soderer.sshkeyformats.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class BitUtilitiesTest {
	@Test
	public void testUnsignedValues() {
		assertEquals(0, BitUtilities.getUnsignedValue((byte) 0));
		assertEquals(127, BitUtilities.getUnsignedValue((byte) 127));
		assertEquals(128, BitUtilities.getUnsignedValue((byte) -128));
		assertEquals(255, BitUtilities.getUnsignedValue((byte) -1));
		assertArrayEquals(new int[] { 0, 255, 128 }, BitUtilities.getUnsignedValue(new byte[] { 0, -1, -128 }));
		assertArrayEquals(new int[0], BitUtilities.getUnsignedValue(new byte[0]));
	}

	@Test
	public void testUnsignedAsByte() {
		assertEquals((byte) 0, BitUtilities.getUnsignedAsByte(0));
		assertEquals((byte) -1, BitUtilities.getUnsignedAsByte(255));
		assertEquals((byte) -128, BitUtilities.getUnsignedAsByte(128));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.getUnsignedAsByte(-1));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.getUnsignedAsByte(256));
	}

	@Test
	public void testBitStrings() {
		assertEquals("00000000", BitUtilities.getBitString((byte) 0));
		assertEquals("10000001", BitUtilities.getBitString((byte) 0x81));
		assertEquals("11111111", BitUtilities.getBitString((byte) -1));
		assertEquals("00000000000000000000000100000010", BitUtilities.getBitString(0x0102));
		assertEquals("11111111111111111111111111111111", BitUtilities.getBitString(-1));
		assertEquals("00000001 10000000", BitUtilities.getBitString(new byte[] { 1, (byte) 0x80 }));
		assertEquals("00000001-10000000", BitUtilities.getBitString(new byte[] { 1, (byte) 0x80 }, "-"));
		assertEquals("0000000110000000", BitUtilities.getBitString(new byte[] { 1, (byte) 0x80 }, null));
		assertEquals("", BitUtilities.getBitString(new byte[0]));
	}

	@Test
	public void testFromBitStrings() throws Exception {
		assertEquals((byte) 0x81, BitUtilities.getByteFromBitString("10000001"));
		assertEquals((byte) 5, BitUtilities.getByteFromBitString(" 101 "));
		assertEquals(0x0102, BitUtilities.getIntegerFromBitString("100000010"));
		assertEquals(-1, BitUtilities.getIntegerFromBitString("11111111111111111111111111111111"));

		assertThrows(Exception.class, () -> BitUtilities.getByteFromBitString(null));
		assertThrows(Exception.class, () -> BitUtilities.getByteFromBitString(""));
		assertThrows(Exception.class, () -> BitUtilities.getByteFromBitString("102"));
		assertThrows(Exception.class, () -> BitUtilities.getByteFromBitString("111111111"));
		assertThrows(Exception.class, () -> BitUtilities.getIntegerFromBitString(null));
		assertThrows(Exception.class, () -> BitUtilities.getIntegerFromBitString("2"));
		assertThrows(Exception.class, () -> BitUtilities.getIntegerFromBitString("111111111111111111111111111111111"));
	}

	@Test
	public void testFromHexString() {
		assertArrayEquals(new byte[] { 0x01, (byte) 0xAB, (byte) 0xFF }, BitUtilities.fromHexString("01abFF"));
		assertArrayEquals(new byte[] { 0x0A }, BitUtilities.fromHexString("0x0A"));
		assertArrayEquals(new byte[] { 0x0A }, BitUtilities.fromHexString("0X0a"));
		assertArrayEquals(new byte[0], BitUtilities.fromHexString(""));
		assertNull(BitUtilities.fromHexString(null));

		assertThrows(IllegalArgumentException.class, () -> BitUtilities.fromHexString("abc"));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.fromHexString("0g"));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.fromHexString("g0"));
		// Only ASCII digits are hex digits, not e.g. fullwidth digits
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.fromHexString("０１"));
	}

	@Test
	public void testFromHexStringIgnoringNonHexCharacters() {
		assertArrayEquals(new byte[] { 0x10, 0x20, (byte) 0xAB }, BitUtilities.fromHexString("10:20:ab", true));
		assertArrayEquals(new byte[] { 0x10, 0x20 }, BitUtilities.fromHexString("0x10 0x20", true));
		// An 'x' directly after a hex digit is a separator, not part of a prefix
		assertArrayEquals(new byte[] { 0x10, 0x20 }, BitUtilities.fromHexString("10x20", true));
		assertNull(BitUtilities.fromHexString(null, true));
		assertArrayEquals(new byte[] { 0x10 }, BitUtilities.fromHexString("10", false));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.fromHexString("10:20", false));
	}

	@Test
	public void testGetByteArrayFromHexString() {
		assertArrayEquals(new byte[] { 0x12, 0x34 }, BitUtilities.getByteArrayFromHexString("1234"));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.getByteArrayFromHexString(null));
	}

	@Test
	public void testToHexString() {
		// Without separator the digits are uppercase
		assertEquals("01ABFF", BitUtilities.toHexString(new byte[] { 0x01, (byte) 0xAB, (byte) 0xFF }));
		assertEquals("", BitUtilities.toHexString(new byte[0]));
		assertNull(BitUtilities.toHexString(null));

		// With separator the digits are lowercase
		assertEquals("01:ab:ff", BitUtilities.toHexString(new byte[] { 0x01, (byte) 0xAB, (byte) 0xFF }, ":"));
		assertEquals("01abff", BitUtilities.toHexString(new byte[] { 0x01, (byte) 0xAB, (byte) 0xFF }, null));
		assertNull(BitUtilities.toHexString(null, ":"));
	}

	@Test
	public void testHexDump() {
		final byte[] data = new byte[] { 0x41, 0x42, 0x00, 0x7F, 0x20 };
		assertEquals("00000000h: 41 42 ; AB\n00000002h: 00 7F ; ..\n00000004h: 20    ;  ", BitUtilities.getHexString(data, " ", 2, true, true));
		assertEquals("41 42\n00 7F\n20", BitUtilities.getHexString(data, " ", 2, false, false));
		assertEquals("4142007F20", BitUtilities.getHexString(data, null, 0, false, false));
		assertEquals("41-42-00-7F-20 ; AB.. ", BitUtilities.getHexString(data, "-", 0, false, true));
		// A complete last line needs no filling before the ASCII text
		assertEquals("4142 ; AB\n007F ; ..", BitUtilities.getHexString(Arrays.copyOf(data, 4), null, 2, false, true));
		// Filling without separator
		assertEquals("4142 ; AB\n00   ; .", BitUtilities.getHexString(Arrays.copyOf(data, 3), null, 2, false, true));
		assertEquals("", BitUtilities.getHexString(new byte[0], " ", 16, true, true));
		assertNull(BitUtilities.getHexString(null, " ", 16, true, true));
		// Negative bytes are no printable ASCII characters
		assertEquals("FF ; .", BitUtilities.getHexString(new byte[] { -1 }, " ", 0, false, true));
	}

	@Test
	public void testXorOfArrays() {
		assertArrayEquals(new byte[] { 0x03, 0x00 }, BitUtilities.xor(new byte[] { 0x01, 0x0F }, new byte[] { 0x02, 0x0F }));
		assertArrayEquals(new byte[] { 0x07 }, BitUtilities.xor(List.of(new byte[] { 0x01 }, new byte[] { 0x02 }, new byte[] { 0x04 })));
		final byte[] single = new byte[] { 0x05 };
		assertArrayEquals(single, BitUtilities.xor(new byte[][] { single }));

		assertThrows(IllegalArgumentException.class, () -> BitUtilities.xor((byte[][]) null));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.xor((List<byte[]>) null));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.xor(List.of()));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.xor(new byte[] { 1 }, null));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.xor(new byte[] { 1 }, new byte[] { 1, 2 }));
	}

	@Test
	public void testXorOfBytes() {
		assertEquals((byte) 0x07, BitUtilities.xor((byte) 0x01, (byte) 0x02, (byte) 0x04));
		assertEquals((byte) 0, BitUtilities.xor((byte) 0x55, (byte) 0x55));
		assertEquals((byte) 0, BitUtilities.xor(new byte[0]));
	}

	@Test
	public void testJoinByteArrays() {
		assertArrayEquals(new byte[] { 1, 2, 3 }, BitUtilities.joinByteArrays(new byte[] { 1 }, new byte[0], new byte[] { 2, 3 }));
		assertArrayEquals(new byte[0], BitUtilities.joinByteArrays());
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.joinByteArrays((byte[][]) null));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.joinByteArrays(new byte[] { 1 }, null));
	}

	@Test
	public void testLengthCodedPadding() {
		final byte[] padded = BitUtilities.addLengthCodedPadding(new byte[] { 1, 2, 3 }, 4);
		assertArrayEquals(new byte[] { 1, 2, 3, 1 }, padded);
		assertArrayEquals(new byte[] { 1, 2, 3 }, BitUtilities.removeLengthCodedPadding(padded, 4));

		// Data of a multiple of the padding size gets a whole padding block
		final byte[] fullBlockPadded = BitUtilities.addLengthCodedPadding(new byte[] { 1, 2 }, 2);
		assertArrayEquals(new byte[] { 1, 2, 2, 2 }, fullBlockPadded);
		assertArrayEquals(new byte[] { 1, 2 }, BitUtilities.removeLengthCodedPadding(fullBlockPadded, 2));

		assertArrayEquals(new byte[] { 8, 8, 8, 8, 8, 8, 8, 8 }, BitUtilities.addLengthCodedPadding(new byte[0], 8));
	}

	@Test
	public void testLengthCodedPaddingErrors() {
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.addLengthCodedPadding(new byte[1], 0));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.addLengthCodedPadding(new byte[1], 256));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[4], 0));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[4], 256));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(null, 4));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[0], 4));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[3], 4));
		// Padding length 0 and too large padding lengths are invalid
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[] { 1, 2, 3, 0 }, 4));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[] { 5, 5, 5, 5 }, 4));
		// All padding bytes must contain the padding length
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.removeLengthCodedPadding(new byte[] { 1, 3, 2, 3 }, 4));
	}

	@Test
	public void testRandomPadding() {
		final byte[] data = new byte[] { 1, 2, 3 };
		final byte[] padded = BitUtilities.addRandomPadding(data, 8);
		assertEquals(8, padded.length);
		assertArrayEquals(data, Arrays.copyOf(padded, 3));

		// Data of a multiple of the padding size is returned as copy
		final byte[] fullBlock = new byte[] { 1, 2, 3, 4 };
		final byte[] notPadded = BitUtilities.addRandomPadding(fullBlock, 4);
		assertArrayEquals(fullBlock, notPadded);
		assertNotSame(fullBlock, notPadded);

		assertThrows(IllegalArgumentException.class, () -> BitUtilities.addRandomPadding(data, 0));
	}

	@Test
	public void testHexBytes() {
		assertEquals((byte) 0xAB, BitUtilities.hexToByte("ab"));
		assertEquals((byte) 0xAB, BitUtilities.hexToByte("AB"));
		assertEquals((byte) 0x09, BitUtilities.hexToByte("09xyz"));
		assertEquals((byte) 0x9F, BitUtilities.hexToByte('9', 'f'));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.hexToByte(null));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.hexToByte("a"));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.hexToByte('g', '0'));
		assertThrows(IllegalArgumentException.class, () -> BitUtilities.hexToByte('0', 'G'));

		assertEquals("00", BitUtilities.byteToHex((byte) 0));
		assertEquals("7F", BitUtilities.byteToHex((byte) 0x7F));
		assertEquals("FF", BitUtilities.byteToHex((byte) -1));
	}

	@Test
	public void testHexRoundTrip() {
		final byte[] data = new byte[256];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) i;
		}
		assertArrayEquals(data, BitUtilities.fromHexString(BitUtilities.toHexString(data)));
		assertArrayEquals(data, BitUtilities.fromHexString(BitUtilities.toHexString(data, ":"), true));
		assertTrue(BitUtilities.toHexString(data, ":").startsWith("00:01:02"));
	}
}
