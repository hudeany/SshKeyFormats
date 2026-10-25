package de.soderer.sshkeyformats.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class OIDTest {
	@Test
	public void testStringRoundTrip() throws Exception {
		final OID oid = new OID("1.2.840.113549.1.1.1");
		assertEquals("1.2.840.113549.1.1.1", oid.getStringEncoding());
		assertEquals("1.2.840.113549.1.1.1", oid.toString());
		assertArrayEquals(new byte[] { 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01 }, oid.getByteArrayEncoding());
		assertEquals(oid, new OID(oid.getByteArrayEncoding()));
		assertEquals(" 1.3.101.112 ".trim(), new OID(" 1.3.101.112 ").getStringEncoding());
	}

	@Test
	public void testFirstArcsOfByteEncoding() throws Exception {
		// The first byte combines the first two arcs: 0.x (below 40), 1.x (below 80), 2.x (all others)
		assertEquals("0.9.2342", new OID(new byte[] { 0x09, (byte) 0x92, 0x26 }).getStringEncoding());
		assertEquals("1.3.132.0.34", new OID(new byte[] { 0x2B, (byte) 0x81, 0x04, 0x00, 0x22 }).getStringEncoding());
		assertEquals("2.16.840", new OID(new byte[] { 0x60, (byte) 0x86, 0x48 }).getStringEncoding());
		assertEquals("2.100", new OID("2.100").getStringEncoding());
		assertEquals("2.100", new OID(new OID("2.100").getByteArrayEncoding()).getStringEncoding());
		assertEquals("0.0", new OID("0.0").getStringEncoding());
	}

	@Test
	public void testInvalidStrings() {
		assertThrows(Exception.class, () -> new OID((String) null));
		assertThrows(Exception.class, () -> new OID(" "));
		assertThrows(Exception.class, () -> new OID("1"));
		assertThrows(Exception.class, () -> new OID("1.a.3"));
		assertThrows(Exception.class, () -> new OID("1.-2.3"));
		// First arc greater than 2, second arc greater than 39 below the first arc 2
		assertThrows(Exception.class, () -> new OID("3.1"));
		assertThrows(Exception.class, () -> new OID("1.40"));
		assertThrows(Exception.class, () -> new OID("0.40"));
	}

	@Test
	public void testInvalidByteEncodings() {
		assertThrows(Exception.class, () -> new OID((byte[]) null));
		assertThrows(Exception.class, () -> new OID(new byte[0]));
		// Last byte still has the continuation bit
		assertTrue(assertThrows(Exception.class, () -> new OID(new byte[] { 0x2A, (byte) 0x86 })).getMessage().contains("Final byte"));
		// Sub identifier with more than 8 bytes
		assertTrue(assertThrows(Exception.class, () -> new OID(new byte[] { 0x2A, (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, 0x01 })).getMessage().contains("too large"));
	}

	@Test
	public void testMatchesEqualsAndHashCode() throws Exception {
		final OID oid = new OID("1.3.132.0.35");
		assertTrue(OID.ECDSA_CURVE_NISTP521.matches(oid.getByteArrayEncoding()));
		assertFalse(OID.ECDSA_CURVE_NISTP384.matches(oid.getByteArrayEncoding()));
		assertFalse(oid.matches(null));

		assertEquals(OID.ECDSA_CURVE_NISTP521, oid);
		assertEquals(OID.ECDSA_CURVE_NISTP521.hashCode(), oid.hashCode());
		assertNotEquals(OID.ECDSA_CURVE_NISTP384, oid);
		assertNotEquals("1.3.132.0.35", oid);
	}

	@Test
	public void testEncodeInteger() {
		assertArrayEquals(new byte[] { 0x00 }, OID.encodeInteger(0));
		assertArrayEquals(new byte[] { 0x7F }, OID.encodeInteger(127));
		assertArrayEquals(new byte[] { (byte) 0x81, 0x00 }, OID.encodeInteger(128));
		assertArrayEquals(new byte[] { (byte) 0x86, 0x48 }, OID.encodeInteger(840));
		assertArrayEquals(new byte[] { (byte) 0x86, (byte) 0xF7, 0x0D }, OID.encodeInteger(113549));
		assertThrows(IllegalArgumentException.class, () -> OID.encodeInteger(-1));
	}
}
