package de.soderer.sshkeyformats.data;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Immutable ASN.1 object identifier (OID).
 */
public final class OID {
	/** RSA encryption (1.2.840.113549.1.1.1). */
	public static final OID RSA_ALGORITHM = createConstant("1.2.840.113549.1.1.1");
	/** DSA (1.2.840.10040.4.1). */
	public static final OID DSA_ALGORITHM = createConstant("1.2.840.10040.4.1");
	/** EC public key (1.2.840.10045.2.1). */
	public static final OID ECDSA_PUBLICKEY = createConstant("1.2.840.10045.2.1");
	/** NIST P-256 / secp256r1 (1.2.840.10045.3.1.7). */
	public static final OID ECDSA_CURVE_NISTP256 = createConstant("1.2.840.10045.3.1.7");
	/** NIST P-384 / secp384r1 (1.3.132.0.34). */
	public static final OID ECDSA_CURVE_NISTP384 = createConstant("1.3.132.0.34");
	/** NIST P-521 / secp521r1 (1.3.132.0.35). */
	public static final OID ECDSA_CURVE_NISTP521 = createConstant("1.3.132.0.35");
	/** Ed25519 (1.3.101.112). */
	public static final OID EDDSA25519_ALGORITHM = createConstant("1.3.101.112");
	/** Ed448 (1.3.101.113). */
	public static final OID EDDSA448_ALGORITHM = createConstant("1.3.101.113");

	private final long[] id;
	private final byte[] encoding;

	private static OID createConstant(final String oidString) {
		try {
			return new OID(oidString);
		} catch (final Exception e) {
			throw new IllegalStateException("Invalid OID constant: " + oidString, e);
		}
	}

	/**
	 * Creates an OID from its dotted string representation, e.g. "1.2.840.10045.2.1".
	 *
	 * @param oidString the dotted OID string
	 * @throws Exception if the string is not a valid OID
	 */
	public OID(final String oidString) throws Exception {
		if (oidString == null || "".equals(oidString.trim())) {
			throw new Exception("Invalid OID empty data");
		}
		final String[] parts = oidString.trim().split("\\.");
		if (parts.length < 2) {
			throw new Exception("Invalid OID data (at least two arcs needed): " + oidString);
		}
		id = new long[parts.length];
		for (int i = 0; i < parts.length; i++) {
			try {
				id[i] = Long.parseLong(parts[i]);
			} catch (final Exception e) {
				throw new Exception("Invalid OID data: " + oidString, e);
			}
			if (id[i] < 0) {
				throw new Exception("Invalid OID data: " + oidString);
			}
		}
		if (id[0] > 2 || (id[0] < 2 && id[1] > 39)) {
			throw new Exception("Invalid OID data: " + oidString);
		}
		encoding = encode(id);
	}

	/**
	 * Creates an OID from its DER content encoding (without tag and length bytes).
	 *
	 * @param oidArray the DER content bytes of the OID
	 * @throws Exception if the data is not a valid OID encoding
	 */
	public OID(final byte[] oidArray) throws Exception {
		if (oidArray == null || oidArray.length == 0) {
			throw new Exception("Invalid OID empty data");
		}
		final List<Long> idList = new ArrayList<>();
		int index = 0;
		while (index < oidArray.length) {
			long value = 0;
			int bytesOfValue = 0;
			while (true) {
				if (index >= oidArray.length) {
					throw new Exception("Invalid encoded OID data: Final byte sign is missing");
				}
				final int nextByte = oidArray[index++] & 0xFF;
				if (++bytesOfValue > 8) {
					throw new Exception("Invalid encoded OID data: Sub identifier too large");
				}
				value = (value << 7) | (nextByte & 0x7F);
				if ((nextByte & 0x80) == 0) {
					break;
				}
			}
			if (idList.isEmpty()) {
				// First sub identifier combines the first two arcs (X.690 8.19.4)
				if (value < 40) {
					idList.add(0L);
					idList.add(value);
				} else if (value < 80) {
					idList.add(1L);
					idList.add(value - 40);
				} else {
					idList.add(2L);
					idList.add(value - 80);
				}
			} else {
				idList.add(value);
			}
		}
		id = idList.stream().mapToLong(Long::longValue).toArray();
		encoding = oidArray.clone();
	}

	/**
	 * Returns the dotted string representation of this OID.
	 *
	 * @return the dotted OID string
	 */
	public String getStringEncoding() {
		final StringBuilder returnValue = new StringBuilder();
		for (final long idPart : id) {
			if (returnValue.length() > 0) {
				returnValue.append(".");
			}
			returnValue.append(idPart);
		}
		return returnValue.toString();
	}

	/**
	 * Returns a copy of the DER content encoding (without tag and length bytes).
	 *
	 * @return the DER content bytes of this OID
	 */
	public byte[] getByteArrayEncoding() {
		return encoding.clone();
	}

	/**
	 * Checks whether the given DER content encoding represents this OID.
	 *
	 * @param oidEncoding the DER content bytes to compare
	 * @return true if the encoding equals the encoding of this OID
	 */
	public boolean matches(final byte[] oidEncoding) {
		return oidEncoding != null && Arrays.equals(encoding, oidEncoding);
	}

	@Override
	public boolean equals(final Object other) {
		return other instanceof OID && Arrays.equals(encoding, ((OID) other).encoding);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(encoding);
	}

	@Override
	public String toString() {
		return getStringEncoding();
	}

	private static byte[] encode(final long[] id) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] first = encodeInteger(id[0] * 40 + id[1]);
		out.write(first, 0, first.length);
		for (int i = 2; i < id.length; i++) {
			final byte[] next = encodeInteger(id[i]);
			out.write(next, 0, next.length);
		}
		return out.toByteArray();
	}

	/**
	 * Encodes a non-negative value as base-128 sub identifier.
	 *
	 * @param value the value to encode
	 * @return the encoded bytes
	 */
	public static byte[] encodeInteger(final long value) {
		if (value < 0) {
			throw new IllegalArgumentException("Minimum encoded Integer underrun");
		} else if (value < 0x80) {
			return new byte[] { (byte) value };
		} else {
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			long buffer = value;
			out.write((byte) (buffer & 0x7F));
			buffer = (buffer >> 7);
			while (buffer > 0) {
				out.write((byte) (0x80 | (buffer & 0x7F)));
				buffer = buffer >> 7;
			}
			final byte[] returnArray = out.toByteArray();
			for (int i = 0; i < returnArray.length / 2; i++) {
				final byte swap = returnArray[i];
				returnArray[i] = returnArray[returnArray.length - 1 - i];
				returnArray[returnArray.length - 1 - i] = swap;
			}
			return returnArray;
		}
	}
}
