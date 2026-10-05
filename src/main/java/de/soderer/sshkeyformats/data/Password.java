package de.soderer.sshkeyformats.data;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Wrapper for password charArrays.<br />
 * This wrapper is closeable and autocloseable, so that IDE warnings will pop up if this Object is not closed.<br />
 * The close action removes the password data from memory.<br />
 * <br />
 * Watchout:<br />
 * If the constructor parameter passwordChars is an object that was not created only for this Password, ist will be cleared after closing the Password Object.<br />
 * If you want to keep the original passwordChars for later use outside of the Password object use "new Password(passwordChars.clone())"<br />
 */
public class Password implements Closeable {
	private char[] passwordChars = null;
	private byte[] passwordBytesUtfEncoded = null;
	private byte[] passwordBytesIsoEncoded = null;
	private final List<byte[]> sensitiveDataToCleanup = new ArrayList<>();

/**
 * Password operation.
 * @param passwordChars the passwordChars value.
 */
	public Password(final char[] passwordChars) {
		this.passwordChars = passwordChars;
	}

/**
 * getPasswordChars operation.
 * @return the resulting value.
 */
	public char[] getPasswordChars() {
		return passwordChars;
	}

/**
 * getPasswordBytesUtfEncoded operation.
 * @return the resulting value.
 */
	public byte[] getPasswordBytesUtfEncoded() {
		if (passwordBytesUtfEncoded == null) {
			passwordBytesUtfEncoded = encodeCharArrayToByteArray(passwordChars, StandardCharsets.UTF_8);
		}
		return passwordBytesUtfEncoded;
	}

/**
 * getPasswordBytesIsoEncoded operation.
 * @return the resulting value.
 */
	public byte[] getPasswordBytesIsoEncoded() {
		if (passwordBytesIsoEncoded == null) {
			passwordBytesIsoEncoded = encodeCharArrayToByteArray(passwordChars, StandardCharsets.ISO_8859_1);
		}
		return passwordBytesIsoEncoded;
	}

/**
 * addSensitiveDataToCleanup operation.
 * @param sensitiveData the sensitiveData value.
 */
	public void addSensitiveDataToCleanup(final byte[] sensitiveData) {
		sensitiveDataToCleanup.add(sensitiveData);
	}

	@Override
/**
 * close operation.
 */
	public void close() {
		if (passwordChars != null) {
			Arrays.fill(passwordChars, (char) 0);
			passwordChars = null;
		}
		if (passwordBytesIsoEncoded != null) {
			Arrays.fill(passwordBytesIsoEncoded, (byte) 0);
			passwordBytesIsoEncoded = null;
		}
		if (passwordBytesIsoEncoded != null) {
			Arrays.fill(passwordBytesIsoEncoded, (byte) 0);
			passwordBytesIsoEncoded = null;
		}
		for (final byte[] sensitiveData : sensitiveDataToCleanup) {
			if (sensitiveData != null) {
				Arrays.fill(sensitiveData, (byte) 0);
			}
		}
	}

	private static byte[] encodeCharArrayToByteArray(final char[] chars, final Charset encoding) {
		ByteBuffer byteBuffer = null;
		try {
			byteBuffer = encoding.encode(CharBuffer.wrap(chars));
			return Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		} finally {
			if (byteBuffer != null && byteBuffer.array() != null) {
				Arrays.fill(byteBuffer.array(), (byte) 0);
				byteBuffer = null;
			}
		}

	}
}
