package de.soderer.sshkeyformats.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class PasswordAndBCryptPBKDFTest {
	@Test
	public void testPasswordWithoutChars() {
		try (Password password = new Password(null)) {
			assertFalse(password.hasPassword());
			assertNull(password.getPasswordChars());
			assertNull(password.getPasswordBytesUtfEncoded());
			assertNull(password.getPasswordBytesIsoEncoded());
		}
		try (Password password = new Password(new char[0])) {
			assertFalse(password.hasPassword());
			assertArrayEquals(new byte[0], password.getPasswordBytesUtfEncoded());
		}
	}

	@Test
	public void testPasswordEncodingsAreCached() {
		try (Password password = new Password("Ä".toCharArray())) {
			assertTrue(password.hasPassword());
			assertArrayEquals("Ä".getBytes(StandardCharsets.UTF_8), password.getPasswordBytesUtfEncoded());
			assertArrayEquals("Ä".getBytes(StandardCharsets.UTF_8), password.getPasswordBytesUtfEncoded());
			assertArrayEquals("Ä".getBytes(StandardCharsets.ISO_8859_1), password.getPasswordBytesIsoEncoded());
			assertArrayEquals("Ä".getBytes(StandardCharsets.ISO_8859_1), password.getPasswordBytesIsoEncoded());
		}
	}

	@Test
	public void testAdditionalSensitiveDataIsCleared() {
		final byte[] sensitiveData = new byte[] { 1, 2, 3 };
		try (final Password password = new Password("secret".toCharArray())) {
			password.addSensitiveDataToCleanup(sensitiveData);
			password.addSensitiveDataToCleanup(null);
			password.close();
			assertArrayEquals(new byte[3], sensitiveData);
			assertFalse(password.hasPassword());
		}
	}

	@Test
	public void testBCryptPBKDFParameterChecks() {
		final BCryptPBKDF bcrypt = new BCryptPBKDF();
		final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = new byte[16];
		final byte[] output = new byte[32];

		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(null, salt, 1, output));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(new byte[0], salt, 1, output));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, null, 1, output));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, new byte[0], 1, output));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, new byte[BCryptPBKDF.MAX_SALT_LENGTH + 1], 1, output));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, salt, 0, output));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, salt, 1, null));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, salt, 1, new byte[0]));
		assertThrows(IllegalArgumentException.class, () -> bcrypt.derivePassword(password, salt, 1, new byte[BCryptPBKDF.MAX_OUTPUT_LENGTH + 1]));
	}

	@Test
	public void testBCryptPBKDFIsDeterministic() throws Exception {
		final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);

		final byte[] output1 = new byte[48];
		new BCryptPBKDF().derivePassword(password, salt, 2, output1);
		final byte[] output2 = new byte[48];
		new BCryptPBKDF().derivePassword(password, salt, 2, output2);
		assertArrayEquals(output1, output2);
		assertFalse(Arrays.equals(new byte[48], output1));

		// Other salt, other result
		final byte[] output3 = new byte[48];
		new BCryptPBKDF().derivePassword(password, "pepper".getBytes(StandardCharsets.UTF_8), 2, output3);
		assertNotEquals(Arrays.toString(output1), Arrays.toString(output3));
	}
}
