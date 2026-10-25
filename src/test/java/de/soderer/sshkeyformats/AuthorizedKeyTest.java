package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.AuthorizedKeyException;
import de.soderer.sshkeyformats.data.AuthorizedKeyLineParser;

/**
 * Tests of the option accessors of {@link AuthorizedKey}, the generation of authorized_keys lines and the error
 * handling of {@link AuthorizedKeyLineParser}.
 */
@SuppressWarnings("static-method")
public class AuthorizedKeyTest {
	private static final String ED25519_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX";

	@Test
	public void testFluentSettersAndGetters() throws Exception {
		final Map<String, String> environment = new LinkedHashMap<>();
		environment.put("A", "1");
		final AuthorizedKey key = new AuthorizedKey(Algorithm.ED25519, ED25519_KEY, "comment");
		assertSame(key, key
				.withEnvironment(environment)
				.withEnvironmentValue("B", "2")
				.withCommand("/bin/true")
				.withCertAuthority(true)
				.withFromList("10.0.0.0/8")
				.withNoAgentForwarding(true)
				.withNoPortForwarding(true)
				.withNoPty(true)
				.withNoUserRc(true)
				.withNoX11Forwarding(true)
				.withPermitOpen("host:22")
				.withPrincipals("alice,bob")
				.withTunnel("0")
				.withPermitListen("localhost:8080")
				.withExpiryTime("20301231")
				.withRestrict(true)
				.withAgentForwarding(true)
				.withPortForwarding(true)
				.withPty(true)
				.withUserRc(true)
				.withX11Forwarding(true)
				.withNoTouchRequired(true)
				.withVerifyRequired(true));

		assertEquals("1", key.getEnvironment().get("A"));
		assertEquals("2", key.getEnvironment().get("B"));
		assertEquals("/bin/true", key.getCommand());
		assertTrue(key.isCertAuthority());
		assertEquals("10.0.0.0/8", key.getFromList());
		assertTrue(key.isNoAgentForwarding());
		assertTrue(key.isNoPortForwarding());
		assertTrue(key.isNoPty());
		assertTrue(key.isNoUserRc());
		assertTrue(key.isNoX11Forwarding());
		assertEquals("host:22", key.getPermitOpen());
		assertEquals("alice,bob", key.getPrincipals());
		assertEquals("0", key.getTunnel());
		assertEquals("localhost:8080", key.getPermitListen());
		assertEquals("20301231", key.getExpiryTime());
		assertTrue(key.isRestrict());
		assertTrue(key.isAgentForwarding());
		assertTrue(key.isPortForwarding());
		assertTrue(key.isPty());
		assertTrue(key.isUserRc());
		assertTrue(key.isX11Forwarding());
		assertTrue(key.isNoTouchRequired());
		assertTrue(key.isVerifyRequired());
	}

	@Test
	public void testToAuthorizedKeysLineWithAllOptions() throws Exception {
		final AuthorizedKey key = new AuthorizedKey(Algorithm.ED25519, ED25519_KEY, " my comment ")
				.withRestrict(true)
				.withCertAuthority(true)
				.withCommand("echo \"hi\"")
				.withEnvironmentValue("NAME", "value")
				.withEnvironmentValue("EMPTY", null)
				.withExpiryTime("20301231")
				.withFromList("10.0.0.0/8")
				.withPrincipals("alice")
				.withTunnel("1")
				.withPermitOpen("a:1, ,b:2")
				.withPermitListen("c:3")
				.withNoAgentForwarding(true)
				.withPty(true)
				.withVerifyRequired(true);

		final String line = key.toAuthorizedKeysLine();
		assertEquals("restrict,cert-authority,command=\"echo \\\"hi\\\"\",environment=\"NAME=value\",environment=\"EMPTY=\",expiry-time=\"20301231\",from=\"10.0.0.0/8\","
				+ "principals=\"alice\",tunnel=\"1\",permitopen=\"a:1\",permitopen=\"b:2\",permitlisten=\"c:3\",no-agent-forwarding,pty,verify-required "
				+ "ssh-ed25519 " + ED25519_KEY + " my comment", line);

		// The line can be parsed again
		final AuthorizedKey parsedKey = AuthorizedKeyLineParser.parseAuthorizedKeyLine(line);
		assertEquals("echo \"hi\"", parsedKey.getCommand());
		assertEquals("value", parsedKey.getEnvironment().get("NAME"));
		assertEquals("", parsedKey.getEnvironment().get("EMPTY"));
		assertEquals("a:1,b:2", parsedKey.getPermitOpen());
		assertEquals("alice", parsedKey.getPrincipals());
		assertEquals("1", parsedKey.getTunnel());
		assertEquals("20301231", parsedKey.getExpiryTime());
		assertTrue(parsedKey.isCertAuthority());
		assertTrue(parsedKey.isRestrict());
		assertEquals(line, parsedKey.toAuthorizedKeysLine());
	}

	@Test
	public void testToAuthorizedKeysLineWithoutOptions() throws Exception {
		assertEquals("ssh-ed25519 " + ED25519_KEY, new AuthorizedKey(Algorithm.ED25519, ED25519_KEY).toAuthorizedKeysLine());
		// A blank comment is omitted
		assertEquals("ssh-ed25519 " + ED25519_KEY, new AuthorizedKey(Algorithm.ED25519, ED25519_KEY, "  ").toAuthorizedKeysLine());
	}

	@Test
	public void testLinebreaksInOptionValuesAreRejected() throws Exception {
		final AuthorizedKey key = new AuthorizedKey(Algorithm.ED25519, ED25519_KEY).withCommand("ls\nrm -rf /");
		assertThrows(IllegalArgumentException.class, () -> key.toAuthorizedKeysLine());
		final AuthorizedKey key2 = new AuthorizedKey(Algorithm.ED25519, ED25519_KEY).withFromList("a\rb");
		assertThrows(IllegalArgumentException.class, () -> key2.toAuthorizedKeysLine());
	}

	@Test
	public void testToString() throws Exception {
		assertEquals("ssh-ed25519 " + ED25519_KEY + " comment", new AuthorizedKey(Algorithm.ED25519, ED25519_KEY, "comment").toString());
		// toString contains no options
		assertEquals("ssh-ed25519 " + ED25519_KEY, new AuthorizedKey(Algorithm.ED25519, ED25519_KEY).withNoPty(true).toString());
	}

	@Test
	public void testHashIsCached() throws Exception {
		final AuthorizedKey key = new AuthorizedKey(Algorithm.ED25519, ED25519_KEY);
		final String hash = key.getHash();
		assertEquals("DDF0BB6EB54E22BB80C0F256C76D5ADF", hash);
		assertSame(hash, key.getHash());
		assertEquals(Algorithm.ED25519, key.getAlgorithm());
	}

	@Test
	public void testHashOfInvalidKeyString() throws Exception {
		// A key string without decodable public key data
		final AuthorizedKey key = new AuthorizedKey(Algorithm.ED25519, "AAAA");
		assertThrows(Exception.class, () -> key.getHash());

		// A key string, which is read as comment line, contains no key at all
		final AuthorizedKey commentKey = new AuthorizedKey(Algorithm.ED25519, "#comment");
		assertTrue(assertThrows(Exception.class, () -> commentKey.getHash()).getMessage().contains("No public key data found"));
	}

	@Test
	public void testDefaultFlags() throws Exception {
		final AuthorizedKey key = new AuthorizedKey(Algorithm.RSA, ED25519_KEY);
		assertFalse(key.isCertAuthority());
		assertFalse(key.isRestrict());
		assertFalse(key.isNoPty());
		assertNull(key.getEnvironment());
		assertNull(key.getComment());
		key.setEnvironment(null);
		assertNull(key.getEnvironment());
	}

	@Test
	public void testParserErrors() {
		assertThrows(AuthorizedKeyException.class, () -> AuthorizedKeyLineParser.parseAuthorizedKeyLine(null));
		for (final String invalidLine : new String[] {
				// Invalid environment variable name
				"environment=\"A-B=1\" ssh-ed25519 " + ED25519_KEY,
				// Option without the required value
				"permitopen ssh-ed25519 " + ED25519_KEY,
				// Trailing comma
				"no-pty, ssh-ed25519 " + ED25519_KEY,
				// Unescaped quote within the value
				"command=\"a\"b\"\" ssh-ed25519 " + ED25519_KEY,
				// Unclosed quote
				"command=\"abc ssh-ed25519 " + ED25519_KEY,
				// Only options
				"no-pty" }) {
			assertThrows(AuthorizedKeyException.class, () -> AuthorizedKeyLineParser.parseAuthorizedKeyLine(invalidLine), invalidLine);
		}
	}
}
