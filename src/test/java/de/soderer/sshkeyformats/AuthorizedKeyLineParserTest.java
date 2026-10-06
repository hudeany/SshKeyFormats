package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.AuthorizedKeyException;
import de.soderer.sshkeyformats.data.AuthorizedKeyLineParser;

/**
 * Tests for the authorized_keys line syntax as specified in sshd(8), section "AUTHORIZED_KEYS FILE FORMAT".
 */
@SuppressWarnings("static-method")
public class AuthorizedKeyLineParserTest {
	private static final String ED25519_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX";
	private static final String RSA_KEY = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCNaf7jmjy/WzwTjc5eseYVNK/tQIBIyIUt5RC64HU6gKgAn2mv538Yf0sMR7cq4qQzhosGD4xOJUh1LmQnHwJ4pWC9lhh3FwKk2kLDnOqULTOMUhnWSHKw/tweJsy81+mXettuyt102cQuqF9vIexmLwTv+bMvtM3bmTSYAuk9iw==";

	private static AuthorizedKey parse(final String line) throws Exception {
		return AuthorizedKeyLineParser.parseAuthorizedKeyLine(line);
	}

	@Test
	public void testWithoutOptions() throws Exception {
		final AuthorizedKey key1 = parse("ssh-ed25519 " + ED25519_KEY + " my comment");
		assertEquals(Algorithm.ED25519, key1.getKeyType());
		assertEquals(ED25519_KEY, key1.getKeyString());
		assertEquals("my comment", key1.getComment());
		assertNull(key1.getEnvironment());
		assertNull(key1.getCommand());

		final AuthorizedKey key2 = parse("ssh-ed25519 " + ED25519_KEY);
		assertNull(key2.getComment());

		final AuthorizedKey key3 = parse("  ssh-ed25519 \t " + ED25519_KEY + "   ");
		assertEquals(ED25519_KEY, key3.getKeyString());
		assertNull(key3.getComment());
		assertEquals("DDF0BB6EB54E22BB80C0F256C76D5ADF", key3.getHash());
	}

	@Test
	public void testOpenSshOptionSyntax() throws Exception {
		final AuthorizedKey key = parse("no-pty,command=\"ls -l /tmp\",from=\"10.0.0.0/8,*.example.com\" ssh-rsa " + RSA_KEY + " my comment");
		assertTrue(key.isNoPty());
		assertEquals("ls -l /tmp", key.getCommand());
		assertEquals("10.0.0.0/8,*.example.com", key.getFromList());
		assertEquals(Algorithm.RSA, key.getKeyType());
		assertEquals(RSA_KEY, key.getKeyString());
		assertEquals("my comment", key.getComment());
	}

	@Test
	public void testLeadingWhitespace() throws Exception {
		final AuthorizedKey key = parse("   command=\"ls\" ssh-ed25519 " + ED25519_KEY + " comment");
		assertEquals("ls", key.getCommand());
		assertEquals("comment", key.getComment());
	}

	@Test
	public void testAllOptions() throws Exception {
		final AuthorizedKey key = parse("restrict,cert-authority,command=\"echo \\\"quoted\\\"\",environment=\"NAME=my value, with comma\",environment=\"KEY=key value\","
				+ "expiry-time=\"20301231\",from=\"192.168.0.1\",principals=\"alice,bob\",tunnel=\"1\",permitopen=\"host1:22\",permitopen=\"[::1]:80\","
				+ "permitlisten=\"localhost:8080\",no-agent-forwarding,agent-forwarding,no-port-forwarding,port-forwarding,no-pty,pty,"
				+ "no-user-rc,user-rc,No-X11-Forwarding,X11-forwarding,no-touch-required,verify-required ssh-ed25519 " + ED25519_KEY + " My comment");
		assertTrue(key.isRestrict());
		assertTrue(key.isCertAuthority());
		assertEquals("echo \"quoted\"", key.getCommand());
		assertEquals(2, key.getEnvironment().size());
		assertEquals("my value, with comma", key.getEnvironment().get("NAME"));
		assertEquals("key value", key.getEnvironment().get("KEY"));
		assertEquals("20301231", key.getExpiryTime());
		assertEquals("192.168.0.1", key.getFromList());
		assertEquals("alice,bob", key.getPrincipals());
		assertEquals("1", key.getTunnel());
		assertEquals("host1:22,[::1]:80", key.getPermitOpen());
		assertEquals("localhost:8080", key.getPermitListen());
		assertTrue(key.isNoAgentForwarding() && key.isAgentForwarding());
		assertTrue(key.isNoPortForwarding() && key.isPortForwarding());
		assertTrue(key.isNoPty() && key.isPty());
		assertTrue(key.isNoUserRc() && key.isUserRc());
		assertTrue(key.isNoX11Forwarding() && key.isX11Forwarding());
		assertTrue(key.isNoTouchRequired() && key.isVerifyRequired());
		assertEquals("My comment", key.getComment());
	}

	@Test
	public void testRoundTrip() throws Exception {
		final String line = "restrict,command=\"echo \\\"hi\\\"\",environment=\"NAME=a,b\",from=\"10.0.0.1\",permitopen=\"h1:1\",permitopen=\"h2:2\",no-pty ssh-ed25519 " + ED25519_KEY + " comment";
		final AuthorizedKey key = parse(line);
		final AuthorizedKey reparsedKey = parse(key.toAuthorizedKeysLine());
		assertEquals(key.toAuthorizedKeysLine(), reparsedKey.toAuthorizedKeysLine());
		assertEquals("echo \"hi\"", reparsedKey.getCommand());
		assertEquals("a,b", reparsedKey.getEnvironment().get("NAME"));
		assertEquals("h1:1,h2:2", reparsedKey.getPermitOpen());
		assertTrue(reparsedKey.isRestrict() && reparsedKey.isNoPty());
	}

	@Test
	public void testEnvironmentFirstValueWins() throws Exception {
		final AuthorizedKey key = parse("environment=\"A=1\",environment=\"A=2\" ssh-ed25519 " + ED25519_KEY);
		assertEquals("1", key.getEnvironment().get("A"));
	}

	@Test
	public void testInvalidLines() {
		// Space separated options are not valid in OpenSSH syntax
		assertThrows(AuthorizedKeyException.class, () -> parse("no-pty command=\"ls\" ssh-ed25519 " + ED25519_KEY));
		// Single quotes are not supported by OpenSSH
		assertThrows(AuthorizedKeyException.class, () -> parse("command='ls' ssh-ed25519 " + ED25519_KEY));
		// Unquoted option values are not supported by OpenSSH
		assertThrows(AuthorizedKeyException.class, () -> parse("command=ls ssh-ed25519 " + ED25519_KEY));
		// Unknown options are rejected like sshd does
		assertThrows(AuthorizedKeyException.class, () -> parse("no-such-option ssh-ed25519 " + ED25519_KEY));
		// Missing closing quote
		assertThrows(AuthorizedKeyException.class, () -> parse("command=\"ls ssh-ed25519 " + ED25519_KEY));
		// Duplicate single value options
		assertThrows(AuthorizedKeyException.class, () -> parse("command=\"a\",command=\"b\" ssh-ed25519 " + ED25519_KEY));
		// Flag with value
		assertThrows(AuthorizedKeyException.class, () -> parse("no-pty=\"x\" ssh-ed25519 " + ED25519_KEY));
		// Empty option
		assertThrows(AuthorizedKeyException.class, () -> parse("no-pty,,pty ssh-ed25519 " + ED25519_KEY));
		// Invalid environment
		assertThrows(AuthorizedKeyException.class, () -> parse("environment=\"=x\" ssh-ed25519 " + ED25519_KEY));
		// Unknown key type
		assertThrows(AuthorizedKeyException.class, () -> parse("ssh-foo " + ED25519_KEY));
		// Invalid base64
		assertThrows(AuthorizedKeyException.class, () -> parse("ssh-ed25519 AAAA!!!"));
		// Missing key data
		assertThrows(AuthorizedKeyException.class, () -> parse("ssh-ed25519"));
		assertThrows(AuthorizedKeyException.class, () -> parse("# comment line"));
		assertThrows(AuthorizedKeyException.class, () -> parse(""));
	}

	@Test
	public void testReaderWithAuthorizedKeysFile() throws Exception {
		final String authorizedKeys = "# authorized_keys\n"
				+ "\n"
				+ "no-pty,command=\"/usr/bin/backup\" ssh-ed25519 " + ED25519_KEY + " backup key\n"
				+ "ssh-rsa " + RSA_KEY + " other key\n";
		final java.util.List<SshKey> keys = SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(authorizedKeys.getBytes(StandardCharsets.UTF_8)));
		assertEquals(2, keys.size());
		assertEquals("/usr/bin/backup", ((AuthorizedKey) keys.get(0)).getCommand());
		assertEquals("backup key", keys.get(0).getComment());
		assertFalse(((AuthorizedKey) keys.get(1)).isNoPty());
		// Key type in line and key data must match
		assertThrows(Exception.class, () -> SshKeyReader.readAllPublicKeys(new ByteArrayInputStream(("ssh-rsa " + ED25519_KEY + "\n").getBytes(StandardCharsets.UTF_8))));
	}
}
