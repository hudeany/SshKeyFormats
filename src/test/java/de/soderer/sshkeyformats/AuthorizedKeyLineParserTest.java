package de.soderer.sshkeyformats;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import de.soderer.sshkeyformats.data.Algorithm;
import de.soderer.sshkeyformats.data.AuthorizedKeyLineParser;

@SuppressWarnings("static-method")
public class AuthorizedKeyLineParserTest {
	private final String[] testContent = new String[]{
			"environment=NAME=value ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX",
			"command=Command ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOvbS7rC4qN+z/DnBoUDCQDi6OEyV3sGyqKPeEOsuxvN",
			"command=Command environment=\"NAME=my value, KEY=key value\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX",
			"command=Command environment='NAME=my value' ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCNaf7jmjy/WzwTjc5eseYVNK/tQIBIyIUt5RC64HU6gKgAn2mv538Yf0sMR7cq4qQzhosGD4xOJUh1LmQnHwJ4pWC9lhh3FwKk2kLDnOqULTOMUhnWSHKw/tweJsy81+mXettuyt102cQuqF9vIexmLwTv+bMvtM3bmTSYAuk9iw== my comment",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX my comment",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX",
			"environment=\"NAME=my value\" command=Command ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX",
			"ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX "
	};

	@Test
	public void test() throws Exception {
		final AuthorizedKey key1 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[0]);
		final AuthorizedKey key2 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[1]);
		final AuthorizedKey key3 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[2]);
		final AuthorizedKey key4 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[3]);
		final AuthorizedKey key5 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[4]);
		final AuthorizedKey key6 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[5]);
		final AuthorizedKey key7 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[6]);

		assertEquals(1, key1.getEnvironment().size());
		assertEquals("value", key1.getEnvironment().get("NAME"));
		assertEquals(Algorithm.ED25519, key1.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key1.getKeyString());
		assertEquals(null, key1.getComment());

		assertEquals(null, key2.getEnvironment());
		assertEquals(Algorithm.ED25519, key2.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIOvbS7rC4qN+z/DnBoUDCQDi6OEyV3sGyqKPeEOsuxvN", key2.getKeyString());
		assertEquals(null, key2.getComment());

		assertEquals(2, key3.getEnvironment().size());
		assertEquals("my value", key3.getEnvironment().get("NAME"));
		assertEquals("key value", key3.getEnvironment().get("KEY"));
		assertEquals(Algorithm.ED25519, key3.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key3.getKeyString());
		assertEquals(null, key3.getComment());

		assertEquals(1, key4.getEnvironment().size());
		assertEquals("my value", key4.getEnvironment().get("NAME"));
		assertEquals(Algorithm.RSA, key4.getKeyType());
		assertEquals("AAAAB3NzaC1yc2EAAAADAQABAAAAgQCNaf7jmjy/WzwTjc5eseYVNK/tQIBIyIUt5RC64HU6gKgAn2mv538Yf0sMR7cq4qQzhosGD4xOJUh1LmQnHwJ4pWC9lhh3FwKk2kLDnOqULTOMUhnWSHKw/tweJsy81+mXettuyt102cQuqF9vIexmLwTv+bMvtM3bmTSYAuk9iw==", key4.getKeyString());
		assertEquals("my comment", key4.getComment());

		assertEquals(null, key5.getEnvironment());
		assertEquals(Algorithm.ED25519, key5.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key5.getKeyString());
		assertEquals("my comment", key5.getComment());

		assertEquals(null, key6.getEnvironment());
		assertEquals(Algorithm.ED25519, key6.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key6.getKeyString());
		assertEquals(null, key6.getComment());

		assertEquals(1, key7.getEnvironment().size());
		assertEquals("my value", key7.getEnvironment().get("NAME"));
		assertEquals(Algorithm.ED25519, key7.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key7.getKeyString());
		assertEquals(null, key7.getComment());

		final AuthorizedKey key8 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[7]);
		assertEquals(null, key8.getEnvironment());
		assertEquals(Algorithm.ED25519, key8.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key8.getKeyString());
		assertEquals(null, key8.getComment());
		assertEquals("DDF0BB6EB54E22BB80C0F256C76D5ADF", key8.getHash());
	}

	@Test
	public void testAllTokens() throws Exception {
		final AuthorizedKey key = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(
				"command=\"Command\" environment=\"NAME=my value\" cert-authority from=\"from, list\" no-agent-forwarding no-port-forwarding no-pty no-user-rc "
						+ "no-x11-forwarding permitopen=\"allowed to open\" principals=\"pricipal\" tunnel=\"host:port\" "
						+ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX My comment"
				);
		assertEquals(Algorithm.ED25519, key.getKeyType());
		assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key.getKeyString());
	}
}
