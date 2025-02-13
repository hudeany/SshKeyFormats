package de.soderer.sshkeyformats;

import org.junit.Assert;
import org.junit.Test;

import de.soderer.sshkeyformats.data.AuthorizedKey;
import de.soderer.sshkeyformats.data.AuthorizedKey.AuthorizedKeyType;
import de.soderer.sshkeyformats.data.AuthorizedKeyLineParser;

public class AuthorizedKeysFileReaderTest {
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
		//		final AuthorizedKey key1 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[0]);
		//		final AuthorizedKey key2 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[1]);
		//		final AuthorizedKey key3 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[2]);
		//		final AuthorizedKey key4 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[3]);
		//		final AuthorizedKey key5 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[4]);
		//		final AuthorizedKey key6 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[5]);
		//		final AuthorizedKey key7 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[6]);
		//
		//		Assert.assertEquals(1, key1.getEnvironment().size());
		//		Assert.assertEquals("value", key1.getEnvironment().get("NAME"));
		//		Assert.assertEquals(AuthorizedKeyType.ED25519, key1.getKeyType());
		//		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key1.getKeyString());
		//		Assert.assertEquals(null, key1.getComment());
		//
		//		Assert.assertEquals(null, key2.getEnvironment());
		//		Assert.assertEquals(AuthorizedKeyType.ED25519, key2.getKeyType());
		//		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIOvbS7rC4qN+z/DnBoUDCQDi6OEyV3sGyqKPeEOsuxvN", key2.getKeyString());
		//		Assert.assertEquals(null, key2.getComment());
		//
		//		Assert.assertEquals(2, key3.getEnvironment().size());
		//		Assert.assertEquals("my value", key3.getEnvironment().get("NAME"));
		//		Assert.assertEquals("key value", key3.getEnvironment().get("KEY"));
		//		Assert.assertEquals(AuthorizedKeyType.ED25519, key3.getKeyType());
		//		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key3.getKeyString());
		//		Assert.assertEquals(null, key3.getComment());
		//
		//		Assert.assertEquals(1, key4.getEnvironment().size());
		//		Assert.assertEquals("my value", key4.getEnvironment().get("NAME"));
		//		Assert.assertEquals(AuthorizedKeyType.RSA, key4.getKeyType());
		//		Assert.assertEquals("AAAAB3NzaC1yc2EAAAADAQABAAAAgQCNaf7jmjy/WzwTjc5eseYVNK/tQIBIyIUt5RC64HU6gKgAn2mv538Yf0sMR7cq4qQzhosGD4xOJUh1LmQnHwJ4pWC9lhh3FwKk2kLDnOqULTOMUhnWSHKw/tweJsy81+mXettuyt102cQuqF9vIexmLwTv+bMvtM3bmTSYAuk9iw==", key4.getKeyString());
		//		Assert.assertEquals("my comment", key4.getComment());
		//
		//		Assert.assertEquals(null, key5.getEnvironment());
		//		Assert.assertEquals(AuthorizedKeyType.ED25519, key5.getKeyType());
		//		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key5.getKeyString());
		//		Assert.assertEquals("my comment", key5.getComment());
		//
		//		Assert.assertEquals(null, key6.getEnvironment());
		//		Assert.assertEquals(AuthorizedKeyType.ED25519, key6.getKeyType());
		//		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key6.getKeyString());
		//		Assert.assertEquals(null, key6.getComment());
		//
		//		Assert.assertEquals(1, key7.getEnvironment().size());
		//		Assert.assertEquals("my value", key7.getEnvironment().get("NAME"));
		//		Assert.assertEquals(AuthorizedKeyType.ED25519, key7.getKeyType());
		//		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key7.getKeyString());
		//		Assert.assertEquals(null, key7.getComment());

		final AuthorizedKey key8 = new AuthorizedKeyLineParser().parseAuthorizedKeyLine(testContent[7]);
		Assert.assertEquals(null, key8.getEnvironment());
		Assert.assertEquals(AuthorizedKeyType.ED25519, key8.getKeyType());
		Assert.assertEquals("AAAAC3NzaC1lZDI1NTE5AAAAIBYfzoo5dutqetlb/jD+wwKCfLFk6trcSjnbjB/HBgLX", key8.getKeyString());
		Assert.assertEquals(null, key8.getComment());
	}
}
