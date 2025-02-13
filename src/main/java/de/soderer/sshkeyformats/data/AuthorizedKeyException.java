package de.soderer.sshkeyformats.data;

public class AuthorizedKeyException extends Exception {
	private static final long serialVersionUID = 1323513234197922498L;

	public AuthorizedKeyException(final String string, final Exception e) {
		super(string, e);
	}
}
