package de.soderer.sshkeyformats.data;

/**
 * AuthorizedKeyException API.
 */
public class AuthorizedKeyException extends Exception {
	private static final long serialVersionUID = 1323513234197922498L;

/**
 * AuthorizedKeyException operation.
 * @param string the string value.
 * @param e the e value.
 */
	public AuthorizedKeyException(final String string, final Exception e) {
		super(string, e);
	}
}
