package de.soderer.sshkeyformats.data;

/**
 * Exception thrown when a authorized key error occurs.
 */
public class AuthorizedKeyException extends Exception {
	private static final long serialVersionUID = 1323513234197922498L;

	/**
	 * Creates an exception with a message and the underlying cause.
	 * @param string the string
	 * @param e the e
	 */
	public AuthorizedKeyException(final String string, final Exception e) {
		super(string, e);
	}
}
