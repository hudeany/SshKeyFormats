package de.soderer.sshkeyformats.data;

/**
 * Signals that the key data could not be decrypted, because the password is missing or wrong.
 */
public class WrongPasswordException extends Exception {
	private static final long serialVersionUID = -6791318805414429659L;

	/**
	 * Creates the exception with a default message.
	 */
	public WrongPasswordException() {
		super("Missing or wrong password");
	}

	/**
	 * Creates the exception with the given message.
	 *
	 * @param message the detail message
	 */
	public WrongPasswordException(final String message) {
		super(message);
	}

	/**
	 * Creates the exception with the given message and cause.
	 *
	 * @param message the detail message
	 * @param cause the original exception
	 */
	public WrongPasswordException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
