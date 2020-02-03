package pem;

/**
 * Thrown when an invalid Object Identifier is encountered.
 *
 */
public class InvalidObjectIdException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new InvalidObjectIdException.
	 */
	public InvalidObjectIdException() {
		super();
	}

	/**
	 * Creates a new InvalidObjectIdException with the specified message.
	 *
	 * @param message
	 *            Exception message
	 */
	public InvalidObjectIdException(String message) {
		super(message);
	}

	/**
	 * Creates a new InvalidObjectIdException with the specified message and
	 * cause throwable.
	 *
	 * @param message
	 *            Exception message
	 * @param causeThrowable
	 *            The throwable that caused this exception to be thrown
	 */
	public InvalidObjectIdException(String message, Throwable causeThrowable) {
		super(message, causeThrowable);
	}

	/**
	 * Creates a new InvalidObjectIdException with the specified cause
	 * throwable.
	 *
	 * @param causeThrowable
	 *            The throwable that caused this exception to be thrown
	 */
	public InvalidObjectIdException(Throwable causeThrowable) {
		super(causeThrowable);
	}
}
