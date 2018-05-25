package com.goodbyeq.exception;


public class CryptoException extends Exception {

    private static final long serialVersionUID = 5698479920593359816L;

    /**
     * Constructs an CryptoException with no detail message. A
     * detail message is a String that describes this particular
     * exception.
     */
    public CryptoException() {
	super();
    }

    /**
     * Constructs an CryptoException with the specified detail
     * message. A detail message is a String that describes this
     * particular exception.  
     *
     * @param msg the detail message.  
     */
    public CryptoException(String msg) {
    	super(msg);
    }

    /**
     * Creates a <code>CryptoException</code> with the specified
     * detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval
     *        by the {@link #getMessage()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).  (A <tt>null</tt> value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     * @since 1.5
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a <code>CryptoException</code> with the specified cause
     * and a detail message of <tt>(cause==null ? null : cause.toString())</tt>
     * (which typically contains the class and detail message of
     * <tt>cause</tt>).
     *
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).  (A <tt>null</tt> value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     * @since 1.5
     */
    public CryptoException(Throwable cause) {
        super(cause);
    }
}
