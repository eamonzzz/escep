package com.eamon.escep.exception;

/**
 * @author: eamon
 * @date: 2019-07-11 17:42
 * @description:
 */
public class MessageEncodingException extends Exception {
    /**
     * Serialization ID.
     */
    private static final long serialVersionUID = -6111956271602335933L;

    /**
     * Creates a new <tt>MessageEncodingException</tt> with the provided cause.
     *
     * @param cause the initial cause of the encoding exception.
     */
    public MessageEncodingException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates a new <tt>MessageEncodingException</tt> with the provided error
     * message.
     *
     * @param message the description of the encoding exception.
     */
    public MessageEncodingException(final String message) {
        super(message);
    }
}