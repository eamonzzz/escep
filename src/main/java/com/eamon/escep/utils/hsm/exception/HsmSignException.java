package com.eamon.escep.utils.hsm.exception;

/**
 * @author: eamon
 * @date: 2019-03-21 10:46
 * @description:
 */
public class HsmSignException extends Exception {
    public HsmSignException() {
    }

    public HsmSignException(String message) {
        super(message);
    }

    public HsmSignException(String message, Throwable cause) {
        super(message, cause);
    }

    public HsmSignException(Throwable cause) {
        super(cause);
    }

    public HsmSignException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
