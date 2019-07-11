package com.eamon.escep.utils.hsm.exception;

/**
 * @author: eamon
 * @date: 2019-03-21 09:20
 * @description:
 */
public class HsmGenException extends Exception {
    public HsmGenException() {
    }

    public HsmGenException(String message) {
        super(message);
    }

    public HsmGenException(String message, Throwable cause) {
        super(message, cause);
    }

    public HsmGenException(Throwable cause) {
        super(cause);
    }

    public HsmGenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
