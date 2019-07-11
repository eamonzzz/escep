package com.eamon.escep.utils.hsm.exception;

/**
 * @author: eamon
 * @date: 2019-05-15 16:35
 * @description:
 */
public class HsmDecryptException extends Exception {
    public HsmDecryptException() {
    }

    public HsmDecryptException(String message) {
        super(message);
    }

    public HsmDecryptException(String message, Throwable cause) {
        super(message, cause);
    }

    public HsmDecryptException(Throwable cause) {
        super(cause);
    }

    public HsmDecryptException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
