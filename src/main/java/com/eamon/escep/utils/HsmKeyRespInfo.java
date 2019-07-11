package com.eamon.escep.utils;

import java.security.PublicKey;

/**
 * @author: eamon
 * @date: 2019-03-11 11:08
 * @description:
 */
public class HsmKeyRespInfo {
    private Long keyId;
    private PublicKey publicKey;

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
