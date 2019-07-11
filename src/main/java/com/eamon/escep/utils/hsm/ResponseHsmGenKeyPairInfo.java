package com.eamon.escep.utils.hsm;

/**
 * @author: eamon
 * @date: 2019-03-08 16:59
 * @description: 接收 hsm 生成的密钥信息
 */
public class ResponseHsmGenKeyPairInfo {

    private Long keyId;
    private String publicKey;

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
