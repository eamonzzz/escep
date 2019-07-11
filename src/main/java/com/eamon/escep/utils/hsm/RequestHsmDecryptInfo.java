package com.eamon.escep.utils.hsm;

/**
 * @author: eamon
 * @date: 2019-05-15 16:30
 * @description:
 */
public class RequestHsmDecryptInfo {

    private long keyId;
    private String data;

    public RequestHsmDecryptInfo() {
    }

    public RequestHsmDecryptInfo(long keyId, String data) {
        this.keyId = keyId;
        this.data = data;
    }

    public long getKeyId() {
        return keyId;
    }

    public void setKeyId(long keyId) {
        this.keyId = keyId;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
