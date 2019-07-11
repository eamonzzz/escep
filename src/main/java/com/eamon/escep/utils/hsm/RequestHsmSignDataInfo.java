package com.eamon.escep.utils.hsm;

import java.util.StringJoiner;

/**
 * @author: eamon
 * @date: 2019-03-08 17:01
 * @description: 请求Hsm 签名
 */
public class RequestHsmSignDataInfo {
    /**
     * base 64 编码后的数据
     */
    private String data;

    private Long keyId;

    private String hash;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public RequestHsmSignDataInfo() {
    }

    public RequestHsmSignDataInfo(String data, Long keyId, String hash) {
        this.data = data;
        this.keyId = keyId;
        this.hash = hash;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", RequestHsmSignDataInfo.class.getSimpleName() + "[", "]")
                .add("data='" + data + "'")
                .add("keyId=" + keyId)
                .add("hash='" + hash + "'")
                .toString();
    }
}
