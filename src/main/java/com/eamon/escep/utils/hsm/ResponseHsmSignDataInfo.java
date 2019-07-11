package com.eamon.escep.utils.hsm;

/**
 * @author: eamon
 * @date: 2019-03-08 17:02
 * @description:
 */
public class ResponseHsmSignDataInfo {
    /**
     * base 64 编码后的数据
     */
    private String signature;

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
