package com.eamon.escep.utils.hsm;

/**
 * @author: eamon
 * @date: 2019-03-08 16:58
 * @description:
 */
public class RequestHsmGenKeyPairInfo {

    private String keyType;
    private Integer keySize;
    private String ecp;

    public RequestHsmGenKeyPairInfo() {
    }

    public RequestHsmGenKeyPairInfo(String keyType, Integer keySize, String ecp) {
        this.keyType = keyType;
        this.keySize = keySize;
        this.ecp = ecp;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    public String getEcp() {
        return ecp;
    }

    public void setEcp(String ecp) {
        this.ecp = ecp;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("RequestHsmGenKeyPairInfo{");
        sb.append("keyType='").append(keyType).append('\'');
        sb.append(", keySize=").append(keySize);
        sb.append(", ecp='").append(ecp).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
