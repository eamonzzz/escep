package com.eamon.escep.utils.hsm;


import com.alibaba.fastjson.JSON;
import com.eamon.escep.utils.ViewData;
import com.eamon.escep.utils.hsm.exception.HsmDecryptException;
import com.eamon.escep.utils.hsm.exception.HsmGenException;
import com.eamon.escep.utils.hsm.exception.HsmSignException;
import com.eamon.escep.utils.http.HttpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: eamon
 * @date: 2019-03-08 16:55
 * @description:
 */
@Component
public class HsmUtil {

    private static final Logger log = LoggerFactory.getLogger(HsmUtil.class);

    public static final String ALG_RSA = "RSA";
    public static final String ALG_EC = "ECDSA";
    public static final String ALG_SM2 = "SM2";

    public static final String HSM_GEN_KEYPAIR = "/createKey";
    public static final String HSM_SIGN_DATA = "/sign";
    public static final String HSM_DECRYPT = "/decrypt";

    private static String hsmUrl;

    @Value("${hsmUrl}")
    public void setHsmUrl(String url) {
        hsmUrl = url;
    }


    /**
     * 请求 生成密钥接口
     *
     * @param requestHsmGenKeyPairInfo
     * @return
     */
    public static ResponseHsmGenKeyPairInfo requestHsmGenKeyPair(RequestHsmGenKeyPairInfo requestHsmGenKeyPairInfo) throws HsmGenException {
        ResponseHsmGenKeyPairInfo responseHsmGenKeyPairInfo;

        String params = JSON.toJSONString(requestHsmGenKeyPairInfo, true);
        log.info("request hsm to gen key ：{}, params: {}", hsmUrl + HSM_GEN_KEYPAIR, params);
        String response;
        try {
            Map<String, String> map = new HashMap<>();
            map.put("keyType", requestHsmGenKeyPairInfo.getKeyType());
            map.put("keySize", String.valueOf(requestHsmGenKeyPairInfo.getKeySize()));
            map.put("ecp", requestHsmGenKeyPairInfo.getEcp());
            response = HttpUtil.getRequest(hsmUrl + HSM_GEN_KEYPAIR, map);
        } catch (IOException e) {
            log.error("hsm 连接失败！");
            throw new HsmGenException("hsm 密钥生成失败！");
        }
        if (isJson(response)) {
            ViewData viewData = JSON.parseObject(response, ViewData.class);
            if (viewData == null) {
                throw new HsmGenException("HSM 返回值错误！");
            }
            int code = viewData.getCode();
            if (code != 0) {
                throw new HsmGenException(code + " hsm 密钥生成失败！");
            } else {
                Object data = viewData.getData();
                responseHsmGenKeyPairInfo = JSON.parseObject(JSON.toJSONString(data), ResponseHsmGenKeyPairInfo.class);
            }
        } else {
            throw new HsmGenException("hsm 密钥生成失败！");
        }

        return responseHsmGenKeyPairInfo;
    }

    /**
     * 请求 签名接口
     *
     * @param requestHsmSignDataInfo
     * @return
     */
    public static ResponseHsmSignDataInfo requestHsmSignData(RequestHsmSignDataInfo requestHsmSignDataInfo) throws HsmSignException {
        return requestHsmSignData(requestHsmSignDataInfo, hsmUrl + HSM_SIGN_DATA);
    }

    public static ResponseHsmSignDataInfo requestHsmSignData(RequestHsmSignDataInfo requestHsmSignDataInfo, String url) throws HsmSignException {
        RestTemplate restTemplate = new RestTemplate();
        ResponseHsmSignDataInfo responseHsmSignDataInfo = new ResponseHsmSignDataInfo();
        MultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
        map.add("keyId", requestHsmSignDataInfo.getKeyId());
        map.add("data", requestHsmSignDataInfo.getData());
        map.add("hash", requestHsmSignDataInfo.getHash());
        ViewData response = restTemplate.postForObject(url, map, ViewData.class);
        if (response != null) {
            int code = response.getCode();
            if (code != 0) {
                throw new HsmSignException("hsm 签名失败！code: " + code);
            }
            Object data = response.getData();
            responseHsmSignDataInfo.setSignature(String.valueOf(data));
        } else {
            throw new HsmSignException("hsm 签名失败！");
        }
        return responseHsmSignDataInfo;
    }

    public static ResponseHsmDecryptInfo requestHsmDecrypt(RequestHsmDecryptInfo decryptInfo) throws HsmDecryptException {
        RestTemplate restTemplate = new RestTemplate();
        ResponseHsmDecryptInfo responseHsmDecryptInfo = new ResponseHsmDecryptInfo();
        MultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
        map.add("keyId", decryptInfo.getKeyId());
        map.add("data", decryptInfo.getData());
        ViewData response = restTemplate.postForObject(hsmUrl + HSM_DECRYPT, map, ViewData.class);
        if (response == null) {
            throw new HsmDecryptException("hsm 解密失败！");
        } else {
            int code = response.getCode();
            if (code != 0) {
                throw new HsmDecryptException("hsm 解密失败！code: " + code);
            }
            Object data = response.getData();
            responseHsmDecryptInfo.setDecryptData(String.valueOf(data));
        }
        return responseHsmDecryptInfo;
    }

    public static boolean isJson(String jsonInString) {
        boolean result = false;
        try {
            Object obj = JSON.parse(jsonInString);
            result = true;
        } catch (Exception e) {
        }
        return result;
    }

}
