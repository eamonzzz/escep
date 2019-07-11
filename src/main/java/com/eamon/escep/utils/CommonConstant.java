package com.eamon.escep.utils;


/**
 * 公共常量
 *
 * @author eamon
 */
public class CommonConstant {

    public static final String HTTP_METHOD_GET = "GET";
    public static final String HTTP_METHOD_POST = "POST";
    /**
     * 系统默认的 私钥加密解密密码
     */
    public static final String DEFAULT_PRIVATEKEY_PWD = "trustasia-cloudpki";

    /**
     * 证书类型
     */
    public static final String CERT_TYPE_ROOT_CA = "RootCA";
    public static final String CERT_TYPE_SUB_CA = "SubCA";
    public static final String CERT_TYPE_END_ENTITY = "End";

    /**
     * 定义两个系列的证书类型常量
     */
    public static final String RSA_SERIES = "RSA";
    public static final String ECDSA_SERIES = "ECDSA";
    public static final String SM2_SERIES = "SM2";

    /**
     * SM2 密钥算法
     */
    public static final String SM2_ALGORITHM = "EC";
    public static final String SM2_KEY_CURVE = "sm2p256v1";
    public static final int SM2_KEY_SIZE = 256;

    public static final String SIGN_ALG_INHERIT_FROM_ISSUING_CA = "-1";
    public static final String DEFAULT_RSA_ALGORITHM = "SHA256WITHRSA";
    public static final String DEFAULT_ECDSA_ALGORITHM = "SHA256WITHECDSA";
    public static final String DEFAULT_SM2_ALGORITHM = "SM3WITHSM2";

    /**
     * 默认每页显示条数
     */
    public static int DEFAULT_PAGE_SIZE = 20;

    /**
     * 证书下载时 整数类型常量
     */
    public static final String DOWNLOAD_FILE_PEM = "PEM";
    public static final String DOWNLOAD_FILE_JKS = "JKS";
    public static final String DOWNLOAD_FILE_PKCS12 = "PKCS12";

    public static final String ALL = "ALL";

    /**
     * mq 证书吊销
     */
    public static final String MQ_REVOKE = "revoke";
    /**
     * mq 生成 ocsp证书
     */
    public static final String MQ_GEN_OCSP = "genOcsp";

}
