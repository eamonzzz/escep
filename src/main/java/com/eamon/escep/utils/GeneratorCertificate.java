package com.eamon.escep.utils;



import com.eamon.escep.utils.algorithm.AlgorithmUtil;
import com.eamon.escep.utils.hsm.*;
import com.eamon.escep.utils.hsm.exception.HsmGenException;
import com.eamon.escep.utils.hsm.exception.HsmSignException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

/**
 * @author robert
 * @description 生成证书接口
 */
public class GeneratorCertificate {

    private static final Logger log = LoggerFactory.getLogger(GeneratorCertificate.class);

    /**
     * 通用 证书生成 方法
     *
     * @param subjectDn      dn
     * @param issuerDn       签发者dn
     * @param notBefore      生效时间
     * @param notAfter       过期时间
     * @param extensions     扩展
     * @param serialNumber   序列号
     * @param issuerHsmKeyId 如果 上级CA 时通过 hsm生成的密钥  则  应传入 hsm的keyid
     * @param publicKeyInfo  当前证书公钥
     * @param hashAlg        签名hash算法
     * @param signAlg        签名密钥算法
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CertificateException
     */
    public X509Certificate generateCertificate(X500Name subjectDn, X500Name issuerDn, Date notBefore, Date notAfter,
                                               Extensions extensions, BigInteger serialNumber, Long issuerHsmKeyId,
                                               SubjectPublicKeyInfo publicKeyInfo, String hashAlg, String signAlg)
            throws NoSuchAlgorithmException, IOException, CertificateException, NullPointerException, HsmSignException {
        // 设置 哈希算法  如果根据上级CA决定 上级如果是SM2 则 哈希算法为 SM3
        if (CommonConstant.SIGN_ALG_INHERIT_FROM_ISSUING_CA.equals(hashAlg)) {
            hashAlg = "SHA256";
        }
        if (signAlg.equals(CommonConstant.SM2_SERIES)) {
            hashAlg = "SM3";
        }
        // 拼装 签名算法
        String signatureAlg = hashAlg + "WITH" + signAlg;
        // 生成 代签名证书
        TBSCertificate tbsCertificate = generatorTBS(issuerDn, subjectDn, new Time(notBefore),
                new Time(notAfter), extensions, new ASN1Integer(serialNumber),
                publicKeyInfo, AlgorithmUtil.getSigAlgId(signatureAlg));
        // 进行签名 签名算法是 SM2 则不进行哈希计算 由 hsm进行计算哈希
        String signData;
        if (issuerHsmKeyId != null) {
            byte[] bytes;
            if (signAlg.equals(CommonConstant.SM2_SERIES)) {
                bytes = tbsCertificate.getEncoded();
            } else {
                // 计算哈希
                bytes = calculateHash(hashAlg, tbsCertificate.getEncoded());
                // 请求签名
                log.info("请求 HSM 签名：keyid：{}，签名算法：{}", issuerHsmKeyId, signAlg);
            }

            signData = calculateSignWithHsm(hashAlg, issuerHsmKeyId, bytes);
        } else {
            throw new NullPointerException("私钥或hsm的keyid为空！");
        }
        byte[] data = Base64.decodeBase64(signData);
        // 进行证书组装
        return generateStructure(tbsCertificate, data);

    }

    /**
     * 通过 hsm 生成 密钥
     *
     * @param requestHsmGenKeyPairInfo
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public HsmKeyRespInfo genKeyWithHsm(RequestHsmGenKeyPairInfo requestHsmGenKeyPairInfo)
            throws NoSuchAlgorithmException, InvalidKeySpecException, HsmGenException, IOException {
        String keyType = requestHsmGenKeyPairInfo.getKeyType();
        // 生成密钥
        ResponseHsmGenKeyPairInfo responseHsmGenKeyPairInfo = HsmUtil.requestHsmGenKeyPair(requestHsmGenKeyPairInfo);
        if (responseHsmGenKeyPairInfo == null) {
            throw new HsmGenException("hsm 生成密钥失败！");
        }
        Long keyId = responseHsmGenKeyPairInfo.getKeyId();
        String pubKey = responseHsmGenKeyPairInfo.getPublicKey();

        KeyFactory keyFactory;
        PublicKey publicKey = null;
        // 由于 hsm 生成的 公钥 转换为 公钥对象 格式问题，需要对 RSA进行单独处理
        if (keyType.equals(HsmUtil.ALG_RSA)) {
            ASN1Sequence sequence = ASN1Sequence.getInstance(Base64.decodeBase64(pubKey));
            ASN1Integer modulus = ASN1Integer.getInstance(sequence.getObjectAt(0));
            ASN1Integer exponent = ASN1Integer.getInstance(sequence.getObjectAt(1));
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus.getPositiveValue(),
                    exponent.getPositiveValue());
            keyFactory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
            publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
        } else if (keyType.equals(HsmUtil.ALG_EC) || keyType.equals(HsmUtil.ALG_SM2)) {
            keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(pubKey));
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        }
        if (publicKey == null) {
            throw new NoSuchAlgorithmException();
        }
        HsmKeyRespInfo hsmKeyRespInfo = new HsmKeyRespInfo();
        hsmKeyRespInfo.setKeyId(keyId);
        hsmKeyRespInfo.setPublicKey(publicKey);
        return hsmKeyRespInfo;
    }

    /**
     * @param issuer
     * @param subject
     * @param start
     * @param end
     * @param extensions
     * @param serialNumber
     * @param publicKeyInfo
     * @param algorithmIdentifier 签名算法 oid
     * @return
     */
    public TBSCertificate generatorTBS(X500Name issuer, X500Name subject, Time start, Time end,
                                       Extensions extensions, ASN1Integer serialNumber, SubjectPublicKeyInfo publicKeyInfo,
                                       AlgorithmIdentifier algorithmIdentifier) {
        V3TBSCertificateGenerator v3TBSCertificateGenerator = new V3TBSCertificateGenerator();
        v3TBSCertificateGenerator.setIssuer(issuer);
        v3TBSCertificateGenerator.setEndDate(end);
        v3TBSCertificateGenerator.setStartDate(start);
        v3TBSCertificateGenerator.setSubject(subject);
        v3TBSCertificateGenerator.setExtensions(extensions);
        v3TBSCertificateGenerator.setSerialNumber(serialNumber);
        v3TBSCertificateGenerator.setSubjectPublicKeyInfo(publicKeyInfo);
        v3TBSCertificateGenerator.setSignature(algorithmIdentifier);
        return v3TBSCertificateGenerator.generateTBSCertificate();
    }

    /**
     * 计算哈希
     *
     * @param hashAlg 哈希算法
     * @param data    待哈希数据
     * @return
     * @throws NoSuchAlgorithmException
     */
    public byte[] calculateHash(String hashAlg, byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlg, new BouncyCastleProvider());
        messageDigest.update(data);
        return messageDigest.digest();
    }

    /**
     * 用 hsm 签名数据
     *
     * @param hashAlg  哈希算法
     * @param hsmKeyId hsm 槽id
     * @param data     代签名数据
     * @return
     */
    public String calculateSignWithHsm(String hashAlg, Long hsmKeyId, byte[] data) throws IOException, HsmSignException {
        RequestHsmSignDataInfo requestHsmSignDataInfo = new RequestHsmSignDataInfo();
        requestHsmSignDataInfo.setData(Base64.encodeBase64String(data));
        requestHsmSignDataInfo.setKeyId(hsmKeyId);
        requestHsmSignDataInfo.setHash(hashAlg);
        ResponseHsmSignDataInfo responseHsmSignDataInfo = HsmUtil.requestHsmSignData(requestHsmSignDataInfo);
        return responseHsmSignDataInfo.getSignature();
    }

    /**
     * 用私钥签名数据
     *
     * @param signatureAlg 签名算法
     * @param privateKey   私钥
     * @param data         代签名数据
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public byte[] calculateSignWithPrivateKey(String signatureAlg, PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signatureAlg, new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 组装 签名后的证书
     *
     * @param tbsCertificate
     * @param sign
     * @return
     * @throws CertificateException
     */
    public X509Certificate generateStructure(TBSCertificate tbsCertificate, byte[] sign) throws CertificateException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCertificate);
        v.add(tbsCertificate.getSignature());
        v.add(new DERBitString(sign));
        DERSequence derSequence = new DERSequence(v);

        X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(Certificate.getInstance(derSequence));

        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider());
        return jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
    }

}
