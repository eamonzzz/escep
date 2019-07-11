package com.eamon.escep.utils;

import com.eamon.escep.exception.MessageDecodingException;
import com.eamon.escep.utils.hsm.HsmUtil;
import com.eamon.escep.utils.hsm.RequestHsmDecryptInfo;
import com.eamon.escep.utils.hsm.ResponseHsmDecryptInfo;
import com.eamon.escep.utils.hsm.exception.HsmDecryptException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import static com.eamon.escep.utils.EnvelopedDataHelper.BASE_CIPHER_NAMES;
import static com.eamon.escep.utils.EnvelopedDataHelper.CIPHER_ALG_NAMES;

/**
 * @author: eamon
 * @date: 2019-07-11 18:01
 * @description:
 */
public class CmsUtil {

    public static byte[] hsmDecode(CMSEnvelopedData envelopedData, long hsmKeyId) throws GeneralSecurityException, HsmDecryptException {
        byte[] decoded;
        EnvelopedData instance = EnvelopedData.getInstance(envelopedData.toASN1Structure().getContent());
        EncryptedContentInfo encryptedContentInfo = instance.getEncryptedContentInfo();
        ASN1Set recipientInfos = instance.getRecipientInfos();
        ASN1Encodable[] asn1Encodables = recipientInfos.toArray();
        String encryptedStr = "";
        for (ASN1Encodable asn1Encodable : asn1Encodables) {
            ASN1Sequence sequence = BERSequence.getInstance(asn1Encodable.toASN1Primitive());
            ASN1Encodable[] encodables = sequence.toArray();
            for (ASN1Encodable encodable : encodables) {
                ASN1Object asn1Object = encodable.toASN1Primitive();
                if (asn1Object instanceof ASN1OctetString) {
                    encryptedStr = Base64.encodeBase64String(((ASN1OctetString) asn1Object).getOctets());
                }
            }
        }

        RequestHsmDecryptInfo requestHsmDecryptInfo = new RequestHsmDecryptInfo();
        requestHsmDecryptInfo.setKeyId(hsmKeyId);
        requestHsmDecryptInfo.setData(encryptedStr);

        ResponseHsmDecryptInfo responseHsmDecryptInfo = HsmUtil.requestHsmDecrypt(requestHsmDecryptInfo);
        String decryptData = responseHsmDecryptInfo.getDecryptData();

        KeySpec desKey = null;

        String baseCipherName = (String) BASE_CIPHER_NAMES.get(encryptedContentInfo.getContentEncryptionAlgorithm().getAlgorithm());
        String cipherAlgName = (String) CIPHER_ALG_NAMES.get(encryptedContentInfo.getContentEncryptionAlgorithm().getAlgorithm());

        if ("DES".equalsIgnoreCase(baseCipherName)) {
            desKey = new DESKeySpec(Base64.decodeBase64(decryptData));
        } else if ("DESEDE".equalsIgnoreCase(baseCipherName)) {
            desKey = new DESedeKeySpec(Base64.decodeBase64(decryptData));
        } else if ("AES".equalsIgnoreCase(baseCipherName)) {
            desKey = new SecretKeySpec(Base64.decodeBase64(decryptData), "AES");
        }

        SecureRandom random = new SecureRandom(Base64.decodeBase64(decryptData));

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(baseCipherName);
        SecretKey securekey = keyFactory.generateSecret(desKey);
        Cipher cipher = Cipher.getInstance(cipherAlgName);


        AlgorithmParameterSpec iv = getIV(encryptedContentInfo.getContentEncryptionAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, securekey, iv, random);
        decoded = cipher.doFinal(encryptedContentInfo.getEncryptedContent().getOctets());

        return decoded;
    }

    private static AlgorithmParameterSpec getIV(AlgorithmIdentifier envelopingAlgorithm) {
        ASN1Encodable ivParams = envelopingAlgorithm.getParameters();
        return new IvParameterSpec(ASN1OctetString.getInstance(ivParams).getOctets());
    }


    private CMSEnvelopedData getEnvelopedData(final Object bytes)
            throws MessageDecodingException {
        // We expect the byte array to be a sequence
        // ... and that sequence to be a ContentInfo (but might be the
        // EnvelopedData)
        try {
            return new CMSEnvelopedData((byte[]) bytes);
        } catch (CMSException e) {
            throw new MessageDecodingException(e);
        }
    }
}
