package com.eamon.escep.utils;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.PasswordRecipient;

import java.util.HashMap;
import java.util.Map;

/**
 * @author: eamon
 * @date: 2019-06-12 13:39
 * @description:
 */
public class EnvelopedDataHelper {

    public static final Map BASE_CIPHER_NAMES = new HashMap();
    public static final Map CIPHER_ALG_NAMES = new HashMap();
    public static final Map MAC_ALG_NAMES = new HashMap();

    public static final Map PBKDF2_ALG_NAMES = new HashMap();

    static
    {
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_CBC,  "DES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDE");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.RC2_CBC,  "RC2");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.CAST5_CBC, "CAST5");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.CAMELLIA128_CBC, "Camellia");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.CAMELLIA192_CBC, "Camellia");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.CAMELLIA256_CBC, "Camellia");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.SEED_CBC, "SEED");
        BASE_CIPHER_NAMES.put(PKCSObjectIdentifiers.rc4, "RC4");
        BASE_CIPHER_NAMES.put(CryptoProObjectIdentifiers.gostR28147_gcfb, "GOST28147");

        CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_CBC,  "DES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.RC2_CBC,  "RC2/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDE/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES128_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES192_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES256_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(PKCSObjectIdentifiers.rsaEncryption, "RSA/ECB/PKCS1Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.CAST5_CBC, "CAST5/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.CAMELLIA128_CBC, "Camellia/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.CAMELLIA192_CBC, "Camellia/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.CAMELLIA256_CBC, "Camellia/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.SEED_CBC, "SEED/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(PKCSObjectIdentifiers.rc4, "RC4");

        MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDEMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.RC2_CBC,  "RC2Mac");

        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA1.getAlgorithmID(), "PBKDF2WITHHMACSHA1");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA224.getAlgorithmID(), "PBKDF2WITHHMACSHA224");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA256.getAlgorithmID(), "PBKDF2WITHHMACSHA256");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA384.getAlgorithmID(), "PBKDF2WITHHMACSHA384");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA512.getAlgorithmID(), "PBKDF2WITHHMACSHA512");
    }

}
