package com.eamon.escep.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * @author: eamon
 * @date: 2019-07-08 19:21
 * @description:
 */
public class CommonUtils {

    public static final String subcaCertStr = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDLDCCAhSgAwIBAgIJCHh7IEvIHXk2MA0GCSqGSIb3DQEBCwUAMB8xDDAKBgNV\n" +
            "BAMMAzEyMzEPMA0GA1UEAwwGdGVzdDEyMCAXDTE5MDcwODAzMDY0N1oYDzIwNjkw\n" +
            "NzA4MDMwNjQ3WjAUMRIwEAYDVQQDDAl0ZXN0MTIzNDUwggEiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4IBDwAwggEKAoIBAQDbZ93X1K0q0dopoM0jtd1rDRBPDc9gsluJ40TUIERv\n" +
            "1/osYtZuuBfpOJtDCxqyfFoCLthJrYISBkH0bBZFywFRoV0Cv6R8SBl/AsL2WTJf\n" +
            "MTUCPfIJ8BqsZcUmLZ/quaLvZhFWzGPW87ufAfCtS146VZUoCMX/PFZQxnfKC/VF\n" +
            "DQczGNp5F8oAt/hH3H50quIRag6nbQnQsWKQrix9G4POMb1z8XgSJ6mCYMYeaV1N\n" +
            "AOhAraBFM2n+nQQkQCqCwT6oGI2ltLDpyZTHNGcX/1IGN3a2lr5asMo9ORCJ9coP\n" +
            "/s6xNslDtbxT9QqA8HN1Y7JPD1OOTBSUo/ZfbdGJGk/DAgMBAAGjdDByMBIGA1Ud\n" +
            "EwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgeAMA8GA1UdIAQIMAYwBAYCKgMwHQYD\n" +
            "VR0OBBYEFAe+af3s+CUCCf2Cvsoa9wboDif+MB8GA1UdIwQYMBaAFIN2GhtMi4xt\n" +
            "1QPH3aq2wN3dGzQ0MA0GCSqGSIb3DQEBCwUAA4IBAQBEXCvMN6MBrqFLroT3mGFU\n" +
            "NBZUqfQLKFaXcDy16nFJ7lUx9EpmRtiCUa/ORjufaiKTFI3n1h29f2ClxVXeEEr+\n" +
            "qMZOIzUFtle3rh2nrhj77IMtpgbvw4aK0VXDACuwlXwgsyXeGYxAqIdcJ4UtsBpq\n" +
            "vN6glZZe9Ehpd8KZJ0COuDA/4NT5GQ3kCwabAoYPYQfphXHVF1uQNp4NqkaFNFGb\n" +
            "8tu2nb4S2yN/mEFVhwrSzIJJezyVmSolDyVtwsOrwgkVUM8GHZAEkuJoouq+q2sm\n" +
            "0y2p9yf8dcBAcigDENCZNG6CMFaL1Ag1WWx+5XwYngffIYzjTOw3mRPt3q8Nk3UM\n" +
            "-----END CERTIFICATE-----\n";

    public static final long subcaCertHsmKeyId = 260;

    public static X509Certificate getTestSubca() throws IOException, CertificateException {
        X509CertificateHolder certObject = (X509CertificateHolder) new PEMParser(new StringReader(subcaCertStr)).readObject();
        return new JcaX509CertificateConverter().getCertificate(certObject);
    }


    public static X509Certificate buildRoot() {
        X500Name subjectDn = new X500Name("CN=Test CA");
        X500Name issuerDn = subjectDn;
        BigInteger serialNumber = BigInteger.ONE;
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date notAfter = calendar.getTime();
        KeyPair keyPair = null;
        try {
            keyPair = buildKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("密钥构建失败!");
        }
        assert keyPair != null;
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
        ContentSigner contentSigner = null;
        try {
            contentSigner = contentSignerBuilder.build(aPrivate);
        } catch (OperatorCreationException e) {
            System.out.println("内容签名创建失败！");
        }
        X509Certificate x509Certificate = null;
        try {
            x509Certificate = buildX509Cert(issuerDn, subjectDn, serialNumber, notBefore, notAfter, aPublic, contentSigner);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return x509Certificate;
    }

    public static X509Certificate buildX509Cert(X500Name issuerDn, X500Name subjectDn, BigInteger serialNumber,
                                                Date notBefore, Date notAfter, PublicKey publicKey,
                                                ContentSigner contentSigner) throws CertificateException {

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuerDn, serialNumber,
                notBefore, notAfter, subjectDn, publicKey);
        X509CertificateHolder holder = certificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static KeyPair buildKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

}
