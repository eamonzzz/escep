package com.eamon.escep.utils;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author: eamon
 * @date: 2019-07-11 16:41
 * @description:
 */
public class CertTools {

    public static final List<JcaX509CertificateHolder> convertToX509CertificateHolder(List<X509Certificate> certificateChain)
            throws CertificateEncodingException {
        final List<JcaX509CertificateHolder> certificateHolderChain = new ArrayList<JcaX509CertificateHolder>();
        for (X509Certificate certificate : certificateChain) {
            certificateHolderChain.add(new JcaX509CertificateHolder(certificate));
        }
        return certificateHolderChain;
    }

    public static X509Certificate parseCertfromByteArray(byte[] cert) throws CertificateParsingException {
        X509Certificate x509Certificate = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
        } catch (CertificateException e) {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
        }
        return x509Certificate;
    }

}
