package com.eamon.escep.scep;

import com.eamon.escep.asn1.ScepObjectIdentifier;
import com.eamon.escep.cms.ExternalSignatureCMSSignedDataGenerator;
import com.eamon.escep.cms.ExternalSignatureSignerInfoGenerator;
import com.eamon.escep.exception.MessageEncodingException;
import com.eamon.escep.transaction.*;
import com.eamon.escep.utils.AlgorithmTools;
import com.eamon.escep.utils.CertTools;
import com.eamon.escep.utils.CommonUtils;
import com.eamon.escep.utils.hsm.HsmUtil;
import com.eamon.escep.utils.hsm.RequestHsmSignDataInfo;
import com.eamon.escep.utils.hsm.ResponseHsmSignDataInfo;
import com.eamon.escep.utils.hsm.exception.HsmSignException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * @author: eamon
 * @date: 2019-07-11 15:59
 * @description:
 */
public class ScepResponseMessage {

    private static final Logger log = LoggerFactory.getLogger(ScepResponseMessage.class);

    /**
     * The encoded response message
     */
    private byte[] responseMessage = null;

    /**
     * status for the response
     */
    private PkiStatus status = PkiStatus.SUCCESS;

    /**
     * Possible fail information in the response. Defaults to 'badRequest (2)'.
     */
    private FailInfo failInfo = null;

    /**
     * Possible clear text error information in the response. Defaults to null.
     */
    private String failText = null;

    /**
     * Certificate for the signer of the response message (CA or RA)
     */
    private transient Collection<X509Certificate> signCertChain = null;

    /**
     * Private key used to sign the response message
     */
    private transient PrivateKey signKey = null;

    /**
     * RecipientNonce in a response is the senderNonce from the request. This is base64 encoded bytes
     */
    private Nonce recipientNonce = null;

    /**
     * SenderNonce. This is base64 encoded bytes
     */
    private Nonce senderNonce = null;

    /**
     * transaction id
     */
    private TransactionId transactionId = null;

    /** request key info, this is the requester's self-signed certificate used to identify the senders public key */
    /**
     * recipient key identifier, usually IssuerAndSerialno in X509 world.
     */
    private byte[] recipientKeyInfo;

    /**
     * Default digest algorithm for SCEP response message, can be overridden
     */
    private transient String digestAlg = CMSSignedDataGenerator.DIGEST_MD5;

    /**
     * If the CA certificate should be included in the reponse or not, default to true = yes
     */
    private transient boolean includeCACert = true;

    /**
     * Certificate to be in response message, not serialized
     */
    private transient X509Certificate cert = null;

    private transient CRL crl = null;

    /**
     * Certificate for the CA of the response certificate in successful responses, is the same as signCert if not using RA mode
     */
    private transient X509Certificate caCert = null;

    public byte[] getResponseMessage() {
        return responseMessage;
    }

    public void setStatus(PkiStatus status) {
        this.status = status;
    }

    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }


    //Certificate for the signer of the response message (CA or RA)
    public void setSignKeyInfo(Collection<X509Certificate> certs, PrivateKey key) {
        this.signCertChain = certs;
        this.signKey = key;
    }

    public void setRecipientNonce(Nonce recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    public void setSenderNonce(Nonce senderNonce) {
        this.senderNonce = senderNonce;
    }

    public void setTransactionId(TransactionId transactionId) {
        this.transactionId = transactionId;
    }

    public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
        this.recipientKeyInfo = recipientKeyInfo;
    }

    // Which digest algorithm to use to create the response, if applicable
    public void setPreferredDigestAlg(String digestAlg) {
        this.digestAlg = digestAlg;
    }

    public void setIncludeCACert(boolean includeCACert) {
        this.includeCACert = includeCACert;
    }

    public void setCertificate(X509Certificate cert) {
        this.cert = cert;
    }

    public void setCrl(CRL crl) {
        this.crl = crl;
    }

    public void setCACert(X509Certificate caCert) {
        this.caCert = caCert;
    }

    public void create() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            if (status.equals(PkiStatus.SUCCESS)) {
                log.debug("Creating a STATUS_OK message.");
            } else {
                if (status.equals(PkiStatus.FAILURE)) {
                    log.debug("Creating a STATUS_FAILED message (or returning false).");
                    return;
                } else {
                    log.debug("Creating a STATUS_PENDING message.");
                }
            }
            CMSTypedData msg = getContent();

            // add authenticated attributes...status, transactionId, sender- and recipientNonce and more...
            Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
            ASN1ObjectIdentifier oid;
            Attribute attr;
            DERSet value;

            // Message type (certrep)
            oid = new ASN1ObjectIdentifier(ScepObjectIdentifier.MESSAGE_TYPE.id());
            value = new DERSet(new DERPrintableString("3"));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            // TransactionId
            if (transactionId != null) {
                oid = new ASN1ObjectIdentifier(ScepObjectIdentifier.TRANS_ID.id());
                log.debug("Added transactionId: " + transactionId);
                value = new DERSet(new DERPrintableString(transactionId.toString()));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // status
            oid = new ASN1ObjectIdentifier(ScepObjectIdentifier.PKI_STATUS.id());
            value = new DERSet(new DERPrintableString(status.getStringValue()));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            if (status.equals(PkiStatus.FAILURE)) {
                oid = new ASN1ObjectIdentifier(ScepObjectIdentifier.FAIL_INFO.id());
                log.debug("Added failInfo: " + failInfo.getValue());
                value = new DERSet(new DERPrintableString(failInfo.getStringValue()));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // senderNonce
            if (senderNonce != null) {
                oid = new ASN1ObjectIdentifier(ScepObjectIdentifier.SENDER_NONCE.id());
                log.debug("Added senderNonce: " + senderNonce);
                value = new DERSet(new DEROctetString(senderNonce.getBytes()));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // recipientNonce
            if (recipientNonce != null) {
                oid = new ASN1ObjectIdentifier(ScepObjectIdentifier.RECIPIENT_NONCE.id());
                log.debug("Added recipientNonce: " + recipientNonce);
                value = new DERSet(new DEROctetString(recipientNonce.getBytes()));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // Add our signer info and sign the message
            X509Certificate cacert = signCertChain.iterator().next();
            log.debug("Signing SCEP message with cert: " + cacert.getSubjectDN().toString());
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(digestAlg, CMSSignedDataGenerator.ENCRYPTION_RSA);

            ASN1ObjectIdentifier contentType = msg.getContentType();
            AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(AlgorithmTools
                    .getSignAlgOidFromDigestAndKey(digestAlg, CMSSignedDataGenerator.ENCRYPTION_RSA));
            DigestCalculatorProvider digestCalculatorProvider = getDigestCalculator();
            DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
            AlgorithmIdentifier digestAlgId = digestCalculator.getAlgorithmIdentifier();
            byte[] digest = digestCalculator.getDigest();

            Map baseParameters = this.getBaseParameters(contentType, digestAlgId, sigAlgId, digest);
            CMSAttributeTableGenerator atGen = new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes));
            Map map = Collections.unmodifiableMap(baseParameters);

            AttributeTable attributeTable = atGen.getAttributes(map);


            ExternalSignatureCMSSignedDataGenerator cmsSignedDataGenerator = new ExternalSignatureCMSSignedDataGenerator();

            // 这里 放 生成的证书和上级ca证书
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(signCertChain));
            cmsSignedDataGenerator.addCertificatesAndCRLs(certStore);

            // 构建 签名信息
            ExternalSignatureSignerInfoGenerator signerInfoGenerator =
                    new ExternalSignatureSignerInfoGenerator(OIWObjectIdentifiers.idSHA1.getId(),
                            CMSSignedDataGenerator.ENCRYPTION_RSA);
            signerInfoGenerator.setsAttr(attributeTable);
            signerInfoGenerator.setCertificate(caCert);
//1.3.14.3.2.26
            // 获取代签名数据
            byte[] bytesToSign = signerInfoGenerator.getBytesToSign(PKCSObjectIdentifiers.data, msg, "BC");

            // 已签名数据
            byte[] signedData;
            // 开始签名
            String hashAlg = signatureAlgorithmName.substring(0, signatureAlgorithmName.toUpperCase().indexOf("WITH"));
            byte[] calculateHash = calculateHash(hashAlg, bytesToSign);
            String base64Data = Base64.toBase64String(calculateHash);
            log.debug("Signing {} content", msg);
            long hsmKeyId = CommonUtils.subcaCertHsmKeyId;
            RequestHsmSignDataInfo requestHsmSignDataInfo = new RequestHsmSignDataInfo(base64Data, hsmKeyId, hashAlg);
            ResponseHsmSignDataInfo responseHsmSignDataInfo = HsmUtil.requestHsmSignData(requestHsmSignDataInfo);
            signedData = Base64.decode(responseHsmSignDataInfo.getSignature());

            signerInfoGenerator.setSignedBytes(signedData);

            cmsSignedDataGenerator.addSignerInf(signerInfoGenerator);

            CMSSignedData pkimessage = cmsSignedDataGenerator.generate(msg, true);
            responseMessage = pkimessage.getEncoded();

        } catch (CMSException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (MessageEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertStoreException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (HsmSignException e) {
            e.printStackTrace();
        }
    }

    public CMSTypedData getContent() throws CRLException, CertificateEncodingException, CMSException {
        CMSTypedData msg = null;
        if (status.equals(PkiStatus.SUCCESS)) {
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            // Add the issued certificate to the signed portion of the CMS (as signer, degenerate case)
            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            if (cert != null) {
                log.debug("Adding certificates to response message");
                certList.add(cert);
                // Add the CA cert, it's optional but Cisco VPN client complains if it isn't there
                if (includeCACert) {
                    if (caCert != null) {
                        // If we have an explicit CAcertificate
                        log.debug("Including explicitly set CA certificate in SCEP response.");
                        certList.add(caCert);
                    } else {
                        // If we don't have an explicit caCert, we think that the signCert is the CA cert
                        // If we have an explicit caCert, the signCert is probably the RA certificate, and we don't include that one
                        log.debug("Including message signer certificate in SCEP response.");
                        certList.add(signCertChain.iterator().next());
                    }
                }
            }
            // Create the signed CMS message to be contained inside the envelope
            // this message does not contain any message, and no signerInfo
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new CollectionStore<>(CertTools.convertToX509CertificateHolder(certList)));
            if (crl != null) {
                gen.addCRL(new JcaX509CRLHolder((X509CRL) crl));
            }

            CMSSignedData cmsSignedData = gen.generate(new CMSAbsentContent(), false);

            // Envelope the CMS message
            if (recipientKeyInfo != null) {
                try {
                    X509Certificate rec = CertTools.parseCertfromByteArray(recipientKeyInfo);
                    log.debug("Added recipient information - issuer: '" + rec.getIssuerDN().toString()
                            + "', serno: '" + rec.getSerialNumber());
                    edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(rec)
                            .setProvider(new BouncyCastleProvider()));
                } catch (CertificateParsingException e) {
                    throw new IllegalArgumentException("Can not decode recipients self signed certificate!", e);
                }
            } else {
                edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert)
                        .setProvider(new BouncyCastleProvider()));
            }
            try {
                JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder =
                        new JceCMSContentEncryptorBuilder(SMIMECapability.dES_CBC)
                                .setProvider(new BouncyCastleProvider());
                CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(cmsSignedData.getEncoded()),
                        jceCMSContentEncryptorBuilder.build());
                if (log.isDebugEnabled()) {
                    log.debug("Enveloped data is " + ed.getEncoded().length + " bytes long");
                }
                msg = new CMSProcessableByteArray(ed.getEncoded());
            } catch (IOException e) {
                throw new IllegalStateException("Unexpected IOException caught", e);
            }

        } else {
            msg = new CMSProcessableByteArray(new byte[0]);
        }
        return msg;
    }

    private DigestCalculatorProvider getDigestCalculator()
            throws MessageEncodingException {
        try {
            return new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new MessageEncodingException(e);
        }
    }

    private Map<String, Object> getBaseParameters(ASN1ObjectIdentifier contentType, AlgorithmIdentifier digestAlgId,
                                                  AlgorithmIdentifier signatureAlgId, byte[] var3) {
        HashMap<String, Object> var4 = new HashMap<>();
        if (contentType != null) {
            var4.put("contentType", contentType);
        }

        var4.put("digestAlgID", digestAlgId);
        var4.put("digest", Arrays.clone(var3));
        var4.put("signatureAlgID", signatureAlgId);
        return var4;
    }

    public byte[] calculateHash(String hashAlg, byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlg, new BouncyCastleProvider());
        messageDigest.update(data);
        return messageDigest.digest();
    }

}
