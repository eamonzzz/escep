package com.eamon.escep.scep;

import com.eamon.escep.asn1.ScepObjectIdentifier;
import com.eamon.escep.exception.MessageDecodingException;
import com.eamon.escep.transaction.*;
import com.eamon.escep.utils.CmsUtil;
import com.eamon.escep.utils.CommonUtils;
import com.eamon.escep.utils.hsm.exception.HsmDecryptException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import static com.eamon.escep.asn1.ScepObjectIdentifier.*;

/**
 * @author: eamon
 * @date: 2019-07-11 11:28
 * @description:
 */
public class ScepRequestMessage {

    private static final Logger log = LoggerFactory.getLogger(ScepRequestMessage.class);

    private byte[] scepMsg;
    private boolean includeCaCert;

    private transient X509Certificate signercert;

    private MessageType messageType;
    private Nonce senderNonce;
    private TransactionId transactionId;

    private CMSEnvelopedData envelopedData;

    private PrivateKey privateKey;

    /**
     * The pkcs10 request message, not serialized.
     */
    protected transient JcaPKCS10CertificationRequest pkcs10 = null;

    private String password;

    /**
     * IssuerAndSerialNUmber for CRL request
     */
    private transient IssuerAndSerialNumber issuerAndSerno = null;

    /**
     * Type of error
     */
    private int error = 0;

    /**
     * Error text
     */
    private String errorText = null;

    /**
     * 为了兼容之前的草案，所以消息摘要默认为md5
     * 现代的草案中，请求、响应都将使用SHA-1
     */
    private transient String preferredDigestAlg = CMSSignedGenerator.DIGEST_MD5;

    public ScepRequestMessage(byte[] scepMsg, boolean includeCaCert) throws IOException {
        this.scepMsg = scepMsg;
        this.includeCaCert = includeCaCert;
        init();
    }

    private void init() throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("> init");
        }

        CMSSignedData cmsSignedData = null;
        SignerInformationStore signerInformationStore = null;
        try {
            cmsSignedData = new CMSSignedData(scepMsg);
            signerInformationStore = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> signers = signerInformationStore.getSigners();
            Iterator<SignerInformation> iter = signers.iterator();
            if (iter.hasNext()) {
                SignerInformation si = iter.next();
                preferredDigestAlg = si.getDigestAlgOID();
                log.debug("Set " + preferredDigestAlg + " as preferred digest algorithm for SCEP");
            }
        } catch (CMSException e) {
            // 忽略异常，将使用默认的摘要算法
            log.error("CMSException trying to get preferred digest algorithm: ", e);
        }

        if (cmsSignedData != null) {

            // 解析并验证PKIOperation消息PKCS＃7的完整性
            // 获取 请求者 自签名证书
            try {
                Store<X509CertificateHolder> reqStore = cmsSignedData.getCertificates();
                Collection<X509CertificateHolder> reqCerts = reqStore.getMatches(null);
                X509CertificateHolder holder = reqCerts.iterator().next();
                ByteArrayInputStream bais = new ByteArrayInputStream(holder.getEncoded());
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                signercert = (X509Certificate) certificateFactory.generateCertificate(bais);
            } catch (CertificateException e) {
                log.error("Error parsing requestKeyInfo : ", e);
            }

            // 获取 属性
            SignerInformation signerInfo = signerInformationStore.get(new JcaSignerId(signercert));
            Hashtable<ASN1ObjectIdentifier, Attribute> attrTable = signerInfo.getSignedAttributes().toHashtable();

            messageType = toMessageType(attrTable.get(toOid(MESSAGE_TYPE)));
            senderNonce = toNonce(attrTable.get(toOid(SENDER_NONCE)));
            transactionId = toTransactionId(attrTable.get(toOid(TRANS_ID)));

            // 判断是否是 PKCSReq
            if (messageType.equals(MessageType.PKCS_REQ) || messageType.equals(MessageType.GET_CRL) ||
                    messageType.equals(MessageType.GET_CERT_INITIAL)) {
                /**
                 * 提取内容：
                 * 如果是 PKCS_REQ 则为加密的 PKCS10
                 * 如果是 GET_CRL 则提取加密的 IssuerAndSerialNumber
                 * 如果是 GET_CERT_INITIAL 则提取加密的颁发者和主题
                 */
                CMSProcessable signedContent = cmsSignedData.getSignedContent();
                try {
                    envelopedData = getEnvelopedData(signedContent.getContent());
                } catch (MessageDecodingException e) {
                    errorText = "EncapsulatedContentInfo does not contain PKCS7 envelopedData: ";
                    log.error(errorText);
                    error = 2;
                }
            }
        } else {
            errorText = "PKCSReq does not contain 'signedData'";
            log.error(errorText);
            error = 1;
        }
    }

    private void decrypt() throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">decrypt");
        }

        // todo 解密
        long hsmKeyId = CommonUtils.subcaCertHsmKeyId;
        byte[] decBytes = new byte[0];
        try {
            decBytes = CmsUtil.hsmDecode(envelopedData, hsmKeyId);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (HsmDecryptException e) {
            e.printStackTrace();
        }

        if (messageType == MessageType.PKCS_REQ) {
            pkcs10 = new JcaPKCS10CertificationRequest(decBytes);
            if (log.isDebugEnabled()) {
                log.debug("Successfully extracted PKCS10:" + new String(Base64.encode(pkcs10.getEncoded())));
            }
        }
        if (messageType == MessageType.GET_CRL) {
            issuerAndSerno = IssuerAndSerialNumber.getInstance(decBytes);
            log.debug("Successfully extracted IssuerAndSerialNumber.");
        }

        if (log.isTraceEnabled()) {
            log.trace("<decrypt");
        }
    }

    public String getPassword() {
        if (log.isTraceEnabled()) {
            log.trace(">getPassword()");
        }

        String ret = null;
        try {
            if (password != null) {
                return password;
            }
            if (pkcs10 == null) {
                init();
                decrypt();
            }

            org.bouncycastle.asn1.pkcs.Attribute[] attributes = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            ASN1Encodable obj = null;
            if (attributes.length == 0) {
                // See if we have it embedded in an extension request instead
                attributes = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
                if (attributes.length == 0) {
                    return null;
                }
                if (log.isDebugEnabled()) {
                    log.debug("got extension request");
                }
                ASN1Set values = attributes[0].getAttrValues();
                if (values.size() == 0) {
                    return null;
                }
                Extensions exts = Extensions.getInstance(values.getObjectAt(0));
                Extension ext = exts.getExtension(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
                if (ext == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("no challenge password extension");
                    }
                    return null;
                }
                obj = ext.getExtnValue();
            } else {
                // If it is a challengePassword directly, it's just to grab the value
                ASN1Set values = attributes[0].getAttrValues();
                obj = values.getObjectAt(0);
            }

            if (obj != null) {
                ASN1String str = null;
                try {
                    // Should be any DirectoryString according to RFC2985, preferably a PrintableString or UTF8String
                    str = DirectoryString.getInstance((obj));
                } catch (IllegalArgumentException ie) {
                    // This was not a DirectoryString type, it could then be IA5string, breaking pkcs#9 v2.0
                    // but some version of openssl have been known to produce IA5strings
                    str = DERIA5String.getInstance((obj));
                }

                if (str != null) {
                    ret = str.getString();
                }
            }

        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        }
        if (log.isTraceEnabled()) {
            log.trace("<getPassword()");
        }
        return ret;
    }

    private ASN1ObjectIdentifier toOid(final ScepObjectIdentifier oid) {
        return new ASN1ObjectIdentifier(oid.id());
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

    private Nonce toNonce(final Attribute attr) {
        // Sometimes we don't get a sender nonce.
        if (attr == null) {
            return null;
        }
        final DEROctetString octets = (DEROctetString) attr.getAttrValues()
                .getObjectAt(0);

        return new Nonce(octets.getOctets());
    }

    private MessageType toMessageType(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return MessageType.valueOf(Integer.valueOf(string.getString()));
    }

    private TransactionId toTransactionId(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return new TransactionId(string.getOctets());
    }

    private PkiStatus toPkiStatus(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return PkiStatus.valueOf(Integer.valueOf(string.getString()));
    }

    private FailInfo toFailInfo(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return FailInfo.valueOf(Integer.valueOf(string.getString()));
    }

    public void setKeyInfo(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public int getErrorNo() {
        return error;
    }

    public String getErrorText() {
        return errorText;
    }

    public byte[] getScepMsg() {
        return scepMsg;
    }

    public boolean isIncludeCaCert() {
        return includeCaCert;
    }

    public X509Certificate getSignercert() {
        return signercert;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public Nonce getSenderNonce() {
        return senderNonce;
    }

    public TransactionId getTransactionId() {
        return transactionId;
    }

    public CMSEnvelopedData getEnvelopedData() {
        return envelopedData;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public JcaPKCS10CertificationRequest getPkcs10() {
        return pkcs10;
    }

    public IssuerAndSerialNumber getIssuerAndSerno() {
        return issuerAndSerno;
    }

    public String getPreferredDigestAlg() {
        return preferredDigestAlg;
    }
}
