package com.eamon.escep.server;

import com.eamon.escep.exception.ScepServerException;
import com.eamon.escep.scep.ScepRequestMessage;
import com.eamon.escep.scep.ScepResponseMessage;
import com.eamon.escep.service.ScepService;
import com.eamon.escep.transaction.MessageType;
import com.eamon.escep.transaction.Nonce;
import com.eamon.escep.transaction.PkiStatus;
import com.eamon.escep.transport.request.Operation;
import com.eamon.escep.transport.response.Capability;
import com.eamon.escep.utils.CommonUtils;
import com.eamon.escep.utils.GeneratorCertificate;
import com.eamon.escep.utils.MessageUtil;
import com.eamon.escep.utils.hsm.exception.HsmSignException;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.eamon.escep.utils.MessageUtil.*;

/**
 * @author: eamon
 * @date: 2019-07-11 15:14
 * @description:
 */
@Component
public class ScepServer {

    private static final Logger log = LoggerFactory.getLogger(ScepService.class);

    public void server(HttpServletRequest request, HttpServletResponse response) throws IOException, ScepServerException {
        final String reqMethod = request.getMethod();
        byte[] messageBytes = MessageUtil.getMessageBytes(request);
        // 从 request中获取 操作标识
        final Operation op;
        try {
            op = MessageUtil.getOperation(request);
            if (op == null) {
                // The operation parameter must be set.
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing \"operation\" parameter.");
                return;
            }
        } catch (IllegalArgumentException e) {
            // The operation was not recognised.
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid \"operation\" parameter.");
            return;
        }
        log.debug("Incoming Operation: " + op);
        // 如果是 PKIOperation 操作
        if (op == Operation.PKI_OPERATION) {
            if (messageBytes.length == 0) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing \"message\" data.");
            }
            // 校验 get或post请求
            if (!reqMethod.equals(POST) && !reqMethod.equals(GET)) {
                // PKIOperation must be sent using GET or POST
                response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                response.addHeader("Allow", GET + ", " + POST);
                return;
            }
        } else {
            if (!reqMethod.equals(GET)) {
                // Operations other than PKIOperation must be sent using GET
                response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                response.addHeader("Allow", GET);
                return;
            }
        }

        switch (op) {
            case GET_CA_CAPS:
                try {
                    log.debug("Invoking doGetCaCaps");
                    // 返回 CaCaps 大概意思是 返回 ca的功能列表
                    doGetCaCaps(request, response);
                } catch (Exception e) {
                    throw new ScepServerException(e);
                }
                break;
            case GET_CA_CERT:
                // 如果是 GetCACert 操作
                try {
                    log.debug("Invoking doGetCaCert");
                    // 返回 ca证书
                    doGetCaCert(request, response);
                } catch (Exception e) {
                    throw new ScepServerException(e);
                }
                break;
            case PKI_OPERATION:
                response.setHeader("Content-Type", "application/x-pki-message");
                // todo 根据实现情况决定 是否返回CA
                boolean includeCaCert = true;
                ScepRequestMessage scepRequestMessage = new ScepRequestMessage(messageBytes, includeCaCert);
                doScepCertRequest(scepRequestMessage, response);
                break;
            default:
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "operation not supported!");
                break;
        }


    }

    private void doScepCertRequest(ScepRequestMessage reqmsg, HttpServletResponse response) throws IOException {
        if (reqmsg.getErrorNo() != 0) {
            log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "Can not handle request");
        }

        MessageType messageType = reqmsg.getMessageType();
        switch (messageType) {
            case PKCS_REQ:
                // 1. get ca 并 判断 ca 状态是否是 active
                // 2. 设置解密方式 如果有私钥，就设置 privateKey 如果没有私钥，则自己实现 解密方法
                try {
                    reqmsg.setKeyInfo(null);
                    // 3. 获取 csr 密码
                    String password = reqmsg.getPassword();
                    if (StringUtils.isBlank(password)) {
                        response.sendError(HttpServletResponse.SC_BAD_REQUEST, " No password in request");
                    }
                    // todo 生成证书
                    JcaPKCS10CertificationRequest pkcs10 = reqmsg.getPkcs10();
                    X509Certificate x509Certificate = genCert(pkcs10);
                    ScepResponseMessage responseMessage = new ScepResponseMessage();
                    List<X509Certificate> caChain = new ArrayList<>();
                    caChain.add(CommonUtils.getTestSubca());
                    responseMessage.setSignKeyInfo(caChain, null);
                    responseMessage.setRecipientNonce(reqmsg.getSenderNonce());
                    Nonce retNonce = Nonce.nextNonce();
                    responseMessage.setSenderNonce(retNonce);
                    responseMessage.setTransactionId(reqmsg.getTransactionId());
                    if (reqmsg.getSignercert() != null) {
                        responseMessage.setRecipientKeyInfo(reqmsg.getSignercert().getEncoded());
                    }
                    responseMessage.setCertificate(x509Certificate);
                    responseMessage.setCACert(CommonUtils.getTestSubca());
                    responseMessage.setStatus(PkiStatus.SUCCESS);
                    responseMessage.setIncludeCACert(reqmsg.isIncludeCaCert());
                    responseMessage.setPreferredDigestAlg(reqmsg.getPreferredDigestAlg());
                    responseMessage.create();

                    System.out.println(Base64.toBase64String(responseMessage.getResponseMessage()));
                    response.getOutputStream().write(responseMessage.getResponseMessage());
                    response.getOutputStream().close();
                } catch (CertificateException e) {
                    e.printStackTrace();
                }

                break;
            case GET_CRL:
                break;
            default:
                break;
        }

    }


    private void doGetCaCaps(final HttpServletRequest req, final HttpServletResponse response) throws Exception {
        response.setHeader("Content-Type", "text/plain");
        EnumSet<Capability> capabilities = EnumSet.of(Capability.POST_PKI_OPERATION, Capability.SHA_1);
        for (Capability capability : capabilities) {
            response.getWriter().write(capability.toString());
            response.getWriter().write('\n');
        }
        response.getWriter().close();
    }

    private void doGetCaCert(final HttpServletRequest req,
                             final HttpServletResponse response) throws Exception {
        response.setHeader("Content-Type", "application/x-x509-ca-cert");
        X509Certificate x509Certificate = null;
        try {
            x509Certificate = CommonUtils.getTestSubca();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        byte[] certBytes = new byte[0];
        try {
            certBytes = x509Certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        response.getOutputStream().write(certBytes);
        response.getOutputStream().close();
    }

//    private Set<Capability> doCapabilities(final String identifier) {
//
//    }
//
//    private List<X509Certificate> doGetCaCertificate(String identifier) {
//        X509Certificate testSubca = CommonUtils.getTestSubca();
//    }

    private X509Certificate genCert(JcaPKCS10CertificationRequest csr) throws IOException {
        GeneratorCertificate generatorCertificate = new GeneratorCertificate();
        long hsmKeyId = CommonUtils.subcaCertHsmKeyId;
        X500Name subject = csr.getSubject();
        X509Certificate issuer = null;
        try {
            issuer = CommonUtils.getTestSubca();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        X500Name issuerDn = new X500Name(issuer.getSubjectDN().toString());
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date notAfter = calendar.getTime();

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = generatorCertificate.generateCertificate(subject, issuerDn, notBefore,
                    notAfter, null, BigInteger.ONE, hsmKeyId, csr.getSubjectPublicKeyInfo(),
                    "SHA256", "RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (HsmSignException e) {
            e.printStackTrace();
        }
        return x509Certificate;
    }
}
