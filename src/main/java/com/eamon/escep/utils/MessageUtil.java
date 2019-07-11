package com.eamon.escep.utils;

import com.eamon.escep.transport.request.Operation;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * @author: eamon
 * @date: 2019-07-11 14:52
 * @description:
 */
public class MessageUtil {

    private static final Logger log = LoggerFactory.getLogger(MessageUtil.class);

    public static final String GET = "GET";
    public static final String POST = "POST";
    public static final String MSG_PARAM = "message";
    public static final String OP_PARAM = "operation";



    public static byte[] getMessageBytes(final HttpServletRequest req)
            throws IOException {
        if (req.getMethod().equals(POST)) {
            return IOUtils.toByteArray(req.getInputStream());
        } else {
            final Operation op;
            try {
                op = getOperation(req);
            } catch (IllegalArgumentException e) {
                // Assume the caller also calls getOperation and deals with this
                // failure.  For us return the same body we do for non-pki
                // operations.
                return new byte[0];
            }

            if (op == Operation.PKI_OPERATION) {
                String msg = req.getParameter(MSG_PARAM);
                if (msg.length() == 0) {
                    return new byte[0];
                }
                if (log.isDebugEnabled()) {
                    log.debug("Decoding {}", msg);
                }
                return Base64.decode(fixBrokenBase64(msg));
            } else {
                return new byte[0];
            }
        }
    }

    public static Operation getOperation(final HttpServletRequest req) {
        String op = req.getParameter(OP_PARAM);
        if (op == null) {
            return null;
        }
        return Operation.forName(req.getParameter(OP_PARAM));
    }

    /**
     * iOS 11's MDM sends badly encoded Base64 data, with '+' encoded as ' '.
     *
     * @return the base64 string with ' ' replaced by '+'.
     */
    public static String fixBrokenBase64(String base64) {
        return base64.replace(' ', '+');
    }


}
