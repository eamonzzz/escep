package com.eamon.escep.utils.http;

import com.eamon.escep.utils.ViewData;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import sun.security.x509.X509CertImpl;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by rollin on 15/3/29.
 */
public class HttpUtil {

    public static InputStream getRequestStream(String requestUrl, Map<String, String> params, Map<String, String> headParams, boolean ignoreSSLError, int connectTime, int readTime) throws IOException {
        URL url = null;
        InputStream connectionIn = null;
        StringBuffer paramsBuffer = new StringBuffer();
        if (params != null) {
            for (Map.Entry<String, String> e : params.entrySet()) {
                paramsBuffer.append(e.getKey());
                paramsBuffer.append("=");
                paramsBuffer.append(StringUtils.isBlank(e.getValue()) ? "" : URLEncoder.encode(e.getValue(), "UTF-8"));
                //paramsBuffer.append(e.getValue());
                paramsBuffer.append("&");
            }
            if (paramsBuffer.length() > 1)
                paramsBuffer.setLength(paramsBuffer.length() - 1);
        }

        String urlString = null;
        if (paramsBuffer.length() > 1) {
            if (requestUrl.contains("?")) {
                urlString = requestUrl + "&" + paramsBuffer.toString();
            } else {
                urlString = requestUrl + "?" + paramsBuffer.toString();
            }
        } else urlString = requestUrl;

        url = new URL(urlString);

        if (ignoreSSLError && "https".equalsIgnoreCase(url.getProtocol())) {
            try {
                SslUtils.ignoreSsl();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

//        LogUtil.COMMON_LOGGER.info(new LogData(CatalogEnum.ORDER_CA_LOGGER, url, null));
        HttpURLConnection con;
        if (requestUrl.startsWith("https://"))
            con = (HttpsURLConnection) url.openConnection();
        else con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod("GET");
        con.setConnectTimeout(connectTime);
        if (readTime != 0) {
            con.setReadTimeout(readTime);
        }
        if (headParams != null) {
            for (Map.Entry<String, String> e : headParams.entrySet()) {
                con.setRequestProperty(e.getKey(), e.getValue());
            }
        }


        int returnCode = con.getResponseCode();
        connectionIn = null;
        if (returnCode == 200)
            connectionIn = con.getInputStream();
        else
            connectionIn = con.getErrorStream();

        return connectionIn;
    }


    public static String getCert(String requestUrl) throws IOException {
        Map headParams = new HashMap();
        headParams.put("User-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36");
        InputStream inputStream = getRequestStream(requestUrl, null, headParams, false, 3000, 0);
        int count = 0;
        while (count == 0) {
            count = inputStream.available();
        }
        byte[] b = new byte[count];
        inputStream.read(b);

        X509CertImpl cert = null;
        try {
            cert = new X509CertImpl(b);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter caWriter = new JcaPEMWriter(stringWriter);
        caWriter.writeObject(cert);
        caWriter.flush();
        caWriter.close();
        return stringWriter.toString();


    }


    public static String getRequest(String requestUrl, Map<String, String> params) throws IOException {
        return getRequest(requestUrl, params, false, 3000);
    }

    public static String getRequest(String requestUrl, Map<String, String> params, boolean ignoreSSLError) throws IOException {
        return getRequest(requestUrl, params, ignoreSSLError, 3000);
    }

    public static String getRequest(String requestUrl, Map<String, String> params, boolean ignoreSSLError, int connectTime) throws IOException {

        StringBuffer resBuffer = null;
        InputStream connectionIn = getRequestStream(requestUrl, params, null, ignoreSSLError, connectTime, 0);
        BufferedReader buffer = new BufferedReader(new InputStreamReader(connectionIn));
        String inputLine;
        resBuffer = new StringBuffer();
        while ((inputLine = buffer.readLine()) != null)
            resBuffer.append(inputLine);
        buffer.close();

        return resBuffer.toString();


    }


    public static String getRequest(String requestUrl, Map<String, String> params, boolean ignoreSSLError, int connectTime, int readTime) throws IOException {

        StringBuffer resBuffer = null;
        InputStream connectionIn = getRequestStream(requestUrl, params, null, ignoreSSLError, connectTime, readTime);
        BufferedReader buffer = new BufferedReader(new InputStreamReader(connectionIn));
        String inputLine;
        resBuffer = new StringBuffer();
        while ((inputLine = buffer.readLine()) != null)
            resBuffer.append(inputLine);
        buffer.close();

        return resBuffer.toString();


    }

    public static ViewData proxyRequest(HttpServletRequest request, String urlString) {
        ViewData resultData = new ViewData();
        try {

            URL url = new URL(urlString);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setRequestProperty("Accept-Language", "en-US,en;q=0.8");
            urlConnection.setRequestProperty("Cookie", request.getHeader("Cookie"));
            urlConnection.setRequestMethod("GET");

            //设置 X-Forwarded-For IP
            String xff = request.getHeader("X-Forwarded-For");
            if (!StringUtils.isBlank(xff) && !"unknown".equalsIgnoreCase(xff)) {
                urlConnection.setRequestProperty("X-Forwarded-For", xff + ", " + request.getRemoteAddr());
            } else urlConnection.setRequestProperty("X-Forwarded-For", request.getRemoteAddr());

            StringBuilder sb = new StringBuilder();
            int HttpResult = urlConnection.getResponseCode();
            if (HttpResult == HttpURLConnection.HTTP_OK || HttpResult <= HttpURLConnection.HTTP_CREATED
                    || HttpResult == HttpURLConnection.HTTP_ACCEPTED) {
                BufferedReader br = new BufferedReader(
                        new InputStreamReader(urlConnection.getInputStream(), "utf-8"));
                String line = null;
                while ((line = br.readLine()) != null) {
                    sb.append(line + "\n");
                }
                br.close();
                resultData.setData(sb.toString());
                resultData.success();
            } else {
                resultData.addError(urlConnection.getResponseMessage());
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
            resultData.addError(e.getMessage());
        } catch (IOException e) {
            resultData.addError(e.getMessage());
        }
        return resultData;
    }


    public static String postRequest(String requestUrl, TreeMap<String, String[]> params) throws IOException {
        HashMap<String, String> paramsMap = new HashMap<>();
        for (String key : params.keySet()) {
            paramsMap.put(key, paramsMap.get(key));
        }
        return postRequest(requestUrl, paramsMap, 3000);
    }

    public static String postRequest(String requestUrl, Map<String, String> params) throws IOException {
        return postRequest(requestUrl, params, 3000);
    }

    public static String postRequest(String requestUrl, Map<String, String> params, int connectTime) throws IOException {
        return postRequest(requestUrl, params, connectTime, 0);
    }

    public static String postRequest(String requestUrl, Map<String, String> params, int connectTime, int readTime) throws IOException {
        StringBuffer paramsBuffer = new StringBuffer();
        if (params != null) {
            for (Map.Entry<String, String> e : params.entrySet()) {
                paramsBuffer.append(e.getKey());
                paramsBuffer.append("=");
                paramsBuffer.append(StringUtils.isBlank(e.getValue()) ? "" : URLEncoder.encode(e.getValue(), "UTF-8"));
                //paramsBuffer.append(e.getValue());
                paramsBuffer.append("&");
            }
            if (paramsBuffer.length() > 1)
                paramsBuffer.setLength(paramsBuffer.length() - 1);
        }
        URL url = new URL(requestUrl);
        HttpURLConnection con;
        if (requestUrl.startsWith("https://"))
            con = (HttpsURLConnection) url.openConnection();
        else con = (HttpURLConnection) url.openConnection();
        con.setConnectTimeout(connectTime);
        if (readTime != 0) {
            con.setReadTimeout(readTime);
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestMethod("POST");
        con.setUseCaches(false);
        con.setInstanceFollowRedirects(true);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.connect();
        DataOutputStream out = new DataOutputStream(con
                .getOutputStream());
        out.writeBytes(paramsBuffer.toString());
        out.flush();
        out.close();
        int returnCode = con.getResponseCode();
        InputStream connectionIn = null;
        if (returnCode == 200)
            connectionIn = con.getInputStream();
        else
            connectionIn = con.getErrorStream();
        BufferedReader buffer = new BufferedReader(new InputStreamReader(connectionIn));
        String inputLine;
        StringBuffer resBuffer = new StringBuffer();
        while ((inputLine = buffer.readLine()) != null)
            resBuffer.append(inputLine).append("\r\n");
        buffer.close();
        con.disconnect();
        return resBuffer.toString();
    }

    public static String postJsonRequest(String requestUrl, String params) throws IOException {
        return postJsonRequest(requestUrl, params, 60000, 60000);
    }

    public static String postJsonRequest(String requestUrl, String params, int connectTime, int readTime) throws IOException {
        URL url = new URL(requestUrl);
        HttpURLConnection con;
        if (requestUrl.startsWith("https://"))
            con = (HttpsURLConnection) url.openConnection();
        else con = (HttpURLConnection) url.openConnection();
        con.setConnectTimeout(connectTime);
        if (readTime != 0) {
            con.setReadTimeout(readTime);
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestMethod("POST");
        con.setUseCaches(false);
        con.setInstanceFollowRedirects(true);
        con.setRequestProperty("Content-Type", "application/json");
        con.setRequestProperty("Accept", "application/json");
        con.connect();
        OutputStream out = con.getOutputStream();
        if (params != null) {
            out.write(params.getBytes());
        }
        out.flush();
        out.close();
        int returnCode = con.getResponseCode();
        InputStream connectionIn = null;
        if (returnCode == 200 || returnCode == 201 || returnCode == 202 || returnCode == 204)
            connectionIn = con.getInputStream();
        else
            connectionIn = con.getErrorStream();

        BufferedReader buffer = new BufferedReader(new InputStreamReader(connectionIn));
        String inputLine;
        StringBuffer resBuffer = new StringBuffer();
        while ((inputLine = buffer.readLine()) != null)
            resBuffer.append(inputLine).append("\r\n");
        buffer.close();
        con.disconnect();
        return resBuffer.toString();
    }

    //百度云伙伴 回调专用
    public static String callBackBaiduCloud(String url, String params, Map<String, String> headParams) throws IOException {
        HttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost(url);
        // post.addHeader("Content-type", "application/xml; charset=utf-8");
        if (headParams != null) {
            for (Map.Entry<String, String> e : headParams.entrySet()) {
                post.addHeader(e.getKey(), e.getValue());
            }

        }
        post.setEntity(new StringEntity(params, Charset.forName("UTF-8")));

        HttpResponse httpResponse = client.execute(post);
        HttpEntity entity = httpResponse.getEntity();
        String data = EntityUtils.toString(entity);
        return data;

    }
}
