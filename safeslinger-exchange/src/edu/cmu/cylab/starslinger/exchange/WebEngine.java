
package edu.cmu.cylab.starslinger.exchange;

/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2010-2015 Carnegie Mellon University
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;

/**
 * This class does all of the TCP connection setup to the server and handles the
 * HTTP functions GET and POST. In addition to basic GET and POST, it also has
 * web_spate specific functions to get the group size, get the commitments,
 * create the group on the server, send data, ....
 */
public class WebEngine extends ConnectionEngine {

    private static final String TAG = ExchangeConfig.LOG_TAG;
    private String mUrlPrefix = ExchangeConfig.HTTPURL_PREFIX;
    private String mHost;
    private String mUrlSuffix = ExchangeConfig.HTTPURL_SUFFIX;
    private HttpsURLConnection mConn;

    public void setHost(String host) {
        mHost = host;
    }

    private byte[] doPost(String uri, byte[] requestBody) throws ExchangeException {
        mCancelable = false;

        byte[] reqData = null;
        long startTime = SystemClock.elapsedRealtime();
        int statCode = 0;
        String statMsg = "";
        String error = "";
        boolean responseAvailable = false;

        try {
            // sets up parameters
            KeyStore trusted = null;
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {
                new CheckedX509TrustManager(trusted)
            }, null);
            URL url = new URL(uri);
            mConn = (HttpsURLConnection) url.openConnection();
            mConn.setSSLSocketFactory(context.getSocketFactory());
            mConn.setRequestMethod("POST");
            mConn.setRequestProperty("Content-Type", "application/octet-stream; charset=utf-8");
            mConn.setRequestProperty("Expect", "100-continue");
            mConn.setDoOutput(true);
            mConn.setDoInput(true);

            // Execute HTTP Post Request
            OutputStream os = mConn.getOutputStream();
            os.write(requestBody);
            os.flush();
            os.close();
            responseAvailable = true;

            // handle issues
            statCode = mConn.getResponseCode();
            statMsg = mConn.getResponseMessage();
            if (statCode != HttpURLConnection.HTTP_OK) {
                // contains useful data for users, do not swallow, handle
                // properly
                error = (String.format(mCtx.getString(R.string.error_HttpCode), statCode) + ", \'"
                        + statMsg + "\'");
            } else {
                // read output
                InputStream is = ((mConn.getInputStream()));
                byte[] buffer = new byte[8192];
                int bytesRead;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                while ((bytesRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                reqData = baos.toByteArray();
                is.close();
            }
        } catch (UnsupportedEncodingException e) {
            error = e.getLocalizedMessage() + " (" + e.getClass().getSimpleName() + ")";
        } catch (java.io.IOException e) {
            // just show a simple Internet connection error, so as not to
            // confuse users
            e.printStackTrace();
            error = mCtx.getString(R.string.error_CorrectYourInternetConnection);
        } catch (RuntimeException e) {
            error = e.getLocalizedMessage() + " (" + e.getClass().getSimpleName() + ")";
        } catch (OutOfMemoryError e) {
            error = mCtx.getString(R.string.error_OutOfMemoryError);
        } catch (KeyManagementException e) {
            error = e.getLocalizedMessage() + " (" + e.getClass().getSimpleName() + ")";
        } catch (NoSuchAlgorithmException e) {
            error = e.getLocalizedMessage() + " (" + e.getClass().getSimpleName() + ")";
        } catch (KeyStoreException e) {
            error = e.getLocalizedMessage() + " (" + e.getClass().getSimpleName() + ")";
        } finally {
            long msDelta = SystemClock.elapsedRealtime() - startTime;
            if (responseAvailable) {
                Log.d(TAG, uri + ", " + requestBody.length + "b sent, "
                        + (reqData != null ? reqData.length : 0) + "b recv, " + statCode
                        + " code, " + msDelta + "ms");
            }
        }

        if (!TextUtils.isEmpty(error) || reqData == null) {
            throw new ExchangeException(error);
        }
        return reqData;
    }

    @Override
    public void shutdownConnection() {
        if (mConn != null) {
            mConn.disconnect();
            mConn = null;
        }
    }

    @Override
    protected byte[] assignUser(byte[] requestBody) throws ExchangeException {
        mExchStartTimer = new Date(); // total timeout begins at first online
                                      // call
        return doPost(mUrlPrefix + mHost + "/assignUser" + mUrlSuffix, requestBody);
    }

    @Override
    protected byte[] syncUsers(byte[] requestBody) throws ExchangeException {
        return doPost(mUrlPrefix + mHost + "/syncUsers" + mUrlSuffix, requestBody);
    }

    @Override
    protected byte[] syncData(byte[] requestBody) throws ExchangeException {
        return doPost(mUrlPrefix + mHost + "/syncData" + mUrlSuffix, requestBody);
    }

    @Override
    protected byte[] syncSignatures(byte[] requestBody) throws ExchangeException {
        return doPost(mUrlPrefix + mHost + "/syncSignatures" + mUrlSuffix, requestBody);
    }

    @Override
    protected byte[] syncKeyNodes(byte[] requestBody) throws ExchangeException {
        return doPost(mUrlPrefix + mHost + "/syncKeyNodes" + mUrlSuffix, requestBody);
    }

    @Override
    protected byte[] syncMatch(byte[] requestBody) throws ExchangeException {
        return doPost(mUrlPrefix + mHost + "/syncMatch" + mUrlSuffix, requestBody);
    }
}
