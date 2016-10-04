
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import android.app.Activity;
import android.content.Context;

public class ExchangeController {

    private ConnectionEngine mConnect;
    private String mErrMsg = null;
    private boolean mError = false;
    private Context mCtx;
    private String mHost = null;
    private ExchangeProtocol protocol;
    private boolean mFederatedIdentities = false;

    public ExchangeController(Context ctx, String hostName) {
        mCtx = ctx;
        mHost = hostName;

        mErrMsg = "";
        mErrMsg = null;
        mError = false;

        protocol = new ExchangeProtocol(CommType.BATCH);
        mConnect = ConnectionEngine.getServerInstance(ctx, mHost);
    }

    private boolean handleError(int resId) {
        mErrMsg = mCtx.getString(resId);
        mError = true;
        return false;
    }

    private boolean handleError(String msg) {
        mErrMsg = msg;
        mError = true;
        return false;
    }

    private boolean handleError(Exception e) {
        mErrMsg = e.getLocalizedMessage();
        mError = true;
        return false;
    }

    private static int fibonacci(int n) {
        if (n == 0) {
            return 0;
        } else if (n == 1) {
            return 1;
        } else {
            return fibonacci(n - 1) + fibonacci(n - 2);
        }
    }

    public void doSleepBackoff(int attempt, long intervalStart, long totalStart)
            throws InterruptedException {
        // backoff poll the server using Fibonacci sequence
        long now = System.currentTimeMillis();
        long diffInterval = now - intervalStart;
        long diffTotal = now - totalStart;
        long msBackoff = fibonacci(attempt) * 1000;
        if ((diffTotal + msBackoff) > ExchangeConfig.MSSVR_TIMEOUT) {
            // don't sleep past the max timeout
            msBackoff = ExchangeConfig.MSSVR_TIMEOUT - diffTotal;
        }
        if (diffInterval < msBackoff) {
            Thread.sleep(msBackoff - diffInterval);
        }
    }

    public boolean doGenerateCommitment(int numUsers, byte[] data) {
        try {
            return protocol.startProtocol(numUsers, data);

        } catch (NoSuchAlgorithmException e) {
            return handleError(e);
        } catch (InvalidKeyException e) {
            return handleError(e);
        } catch (NoSuchPaddingException e) {
            return handleError(e);
        } catch (IllegalBlockSizeException e) {
            return handleError(e);
        } catch (BadPaddingException e) {
            return handleError(e);
        } catch (InvalidAlgorithmParameterException e) {
            return handleError(e);
        } catch (IllegalStateException e) {
            return handleError(e);
        } catch (NoDataToExchangeException e) {
            return handleError(R.string.error_NoDataToExchange);
        }
    }

    public boolean doRequestUserId() {
        try {
            // get assignUser message for server
            byte[] req = protocol.outMessageAssign();

            // send/receive
            byte[] res = mConnect.assign_user(req);

            // parse assignUser message from server
            return protocol.inMessageAssign(res);

        } catch (ExchangeException e) {
            return handleError(e);
        } catch (NoDataToExchangeException e) {
            return handleError(R.string.error_NoDataToExchange);
        }
    }

    private boolean syncCommitments() {
        try {
            boolean postCommit = true;
            long getCommitWait = System.currentTimeMillis();
            int attempt = 0;
            while (protocol.isCommitPhaseComplete()) {
                if (isCanceled()) {
                    return false;
                }

                long intervalStart = System.currentTimeMillis();
                attempt++;

                // get syncCommitments message for server
                byte[] req = protocol.outMessageCommit(postCommit);

                // send/receive
                // get what is on the server now and create a new group
                // this should be a bunch of signatures
                byte[] res = mConnect.sync_commits(req);
                postCommit = false; // done!

                // parse syncCommitments message from server
                protocol.inMessageCommit(res);

                // make sure we aren't waiting forever
                if ((System.currentTimeMillis() - getCommitWait) > ExchangeConfig.MSSVR_TIMEOUT) {
                    return handleError(R.string.error_TimeoutWaitingForAllMembers);
                }

                if (protocol.isCommitPhaseComplete()) {
                    doSleepBackoff(attempt, intervalStart, getCommitWait);
                }
            }
        } catch (ExchangeException e) {
            return handleError(e);
        } catch (InterruptedException e) {
            return handleError(e);
        } catch (NoDataToExchangeException e) {
            return handleError(R.string.error_NoDataToExchange);
        } catch (MoreDataThanUsersException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (AllMembersMustUpgradeException e) {
            return handleError(R.string.error_AllMembersMustUpgrade);
        } catch (HashValidationException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        }
        return true;
    }

    private boolean syncData() {
        try {
            boolean postData = true;
            long getDataWait = System.currentTimeMillis();
            int attempt = 0;
            while (protocol.isDataPhaseComplete()) {
                if (isCanceled()) {
                    return false;
                }

                long intervalStart = System.currentTimeMillis();
                attempt++;

                // get syncData message for server
                byte[] req = protocol.outMessageData(postData);

                // send/receive
                // get what is on the server now and create a new group
                // this should be a bunch of signatures
                byte[] res = mConnect.sync_data(req);
                postData = false; // done!

                // parse syncData message from server
                protocol.inMessageData(res);

                // make sure we aren't waiting forever
                if ((System.currentTimeMillis() - getDataWait) > ExchangeConfig.MSSVR_TIMEOUT) {
                    return handleError(R.string.error_TimeoutWaitingForAllMembers);
                }

                if (protocol.isDataPhaseComplete()) {
                    doSleepBackoff(attempt, intervalStart, getDataWait);
                }
            }

        } catch (ExchangeException e) {
            return handleError(e);
        } catch (InterruptedException e) {
            return handleError(e);
        } catch (MoreDataThanUsersException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (HashValidationException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (InvalidCommitVerifyException e) {
            return handleError(R.string.error_InvalidCommitVerify);
        } catch (AssignDecoysException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        }
        return true;
    }

    public boolean doGetCommitmentsGetData() {

        // commitment start
        // .................................................................
        if (!syncCommitments())
            return false;
        // .................................................................
        // commitment end

        // data start
        // .................................................................
        if (!syncData())
            return false;
        // data end
        // .................................................................

        return true;
    }

    public boolean doSendInvalidSignature() {
        try {
            long getSigsWait = System.currentTimeMillis();
            int attempt = 0;
            while (protocol.isSigsBadPhaseComplete()) {
                if (isCanceled()) {
                    return false;
                }

                long intervalStart = System.currentTimeMillis();
                attempt++;

                // get syncSigs message for server
                byte[] req = protocol.outMessageSig(true, false);

                // send/receive
                // get what is on the server now and create a new group
                // this should be a bunch of signatures
                byte[] res = mConnect.sync_signatures(req);

                // No need to parse response, just that it was sent, because
                // after this we will automatically abort

                // make sure we aren't waiting forever
                if ((System.currentTimeMillis() - getSigsWait) > ExchangeConfig.MSSVR_TIMEOUT) {
                    return handleError(R.string.error_TimeoutWaitingForAllMembers);
                }

                if (protocol.isSigsBadPhaseComplete()) {
                    doSleepBackoff(attempt, intervalStart, getSigsWait);
                }
            }

            // always automatically abort
            return handleError(R.string.error_LocalGroupCommitDiffer);

        } catch (ExchangeException e) {
            return handleError(e);
        } catch (InterruptedException e) {
            return handleError(e);
        }
    }

    private boolean syncSigs() {
        try {
            boolean postSig = true;
            long getSigsWait = System.currentTimeMillis();
            int attempt = 0;
            while (protocol.isSigsPhaseComplete()) {
                if (isCanceled()) {
                    return false;
                }

                long intervalStart = System.currentTimeMillis();
                attempt++;

                // get syncSigs message for server
                byte[] req = protocol.outMessageSig(postSig, true);

                // send/receive
                // get what is on the server now and create a new group
                // this should be a bunch of signatures
                byte[] res = mConnect.sync_signatures(req);
                postSig = false; // done!

                // parse syncSigs message from server
                protocol.inMessageSig(res);

                // make sure we aren't waiting forever
                if ((System.currentTimeMillis() - getSigsWait) > ExchangeConfig.MSSVR_TIMEOUT) {
                    return handleError(R.string.error_TimeoutWaitingForAllMembers);
                }

                if (protocol.isSigsPhaseComplete()) {
                    doSleepBackoff(attempt, intervalStart, getSigsWait);
                }
            }

        } catch (InterruptedException e) {
            return handleError(e);
        } catch (ExchangeException e) {
            return handleError(e);
        } catch (MoreDataThanUsersException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (HashValidationException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (OtherGroupCommitDifferException e) {
            return handleError(R.string.error_OtherGroupCommitDiffer);
        } catch (InvalidCommitVerifyException e) {
            return handleError(R.string.error_InvalidCommitVerify);
        }
        return true;
    }

    /**
     * begin computing nodes for a asymmetric binary public key tree of
     * Diffie-Hellman values
     */
    private boolean syncHalfKeysAndGenerateSecretKey() {
        try {

            protocol.nodesPrep();

            long getKeyNodesWait = System.currentTimeMillis();
            int attempt = 0;
            while (protocol.isNodePhaseComplete()) {
                if (isCanceled()) {
                    return false;
                }

                long intervalStart = System.currentTimeMillis();
                attempt++;

                byte[] req = protocol.outMessageNode();

                byte[] res = mConnect.sync_keynodes(req);

                // parse syncNodes message from server
                protocol.inMessageNode(res);

                // make sure we aren't waiting forever
                if ((System.currentTimeMillis() - getKeyNodesWait) > ExchangeConfig.MSSVR_TIMEOUT) {
                    return handleError(R.string.error_TimeoutWaitingForAllMembers);
                }

                // "get" should poll with exponential backoff, "put" should post
                // immediately, not wait...
                if (protocol.nodeMustBackoff()) {
                    doSleepBackoff(attempt, intervalStart, getKeyNodesWait);
                }
            }

            protocol.nodesFinal();

        } catch (ExchangeException e) {
            return handleError(e);
        } catch (InvalidKeyException e) {
            return handleError(e);
        } catch (InvalidKeySpecException e) {
            return handleError(e);
        } catch (NoSuchAlgorithmException e) {
            return handleError(e);
        } catch (IllegalStateException e) {
            return handleError(e);
        } catch (InterruptedException e) {
            return handleError(e);
        }

        return true;
    }

    private boolean syncMatchNonce() {
        try {
            boolean postNonce = true;
            long getMatchNoncesWait = System.currentTimeMillis();
            int attempt = 0;
            while (protocol.isMatchPhaseComplete()) {
                if (isCanceled()) {
                    return false;
                }

                long intervalStart = System.currentTimeMillis();
                attempt++;

                // get syncMatch message for server
                byte[] req = protocol.outMessageMatch(postNonce);

                // send/receive
                // get what is on the server now and create a new group
                // this should be a bunch of signatures
                byte[] res = mConnect.sync_match(req);
                postNonce = false; // done!

                // parse syncMatch message from server
                protocol.inMessageMatch(res);

                // make sure we aren't waiting forever
                if ((System.currentTimeMillis() - getMatchNoncesWait) > ExchangeConfig.MSSVR_TIMEOUT) {
                    return handleError(R.string.error_TimeoutWaitingForAllMembers);
                }

                if (protocol.isMatchPhaseComplete()) {
                    doSleepBackoff(attempt, intervalStart, getMatchNoncesWait);
                }
            }

        } catch (ExchangeException e) {
            return handleError(e);
        } catch (InterruptedException e) {
            return handleError(e);
        } catch (InvalidKeyException e) {
            return handleError(e);
        } catch (NoSuchAlgorithmException e) {
            return handleError(e);
        } catch (NoSuchPaddingException e) {
            return handleError(e);
        } catch (IllegalBlockSizeException e) {
            return handleError(e);
        } catch (BadPaddingException e) {
            return handleError(e);
        } catch (InvalidAlgorithmParameterException e) {
            return handleError(e);
        } catch (MoreDataThanUsersException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (HashValidationException e) {
            return handleError(R.string.error_MoreDataThanUsers);
        } catch (InvalidCommitVerifyException e) {
            return handleError(R.string.error_InvalidCommitVerify);
        }
        return true;
    }

    public boolean doSendValidSignatureGetSignatures() {

        // sigs start
        // .................................................................
        if (!syncSigs())
            return false;
        // sigs end
        // .................................................................

        return true;
    }

    public boolean doCreateSharedSecretGetNodesAndMatchNonces() {

        // key node start
        // .................................................................
        // true);
        if (!syncHalfKeysAndGenerateSecretKey())
            return false;

        // key node end
        // .................................................................

        // nonce start
        // .................................................................
        if (!syncMatchNonce())
            return false;
        // nonce end
        // .................................................................

        return true;
    }

    public byte[][] decryptMemData() throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        return protocol.endProtocol();
    }

    public byte[] getDecoyHash(int decoyNum) {
        return protocol.getDecoyHash(decoyNum);
    }

    public String getErrorMsg() {
        return mErrMsg;
    }

    public byte[] getHash() {
        return protocol.getHash();
    }

    public int getNumUsers() {
        return protocol.getNumUsers();
    }

    public void setNumUsers(int numUsers) {
        protocol.setNumUsers(numUsers);
    }

    public int getUserId() {
        return protocol.getUserId();
    }

    public boolean isError() {
        return mError;
    }

    public GroupData getGroupData() {
        return protocol.getGroupData();
    }

    public void setUserIdLink(int usridlink) {
        protocol.setUserIdLink(usridlink);
    }

    public int getUserIdLink() {
        return protocol.getUserIdLink();
    }

    public int getNumUsersCommit() {
        return protocol.getNumUsersCommit();
    }

    public int getNumUsersData() {
        return protocol.getNumUsersData();
    }

    public int getNumUsersSigs() {
        return protocol.getNumUsersSigs();
    }

    public int getNumUsersKeyNodes() {
        return protocol.getNumUsersKeyNodes();
    }

    public int getNumUsersMatchNonces() {
        return protocol.getNumUsersMatchNonces();
    }

    public void cancelProtocol() {
        if (mConnect != null) {
            mConnect.setCancelable(true);
        }
    }

    public boolean isCanceled() {
        if (mConnect != null) {
            return mConnect.isCancelable();
        } else {
            return true;
        }
    }

    public void endProtocol() {
        if (mConnect != null) {
            mConnect.shutdownConnection();
        }
    }

    public int getRandomPos(int n) {
        return protocol.getRandomPos(n);
    }

    public long getExchStartTimeMs() {
        if (mConnect != null && mConnect.getExchStartTimer() != null) {
            return mConnect.getExchStartTimer().getTime();
        } else {
            return 0;
        }
    }

    public void setHashSelection(int hashSelection) {
        protocol.setHashSelection(hashSelection);
    }

    public String getStatusBanner(Activity act) {
        StringBuilder banner = new StringBuilder();
        if (protocol.getHash() != null) {
            byte[] selectedHash = new byte[3];
            if (protocol.getHashSelection() == 0) {
                selectedHash = protocol.getHash();
            } else if (protocol.getHashSelection() == 1) {
                selectedHash = protocol.getDecoyHash(1);
            } else if (protocol.getHashSelection() == 2) {
                selectedHash = protocol.getDecoyHash(2);
            }
            boolean english = Locale.getDefault().getLanguage().equals("en");
            if (english) {
                banner.append(WordList.getWordList(selectedHash, 3)).append("\n")
                        .append(WordList.getNumbersList(selectedHash, 3));
            } else {
                banner.append(WordList.getNumbersList(selectedHash, 3)).append("\n")
                        .append(WordList.getWordList(selectedHash, 3));
            }
        } else if (protocol.getNumUsers() > 0) {
            banner.append(String.format(act.getString(R.string.choice_NumUsers), protocol.getNumUsers()));
            if (protocol.getUserIdLink() > 0 && !mFederatedIdentities) {
                // show lowest id only if user typed it in, otherwise the hash value is too long and confusing to the UX
                banner.append(", ").append(act.getString(R.string.label_UserIdHint).toLowerCase())
                        .append(" ").append(protocol.getUserIdLink());
            }
        }
        return banner.toString();
    }

    public void setFederatedIdentities(boolean federatedIdentities) {
        mFederatedIdentities = federatedIdentities;
    }
}
