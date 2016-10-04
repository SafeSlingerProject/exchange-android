
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

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.BitSet;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ExchangeProtocol {
    private byte[] mEncData = null;
    private byte[] mNonceMatch;
    private byte[] mNonceWrong;
    private byte[] mHashHashMatch;
    private byte[] mHashMatch;
    private byte[] mHashWrong;
    private byte[] mCommitA;
    private byte[] mCommitB;
    private int mUsrId;
    private int mUsrIdLink;
    private int mNumUsers;
    private static SecureRandom mRandom = new SecureRandom();
    private byte[] mPackedData;
    private int[] mGroupIds;
    private GroupData mGrpInfo;
    private byte[] mHashVal;
    private GroupData mSigsInfo;
    private byte[] mDecoyHash1;
    private byte[] mDecoyHash2;
    private byte[] mDHSecretKey;
    private byte[] mDHHalfKey;
    private CryptoAccess mCrypto;
    private int mRandomPosSrc;
    private int mHashSelection;
    private int mNumUsersCommit = 0;
    private int mNumUsersData = 0;
    private int mNumUsersSigs = 0;
    private int mNumUsersKeyNodes = 0;
    private int mNumUsersMatchNonces = 0;
    private int mVersion;
    private int mLatestServerVersion;
    private int mLowestClientVersion;
    private CommType mCommMode;

    private int[] usridList = null;
    private byte[] commitList = null;
    private byte[] dataList = null;
    private byte[] sigsList = null;
    private byte[] nonceList = null;

    private byte[] pub = null;
    private byte[][] excgHalfKeys = null;
    private int[] orderedIDs = null;
    private int pos = -1;
    private int curNodePos;
    private byte[] mynode = null;

    public ExchangeProtocol(CommType mode) {
        mCommMode = mode;

        mNonceMatch = new byte[ExchangeConfig.HASH_LEN];
        mNonceWrong = new byte[ExchangeConfig.HASH_LEN];
        mDecoyHash1 = new byte[3];
        mDecoyHash2 = new byte[3];

        mNumUsers = 0;
        mHashSelection = -1;

        mVersion = ExchangeConfig.getMinVersionCode();
        mLowestClientVersion = ExchangeConfig.getMinVersionCode();

        mNumUsersCommit = 0;
        mNumUsersData = 0;
        mNumUsersSigs = 0;
        mNumUsersKeyNodes = 0;
        mNumUsersMatchNonces = 0;

        // Select a random user id to use to identify yourself when
        // talking with the web server.
        mUsrId = mRandom.nextInt(Integer.MAX_VALUE);
    }

    // Public Methods /////////////////////////////////////////

    /***
     * This will take in the plaintext data you will share with others, and
     * encrypt is while generating the proper multi-commitment hash tree of
     * ephemeral values for later validation.
     */
    public boolean startProtocol(int numUsers, byte[] data) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, NoDataToExchangeException {

        if (mCommMode == CommType.DIRECT) {
            return false;
        }

        if (data == null) {
            throw new NoDataToExchangeException();
        }

        mNumUsers = numUsers;

        // create nonces and hashes here since data may have been updated
        mRandom.nextBytes(mNonceMatch);
        mRandom.nextBytes(mNonceWrong);

        // encrypt the data with match nonce
        mCrypto = new CryptoAccess();
        mEncData = mCrypto.encryptData(data, mNonceMatch);

        // based on those nonces, generate the various commitments
        mHashWrong = CryptoAccess.computeSha3Hash(mNonceWrong);
        mHashMatch = CryptoAccess.computeSha3Hash(mNonceMatch);
        mHashHashMatch = CryptoAccess.computeSha3Hash(mHashMatch);
        mCommitA = CryptoAccess.computeSha3Hash2(mHashHashMatch, mHashWrong);

        // generate DH half key for later encryption of match nonce
        mDHHalfKey = mCrypto.generateDHPublicKey();
        mCommitB = CryptoAccess.computeSha3Hash3(mCommitA, mDHHalfKey, mEncData);

        return true;
    }

    /**
     * send commitment, receives unique short user id
     *
     * @throws NoDataToExchangeException
     */
    public byte[] outMessageAssign() throws NoDataToExchangeException {
        if (mCommitB == null || mCommitB.length == 0) {
            throw new NoDataToExchangeException();
        }

        ByteBuffer msg = ByteBuffer.allocate(4 + mCommitB.length);
        msg.putInt(mVersion);
        msg.put(mCommitB);

        return msg.array();
    }

    public boolean inMessageAssign(byte[] msg) {
        int id = 0;
        ByteBuffer res = ByteBuffer.wrap(msg);
        mLatestServerVersion = res.getInt();

        id = res.getInt();
        if (id > 0) {
            mUsrId = id;
            return true;
        }
        return false;
    }

    /**
     * send our own matches once, list of all users we have, gathers all others
     * when available receives the group id, total user number (including ours),
     * actual user number, list of users we did not get yet
     *
     * @param postCommit
     * @throws NoDataToExchangeException
     */
    public byte[] outMessageCommit(boolean postCommit) throws NoDataToExchangeException {
        if (mCommitB == null || mCommitB.length == 0) {
            throw new NoDataToExchangeException();
        }
        if (postCommit) {
            usridList = null;
            commitList = null;

            mNumUsersCommit = 0;
            mLowestClientVersion = mVersion;
            ByteBuffer ours = ByteBuffer.allocate(4 + 4 + 4 + mCommitB.length);
            ours.putInt(1).putInt(mUsrId).putInt(mCommitB.length).put(mCommitB);

            // add just our own to start
            mNumUsersCommit = 1;
            usridList = appendServerUserIds(usridList, ours.array());
            commitList = appendServerBytes(commitList, ours.array());
        }
        ByteBuffer msg = ByteBuffer.allocate(4 + 4 + 4 + 4 + (usridList.length * 4)
                + mCommitB.length);
        msg.putInt(mVersion);
        msg.putInt(mUsrId);
        msg.putInt(mUsrIdLink);
        msg.putInt(usridList.length);
        for (int user : usridList) {
            msg.putInt(user);
        }
        msg.put(postCommit ? mCommitB : new byte[0]);

        return msg.array();
    }

    public void inMessageCommit(byte[] msg) throws MoreDataThanUsersException,
            AllMembersMustUpgradeException, HashValidationException {
        ByteBuffer theirs = ByteBuffer.wrap(msg);

        // add updates
        int offset = 0;
        mLatestServerVersion = theirs.getInt();
        mLowestClientVersion = theirs.getInt(); // pull out version
        offset += 8;

        byte[] tmpBuf = new byte[theirs.limit() - offset];
        mNumUsersCommit = theirs.getInt(); // pull out grand total
        offset += 4;
        tmpBuf = new byte[theirs.limit() - offset];
        theirs.get(tmpBuf, 0, theirs.remaining());
        if (mNumUsersCommit > 0) {
            usridList = appendServerUserIds(usridList, tmpBuf);
            commitList = appendServerBytes(commitList, tmpBuf);

            if (mNumUsersCommit > mNumUsers) {
                throw new MoreDataThanUsersException();
            }
        }

        if (mNumUsersCommit == mNumUsers) {
            endValidationCommit();
        }
    }

    private void endValidationCommit() throws AllMembersMustUpgradeException,
            HashValidationException {

        mPackedData = commitList;

        // ensure all are using minimum version for this code base
        if (mLowestClientVersion < ExchangeConfig.getMinVersionCode()) {
            throw new AllMembersMustUpgradeException();
        }

        mGrpInfo = new GroupData(mNumUsers);
        if (mGrpInfo.save_ID_data(mPackedData) != 0) {
            throw new HashValidationException();
        }
    }

    /**
     * send our own data once, list of all data we have, gathers all others when
     * available receives the total data number (including ours), actual data
     * number, list of data we did not get yet
     */
    public byte[] outMessageData(boolean postData) {
        byte[] data = new byte[0];
        if (postData) {
            usridList = null;
            dataList = null;
            mNumUsersData = 0;

            ByteBuffer join = ByteBuffer.allocate(mCommitA.length + mDHHalfKey.length
                    + mEncData.length);
            join.put(mCommitA);
            join.put(mDHHalfKey);
            join.put(mEncData);
            data = join.array();

            ByteBuffer ours = ByteBuffer.allocate(4 + 4 + 4 + data.length);
            ours.putInt(1).putInt(mUsrId).putInt(data.length).put(data);

            // add just our own to start
            mNumUsersData = 1;
            usridList = appendServerUserIds(usridList, ours.array());
            dataList = appendServerBytes(dataList, ours.array());
        }

        ByteBuffer msg = ByteBuffer.allocate(4 + 4 + 4 + (usridList.length * 4) + data.length);
        msg.putInt(mVersion);
        msg.putInt(mUsrId);
        msg.putInt(usridList.length);
        for (int user : usridList) {
            msg.putInt(user);
        }
        msg.put(postData ? data : new byte[0]);

        return msg.array();
    }

    public void inMessageData(byte[] msg) throws MoreDataThanUsersException,
            HashValidationException, InvalidCommitVerifyException, AssignDecoysException {
        ByteBuffer theirs = ByteBuffer.wrap(msg);

        // add updates
        int offset = 0;
        mLatestServerVersion = theirs.getInt();
        offset += 4;

        mNumUsersData = theirs.getInt(); // pull out grand total
        offset += 4;
        byte[] tmpBuf = new byte[theirs.limit() - offset];
        theirs.get(tmpBuf, 0, theirs.remaining());
        if (mNumUsersData > 0) {
            usridList = appendServerUserIds(usridList, tmpBuf);
            dataList = appendServerBytes(dataList, tmpBuf);

            if (mNumUsersData > mNumUsers) {
                throw new MoreDataThanUsersException();
            }
        }

        if (mNumUsersData == mNumUsers) {
            endValidationData();
        }
    }

    private void endValidationData() throws MoreDataThanUsersException, HashValidationException,
            InvalidCommitVerifyException, AssignDecoysException {

        // Requirement for matching user ID to group ID and lowest group ID number validation
        // has been removed to allow developers to use their own grouping mechanisms.
        // Lowest number grouping is a UX suggestion for non-federated identity use cases.
        // Federated identity use cases can bypass this step by submitting a unique group
        // identity id and attempt id to ensure no group collisions on the server.

        mPackedData = dataList;

        // again save the data in a new group info in case one of the signatures
        // is invalid
        GroupData newInfo = new GroupData(mNumUsers);
        if (newInfo.save_ID_data(mPackedData) != 0) {
            throw new HashValidationException();
        }

        int retVal = mGrpInfo.isDecommitUpdate(newInfo);

        if (retVal < 0) {
            throw new InvalidCommitVerifyException();
        }

        // by now the return value should be 0, i.e., the data is correct
        mGrpInfo.save_data(mPackedData);

        // get the hash of the data to generate the T-Flag
        mHashVal = mGrpInfo.getHash();

        // establish decoy hashes for all users
        if (!assignDecoys(mHashVal)) {
            throw new AssignDecoysException();
        }
    }

    /**
     * send our own signature once, list of all signatures we have, gathers all
     * others when available receives the total signatures number (including
     * ours), actual sig number, list of signatures we did not get yet
     */
    public byte[] outMessageSig(boolean postSig, boolean matched) {
        byte[] sig = new byte[0];
        if (postSig) {
            usridList = null;
            sigsList = null;
            mNumUsersSigs = 0;

            if (matched) {
                // you say the hashes match so send the match signature
                ByteBuffer sigGood = ByteBuffer.allocate(ExchangeConfig.HASH_LEN
                        + ExchangeConfig.HASH_LEN);
                sigGood.put(mHashMatch).put(mHashWrong);
                sig = sigGood.array();
            } else {
                // send the no signature and quit
                ByteBuffer sigBad = ByteBuffer.allocate(ExchangeConfig.HASH_LEN
                        + ExchangeConfig.HASH_LEN);
                sigBad.put(mHashHashMatch).put(mNonceWrong);
                sig = sigBad.array();
            }

            ByteBuffer ours = ByteBuffer.allocate(12 + sig.length);
            ours.putInt(1).putInt(mUsrId).putInt(sig.length).put(sig);

            // add just our own to start
            mNumUsersSigs = 1;
            usridList = appendServerUserIds(usridList, ours.array());
            sigsList = appendServerBytes(sigsList, ours.array());
        }
        ByteBuffer msg = ByteBuffer.allocate(4 + 4 + 4 + (usridList.length * 4) + sig.length);
        msg.putInt(mVersion);
        msg.putInt(mUsrId);
        msg.putInt(usridList.length);
        for (int user : usridList) {
            msg.putInt(user);
        }
        msg.put(postSig ? sig : new byte[0]);

        return msg.array();
    }

    public void inMessageSig(byte[] msg) throws MoreDataThanUsersException,
            HashValidationException, OtherGroupCommitDifferException, InvalidCommitVerifyException {
        ByteBuffer theirs = ByteBuffer.wrap(msg);

        // add updates
        int offset = 0;
        mLatestServerVersion = theirs.getInt();
        offset += 4;

        mNumUsersSigs = theirs.getInt(); // pull out grand total
        offset += 4;
        byte[] tmpBuf = new byte[theirs.limit() - offset];
        theirs.get(tmpBuf, 0, theirs.remaining());
        if (mNumUsersSigs > 0) {
            usridList = appendServerUserIds(usridList, tmpBuf);
            sigsList = appendServerBytes(sigsList, tmpBuf);

            if (mNumUsersSigs > mNumUsers) {
                throw new MoreDataThanUsersException();
            }
        }

        if (mNumUsersSigs == mNumUsers) {
            endValidationSigs();
        }
    }

    private void endValidationSigs() throws HashValidationException,
            OtherGroupCommitDifferException, InvalidCommitVerifyException {

        mPackedData = sigsList;

        // again save the data in a new group info in case one of the
        // signatures
        // is invalid
        mSigsInfo = new GroupData(mNumUsers);
        if (mSigsInfo.save_ID_data(mPackedData) != 0) {
            throw new HashValidationException();
        }

        int retVal = mGrpInfo.isSignatureUpdate(mSigsInfo);

        // we got a "wrong" signature so quit
        if (retVal == 2) {
            throw new OtherGroupCommitDifferException();
        }

        // there was an error so give up
        if (retVal < 0) {
            throw new InvalidCommitVerifyException();
        }
    }

    public void nodesPrep() {
        mNumUsersKeyNodes = 0;
        pub = null;
        excgHalfKeys = mGrpInfo.sortAllHalfKeys();
        orderedIDs = mGrpInfo.getOrderedIDs();
        pos = -1;

        for (int i = 0; i < orderedIDs.length; i++) {
            if (orderedIDs[i] == mUsrId) {
                pos = i;
                break;
            }
        }

        // assign pub when A or B
        if (pos < 2) {
            pub = excgHalfKeys[pos == 0 ? 1 : 0];
        }

        curNodePos = 2;
        mynode = null;
    }

    /**
     * Send: this method is used by members to post one public key node. send:
     * node to submit (user id, node length, node). Recv: this method is used by
     * members to discover if their key node node has been submitted. receive:
     * the total nodes number for themselves (0 or 1), our own key node if
     * available.
     */
    public byte[] outMessageNode() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, IllegalStateException {
        ByteBuffer msg = ByteBuffer.allocate(0);

        // can calculate node? then calc node.
        if (pos < 2 || mynode != null) {
            // node = getnode(pub)
            pub = mCrypto.createNodeKey(pub);
        }

        // can send node? then send node.
        if (pos < 2) {
            // send(node)
            msg = ByteBuffer.allocate(4 + 4 + 4 + 4 + pub.length);
            msg.putInt(mVersion);
            msg.putInt(mUsrId);
            msg.putInt(orderedIDs[curNodePos]);
            msg.putInt(pub.length);
            msg.put(pub);
        }

        // can recv mynode? then recv node.
        if (pos >= 2 && mynode == null) {
            msg = ByteBuffer.allocate(4 + 4);
            msg.putInt(mVersion);
            msg.putInt(mUsrId);
        }

        return msg.array();
    }

    public void inMessageNode(byte[] msg) {

        // can send node? then send node.
        if (pos < 2) {
            ByteBuffer ours = ByteBuffer.wrap(msg);
            mLatestServerVersion = ours.getInt();
        }

        // can recv mynode? then recv node.
        if (pos >= 2 && mynode == null) {
            ByteBuffer ours = ByteBuffer.wrap(msg);
            int offset = 0;
            mLatestServerVersion = ours.getInt();
            offset += 4;
            mNumUsersKeyNodes = ours.getInt(); // grand total
            offset += 4;
            if (mNumUsersKeyNodes == 1) {
                ours.getInt();
                offset += 4;
                mynode = new byte[ours.limit() - offset];
                ours.get(mynode, 0, ours.remaining());

                // mynode ok? then pub = mynode
                if (mynode != null) {
                    curNodePos = pos + 1;
                    pub = mynode;
                }
            }
        }
        // can assign pub?
        else {
            pub = excgHalfKeys[curNodePos];
            curNodePos++;
        }
    }

    public boolean nodeMustBackoff() {
        return pos >= 2 || mynode == null;
    }

    public void nodesFinal() throws InvalidKeyException, InvalidKeySpecException,
            NoSuchAlgorithmException, IllegalStateException {
        // secret=getsecret(pub)
        mDHSecretKey = mCrypto.createFinalKey(pub);
    }

    /**
     * send our own match nonce once, list of all match nonces we have, gathers
     * all others when available receives the total match nonces number
     * (including ours), actual match nonce number, list of match nonces we did
     * not get yet
     */
    public byte[] outMessageMatch(boolean postNonce) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        byte[] nonceData = new byte[0];
        if (postNonce) {
            usridList = null;
            nonceList = null;
            mNumUsersMatchNonces = 0;

            // encrypt nonce with shared secret
            nonceData = mCrypto.encryptNonce(mNonceMatch, mDHSecretKey);

            ByteBuffer ours = ByteBuffer.allocate(12 + nonceData.length);
            ours.putInt(1).putInt(mUsrId).putInt(nonceData.length).put(nonceData);

            // add just our own to start
            mNumUsersMatchNonces = 1;
            usridList = appendServerUserIds(usridList, ours.array());
            nonceList = appendServerBytes(nonceList, ours.array());
        }
        ByteBuffer msg = ByteBuffer.allocate(4 + 4 + 4 + (usridList.length * 4) + nonceData.length);
        msg.putInt(mVersion);
        msg.putInt(mUsrId);
        msg.putInt(usridList.length);
        for (int user : usridList) {
            msg.putInt(user);
        }
        msg.put(postNonce ? nonceData : new byte[0]);

        return msg.array();
    }

    public void inMessageMatch(byte[] msg) throws MoreDataThanUsersException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, HashValidationException,
            InvalidCommitVerifyException {
        ByteBuffer theirs = ByteBuffer.wrap(msg);

        // add updates
        int offset = 0;
        mLatestServerVersion = theirs.getInt();
        offset += 4;

        mNumUsersMatchNonces = theirs.getInt(); // pull out grand total
        offset += 4;
        byte[] tmpBuf = new byte[theirs.limit() - offset];
        theirs.get(tmpBuf, 0, theirs.remaining());
        if (mNumUsersMatchNonces > 0) {
            usridList = appendServerUserIds(usridList, tmpBuf);
            nonceList = appendServerBytes(nonceList, tmpBuf);

            if (mNumUsersMatchNonces > mNumUsers) {
                throw new MoreDataThanUsersException();
            }
        }

        if (mNumUsersMatchNonces == mNumUsers) {
            endValidationMatch();
        }
    }

    private void endValidationMatch() throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, HashValidationException,
            InvalidCommitVerifyException {

        mPackedData = nonceList;

        // decrypt nonce from all other members
        GroupData newInfo = new GroupData(mNumUsers);
        GroupData newInfoEnc = new GroupData(mNumUsers);
        if (newInfoEnc.save_ID_data(mPackedData) != 0) {
            throw new HashValidationException();
        }

        mPackedData = decryptNonces(newInfoEnc);

        // again save the data in a new group info in case one of the
        // signatures is invalid
        if (newInfo.save_ID_data(mPackedData) != 0) {
            throw new HashValidationException();
        }

        int retVal = mSigsInfo.isDecommitUpdate(newInfo);
        if (retVal < 0) {
            throw new InvalidCommitVerifyException();
        }

        // by now the return value should be 0, i.e., the data is correct
        mSigsInfo.save_data(mPackedData);
    }

    /***
     * This will take the completed protocol values at the end of entire
     * protocol and decrypt them to produce the plaintext values all other
     * members of the group have sent. Reaching this state assures multiple
     * security properties have been preserved during the exchange, especially
     * authenticity and confidentiality together.
     */
    public byte[][] endProtocol() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {

        byte[][] encryptMemData = mGrpInfo.sortOthersDataNew(mUsrId);
        // decrypt the data with each others match nonce

        byte[][] decryptMemData = new byte[encryptMemData.length][];
        byte[][] sigsMatchData = mSigsInfo.sortOthersMatchNonce(mUsrId);
        for (int i = 0; i < sigsMatchData.length; i++) {
            byte[] key = sigsMatchData[i];
            decryptMemData[i] = mCrypto.decryptData(encryptMemData[i], key);
        }
        return decryptMemData;
    }

    public boolean isCommitPhaseComplete() {
        return mNumUsersCommit < mNumUsers;
    }

    public boolean isDataPhaseComplete() {
        return mNumUsersData < mNumUsers;
    }

    public boolean isSigsBadPhaseComplete() {
        return mNumUsersSigs > 0;
    }

    public boolean isSigsPhaseComplete() {
        return mNumUsersSigs < mNumUsers;
    }

    public boolean isNodePhaseComplete() {
        return curNodePos < mNumUsers;
    }

    public boolean isMatchPhaseComplete() {
        return mNumUsersMatchNonces < mNumUsers;
    }

    // Private Methods /////////////////////////////////////////

    private static byte[] appendServerBytes(byte[] dest, byte[] src) {

        if (dest == null && src == null)
            return null;
        else if (dest == null)
            return src;
        else if (src == null)
            return dest;

        // pull out lengths, add, then reassemble
        ByteBuffer dBuf = ByteBuffer.wrap(dest);
        ByteBuffer sBuf = ByteBuffer.wrap(src);
        int dlen = dBuf.getInt();
        int slen = sBuf.getInt();
        int len = dlen + slen;

        if (len > dlen) {
            byte[] deBuf = new byte[dBuf.limit() - 4];
            byte[] srBuf = new byte[sBuf.limit() - 4];
            dBuf.get(deBuf, 0, dBuf.remaining());
            sBuf.get(srBuf, 0, sBuf.remaining());

            byte[] list = ByteBuffer.allocate(deBuf.length + srBuf.length).put(deBuf).put(srBuf)
                    .array();

            return ByteBuffer.allocate(4 + list.length).putInt(len).put(list).array();
        }
        return dest;
    }

    private static int[] appendServerUserIds(int[] dest, byte[] src) {

        if (dest == null && src == null)
            return null;
        else if (dest == null && src != null)
            dest = new int[0];
        else if (dest != null && src == null)
            return dest;

        if (dest == null)
            dest = new int[0];

        // pull out usrids, add to list, return new list
        ByteBuffer sBuf = ByteBuffer.wrap(src);
        int len = dest.length + sBuf.getInt();

        if (len > dest.length) {
            int[] users = new int[len];
            for (int i = 0; i < users.length; i++) {
                if (i < dest.length)
                    users[i] = dest[i];
                else {
                    users[i] = sBuf.getInt();
                    int sizeData = sBuf.getInt();
                    if (sizeData < 0)
                        return null;
                    sBuf.get(new byte[sizeData], 0, sizeData);
                }
            }
            return users;
        }
        return dest;
    }

    private byte[] decryptNonces(GroupData newInfoEnc) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        byte[] decryptedList = null;
        int[] orderedIds = newInfoEnc.getOrderedIDs();
        byte[][] encNonces = newInfoEnc.sortAllMatchNonce();
        for (int i = 0; i < encNonces.length; i++) {
            byte[] decNonce = mCrypto.decryptNonce(encNonces[i], mDHSecretKey);
            ByteBuffer decrypted = ByteBuffer.allocate(12 + decNonce.length).putInt(1)
                    .putInt(orderedIds[i]).putInt(decNonce.length).put(decNonce);
            decryptedList = appendServerBytes(decryptedList, decrypted.array());
        }
        return decryptedList;
    }

    /**
     * use hash value as a seed to walk hashes and assign non-colliding decoy
     * word lists
     */
    private boolean assignDecoys(byte[] hashVal) {

        BitSet even = new BitSet(WordList.wordList.length);
        BitSet odd = new BitSet(WordList.wordList.length);

        // add existing words in use from matching hash to bit vector
        even.set(WordList.btoi(hashVal[0]));
        odd.set(WordList.btoi(hashVal[1]));
        even.set(WordList.btoi(hashVal[2]));

        int[] orderedIDs = mGrpInfo.getOrderedIDs();
        boolean foundUser = false;

        // compute decoy lists for all users, until we get to ours
        for (int n = 0; n < mNumUsers; n++) {

            if (orderedIDs[n] == mUsrId)
                foundUser = true;

            // compute 2 decoy lists for each user

            // pick words that do not collide with others in the bit vector
            // also assure that we correctly seek back to the first byte if
            // collisions exceed the maximum byte value
            byte[] newHash = CryptoAccess.computeSha3Hash2(new byte[]{
                    (byte) n
            }, hashVal);
            // decoy 1
            mDecoyHash1[0] = getNextClearByte(even, newHash[0]);
            even.set(WordList.btoi(mDecoyHash1[0]));
            mDecoyHash1[1] = getNextClearByte(odd, newHash[1]);
            odd.set(WordList.btoi(mDecoyHash1[1]));
            mDecoyHash1[2] = getNextClearByte(even, newHash[2]);
            even.set(WordList.btoi(mDecoyHash1[2]));

            // decoy 2
            mDecoyHash2[0] = getNextClearByte(even, newHash[3]);
            even.set(WordList.btoi(mDecoyHash2[0]));
            mDecoyHash2[1] = getNextClearByte(odd, newHash[4]);
            odd.set(WordList.btoi(mDecoyHash2[1]));
            mDecoyHash2[2] = getNextClearByte(even, newHash[5]);
            even.set(WordList.btoi(mDecoyHash2[2]));

            // last assigned decoy lists will always belong to this user
            if (foundUser)
                return true;
        }
        return false;
    }

    private static byte getNextClearByte(BitSet bits, byte start) {
        int next = bits.nextClearBit(WordList.btoi(start));
        if (next >= WordList.wordList.length)
            next = bits.nextClearBit(0);
        return WordList.itob(next);
    }

    // Accessors /////////////////////////////////////////

    public byte[] getDecoyHash(int decoyNum) {
        if (decoyNum == 1)
            return mDecoyHash1;
        else if (decoyNum == 2)
            return mDecoyHash2;
        else
            return null;
    }

    public byte[] getHash() {
        return mHashVal;
    }

    public int getNumUsers() {
        return mNumUsers;
    }

    public void setNumUsers(int numUsers) {
        mNumUsers = numUsers;
    }

    public int getCurNodePos() {
        return curNodePos;
    }

    public int getUserId() {
        return mUsrId;
    }

    public GroupData getGroupData() {
        return mGrpInfo;
    }

    public int[] getGroupIds() {
        return mGroupIds;
    }

    public void setUserIdLink(int usridlink) {
        mUsrIdLink = usridlink;
    }

    public int getUserIdLink() {
        return mUsrIdLink;
    }

    public int getNumUsersCommit() {
        return mNumUsersCommit;
    }

    public int getNumUsersData() {
        return mNumUsersData;
    }

    public int getNumUsersSigs() {
        return mNumUsersSigs;
    }

    public int getNumUsersKeyNodes() {
        return mNumUsersKeyNodes;
    }

    public int getNumUsersMatchNonces() {
        return mNumUsersMatchNonces;
    }

    public int getRandomPos(int n) {
        byte[] b = new byte[1];
        mRandom.nextBytes(b);
        mRandomPosSrc = WordList.btoi(b[0]);
        double d = mRandomPosSrc / 256.0;
        double e = d * n;
        int floor = (int) Math.floor(e);
        return floor;
    }

    public int getRandomPosSrc() {
        return mRandomPosSrc;
    }

    public void setHashSelection(int hashSelection) {
        mHashSelection = hashSelection;
    }

    public int getHashSelection() {
        return mHashSelection;
    }
}
