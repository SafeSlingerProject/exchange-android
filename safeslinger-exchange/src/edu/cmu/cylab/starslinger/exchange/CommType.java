
package edu.cmu.cylab.starslinger.exchange;

public enum CommType {

    /***
     * Batch communication is more efficient for central server implementations
     * where the server is polled. So "out" messages are meant to form the
     * request body and "in" messages are meant to form the response body for a
     * series of successive calls. "In" messages may contain protocol values
     * from 0-N group members.
     */
    BATCH,

    /***
     * Direct communication is better for implementations that want to avoid the
     * server using a central database for syncing messages, and instead want to
     * format each message is if it will be sent directly to each recipient.
     * This mode is ideal for systems which wish to control the mode of
     * transport for protocol messages.
     */
    DIRECT,
}
