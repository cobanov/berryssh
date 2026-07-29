package berryssh.protocol;

/**
 * SSH message numbers.
 *
 * The ranges matter as much as the values: 1-19 is the transport layer, 20-29
 * is algorithm negotiation, 30-49 is whatever the negotiated key exchange
 * method wants and so is only meaningful in context, 50-79 is user
 * authentication and 80-127 is the connection protocol. A number from a range
 * that is not currently in play is a protocol error rather than something to
 * interpret.
 */
public final class Message {

    private Message() {
    }

    public static final int DISCONNECT = 1;
    public static final int IGNORE = 2;
    public static final int UNIMPLEMENTED = 3;
    public static final int DEBUG = 4;
    public static final int SERVICE_REQUEST = 5;
    public static final int SERVICE_ACCEPT = 6;
    public static final int EXT_INFO = 7;

    public static final int KEXINIT = 20;
    public static final int NEWKEYS = 21;

    /** Numbered per key exchange method; these are RFC 5656 / RFC 8731 ECDH. */
    public static final int KEX_ECDH_INIT = 30;
    public static final int KEX_ECDH_REPLY = 31;

    public static final int USERAUTH_REQUEST = 50;
    public static final int USERAUTH_FAILURE = 51;
    public static final int USERAUTH_SUCCESS = 52;
    public static final int USERAUTH_BANNER = 53;
    /** Also 60 in the publickey method, where it means PK_OK. Context decides. */
    public static final int USERAUTH_PK_OK = 60;

    public static final int GLOBAL_REQUEST = 80;
    public static final int REQUEST_SUCCESS = 81;
    public static final int REQUEST_FAILURE = 82;
    public static final int CHANNEL_OPEN = 90;
    public static final int CHANNEL_OPEN_CONFIRMATION = 91;
    public static final int CHANNEL_OPEN_FAILURE = 92;
    public static final int CHANNEL_WINDOW_ADJUST = 93;
    public static final int CHANNEL_DATA = 94;
    public static final int CHANNEL_EXTENDED_DATA = 95;
    public static final int CHANNEL_EOF = 96;
    public static final int CHANNEL_CLOSE = 97;
    public static final int CHANNEL_REQUEST = 98;
    public static final int CHANNEL_SUCCESS = 99;
    public static final int CHANNEL_FAILURE = 100;

    /** RFC 4254 section 5.2: extended data of this type is stderr. */
    public static final int EXTENDED_DATA_STDERR = 1;

    public static String name(int type) {
        switch (type) {
            case DISCONNECT: return "DISCONNECT";
            case IGNORE: return "IGNORE";
            case UNIMPLEMENTED: return "UNIMPLEMENTED";
            case DEBUG: return "DEBUG";
            case SERVICE_REQUEST: return "SERVICE_REQUEST";
            case SERVICE_ACCEPT: return "SERVICE_ACCEPT";
            case EXT_INFO: return "EXT_INFO";
            case KEXINIT: return "KEXINIT";
            case NEWKEYS: return "NEWKEYS";
            case KEX_ECDH_INIT: return "KEX_ECDH_INIT";
            case KEX_ECDH_REPLY: return "KEX_ECDH_REPLY";
            case USERAUTH_REQUEST: return "USERAUTH_REQUEST";
            case USERAUTH_FAILURE: return "USERAUTH_FAILURE";
            case USERAUTH_SUCCESS: return "USERAUTH_SUCCESS";
            case USERAUTH_BANNER: return "USERAUTH_BANNER";
            case GLOBAL_REQUEST: return "GLOBAL_REQUEST";
            case REQUEST_SUCCESS: return "REQUEST_SUCCESS";
            case REQUEST_FAILURE: return "REQUEST_FAILURE";
            case CHANNEL_OPEN: return "CHANNEL_OPEN";
            case CHANNEL_OPEN_CONFIRMATION: return "CHANNEL_OPEN_CONFIRMATION";
            case CHANNEL_OPEN_FAILURE: return "CHANNEL_OPEN_FAILURE";
            case CHANNEL_WINDOW_ADJUST: return "CHANNEL_WINDOW_ADJUST";
            case CHANNEL_DATA: return "CHANNEL_DATA";
            case CHANNEL_EXTENDED_DATA: return "CHANNEL_EXTENDED_DATA";
            case CHANNEL_EOF: return "CHANNEL_EOF";
            case CHANNEL_CLOSE: return "CHANNEL_CLOSE";
            case CHANNEL_REQUEST: return "CHANNEL_REQUEST";
            case CHANNEL_SUCCESS: return "CHANNEL_SUCCESS";
            case CHANNEL_FAILURE: return "CHANNEL_FAILURE";
            default: return "message " + type;
        }
    }
}
