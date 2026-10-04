package zone.epix.evxfixture;

/** Fixed scalar-only fixture. No files, source code, bytecode or host commands. */
public final class GameProtocol {
    public static final int MAGIC = 0x45565831;
    public static final int VERSION = 1;
    public static final int REQUEST_BYTES = 32;
    public static final int RESPONSE_BYTES = 24;
    public static final int TRANSACTION = 1;
    private GameProtocol() {}

    // IBinder.FLAG_ONEWAY is 1. Other Binder transport flags do not change the
    // request shape or authorize handles; the service still rejects any FDs.
    public static boolean synchronous(int flags) { return (flags & 1) == 0; }

    public static int score(int magic, int version, long high, long low, int level, int coins) {
        if (magic != MAGIC || version != VERSION || (high == 0 && low == 0)
                || level < 0 || level > 100 || coins < 0 || coins > 1000) {
            throw new IllegalArgumentException("invalid game frame");
        }
        return level * 100 + coins;
    }
}
