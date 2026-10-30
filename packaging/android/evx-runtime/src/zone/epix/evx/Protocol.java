package zone.epix.evx;

public final class Protocol {
    public static final int MAGIC = 0x45565832;
    public static final int RUN = 1;
    public static final int HELLO = 2;
    public static final int CALL = 3;
    public static final int MAX_MODULE = 65536;
    public static final int MAX_LIMITS = 4096;
    public static final int MAX_REQUEST = 8192;
    public static final int MAX_RESPONSE = 4096;
    public static final int MAX_RESULT = 4096;
    public static final int MAX_PARCEL = MAX_MODULE + MAX_LIMITS + 256;
    private Protocol() { }
    public static boolean synchronous(int flags) { return (flags & 1) == 0; }
    public static void blob(byte[] bytes, int max) {
        if (bytes == null || bytes.length == 0 || bytes.length > max) throw new IllegalArgumentException("bounded bytes required");
    }
}
