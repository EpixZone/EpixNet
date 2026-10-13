package zone.epix.evx;

/** Loaded only by RuntimeService, never by the trusted node or browser. */
public final class NativeBridge {
    private NativeBridge() { }
    public interface Callback { byte[] call(byte[] request) throws Exception; }
    public static native byte[] execute(byte[] module, byte[] limits, Callback callback);
}
