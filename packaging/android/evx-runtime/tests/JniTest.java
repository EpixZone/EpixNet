package zone.epix.evx;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public final class JniTest {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("library fixture-root mode");
        System.load(Path.of(args[0]).toAbsolutePath().toString());
        Path root = Path.of(args[1]); String mode = args[2];
        byte[] module = Files.readAllBytes(root.resolve(mode.equals("score") ? "score.wasm" : mode.equals("loop") ? "loop.wasm" : "call.wasm"));
        byte[] limits = Files.readAllBytes(root.resolve("limits.json"));
        AtomicInteger calls = new AtomicInteger();
        NativeBridge.Callback callback = request -> {
            if (!Arrays.equals(request, "{\"op\":\"game.score.get\"}".getBytes(StandardCharsets.UTF_8))) throw new AssertionError("request changed");
            calls.incrementAndGet();
            if (mode.equals("throws")) throw new IllegalStateException("host-private error must not escape");
            if (mode.equals("oversized")) return new byte[4097];
            return "{\"ok\":true,\"score\":42}".getBytes(StandardCharsets.UTF_8);
        };
        byte[] frame = NativeBridge.execute(module, limits, callback);
        if (frame.length < 5 || java.nio.ByteBuffer.wrap(frame).getInt() != frame.length - 4) throw new AssertionError("result framing");
        String json = new String(frame, 4, frame.length - 4, StandardCharsets.UTF_8);
        boolean success = mode.equals("score") || mode.equals("call");
        if (!json.contains("\"status\":\"" + (success ? "ok" : "error") + "\"")) throw new AssertionError(json);
        if (json.contains("host-private")) throw new AssertionError("callback exception leaked");
        if (mode.equals("score") && !json.contains("\"value\":42")) throw new AssertionError(json);
        if (mode.equals("call") && !json.contains("\"value\":22")) throw new AssertionError(json);
        if (calls.get() != (mode.equals("score") || mode.equals("loop") ? 0 : 1)) throw new AssertionError("call count");
        try { NativeBridge.execute(module, limits, callback); throw new AssertionError("process reuse accepted"); }
        catch (IllegalStateException expected) { }
        System.out.println("PASS real JVM/JNI Wasm " + mode + "; Android OS containment not tested");
    }
}
