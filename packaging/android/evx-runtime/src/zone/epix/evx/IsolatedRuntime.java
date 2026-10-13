package zone.epix.evx;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Generic isolated-service transport. Not registered with the product node.
 * Requires API34 for kernel-provided isolated UID classification.
 */
public final class IsolatedRuntime implements AutoCloseable {
    /** Trusted host adapter, never implemented or selected by xite content.
     * The eventual node adapter must decode Request again and use the existing
     * grant/commit/revocation checks. Service-side validation is not authority.
     */
    public interface BoundBroker {
        void requireCurrentConsent() throws Exception;
        byte[] call(byte[] evxRequest) throws Exception;
        void untrustedResult(byte[] resultFrame);
        void observation(String state);
    }
    private final Context context;
    private final BoundBroker broker;
    private final int maxCalls;
    private final long high = new SecureRandom().nextLong(), low = new SecureRandom().nextLong();
    private final AtomicBoolean inCall = new AtomicBoolean();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private boolean started, bound, stopping, hello;
    private int isolatedUid = -1, calls;
    private byte[] module, limits;
    private IBinder remote;

    public IsolatedRuntime(Context context, BoundBroker broker, int maxCalls) {
        if (android.os.Build.VERSION.SDK_INT < 34 || maxCalls < 1 || maxCalls > 1024)
            throw new IllegalArgumentException("unsupported isolated runtime profile");
        this.context = context.getApplicationContext(); this.broker = broker; this.maxCalls = maxCalls;
    }
    private void header(Parcel input) {
        if (input.readInt() != Protocol.MAGIC || input.readLong() != high || input.readLong() != low)
            throw new SecurityException("invocation mismatch");
    }
    private final Binder callback = new Binder() {
        @Override protected boolean onTransact(int code, Parcel input, Parcel output, int flags) {
            if (output == null || !Protocol.synchronous(flags) || input.hasFileDescriptors()
                    || input.dataSize() > Protocol.MAX_REQUEST + 64 || input.dataSize() < 20) return false;
            try {
                header(input);
                final byte[] response;
                synchronized (IsolatedRuntime.this) {
                    if (!started || stopping || !Process.isIsolatedUid(Binder.getCallingUid())) return false;
                    if (code == Protocol.HELLO) {
                        if (hello || input.dataAvail() != 0) return false;
                        isolatedUid = Binder.getCallingUid(); hello = true;
                        response = "{}".getBytes(StandardCharsets.US_ASCII);
                    } else {
                        if (code != Protocol.CALL || !hello || Binder.getCallingUid() != isolatedUid
                                || ++calls > maxCalls || !inCall.compareAndSet(false, true)) return false;
                        response = null;
                    }
                }
                byte[] actual = response;
                if (actual == null) {
                    try {
                        byte[] request = input.createByteArray(); Protocol.blob(request, Protocol.MAX_REQUEST);
                        if (input.dataAvail() != 0) return false;
                        broker.requireCurrentConsent();
                        actual = broker.call(request); Protocol.blob(actual, Protocol.MAX_RESPONSE);
                        broker.requireCurrentConsent();
                    } finally { inCall.set(false); }
                }
                synchronized (IsolatedRuntime.this) { if (stopping) return false; }
                output.writeInt(Protocol.MAGIC); output.writeLong(high); output.writeLong(low);
                output.writeByteArray(actual); return true;
            } catch (Exception refused) { return false; }
        }
    };
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            synchronized (IsolatedRuntime.this) {
                if (stopping || !name.equals(new ComponentName(context, RuntimeService.class))) {
                    stop("unexpected or late service connection"); return;
                }
                remote = binder;
            }
            try {
                binder.linkToDeath(() -> {
                    // This proves death of the Binder owner only. Descendant
                    // absence/accounting is not established, so the journal stays.
                    stop("Binder owner death observed; admission remains quarantined");
                }, 0);
                executor.execute(() -> exchange(binder));
            } catch (Exception refused) { stop("service death registration failed"); }
        }
        @Override public void onServiceDisconnected(ComponentName name) { stop("service disconnected; no death inference"); }
        @Override public void onBindingDied(ComponentName name) { stop("binding died; no death inference"); }
        @Override public void onNullBinding(ComponentName name) { stop("null service binding"); }
    };
    /** Test/development transport only. No API enables production admission. */
    public synchronized void startForConformance(byte[] source, byte[] limitSnapshot) throws Exception {
        if (started || stopping) throw new IllegalStateException("invocation already used");
        Protocol.blob(source, Protocol.MAX_MODULE); Protocol.blob(limitSnapshot, Protocol.MAX_LIMITS);
        broker.requireCurrentConsent();
        module = source.clone(); limits = limitSnapshot.clone();
        // Fixed host-private path, no backup/restore enrollment and no reset API.
        File parent = context.getNoBackupFilesDir(); File marker = new File(parent, "evx-runtime-pending");
        if (!marker.createNewFile()) throw new IllegalStateException("prior native invocation unresolved");
        String digest = hex(MessageDigest.getInstance("SHA-256").digest(module));
        try (FileOutputStream stream = new FileOutputStream(marker)) {
            stream.write(("v1:" + high + ":" + low + ":" + digest).getBytes(StandardCharsets.US_ASCII));
            stream.getFD().sync();
        }
        FileDescriptor directory = Os.open(parent.getAbsolutePath(), OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0);
        try {
            if (!OsConstants.S_ISDIR(Os.fstat(directory).st_mode)) throw new SecurityException("invalid journal root");
            Os.fsync(directory);
        } finally { Os.close(directory); }
        started = true;
        broker.requireCurrentConsent();
        bound = context.bindIsolatedService(new Intent(context, RuntimeService.class), Context.BIND_AUTO_CREATE,
                UUID.randomUUID().toString(), context.getMainExecutor(), connection);
        if (!bound) { stop("bind failed; durable quarantine retained"); return; }
        timer.schedule(() -> stop("host deadline; native death unconfirmed"), 3, TimeUnit.SECONDS);
    }
    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte value : bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }
    private void exchange(IBinder binder) {
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            broker.requireCurrentConsent();
            synchronized (this) { if (stopping) return; }
            request.writeInt(Protocol.MAGIC); request.writeLong(high); request.writeLong(low);
            request.writeByteArray(module); request.writeByteArray(limits); request.writeStrongBinder(callback);
            if (!binder.transact(Protocol.RUN, request, reply, 0) || reply.hasFileDescriptors()
                    || reply.dataSize() > Protocol.MAX_RESULT + 64) throw new SecurityException("invalid result frame");
            header(reply); byte[] frame = reply.createByteArray(); Protocol.blob(frame, Protocol.MAX_RESULT);
            if (reply.dataAvail() != 0) throw new SecurityException("trailing result data");
            synchronized (this) { if (stopping) return; }
            broker.requireCurrentConsent(); broker.untrustedResult(frame);
        } catch (Exception refused) { broker.observation("runtime exchange refused"); }
        finally { request.recycle(); reply.recycle(); stop("invocation finished; native accounting/reap gate remains"); }
    }
    public synchronized void revoke() { stop("consent revoked; quarantine retained"); }
    private synchronized void stop(String reason) {
        stopping = true;
        if (bound) { bound = false; context.unbindService(connection); }
        broker.observation(reason);
        // Keep the Binder death recipient and durable marker. Unbind and thread
        // interruption are requests, not evidence of termination.
    }
    @Override public synchronized void close() {
        stop("runtime owner closing"); timer.shutdownNow(); executor.shutdownNow();
    }
}
