package zone.epix.evxfixture;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.system.Os;
import android.system.OsConstants;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/** One disposable admission. Its durable marker is deliberately never reset. */
public final class FixtureHost implements AutoCloseable {
    private final Context context;
    private final Consumer<String> report;
    private final InvocationState state = new InvocationState();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private final java.util.concurrent.ExecutorService worker = Executors.newSingleThreadExecutor();
    private final long high = new SecureRandom().nextLong();
    private final long low = new SecureRandom().nextLong();
    private boolean bound;
    private IBinder remote;
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            try {
                if (!name.equals(new ComponentName(context, GameService.class))) throw new IllegalStateException("wrong service");
                state.connected();
                remote = binder;
                binder.linkToDeath(() -> {
                    state.binderDeath(high, low);
                    report.accept("Binder process death observed. Production isolation/accounting still unverified.");
                }, 0);
                worker.execute(() -> exchange(binder));
            } catch (Exception error) { stop("connection refused"); }
        }
        @Override public void onServiceDisconnected(ComponentName name) { stop("service disconnected; death not established by this callback"); }
        @Override public void onBindingDied(ComponentName name) { stop("binding died; no process-death claim"); }
        @Override public void onNullBinding(ComponentName name) { stop("null binding"); }
    };
    public FixtureHost(Context context, Consumer<String> report) {
        this.context = context.getApplicationContext(); this.report = report;
    }
    public synchronized void run() throws Exception {
        File parent = context.getNoBackupFilesDir();
        File marker = new File(parent, "evx-fixture-admitted");
        if (!marker.createNewFile()) throw new IllegalStateException("fixture already admitted; retained uncertainty, no reset");
        try (FileOutputStream out = new FileOutputStream(marker)) {
            out.write((Long.toUnsignedString(high) + ":" + Long.toUnsignedString(low)).getBytes(StandardCharsets.US_ASCII));
            out.getFD().sync();
        }
        FileDescriptor directory = Os.open(parent.getAbsolutePath(), OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0);
        try {
            if (!OsConstants.S_ISDIR(Os.fstat(directory).st_mode)) throw new IllegalStateException("not a directory");
            Os.fsync(directory);
        } finally { Os.close(directory); }
        state.admit(high, low);
        // Per-invocation instance name prevents accidentally attaching to a prior instance.
        bound = context.bindIsolatedService(new Intent(context, GameService.class), Context.BIND_AUTO_CREATE,
                UUID.randomUUID().toString(), context.getMainExecutor(), connection);
        if (!bound) { stop("bind refused; durable admission retained"); return; }
        timer.schedule(() -> stop("deadline reached; admission retained unless independently resolved"), 3, TimeUnit.SECONDS);
    }
    private void exchange(IBinder binder) {
        Parcel request = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            request.writeInt(GameProtocol.MAGIC); request.writeInt(GameProtocol.VERSION);
            request.writeLong(high); request.writeLong(low); request.writeInt(0); request.writeInt(42);
            if (!binder.transact(GameProtocol.TRANSACTION, request, reply, 0)
                    || reply.dataSize() != GameProtocol.RESPONSE_BYTES || reply.hasFileDescriptors())
                throw new IllegalStateException("invalid reply shape");
            if (reply.readInt() != GameProtocol.MAGIC) throw new IllegalStateException("invalid reply protocol");
            state.reply(reply.readLong(), reply.readLong(), reply.readInt());
            if (reply.dataAvail() != 0) throw new IllegalStateException("trailing reply");
            report.accept("Game score: 42. Reply received; process death not yet established.");
            stop("completed fixed calculation; closing only connection");
        } catch (Exception error) { stop("exchange refused; uncertainty retained"); }
        finally { request.recycle(); reply.recycle(); }
    }
    private synchronized void stop(String reason) {
        state.stopRequested();
        report.accept(reason);
        if (bound) { bound = false; context.unbindService(connection); }
        // Do not clear remote or unlink death notification before it is observed.
        // unbindService, thread interruption and timeout are not death evidence.
    }
    @Override public synchronized void close() {
        stop("host fixture closing"); timer.shutdownNow(); worker.shutdownNow();
    }
}
