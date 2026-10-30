package zone.epix.evx;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Generic binary-Wasm service. Bundled, non-exported, isolated and one-shot. */
public final class RuntimeService extends Service {
    private final AtomicBoolean consumed = new AtomicBoolean();
    @Override public void onCreate() {
        super.onCreate();
        if (!Process.isIsolated()) throw new SecurityException("isolated process required");
        System.loadLibrary("evx_android");
    }
    private static void header(Parcel input, long high, long low) {
        if (input.readInt() != Protocol.MAGIC || input.readLong() != high || input.readLong() != low)
            throw new SecurityException("invocation mismatch");
    }
    private static byte[] broker(IBinder callback, long high, long low, int code, byte[] bytes) throws RemoteException {
        Parcel request = Parcel.obtain(); Parcel reply = Parcel.obtain();
        try {
            request.writeInt(Protocol.MAGIC); request.writeLong(high); request.writeLong(low);
            if (bytes != null) { Protocol.blob(bytes, Protocol.MAX_REQUEST); request.writeByteArray(bytes); }
            if (!callback.transact(code, request, reply, 0) || reply.hasFileDescriptors()
                    || reply.dataSize() > Protocol.MAX_RESPONSE + 64) throw new SecurityException("broker frame refused");
            header(reply, high, low);
            byte[] result = reply.createByteArray(); Protocol.blob(result, Protocol.MAX_RESPONSE);
            if (reply.dataAvail() != 0) throw new SecurityException("trailing broker data");
            return result;
        } finally { request.recycle(); reply.recycle(); }
    }
    private final Binder endpoint = new Binder() {
        @Override protected boolean onTransact(int code, Parcel input, Parcel output, int flags) throws RemoteException {
            if (code != Protocol.RUN || !Protocol.synchronous(flags) || output == null
                    || Binder.getCallingUid() != getApplicationInfo().uid || !Process.isIsolated()
                    || input.hasFileDescriptors() || input.dataSize() > Protocol.MAX_PARCEL
                    || input.dataSize() < 32 || !consumed.compareAndSet(false, true)) return false;
            if (input.readInt() != Protocol.MAGIC) return false;
            final long high = input.readLong(), low = input.readLong();
            if (high == 0 && low == 0) return false;
            byte[] module = input.createByteArray(); Protocol.blob(module, Protocol.MAX_MODULE);
            byte[] limits = input.createByteArray(); Protocol.blob(limits, Protocol.MAX_LIMITS);
            final IBinder callback = input.readStrongBinder();
            if (callback == null || input.dataAvail() != 0) return false;
            // Called before parsing/compiling hostile Wasm. Host records the UID
            // supplied by Binder itself, never a UID field controlled by code.
            broker(callback, high, low, Protocol.HELLO, null);
            byte[] result = NativeBridge.execute(module, limits,
                    request -> broker(callback, high, low, Protocol.CALL, request));
            Protocol.blob(result, Protocol.MAX_RESULT);
            output.writeInt(Protocol.MAGIC); output.writeLong(high); output.writeLong(low);
            output.writeByteArray(result);
            return true;
        }
    };
    @Override public IBinder onBind(Intent intent) { return endpoint; }
}
