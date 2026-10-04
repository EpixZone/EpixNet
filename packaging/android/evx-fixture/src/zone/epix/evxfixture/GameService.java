package zone.epix.evxfixture;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import java.util.concurrent.atomic.AtomicBoolean;

/** A bundled, non-exported isolated process, never an in-process implementation. */
public final class GameService extends Service {
    private final AtomicBoolean used = new AtomicBoolean();
    private final Binder endpoint = new Binder() {
        @Override protected boolean onTransact(int code, Parcel input, Parcel output, int flags) throws RemoteException {
            if (code != GameProtocol.TRANSACTION || !GameProtocol.synchronous(flags) || output == null
                    || Binder.getCallingUid() != getApplicationInfo().uid
                    || input.dataSize() != GameProtocol.REQUEST_BYTES || input.hasFileDescriptors()) return false;
            int magic = input.readInt();
            int version = input.readInt();
            long high = input.readLong();
            long low = input.readLong();
            int level = input.readInt();
            int coins = input.readInt();
            if (input.dataAvail() != 0) return false;
            final int score;
            try { score = GameProtocol.score(magic, version, high, low, level, coins); }
            catch (IllegalArgumentException invalid) { return false; }
            if (!used.compareAndSet(false, true)) return false;
            output.writeInt(GameProtocol.MAGIC);
            output.writeLong(high);
            output.writeLong(low);
            output.writeInt(score);
            return true;
        }
    };
    @Override public IBinder onBind(Intent intent) { return endpoint; }
}
