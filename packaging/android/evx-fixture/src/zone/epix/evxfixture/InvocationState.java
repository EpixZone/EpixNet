package zone.epix.evxfixture;

/** Observations only. A reply, disconnect or unbind never proves process death. */
public final class InvocationState {
    public enum Phase { NEW, ADMITTED, CONNECTED, REPLIED, STOP_REQUESTED, DEATH_OBSERVED }
    private Phase phase = Phase.NEW;
    private long high;
    private long low;
    private boolean replied;

    public synchronized void admit(long high, long low) {
        if (phase != Phase.NEW || (high == 0 && low == 0)) throw new IllegalStateException("already used");
        this.high = high; this.low = low; phase = Phase.ADMITTED;
    }
    public synchronized void connected() {
        if (phase != Phase.ADMITTED) throw new IllegalStateException("connection no longer admitted");
        phase = Phase.CONNECTED;
    }
    public synchronized void reply(long high, long low, int score) {
        if (phase != Phase.CONNECTED || replied || high != this.high || low != this.low || score != 42)
            throw new IllegalStateException("unexpected reply");
        replied = true; phase = Phase.REPLIED;
    }
    public synchronized void stopRequested() {
        if (phase != Phase.NEW && phase != Phase.DEATH_OBSERVED) phase = Phase.STOP_REQUESTED;
    }
    public synchronized void binderDeath(long high, long low) {
        if (phase == Phase.NEW || phase == Phase.ADMITTED || phase == Phase.DEATH_OBSERVED
                || high != this.high || low != this.low) throw new IllegalStateException("unbound death observation");
        phase = Phase.DEATH_OBSERVED;
    }
    public synchronized Phase phase() { return phase; }
    public synchronized boolean resultReceived() { return replied; }
    // Even observed Binder death is not a proven descendant/accounting profile.
    public boolean productionAdmissionAllowed() { return false; }
}
