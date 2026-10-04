package zone.epix.evxfixture;

public final class ProtocolTest {
    private static int assertions;
    private static void check(boolean value) { assertions++; if (!value) throw new AssertionError(); }
    private static void refuses(Runnable action) {
        boolean refused = false;
        try { action.run(); } catch (IllegalArgumentException | IllegalStateException expected) { refused = true; }
        check(refused);
    }
    public static void main(String[] args) throws InterruptedException {
        check(GameProtocol.synchronous(0));
        // Native Binder adds TF_ACCEPT_FDS even to a synchronous transaction.
        check(GameProtocol.synchronous(0x10));
        check(!GameProtocol.synchronous(1));
        check(!GameProtocol.synchronous(0x11));
        check(GameProtocol.score(GameProtocol.MAGIC, 1, 1, 2, 0, 42) == 42);
        check(GameProtocol.score(GameProtocol.MAGIC, 1, 1, 2, 100, 1000) == 11000);
        refuses(() -> GameProtocol.score(0, 1, 1, 2, 0, 42));
        refuses(() -> GameProtocol.score(GameProtocol.MAGIC, 2, 1, 2, 0, 42));
        refuses(() -> GameProtocol.score(GameProtocol.MAGIC, 1, 0, 0, 0, 42));
        for (int bad : new int[]{-1, 101, Integer.MAX_VALUE}) refuses(() -> GameProtocol.score(GameProtocol.MAGIC, 1, 1, 2, bad, 42));
        for (int bad : new int[]{-1, 1001, Integer.MAX_VALUE}) refuses(() -> GameProtocol.score(GameProtocol.MAGIC, 1, 1, 2, 0, bad));
        InvocationState state = new InvocationState();
        refuses(() -> state.reply(1, 2, 42));
        state.admit(1, 2); refuses(() -> state.admit(1, 2));
        refuses(() -> state.binderDeath(1, 2)); state.connected();
        refuses(() -> state.reply(1, 3, 42)); refuses(() -> state.reply(1, 2, 43));
        state.reply(1, 2, 42); check(state.resultReceived());
        check(state.phase() == InvocationState.Phase.REPLIED);
        refuses(() -> state.reply(1, 2, 42)); state.stopRequested();
        check(state.phase() == InvocationState.Phase.STOP_REQUESTED);
        refuses(() -> state.binderDeath(2, 3)); state.binderDeath(1, 2);
        check(state.phase() == InvocationState.Phase.DEATH_OBSERVED);
        refuses(() -> state.admit(1, 2)); check(!state.productionAdmissionAllowed());
        InvocationState timeout = new InvocationState(); timeout.admit(4, 5); timeout.stopRequested();
        refuses(timeout::connected); refuses(() -> timeout.reply(4, 5, 42));
        check(!timeout.productionAdmissionAllowed());
        InvocationState concurrent = new InvocationState();
        java.util.concurrent.atomic.AtomicInteger admitted = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        Thread[] contenders = new Thread[16];
        for (int i = 0; i < contenders.length; i++) {
            contenders[i] = new Thread(() -> {
                try { start.await(); concurrent.admit(9, 10); admitted.incrementAndGet(); }
                catch (IllegalStateException expected) { }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            });
            contenders[i].start();
        }
        start.countDown();
        for (Thread thread : contenders) thread.join();
        check(admitted.get() == 1);
        System.out.println("PASS " + assertions + " protocol/lifecycle assertions; no Android execution claim");
    }
}
