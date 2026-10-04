/* Deterministic lifecycle checks against the saved production adapter.
 * No processes are signalled: only the process syscalls below are replaced. */
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

static unsigned term_signals, kill_signals, wait_calls;
static int interrupt_wait, stopped_wait;
static pid_t fixture_wait4(pid_t pid, int *status, int options, struct rusage *usage) {
    (void)pid; (void)status; (void)options; (void)usage;
    wait_calls++;
    if (stopped_wait) { *status = (SIGSTOP << 8) | 0x7f; return pid; }
    if (interrupt_wait && wait_calls == 1) { errno = EINTR; return -1; }
    return 0;
}
static int fixture_usage(int pid, int flavor, uint64_t arg, void *usage, int size) {
    (void)pid; (void)flavor; (void)arg; (void)usage; (void)size;
    errno = ESRCH;
    return -1;
}
static int fixture_kill(pid_t pid, int signal) {
    (void)pid;
    if (signal == SIGTERM) term_signals++;
    if (signal == SIGKILL) kill_signals++;
    return 0;
}
#define wait4 fixture_wait4
#define proc_pidinfo fixture_usage
#define kill fixture_kill
#define killpg fixture_kill
#include "../../../crates/evx-supervisor/native/apple_xpc.c"
#undef wait4
#undef proc_pidinfo
#undef kill
#undef killpg

static xpc_object_t sample(uint64_t sequence, uint64_t state) {
    xpc_object_t object = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(object, "v", 1);
    xpc_dictionary_set_uint64(object, "state", state);
    xpc_dictionary_set_uint64(object, "pid", 123);
    xpc_dictionary_set_uint64(object, "rss", 2048);
    xpc_dictionary_set_uint64(object, "peak", 4096);
    xpc_dictionary_set_uint64(object, "cpu_ns", 1000000);
    xpc_dictionary_set_uint64(object, "sequence", sequence);
    xpc_dictionary_set_int64(object, "exit", 0);
    return object;
}

static int observations(void) {
    struct client client = {0};
    uint64_t sequence = 0;
    xpc_object_t object = sample(1, 1);
    client_observe(&client, &sequence, object);
    xpc_release(object);
    if (client.sample.state != 1 || sequence != 1) return 10;
    client_observe(&client, &sequence, (xpc_object_t)XPC_ERROR_CONNECTION_INTERRUPTED);
    if (client.sample.state != -1) return 11;
    object = sample(2, 1);
    client_observe(&client, &sequence, object);
    xpc_release(object);
    if (client.sample.state != -1 || sequence != 1) return 12;

    client = (struct client){0};
    sequence = 0;
    object = sample(1, 2);
    client_observe(&client, &sequence, object);
    xpc_release(object);
    client_observe(&client, &sequence, (xpc_object_t)XPC_ERROR_CONNECTION_INVALID);
    return client.sample.state == 2 ? 0 : 13;
}

static int worker_binding(void) {
    char root[] = "/private/tmp/evx-worker-binding-XXXXXX";
    if (!mkdtemp(root)) return 50;
    char path[PATH_MAX], alias[PATH_MAX], aliased[PATH_MAX];
    snprintf(path, sizeof(path), "%s/worker", root);
    snprintf(alias, sizeof(alias), "%s/alias", root);
    snprintf(aliased, sizeof(aliased), "%s/alias/worker", root);
    int file = open(path, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (file < 0 || write(file, "fixture", 7) != 7) return 51;
    close(file);
    unsigned char hash[32]; char digest[65]; CC_SHA256("fixture", 7, hash);
    for (unsigned n = 0; n < 32; ++n) snprintf(digest + n * 2, 3, "%02x", hash[n]);
    bool original = worker_matches(path, digest);
    chmod(path, 0770); bool writable = worker_matches(path, digest); chmod(path, 0700);
    if (symlink(root, alias)) return 52;
    bool symlinked = worker_matches(aliased, digest);
    unlink(alias); unlink(path); rmdir(root);
    return original && !writable && !symlinked ? 0 : 53;
}

static int stale_observation(void) {
    struct client client = {0};
    pthread_mutex_init(&client.mutex, NULL);
    uint64_t sequence = 0;
    xpc_object_t object = sample(1, 1);
    client_observe(&client, &sequence, object);
    xpc_release(object);
    usleep(1100000);
    struct evx_xpc_observation snapshot = {0};
    evx_xpc_snapshot(&client, &snapshot);
    pthread_mutex_destroy(&client.mutex);
    return snapshot.state == -1 ? 0 : 40;
}

static int termination(void) {
    server.child = 123;
    server.disconnected = true;
    poll_child();
    if (!server.stopping || term_signals != 2) return 20;
    server.stop_at = monotonic_ns() - 100000000;
    poll_child();
    if (!server.killed || kill_signals != 2) return 21;
    poll_child();
    return kill_signals == 2 ? 0 : 22;
}

static int idle_lifecycle(void) {
    for (unsigned n = 0; n < 8; ++n) if (!reserve_connection()) return 67;
    if (reserve_connection() || atomic_load(&connections) != 8) return 68;
    atomic_store(&connections, 0);
    server.idle_epoch = 5;
    if (!idle_exit_allowed(5)) return 60;
    atomic_store(&connections, 1); // Includes a listener queued for admission.
    if (idle_exit_allowed(5)) return 61;
    cancel_idle_exit();
    atomic_store(&connections, 0);
    if (idle_exit_allowed(5) || !idle_exit_allowed(server.idle_epoch)) return 62;
    server.child = 123; server.disconnected = true;
    if (idle_exit_allowed(server.idle_epoch)) return 63;
    server.reaped = true;
    if (idle_exit_allowed(server.idle_epoch)) return 64; // Cleanup must finish too.
    clear_invocation();
    if (!idle_exit_allowed(server.idle_epoch) || !server.idle_timer) return 65;
    uint64_t armed = server.idle_epoch;
    cancel_idle_exit();
    return !idle_exit_allowed(armed) && !server.idle_timer ? 0 : 66;
}

static int stopped_status(void) {
    stopped_wait = 1; server.child = 123; server.disconnected = true;
    server.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(server.timer, ^{}); dispatch_resume(server.timer);
    poll_child();
    bool retained = server.child == 123 && !server.reaped;
    clear_invocation(); cancel_idle_exit();
    return retained ? 0 : 70;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "stopped")) return stopped_status();
    if (!strcmp(argv[1], "idle")) return idle_lifecycle();
    if (!strcmp(argv[1], "observations")) return observations();
    if (!strcmp(argv[1], "stale")) return stale_observation();
    if (!strcmp(argv[1], "worker-binding")) return worker_binding();
    if (!strcmp(argv[1], "termination")) return termination();
    if (!strcmp(argv[1], "interrupted-wait")) {
        interrupt_wait = 1;
        int result = termination();
        return result ? result : wait_calls >= 4 ? 0 : 30;
    }
    return 2;
}
