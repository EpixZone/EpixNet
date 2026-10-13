/* Local signed-host admission tests using the production service protocol. */
#include "../../../crates/evx-supervisor/native/apple_xpc.c"
#include <sys/event.h>

struct fixture_peer {
    xpc_connection_t peer;
    dispatch_semaphore_t changed;
    unsigned char challenge[32];
    atomic_int state; /* 1 challenge, 2 accepted, -1 rejected */
};

static void fixture_connect(struct fixture_peer *fixture, const char *service, const char *requirement) {
    fixture->changed = dispatch_semaphore_create(0);
    fixture->peer = xpc_connection_create(service, NULL);
    xpc_connection_set_event_handler(fixture->peer, ^(xpc_object_t event) {
        int state = -1;
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            size_t size = 0; const void *nonce = xpc_dictionary_get_data(event, "challenge", &size);
            if (nonce && size == 32) { memcpy(fixture->challenge, nonce, size); state = 1; }
            else if (xpc_dictionary_get_uint64(event, "state")) state = xpc_dictionary_get_uint64(event, "state") == 2 ? 3 : 2;
        }
        atomic_store(&fixture->state, state); dispatch_semaphore_signal(fixture->changed);
    });
    if (xpc_connection_set_peer_code_signing_requirement(fixture->peer, requirement)) _Exit(3);
    xpc_connection_resume(fixture->peer);
    xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(hello, "v", 1); xpc_dictionary_set_string(hello, "op", "hello");
    xpc_connection_send_message(fixture->peer, hello); xpc_release(hello);
    if (dispatch_semaphore_wait(fixture->changed, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) ||
        atomic_load(&fixture->state) != 1) _Exit(4);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    const char *mode = argv[1], *service = argv[2], *requirement = argv[3], *root = argv[4];
    struct fixture_peer first = {0}, second = {0};
    fixture_connect(&first, service, requirement);
    int directory = secure_directory(root, true); if (directory < 0) return 5;
    char name[65] = {0};
    int authority = create_authority(directory, first.challenge, service, name);
    if (authority < 0) return 5;
    struct fixture_peer *selected = &first;
    if (!strcmp(mode, "replay")) {
        xpc_connection_cancel(first.peer);
        fixture_connect(&second, service, requirement);
        if (!memcmp(first.challenge, second.challenge, 32)) return 6;
        selected = &second;
    } else if (!strcmp(mode, "read-write")) {
        close(authority); authority = openat(directory, name, O_RDWR | O_NOFOLLOW);
    } else if (!strcmp(mode, "malformed")) {
        int output = openat(directory, name, O_WRONLY | O_NOFOLLOW);
        if (output < 0 || write(output, "X", 1) != 1) return 5;
        close(output);
    } else if (!strcmp(mode, "wrong-mode")) {
        if (fchmod(authority, 0644)) return 5;
    } else if (!strcmp(mode, "hardlink")) {
        if (linkat(directory, name, directory, "other-link", 0)) return 5;
    }
    int pipes[3][2]; for (int n = 0; n < 3; ++n) if (pipe(pipes[n])) return 5;
    xpc_object_t start = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(start, "v", 1); xpc_dictionary_set_string(start, "op", "start");
    xpc_dictionary_set_uint64(start, "access", 0);
    xpc_dictionary_set_fd(start, "authority", authority);
    xpc_dictionary_set_fd(start, "input", pipes[0][0]); xpc_dictionary_set_fd(start, "output", pipes[1][1]);
    xpc_dictionary_set_fd(start, "error", pipes[2][1]);
    if (!strcmp(mode, "same-connection") || !strcmp(mode, "idle")) {
        close(pipes[0][1]); // EOF makes the effect-free first worker terminate.
        xpc_connection_send_message(selected->peer, start);
        while (atomic_load(&selected->state) != 3) {
            if (dispatch_semaphore_wait(selected->changed, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) ||
                atomic_load(&selected->state) < 0) return 9;
        }
        if (!strcmp(mode, "idle")) {
            pid_t pid = xpc_connection_get_pid(first.peer);
            int watcher = kqueue(); struct kevent change, event;
            EV_SET(&change, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXIT, 0, NULL);
            if (watcher < 0 || kevent(watcher, &change, 1, NULL, 0, NULL)) return 10;
            xpc_connection_cancel(first.peer);
            usleep(1000000);
            fixture_connect(&second, service, requirement);
            if (xpc_connection_get_pid(second.peer) != pid) return 11;
            xpc_connection_cancel(second.peer);
            struct timespec timeout = {.tv_sec = 35};
            if (kevent(watcher, NULL, 0, &event, 1, &timeout) != 1 || !(event.fflags & NOTE_EXIT)) return 12;
            close(watcher); close(authority); unlinkat(directory, name, 0); close(directory);
            puts("idle-service-retired"); return 0;
        }
        while (!dispatch_semaphore_wait(selected->changed, DISPATCH_TIME_NOW)) {}
        atomic_store(&selected->state, 0);
    }
    xpc_connection_send_message(selected->peer, start); xpc_release(start);
    if (dispatch_semaphore_wait(selected->changed, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) return 7;
    int result = atomic_load(&selected->state);
    xpc_connection_cancel(selected->peer);
    close(authority); unlinkat(directory, name, 0); unlinkat(directory, "other-link", 0); close(directory);
    if (result != -1) return 8;
    puts("admission-denied");
    return 0;
}
