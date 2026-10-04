/* Test driver, not a node-facing API. Service name and requirement are
 * supplied by the local fixture runner, never by a xite. */
#include "protocol.h"
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef EVX_FIXTURE_VARIANT
#define EVX_FIXTURE_VARIANT 1
#endif
static const volatile int fixture_variant = EVX_FIXTURE_VARIANT;

static xpc_object_t round_trip(xpc_connection_t peer, xpc_object_t message) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block xpc_object_t response = NULL;
    xpc_connection_send_message_with_reply(peer, message,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(xpc_object_t reply) {
            response = xpc_retain(reply);
            dispatch_semaphore_signal(done);
        });
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
        /* Exit the fixture on timeout. Cancellation is not used as evidence
         * that the service has stopped. The OS releases this process's blocks. */
        fprintf(stderr, "fixture timed out\n");
        _Exit(3);
    }
    dispatch_release(done);
    return response;
}

int main(int argc, char **argv) {
    (void)fixture_variant;
    if (argc == 3 && !strcmp(argv[1], "authority-probe")) {
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
        int denied = fd < 0 && (errno == EPERM || errno == EACCES);
        if (fd >= 0) { close(fd); unlink(argv[2]); }
        printf("host_authority_denied=%d\n", denied);
        return 0;
    }
    if (argc != 5 && argc != 6) return 2;
    const char *service = argv[1], *requirement = argv[2];
    const char *role = argv[3], *mode = argv[4];
    xpc_connection_t peer = xpc_connection_create(service, NULL);
    if (!peer) return 2;
    if (xpc_connection_set_peer_code_signing_requirement(peer, requirement)) {
        fprintf(stderr, "invalid signing requirement\n");
        return 2;
    }
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) { (void)event; });
    xpc_connection_resume(peer);
    size_t size = strcmp(mode, "oversize") == 0 ? EVX_XPC_FRAME_LIMIT + 1 : 17;
    if (strcmp(mode, "max-frame") == 0 || strcmp(mode, "byte-budget") == 0)
        size = EVX_XPC_FRAME_LIMIT;
    void *bytes = calloc(size, 1);
    if (!bytes) return 2;
    unsigned count = strcmp(mode, "replay") == 0 ? 2 :
        strcmp(mode, "frame-budget") == 0 ? EVX_XPC_FRAME_COUNT + 1 :
        strcmp(mode, "byte-budget") == 0 ? 3 : 1;
    for (unsigned n = 1; n <= count; ++n) {
        xpc_object_t frame = xpc_dictionary_create(NULL, NULL, 0);
        uint64_t sequence = strcmp(mode, "replay") == 0 ? 1 : n;
        evx_xpc_put_frame(frame, role, sequence, bytes, size);
        if (strcmp(mode, "bad-type") == 0) xpc_dictionary_set_string(frame, "body", "data");
        if (strcmp(mode, "bad-version") == 0) xpc_dictionary_set_uint64(frame, "version", 2);
        if (strcmp(mode, "extra-key") == 0) xpc_dictionary_set_string(frame, "path", "/private");
        if (strcmp(mode, "descriptor") == 0) {
            int fd = open("/dev/null", O_RDONLY);
            if (fd < 0) return 2;
            xpc_dictionary_set_fd(frame, "workspace", fd);
            close(fd);
        }
        if (argc == 6) {
            int fd = open(argv[5], O_RDONLY);
            if (fd < 0) return 2;
            xpc_dictionary_set_fd(frame, "scoped", fd);
            close(fd);
        }
        xpc_object_t reply = round_trip(peer, frame);
        xpc_release(frame);
        if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
            puts(reply == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT ? "identity-denied" : "connection-denied");
            xpc_release(reply);
            break;
        }
        if (xpc_dictionary_get_string(reply, "error")) {
            printf("frame-denied:%u\n", n);
            xpc_release(reply);
            break;
        }
        size_t length = 0;
        if (strcmp(mode, "sandbox-child") == 0) {
            if (!evx_xpc_frame(reply, role, sequence, &length) || length >= 128) return 4;
            size_t ignored = 0;
            const char *result = xpc_dictionary_get_data(reply, "body", &ignored);
            fwrite(result, 1, length, stdout);
            xpc_release(reply);
            break;
        }
        if (!evx_xpc_frame(reply, role, sequence, &length) || length != size) return 4;
        size_t ignored = 0;
        if (memcmp(bytes, xpc_dictionary_get_data(reply, "body", &ignored), size)) return 4;
        printf("accepted:%u:%zu\n", n, size);
        xpc_release(reply);
    }
    free(bytes);
    if (strcmp(mode, "cancel-survival") == 0) {
        /* Evidence only: production must not use this PID snapshot to signal
         * a peer. No signal is sent, and the fixture exits on its own timer. */
        pid_t pid = xpc_connection_get_pid(peer);
        struct rusage_info_v4 before = {0}, after = {0};
        int descriptor = kqueue();
        struct kevent watch, event;
        EV_SET(&watch, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
        if (pid <= 0 || descriptor < 0 ||
            proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&before) != 0 ||
            kevent(descriptor, &watch, 1, NULL, 0, NULL) != 0) return 4;
        xpc_connection_cancel(peer);
        usleep(100000);
        if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&after) != 0 ||
            before.ri_proc_start_abstime != after.ri_proc_start_abstime) return 4;
        puts("connection-cancelled:process-alive");
        const struct timespec timeout = {.tv_sec = 10, .tv_nsec = 0};
        if (kevent(descriptor, NULL, 0, &event, 1, &timeout) != 1 ||
            !(event.fflags & NOTE_EXIT)) return 4;
        close(descriptor);
        for (unsigned n = 0; n < 20; ++n) {
            if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&after) != 0) {
                puts("kernel-usage:unavailable-after-exit");
                xpc_release(peer);
                return 0;
            }
            usleep(10000);
        }
        return 4;
    }
    xpc_connection_cancel(peer);
    xpc_release(peer);
    return 0;
}
