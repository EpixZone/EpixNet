/* Test-only sandboxed host. Uses the actual bounded production XPC adapter. */
#include "../../../crates/evx-supervisor/native/apple_xpc.c"
#include "native-isolation.h"
#include <sys/event.h>

static int run_probe(const char *service, const char *requirement, const char *authority,
                     unsigned access, const struct native_request *request, void *response, size_t size) {
    int pipes[3][2]; for (unsigned n = 0; n < 3; ++n) if (pipe(pipes[n])) return 10;
    void *peer = evx_xpc_open(service, requirement, authority, access, pipes[0][0], pipes[1][1], pipes[2][1]);
    close(pipes[0][0]); close(pipes[1][1]); close(pipes[2][1]);
    if (!peer) return 11;
    size_t used = 0;
    while (used < sizeof(*request)) {
        ssize_t count = write(pipes[0][1], (const char *)request + used, sizeof(*request) - used);
        if (count <= 0) return 12;
        used += (size_t)count;
    }
    close(pipes[0][1]);
    used = 0;
    while (used < size) {
        ssize_t count = read(pipes[1][0], (char *)response + used, size - used);
        if (count <= 0) return 13;
        used += (size_t)count;
    }
    struct evx_xpc_observation sample = {0};
    uint64_t deadline = monotonic_ns() + 5 * NSEC_PER_SEC;
    do { evx_xpc_snapshot(peer, &sample); if (sample.state != 1) break; usleep(10000); }
    while (monotonic_ns() < deadline);
    evx_xpc_release(peer); close(pipes[1][0]); close(pipes[2][0]);
    return sample.state == 2 && sample.exit_code == 0 && sample.cpu > 0 && sample.peak_rss > 0 ? 0 : 14;
}

int main(int argc, char **argv) {
    if (argc != 8) return 2;
    char authority[PATH_MAX], host_root[PATH_MAX], guest_root[PATH_MAX], file_root[PATH_MAX], own_root[PATH_MAX];
    if (evx_xpc_authority_directory(argv[1], authority, sizeof(authority)) || fixture_directory(authority) ||
        container_directory(argv[1], "NativeFixture", host_root, sizeof(host_root)) ||
        container_directory(argv[4], "NativeFixture", guest_root, sizeof(guest_root)) ||
        container_directory(argv[6], "NativeFixture", file_root, sizeof(file_root)) ||
        container_directory(argv[2], "NativeFixture", own_root, sizeof(own_root))) return 3;
    struct native_request request = {0};
    const char *roots[] = {host_root, guest_root, file_root, own_root};
    for (unsigned n = 0; n < 4; ++n)
        if (snprintf(request.paths[n], PATH_MAX, "%s/private-game-record", roots[n]) >= PATH_MAX) return 3;
    if (fixture_seed(request.paths[0])) return 4;
    for (unsigned n = 1; n <= 2; ++n) {
        struct native_request seed = {.command = 1}; strcpy(seed.paths[0], request.paths[n]);
        char response[7];
        int result = run_probe(argv[n * 2 + 2], argv[n * 2 + 3], authority, n == 2 ? 2 : 0, &seed, response, sizeof(response));
        if (result || memcmp(response, "seeded\n", sizeof(response))) return result ? result : 5;
    }
    request.command = 2;
    struct native_result result;
    int status = run_probe(argv[2], argv[3], authority, 0, &request, &result, sizeof(result));
    if (status) return status;
    printf("{\"host_denied\":%u,\"guest_denied\":%u,\"file_denied\":%u,\"own_allowed\":%u,"
           "\"network_denied\":%u,\"fork_denied\":%u,\"spawn_denied\":%u,\"limit_immutable\":%u,\"descriptors_closed\":%u}\n",
           result.host_denied, result.guest_denied, result.file_denied, result.own_allowed,
           result.network_denied, result.fork_denied, result.spawn_denied, result.limit_immutable, result.descriptors_closed);
    unlink(request.paths[0]); rmdir(host_root);
    return 0;
}
