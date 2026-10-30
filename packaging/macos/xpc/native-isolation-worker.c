/* Native syscall probe launched by the production signed XPC service. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "native-isolation.h"

static bool denied_path(const char *path) {
    int input = open(path, O_RDONLY | O_NOFOLLOW);
    bool read_denied = input < 0 && (errno == EPERM || errno == EACCES);
    if (input >= 0) close(input);
    int output = open(path, O_WRONLY | O_NOFOLLOW);
    bool write_denied = output < 0 && (errno == EPERM || errno == EACCES);
    if (output >= 0) close(output);
    return read_denied && write_denied;
}

int main(int argc, char **argv) {
    if (argc != 2 || geteuid() == 0) return 2;
    if (!strcmp(argv[1], "descendant")) return 7;
    struct rlimit zero = {0, 0}, raised = {1, 1};
    if (setrlimit(RLIMIT_NPROC, &zero)) return 3;
    struct native_request request;
    size_t used = 0;
    while (used < sizeof(request)) {
        ssize_t count = read(STDIN_FILENO, (char *)&request + used, sizeof(request) - used);
        if (count <= 0) return 4;
        used += (size_t)count;
    }
    for (unsigned n = 0; n < 4; ++n) if (!memchr(request.paths[n], 0, PATH_MAX)) return 4;
    if (request.command == 1) {
        if (fixture_seed(request.paths[0])) return 5;
        puts("seeded"); return 0;
    }
    if (request.command != 2) return 4;
    struct native_result result = {0};
    result.host_denied = denied_path(request.paths[0]);
    result.guest_denied = denied_path(request.paths[1]);
    result.file_denied = denied_path(request.paths[2]);
    result.own_allowed = fixture_seed(request.paths[3]) == 0;
    result.limit_immutable = setrlimit(RLIMIT_NPROC, &raised) < 0 && errno == EPERM;
    pid_t child = fork();
    if (!child) { setsid(); _Exit(7); }
    result.fork_denied = child < 0 && errno == EAGAIN;
    if (child > 0) waitpid(child, NULL, 0);
    char *args[] = {argv[0], "descendant", NULL}; char *environment[] = {NULL};
    int spawned = posix_spawn(&child, argv[0], NULL, NULL, args, environment);
    result.spawn_denied = spawned == EAGAIN;
    if (!spawned) waitpid(child, NULL, 0);
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    int connected = -1, network_error = errno;
    if (socket_fd >= 0) {
        struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET,
            .sin_port = htons(9), .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
        connected = connect(socket_fd, (struct sockaddr *)&address, sizeof(address));
        network_error = errno; close(socket_fd);
    }
    result.network_denied = connected < 0 && (network_error == EPERM || network_error == EACCES);
    result.descriptors_closed = 1;
    for (int fd = 3; fd < 128; ++fd) {
        struct stat info;
        if (!fstat(fd, &info)) result.descriptors_closed = 0;
    }
    if (write(STDOUT_FILENO, &result, sizeof(result)) != sizeof(result)) return 6;
    return 0;
}
