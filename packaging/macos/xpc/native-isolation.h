/* Bounded, test-only messages. No production worker accepts this protocol. */
#ifndef EVX_NATIVE_ISOLATION_H
#define EVX_NATIVE_ISOLATION_H
#include <limits.h>
struct native_request { unsigned command; char paths[4][PATH_MAX]; };
struct native_result {
    unsigned host_denied, guest_denied, file_denied, own_allowed;
    unsigned network_denied, fork_denied, spawn_denied, limit_immutable, descriptors_closed;
};
static int fixture_directory(const char *path) {
    char copy[PATH_MAX];
    if (path[0] != '/' || strlen(path) >= sizeof(copy)) return -1;
    strcpy(copy, path);
    for (char *part = copy + 1; ; ++part) {
        if (*part != '/' && *part) continue;
        char saved = *part; *part = 0;
        struct stat info;
        if (stat(copy, &info)) {
            if (errno != ENOENT || mkdir(copy, 0700)) return -1;
        } else if (!S_ISDIR(info.st_mode)) return -1;
        *part = saved;
        if (!saved) break;
    }
    return 0;
}
static int fixture_seed(const char *path) {
    char parent[PATH_MAX];
    if (strlen(path) >= sizeof(parent)) return -1;
    strcpy(parent, path); char *last = strrchr(parent, '/');
    if (!last) return -1; *last = 0;
    if (fixture_directory(parent)) return -1;
    int file = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (file < 0) return -1;
    int result = write(file, "game-private", 12) == 12 ? 0 : -1;
    close(file); return result;
}
#endif
