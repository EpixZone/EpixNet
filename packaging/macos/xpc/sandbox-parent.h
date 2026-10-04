/* Real child ownership and wait4 inside an App-Sandboxed XPC service. */
#include <CoreFoundation/CoreFoundation.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static bool sandbox_child_probe(char *output, size_t capacity, int scoped_fd) {
    CFURLRef url = CFBundleCopyExecutableURL(CFBundleGetMainBundle());
    char path[PATH_MAX];
    if (!url) return false;
    bool copied = CFURLGetFileSystemRepresentation(url, true, (UInt8 *)path, sizeof(path));
    CFRelease(url);
    if (!copied) return false;
    char *last = strrchr(path, '/');
    if (!last) return false;
    *last = '\0';
    char child_path[PATH_MAX], probe_path[PATH_MAX];
    if (snprintf(child_path, sizeof(child_path), "%s/probe-child", path) >= PATH_MAX ||
        snprintf(probe_path, sizeof(probe_path), "%s/probe-write", path) >= PATH_MAX) return false;
    CFTypeRef authority = CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), CFSTR("EVXFixtureAuthorityRoot"));
    if (authority) {
        char root[PATH_MAX];
        if (CFGetTypeID(authority) != CFStringGetTypeID() ||
            !CFStringGetCString(authority, root, sizeof(root), kCFStringEncodingUTF8) ||
            snprintf(probe_path, sizeof(probe_path), "%s/reexec-proof", root) >= PATH_MAX) return false;
    }
    int channel[2];
    if (pipe(channel)) return false;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, channel[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, channel[0]);
    posix_spawn_file_actions_addclose(&actions, channel[1]);
    if (scoped_fd >= 0) posix_spawn_file_actions_adddup2(&actions, scoped_fd, 3);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
    char *args[] = {child_path, probe_path, NULL};
    char *environment[] = {NULL};
    pid_t child = 0;
    int error = posix_spawn(&child, child_path, &actions, &attributes, args, environment);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    close(channel[1]);
    if (error) {
        close(channel[0]);
        snprintf(output, capacity, "spawn_error=%d\n", error);
        return true;
    }
    ssize_t used = read(channel[0], output, capacity - 1);
    close(channel[0]);
    if (used < 0) used = 0;
    output[used] = '\0';
    int status = 0;
    struct rusage usage = {0};
    if (wait4(child, &status, 0, &usage) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        return false;
    return used > 0;
}
