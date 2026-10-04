/* Sacrificial inherited-App-Sandbox probe. No untrusted input is executed. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sandbox.h>
#include <stdio.h>
#include <spawn.h>
#include <stdbool.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "descendant")) return 7;
#ifdef EVX_FIXTURE_REEXEC_HOST
    char host[PATH_MAX];
    if (strlen(argv[0]) >= sizeof(host)) return 3;
    strcpy(host, argv[0]); char *name = strrchr(host, '/');
    if (!name) return 3;
    if (snprintf(name + 1, sizeof(host) - (size_t)(name + 1 - host), "probe-host") < 0) return 3;
    execl(host, host, "authority-probe", argv[1], NULL);
    return 3;
#endif
    struct stat inherited;
    if (fstat(3, &inherited) == 0) {
        int selected = S_ISDIR(inherited.st_mode) ? openat(3, "score.json", O_RDONLY) : dup(3);
        char value = 0;
        int readable = selected >= 0 && read(selected, &value, 1) == 1 && value == '4';
        if (selected >= 0) close(selected);
        printf("scoped_descriptor_read=%d\n", readable);
        return 0;
    }
    /* This location is inside the disposable fixture bundle, writable by the
     * test user but outside the service's App Sandbox data container. */
    int descriptor = open(argv[1], O_CREAT | O_EXCL | O_WRONLY, 0600);
    int write_error = descriptor < 0 ? errno : 0;
    if (descriptor >= 0) {
        close(descriptor);
        unlink(argv[1]);
    }
    if (geteuid() == 0) return 3;
    struct rlimit zero = {0, 0}, raised = {1, 1};
    bool limited = setrlimit(RLIMIT_NPROC, &zero) == 0;
    bool immutable = setrlimit(RLIMIT_NPROC, &raised) == -1 && errno == EPERM;
    pid_t descendant = fork();
    if (descendant == 0) _Exit(7);
    bool fork_denied = descendant < 0 && errno == EAGAIN;
    if (descendant > 0) waitpid(descendant, NULL, 0);
    char *args[] = {argv[0], "descendant", NULL};
    char *environment[] = {NULL};
    int spawned = posix_spawn(&descendant, argv[0], NULL, NULL, args, environment);
    if (!spawned) waitpid(descendant, NULL, 0);
    bool descendants_denied = limited && immutable && fork_denied && spawned == EAGAIN;
    char *detail = NULL;
    int confined = sandbox_init(kSBXProfilePureComputation, SANDBOX_NAMED, &detail);
    if (detail) sandbox_free_error(detail);
    printf("write_denied=%d;sandbox_init_denied=%d;descendants_denied=%d\n",
           write_error == EPERM || write_error == EACCES, confined != 0, descendants_denied);
    return 0;
}
