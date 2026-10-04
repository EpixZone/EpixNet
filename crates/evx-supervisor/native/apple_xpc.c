/* Trusted XPC child owner. Guest bytes use pipes and never enter this decoder.
 * Service identity, role and worker requirement come from the signed bundle. */
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach_time.h>
#include <math.h>
#include <os/log.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>

struct evx_xpc_observation {
    int32_t state; /* 0 starting, 1 live, 2 reaped, -1 unavailable */
    int32_t pid;
    int32_t exit_code;
    uint64_t rss;
    uint64_t peak_rss;
    double cpu;
};

static uint64_t monotonic_ns(void);

struct client {
    xpc_connection_t connection;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct evx_xpc_observation sample;
    uint64_t observed_at;
    unsigned char challenge[32];
    bool challenged;
    bool admitted;
};

enum { AUTHORITY_SIZE = 304 };
static const unsigned char authority_magic[8] = {'E','V','X','A','U','T','H','1'};

/* Fixed host-container authority domain. Neither HOME nor a caller-selected
 * root participates in this resolution. The identifier is signed package data. */
static int container_directory(const char *identifier, const char *leaf, char *output, size_t capacity) {
    if (!identifier || !output || !capacity || geteuid() == 0 || geteuid() != getuid()) return -1;
    size_t length = strlen(identifier);
    if (!length || length > 255 || !strchr(identifier, '.')) return -1;
    bool segment = false;
    for (size_t n = 0; n < length; ++n) {
        unsigned char ch = (unsigned char)identifier[n];
        if (ch == '.') {
            if (!segment) return -1;
            segment = false;
        }
        else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') || ch == '-') segment = true;
        else return -1;
    }
    if (!segment) return -1;
    char buffer[16384]; struct passwd entry; struct passwd *result = NULL;
    if (getpwuid_r(geteuid(), &entry, buffer, sizeof(buffer), &result) || !result ||
        result->pw_uid != geteuid() || !result->pw_dir || result->pw_dir[0] != '/' ||
        !result->pw_dir[1]) return -1;
    const char *home = result->pw_dir;
    size_t home_size = strlen(home);
    if (home_size >= PATH_MAX || home[home_size - 1] == '/' || strstr(home, "//") ||
        strstr(home, "/./") || strstr(home, "/../") ||
        (home_size >= 2 && !strcmp(home + home_size - 2, "/.")) ||
        (home_size >= 3 && !strcmp(home + home_size - 3, "/.."))) return -1;
    int written = snprintf(output, capacity, "%s/Library/Containers/%s/Data/Library/Application Support/EpixNet/%s", home, identifier, leaf);
    return written >= 0 && (size_t)written < capacity ? 0 : -1;
}

int evx_xpc_authority_directory(const char *identifier, char *output, size_t capacity) {
    return container_directory(identifier, "EVXAuthority", output, capacity);
}

/* The standard installation directory is root:admin and group-writable on
 * macOS. Administrators are trusted installation authorities. This allowance
 * applies only to that root-level component, never arbitrary writable paths. */
int evx_xpc_system_applications_directory(unsigned uid, unsigned gid, unsigned mode) {
    char buffer[4096]; struct group group; struct group *found = NULL;
    return uid == 0 && (mode & 0022) == 0020 &&
        getgrnam_r("admin", &group, buffer, sizeof(buffer), &found) == 0 && found && gid == found->gr_gid;
}

/* Trusted directory walk: reject aliases and writable package/authority ancestors.
 * System-owned sticky temporary directories are allowed for local fixtures;
 * the final authority directory must still be privately owned and mode0700. */
static int secure_directory(const char *path, bool private) {
    if (!path || path[0] != '/' || strlen(path) >= PATH_MAX || !path[1]) return -1;
    char copy[PATH_MAX];
    if (strlcpy(copy, path + 1, sizeof(copy)) >= sizeof(copy)) return -1;
    int current = open("/", O_SEARCH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    char *component = copy;
    while (current >= 0 && component && *component) {
        char *next = strchr(component, '/');
        if (next) *next++ = '\0';
        if (!*component || !strcmp(component, ".") || !strcmp(component, "..") || (next && !*next)) {
            close(current); return -1;
        }
        int child = openat(current, component, O_SEARCH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(current); current = child;
        struct stat info;
        if (current < 0) return -1;
        if (fstat(current, &info) || (info.st_uid != geteuid() && info.st_uid != 0) ||
            ((info.st_mode & 0022) && !(info.st_uid == 0 && (info.st_mode & S_ISVTX)) &&
             !(component == copy && !strcmp(component, "Applications") &&
               evx_xpc_system_applications_directory(info.st_uid, info.st_gid, info.st_mode)))) {
            close(current); return -1;
        }
        if (!next && private && (info.st_uid != geteuid() || (info.st_mode & 0777) != 0700)) {
            close(current); return -1;
        }
        component = next;
    }
    return current;
}

static void authority_record(unsigned char record[AUTHORITY_SIZE], const unsigned char challenge[32],
                             pid_t pid, const char *service) {
    memset(record, 0, AUTHORITY_SIZE);
    memcpy(record, authority_magic, 8); memcpy(record + 8, challenge, 32);
    for (unsigned n = 0; n < 8; ++n) record[40 + n] = ((uint64_t)pid >> (56 - 8 * n)) & 255;
    memcpy(record + 48, service, strlen(service));
}

static int create_authority(int directory, const unsigned char challenge[32], const char *service,
                            char filename[65]) {
    if (strlen(service) > 255 || geteuid() == 0) return -1;
    unsigned char random[32]; unsigned char record[AUTHORITY_SIZE]; arc4random_buf(random, sizeof(random));
    for (unsigned n = 0; n < 32; ++n) snprintf(filename + 2 * n, 3, "%02x", random[n]);
    int output = openat(directory, filename, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) return -1;
    authority_record(record, challenge, getpid(), service);
    ssize_t size; do { size = write(output, record, sizeof(record)); } while (size < 0 && errno == EINTR);
    bool written = size == sizeof(record);
    close(output);
    if (!written) { unlinkat(directory, filename, 0); return -1; }
    return openat(directory, filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

static void client_free(void *opaque) {
    struct client *client = opaque;
    pthread_cond_destroy(&client->condition);
    pthread_mutex_destroy(&client->mutex);
    free(client);
}

static bool unsigned_field(xpc_object_t object, const char *key) {
    xpc_object_t value = xpc_dictionary_get_value(object, key);
    return value && xpc_get_type(value) == XPC_TYPE_UINT64;
}

static bool observation(xpc_object_t object, struct evx_xpc_observation *sample) {
    if (xpc_get_type(object) != XPC_TYPE_DICTIONARY ||
        xpc_dictionary_get_count(object) != 8 ||
        !unsigned_field(object, "v") || xpc_dictionary_get_uint64(object, "v") != 1 ||
        !unsigned_field(object, "state") || !unsigned_field(object, "pid") ||
        !unsigned_field(object, "rss") || !unsigned_field(object, "peak") ||
        !unsigned_field(object, "cpu_ns") || !unsigned_field(object, "sequence")) return false;
    xpc_object_t exit = xpc_dictionary_get_value(object, "exit");
    uint64_t state = xpc_dictionary_get_uint64(object, "state");
    uint64_t pid = xpc_dictionary_get_uint64(object, "pid");
    if (!exit || xpc_get_type(exit) != XPC_TYPE_INT64 || state < 1 || state > 2 ||
        pid == 0 || pid > INT_MAX) return false;
    int64_t code = xpc_dictionary_get_int64(object, "exit");
    if (code < -128 || code > 255) return false;
    sample->state = (int32_t)state;
    sample->pid = (int32_t)pid;
    sample->exit_code = (int32_t)code;
    sample->rss = xpc_dictionary_get_uint64(object, "rss");
    sample->peak_rss = xpc_dictionary_get_uint64(object, "peak");
    sample->cpu = xpc_dictionary_get_uint64(object, "cpu_ns") / 1e9;
    return true;
}

static void client_observe(struct client *client, uint64_t *sequence, xpc_object_t object) {
    struct evx_xpc_observation next = {0};
    bool valid = observation(object, &next);
    if (valid) {
        uint64_t number = xpc_dictionary_get_uint64(object, "sequence");
        valid = number == *sequence + 1 && client->sample.state >= 0 &&
            client->sample.state != 2 &&
            (client->sample.pid == 0 || client->sample.pid == next.pid) &&
            next.cpu >= client->sample.cpu && next.peak_rss >= client->sample.peak_rss;
        if (valid) { client->sample = next; client->observed_at = monotonic_ns(); *sequence = number; }
    }
    if (!valid && client->sample.state != 2) client->sample.state = -1;
}

void evx_xpc_release(void *opaque) {
    struct client *client = opaque;
    xpc_connection_cancel(client->connection);
    xpc_release(client->connection);
}

static int wait_client(struct client *client, uint64_t deadline) {
    uint64_t now = monotonic_ns();
    if (now >= deadline) return ETIMEDOUT;
    uint64_t remaining = deadline - now;
    struct timespec relative = {.tv_sec = (time_t)(remaining / 1000000000),
                                .tv_nsec = (long)(remaining % 1000000000)};
    return pthread_cond_timedwait_relative_np(&client->condition, &client->mutex, &relative);
}

static void client_event(struct client *client, uint64_t *sequence, xpc_object_t object) {
    const char *op = xpc_get_type(object) == XPC_TYPE_DICTIONARY ? xpc_dictionary_get_string(object, "op") : NULL;
    if (op && !strcmp(op, "challenge") && !client->challenged && client->sample.state == 0 &&
        xpc_dictionary_get_count(object) == 3 && unsigned_field(object, "v") &&
        xpc_dictionary_get_uint64(object, "v") == 1) {
        size_t size = 0; const void *bytes = xpc_dictionary_get_data(object, "challenge", &size);
        if (bytes && size == sizeof(client->challenge)) {
            memcpy(client->challenge, bytes, size); client->challenged = true;
        } else client->sample.state = -1;
    } else if (client->admitted) client_observe(client, sequence, object);
    else client->sample.state = -1;
}

void *evx_xpc_open(const char *name, const char *requirement, const char *authority_root, uint32_t access, int input, int output, int error) {
    if (__builtin_available(macOS 12.0, *)) { /* Peer identity checks require macOS 12. */ } else { return NULL; }
    struct client *client = calloc(1, sizeof(*client));
    if (!client) return NULL;
    pthread_mutex_init(&client->mutex, NULL);
    pthread_cond_init(&client->condition, NULL);
    dispatch_queue_t queue = dispatch_queue_create("zone.epix.evx.xpc.client", NULL);
    client->connection = xpc_connection_create(name, queue);
    dispatch_release(queue);
    if (!client->connection) { client_free(client); return NULL; }
    xpc_connection_set_context(client->connection, client);
    xpc_connection_set_finalizer_f(client->connection, client_free);
    __block uint64_t sequence = 0;
    xpc_connection_set_event_handler(client->connection, ^(xpc_object_t object) {
        pthread_mutex_lock(&client->mutex);
        client_event(client, &sequence, object);
        pthread_cond_broadcast(&client->condition);
        pthread_mutex_unlock(&client->mutex);
    });
    int identity = xpc_connection_set_peer_code_signing_requirement(client->connection, requirement);
    xpc_connection_resume(client->connection);
    if (identity) { evx_xpc_release(client); return NULL; }
    xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(hello, "v", 1); xpc_dictionary_set_string(hello, "op", "hello");
    xpc_connection_send_message(client->connection, hello); xpc_release(hello);
    uint64_t deadline = monotonic_ns() + 5000000000;
    pthread_mutex_lock(&client->mutex);
    while (!client->challenged && client->sample.state == 0) {
        if (wait_client(client, deadline) == ETIMEDOUT) break;
    }
    bool challenged = client->challenged && client->sample.state == 0;
    pthread_mutex_unlock(&client->mutex);
    if (!challenged) { evx_xpc_release(client); return NULL; }
    int directory = secure_directory(authority_root, true);
    char filename[65] = {0};
    int authority = directory >= 0 ? create_authority(directory, client->challenge, name, filename) : -1;
    if (authority < 0) {
        if (directory >= 0) {
            if (filename[0]) unlinkat(directory, filename, 0);
            close(directory);
        }
        evx_xpc_release(client); return NULL;
    }
    pthread_mutex_lock(&client->mutex); client->admitted = true; pthread_mutex_unlock(&client->mutex);
    xpc_object_t start = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(start, "v", 1);
    xpc_dictionary_set_string(start, "op", "start");
    xpc_dictionary_set_uint64(start, "access", access);
    xpc_dictionary_set_fd(start, "authority", authority);
    xpc_dictionary_set_fd(start, "input", input);
    xpc_dictionary_set_fd(start, "output", output);
    xpc_dictionary_set_fd(start, "error", error);
    xpc_connection_send_message(client->connection, start);
    xpc_release(start);
    close(authority);
    pthread_mutex_lock(&client->mutex);
    while (client->sample.state == 0) {
        if (wait_client(client, deadline) == ETIMEDOUT) break;
    }
    bool ready = client->sample.state > 0;
    pthread_mutex_unlock(&client->mutex);
    unlinkat(directory, filename, 0); close(directory);
    if (!ready) { evx_xpc_release(client); return NULL; }
    return client;
}

void evx_xpc_snapshot(void *opaque, struct evx_xpc_observation *sample) {
    struct client *client = opaque;
    pthread_mutex_lock(&client->mutex);
    if (client->sample.state == 1 && monotonic_ns() - client->observed_at > 1000000000)
        client->sample.state = -1;
    *sample = client->sample;
    pthread_mutex_unlock(&client->mutex);
}

void evx_xpc_stop(void *opaque) {
    struct client *client = opaque;
    xpc_object_t stop = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(stop, "v", 1);
    xpc_dictionary_set_string(stop, "op", "stop");
    xpc_connection_send_message(client->connection, stop);
    xpc_release(stop);
}

struct server_policy {
    char client_requirement[2048];
    char worker_digest[65];
    char worker_path[PATH_MAX];
    char *mode;
    char authority_root[PATH_MAX];
    char identifier[256];
    char workspace[PATH_MAX];
};

struct server {
    struct server_policy policy;
    int workspace_lease;
    xpc_connection_t peer;
    dispatch_source_t timer;
    dispatch_source_t idle_timer;
    uint64_t idle_epoch;
    pid_t child;
    bool stopping;
    bool killed;
    bool disconnected;
    bool reaped;
    uint64_t stop_at;
    uint64_t sequence;
    uint64_t peak;
    uint64_t child_peak;
    uint64_t started_at;
    double cpu;
    double own_base;
    double own_accounted;
    int exit_code;
};
static struct server server = {.workspace_lease = -1};
static atomic_uint connections;

/* All service state and idle timer mutations run on the main dispatch queue.
 * Pending listener callbacks count as connections before entering that queue. */
static void cancel_idle_exit(void) {
    ++server.idle_epoch;
    if (server.idle_timer) {
        dispatch_source_cancel(server.idle_timer); dispatch_release(server.idle_timer);
        server.idle_timer = NULL;
    }
}

static bool idle_exit_allowed(uint64_t epoch) {
    return epoch == server.idle_epoch && !atomic_load(&connections) &&
        server.child <= 0 && !server.peer;
}

static void arm_idle_exit(void) {
    if (server.idle_timer || !idle_exit_allowed(server.idle_epoch)) return;
    uint64_t epoch = ++server.idle_epoch;
    server.idle_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(server.idle_timer, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
    dispatch_source_set_event_handler(server.idle_timer, ^{
        if (idle_exit_allowed(epoch)) _Exit(0);
        cancel_idle_exit();
    });
    dispatch_resume(server.idle_timer);
}

static uint64_t monotonic_ns(void) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}

static void terminate_owned(void) {
    if (server.child <= 0 || server.reaped || server.stopping) return;
    server.stopping = true;
    server.stop_at = monotonic_ns();
    killpg(server.child, SIGTERM);
    kill(server.child, SIGTERM);
}

static void clear_invocation(void) {
    if (server.workspace_lease >= 0) { close(server.workspace_lease); server.workspace_lease = -1; }
    if (server.timer) { dispatch_source_cancel(server.timer); dispatch_release(server.timer); server.timer = NULL; }
    if (server.peer) { xpc_release(server.peer); server.peer = NULL; }
    server.child = 0; server.stopping = false; server.killed = false;
    server.disconnected = false; server.reaped = false;
    server.stop_at = 0; server.sequence = 0; server.peak = 0; server.child_peak = 0;
    server.started_at = 0; server.cpu = 0; server.exit_code = 0;
    server.own_base = server.own_accounted;
    arm_idle_exit();
}

static void publish_sample(uint64_t rss, double child_cpu) {
    if (server.disconnected) return;
    struct rusage own = {0};
    if (getrusage(RUSAGE_SELF, &own)) { terminate_owned(); xpc_connection_cancel(server.peer); return; }
    server.own_accounted = own.ru_utime.tv_sec + own.ru_utime.tv_usec / 1e6 +
                           own.ru_stime.tv_sec + own.ru_stime.tv_usec / 1e6;
    double cpu = child_cpu + fmax(0, server.own_accounted - server.own_base);
    if (cpu > server.cpu) server.cpu = cpu;
    if (rss > server.child_peak) server.child_peak = rss;
    /* Sum of each process's kernel high-watermark is conservative. Peaks need
     * not occur simultaneously; do not describe it as an exact live sample. */
    uint64_t peak = server.child_peak + (uint64_t)own.ru_maxrss;
    if (peak > server.peak) server.peak = peak;
    rss += (uint64_t)own.ru_maxrss;
    xpc_object_t update = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(update, "v", 1);
    xpc_dictionary_set_uint64(update, "state", server.reaped ? 2 : 1);
    xpc_dictionary_set_uint64(update, "pid", (uint64_t)server.child);
    xpc_dictionary_set_uint64(update, "rss", rss);
    xpc_dictionary_set_uint64(update, "peak", server.peak);
    xpc_dictionary_set_uint64(update, "cpu_ns", (uint64_t)(server.cpu * 1e9));
    xpc_dictionary_set_uint64(update, "sequence", ++server.sequence);
    xpc_dictionary_set_int64(update, "exit", server.exit_code);
    xpc_connection_send_message(server.peer, update);
    xpc_release(update);
}

static void poll_child(void) {
    if (server.reaped) return;
    int status = 0;
    struct rusage usage = {0};
    pid_t reaped;
    do { reaped = wait4(server.child, &status, WNOHANG, &usage); }
    while (reaped < 0 && errno == EINTR);
    if (reaped == server.child && (WIFEXITED(status) || WIFSIGNALED(status))) {
        /* A traced child may report a stop without being reaped. */
        server.reaped = true;
        double cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 +
                     usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
        if ((uint64_t)usage.ru_maxrss > server.child_peak) server.child_peak = (uint64_t)usage.ru_maxrss;
        server.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
        publish_sample(0, cpu);
        dispatch_source_cancel(server.timer);
        if (server.disconnected) clear_invocation();
        return;
    }
    if (reaped < 0) {
        /* Losing ownership is not a successful cleanup acknowledgement. */
        xpc_connection_cancel(server.peer);
        _Exit(1);
    }
    if (monotonic_ns() - server.started_at > 605ULL * 1000000000) terminate_owned();
    /* Escalation must not depend on a successful resource observation. */
    if (server.stopping && !server.killed && monotonic_ns() - server.stop_at >= 50000000) {
        killpg(server.child, SIGKILL);
        kill(server.child, SIGKILL);
        server.killed = true;
    }
    struct proc_taskinfo observation = {0};
    if (proc_pidinfo(server.child, PROC_PIDTASKINFO, 0, &observation, sizeof(observation)) != sizeof(observation)) {
        if (!server.stopping) os_log_error(OS_LOG_DEFAULT, "EVX XPC child observation refused: %{public}d", errno);
        terminate_owned();
        return;
    }
    double cpu = ((double)observation.pti_total_user + observation.pti_total_system) / 1e9;
    publish_sample(observation.pti_resident_size, cpu);
}

static bool hash_worker(int fd, const struct stat *before, unsigned char hash[CC_SHA256_DIGEST_LENGTH]) {
    CC_SHA256_CTX digest;
    CC_SHA256_Init(&digest);
    unsigned char bytes[65536];
    uint64_t total = 0;
    for (;;) {
        ssize_t size = read(fd, bytes, sizeof(bytes));
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) return false;
        if (size == 0) break;
        total += (uint64_t)size;
        if (total > (uint64_t)before->st_size) return false;
        CC_SHA256_Update(&digest, bytes, (CC_LONG)size);
    }
    struct stat after;
    bool valid = total == (uint64_t)before->st_size && !fstat(fd, &after) &&
        before->st_size == after.st_size && before->st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
        before->st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
    CC_SHA256_Final(hash, &digest);
    return valid;
}

static bool worker_matches(const char *path, const char *expected) {
    /* The signed service manifest pins exact packaged bytes. App Sandbox
     * refuses Security's additional CodeSigningHelper validation. The host
     * package check verifies signatures, and exec enforces the signed pages. */
    if (strlen(expected) != 64) return false;
    for (size_t n = 0; n < 64; ++n)
        if (!((expected[n] >= '0' && expected[n] <= '9') ||
              (expected[n] >= 'a' && expected[n] <= 'f'))) return false;
    char parent[PATH_MAX];
    if (strlen(path) >= sizeof(parent)) return false;
    if (strlcpy(parent, path, sizeof(parent)) >= sizeof(parent)) return false;
    char *name = strrchr(parent, '/');
    if (!name || name == parent || !name[1]) return false;
    *name++ = '\0';
    int directory = secure_directory(parent, false);
    if (directory < 0) { os_log_error(OS_LOG_DEFAULT, "EVX XPC package directory refused: %{public}d", errno); return false; }
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(directory);
    if (fd < 0) {
        os_log_error(OS_LOG_DEFAULT, "EVX XPC worker read refused: %{public}d", errno);
        return false;
    }
    struct stat before;
    bool valid = !fstat(fd, &before) && S_ISREG(before.st_mode) &&
        (before.st_uid == geteuid() || before.st_uid == 0) && !(before.st_mode & 0022) &&
        before.st_nlink == 1 && (before.st_mode & 0111) && before.st_size > 0 && before.st_size <= 512 * 1024 * 1024;
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    if (valid) valid = hash_worker(fd, &before, hash);

    close(fd);
    if (!valid) return false;
    char actual[65];
    for (size_t n = 0; n < sizeof(hash); ++n) snprintf(actual + n * 2, 3, "%02x", hash[n]);
    return valid && !strcmp(actual, expected);
}

static int pipe_descriptor(xpc_object_t request, const char *name, bool writable) {
    xpc_object_t value = xpc_dictionary_get_value(request, name);
    if (!value || xpc_get_type(value) != XPC_TYPE_FD) return -1;
    int descriptor = xpc_dictionary_dup_fd(request, name);
    struct stat info;
    int flags = descriptor >= 0 ? fcntl(descriptor, F_GETFL) : -1;
    if (flags < 0 || fstat(descriptor, &info) || !S_ISFIFO(info.st_mode) ||
        (flags & O_ACCMODE) != (writable ? O_WRONLY : O_RDONLY)) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    return descriptor;
}

/* Only the file role creates this fixed, signed service-container directory.
 * Its lock serializes cooperative helpers. It is not proof that an orphan or
 * native-compromised worker has died; host quarantine must survive restart. */
static int workspace_lease(void) {
    char copy[PATH_MAX];
    if (strlcpy(copy, server.policy.workspace + 1, sizeof(copy)) >= sizeof(copy)) return -1;
    int current = open("/", O_SEARCH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    char *component = copy;
    while (current >= 0 && component && *component) {
        char *next = strchr(component, '/'); if (next) *next++ = '\0';
        int child = openat(current, component, O_SEARCH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0 && errno == ENOENT) {
            if (mkdirat(current, component, 0700) && errno != EEXIST) { close(current); return -1; }
            child = openat(current, component, O_SEARCH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        close(current); current = child;
        struct stat info;
        if (current < 0) return -1;
        if (fstat(current, &info) || (info.st_uid != 0 && info.st_uid != geteuid()) ||
            ((info.st_mode & 0022) && !(info.st_uid == 0 && (info.st_mode & S_ISVTX))) ||
            (!next && (info.st_uid != geteuid() || (info.st_mode & 0777) != 0700))) {
            close(current); return -1;
        }
        component = next;
    }
    int lease = openat(current, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(current);
    if (lease >= 0 && flock(lease, LOCK_EX | LOCK_NB)) { close(lease); return -1; }
    return lease;
}

static bool spawn_worker(xpc_object_t request) {
    int descriptors[3] = {
        pipe_descriptor(request, "input", false),
        pipe_descriptor(request, "output", true),
        pipe_descriptor(request, "error", true),
    };
    bool valid = descriptors[0] >= 0 && descriptors[1] >= 0 && descriptors[2] >= 0 &&
                 worker_matches(server.policy.worker_path, server.policy.worker_digest);
    uint64_t access = xpc_dictionary_get_uint64(request, "access");
    bool file = !strcmp(server.policy.mode, "apple-file");
    valid = valid && unsigned_field(request, "access") && (file ? (access == 1 || access == 2) : access == 0);
    if (valid && file) {
        server.workspace_lease = workspace_lease(); valid = server.workspace_lease >= 0;
    }
    int error = EINVAL;
    if (valid) {
        posix_spawn_file_actions_t actions;
        posix_spawnattr_t attributes;
        posix_spawn_file_actions_init(&actions);
        posix_spawnattr_init(&attributes);
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP);
        posix_spawnattr_setpgroup(&attributes, 0);
        for (int n = 0; n < 3; ++n) posix_spawn_file_actions_adddup2(&actions, descriptors[n], n);
        if (file) {
            posix_spawn_file_actions_adddup2(&actions, server.workspace_lease, 3);
            posix_spawn_file_actions_addchdir_np(&actions, server.policy.workspace);
        }
        char *mode = file && access == 1 ? "apple-file-read" : server.policy.mode;
        char *arguments[] = {server.policy.worker_path, mode, NULL};
        char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "EVX_APPLE_XPC_CHILD=1", NULL};
        error = posix_spawn(&server.child, server.policy.worker_path, &actions, &attributes, arguments, environment);
        posix_spawnattr_destroy(&attributes);
        posix_spawn_file_actions_destroy(&actions);
    }
    for (int n = 0; n < 3; ++n) if (descriptors[n] >= 0) close(descriptors[n]);
    if (error) os_log_error(OS_LOG_DEFAULT, "EVX XPC worker launch refused: validation=%{public}d spawn=%{public}d", valid, error);
    if (!error) server.started_at = monotonic_ns();
    return error == 0;
}

struct admission { unsigned char challenge[32]; bool hello; bool consumed; dispatch_source_t timer; };
static void admission_free(void *opaque) {
    free(opaque); atomic_fetch_sub(&connections, 1);
    dispatch_async(dispatch_get_main_queue(), ^{ arm_idle_exit(); });
}

static void stop_admission_timer(struct admission *admission) {
    if (admission->timer) {
        dispatch_source_cancel(admission->timer); dispatch_release(admission->timer);
        admission->timer = NULL;
    }
}

static bool accept_authority(xpc_object_t request, xpc_connection_t peer, struct admission *admission) {
    xpc_object_t value = xpc_dictionary_get_value(request, "authority");
    if (!value || xpc_get_type(value) != XPC_TYPE_FD || geteuid() == 0) return false;
    int descriptor = xpc_dictionary_dup_fd(request, "authority");
    if (descriptor < 0) return false;
    struct stat info; char path[PATH_MAX]; unsigned char actual[AUTHORITY_SIZE]; unsigned char expected[AUTHORITY_SIZE];
    int flags = fcntl(descriptor, F_GETFL);
    size_t root = strlen(server.policy.authority_root);
    bool valid = flags >= 0 && (flags & O_ACCMODE) == O_RDONLY && !fstat(descriptor, &info) &&
        S_ISREG(info.st_mode) && info.st_uid == geteuid() && (info.st_mode & 0777) == 0600 &&
        info.st_nlink == 1 && info.st_size == AUTHORITY_SIZE && !fcntl(descriptor, F_GETPATH, path) &&
        strlen(path) == root + 65 && !memcmp(path, server.policy.authority_root, root) && path[root] == '/';
    if (valid) for (size_t n = root + 1; n < root + 65; ++n)
        valid &= (path[n] >= '0' && path[n] <= '9') || (path[n] >= 'a' && path[n] <= 'f');
    if (valid) {
        ssize_t size; do { size = pread(descriptor, actual, sizeof(actual), 0); } while (size < 0 && errno == EINTR);
        authority_record(expected, admission->challenge, xpc_connection_get_pid(peer), server.policy.identifier);
        valid = size == sizeof(actual) && !memcmp(actual, expected, sizeof(actual));
    }
    close(descriptor);
    return valid;
}

static void service_request(xpc_connection_t peer, struct admission *admission, xpc_object_t request) {
    if (xpc_get_type(request) == XPC_TYPE_ERROR) {
        stop_admission_timer(admission);
        if (server.peer == peer) {
            server.disconnected = true;
            if (server.reaped || server.child <= 0) clear_invocation();
            else terminate_owned();
        }
        return;
    }
    bool dictionary = xpc_get_type(request) == XPC_TYPE_DICTIONARY;
    const char *operation = dictionary ? xpc_dictionary_get_string(request, "op") : NULL;
    if (!dictionary || !unsigned_field(request, "v") ||
        xpc_dictionary_get_uint64(request, "v") != 1 || !operation) {
        xpc_connection_cancel(peer);
        return;
    }
    if (!strcmp(operation, "hello") && xpc_dictionary_get_count(request) == 2 && !admission->hello && (!server.peer || server.reaped)) {
        admission->hello = true;
    } else if (!strcmp(operation, "start") && xpc_dictionary_get_count(request) == 7 && admission->hello && !admission->consumed && (!server.peer || server.reaped) &&
        accept_authority(request, peer, admission)) {
        admission->consumed = true;
        stop_admission_timer(admission);
        clear_invocation();
        server.peer = xpc_retain(peer);
        if (!spawn_worker(request)) { xpc_connection_cancel(peer); _Exit(1); }
        server.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(server.timer, DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC, NSEC_PER_MSEC);
        dispatch_source_set_event_handler(server.timer, ^{ poll_child(); });
        dispatch_resume(server.timer);
    } else if (!strcmp(operation, "stop") && xpc_dictionary_get_count(request) == 2 && server.peer == peer) {
        terminate_owned();
    } else {
        xpc_connection_cancel(peer);
    }
}

static void service_peer_serial(xpc_connection_t peer) {
    cancel_idle_exit();
    if (xpc_connection_set_peer_code_signing_requirement(peer, server.policy.client_requirement)) {
        xpc_connection_set_event_handler(peer, ^(xpc_object_t object) { (void)object; });
        xpc_connection_resume(peer);
        xpc_connection_cancel(peer);
        atomic_fetch_sub(&connections, 1); arm_idle_exit();
        return;
    }
    struct admission *admission = calloc(1, sizeof(*admission));
    if (!admission) { atomic_fetch_sub(&connections, 1); _Exit(1); }
    arc4random_buf(admission->challenge, sizeof(admission->challenge));
    xpc_connection_set_context(peer, admission); xpc_connection_set_finalizer_f(peer, admission_free);
    xpc_connection_set_target_queue(peer, dispatch_get_main_queue());
    xpc_connection_set_event_handler(peer, ^(xpc_object_t request) {
        service_request(peer, admission, request);
    });
    xpc_connection_resume(peer);
    xpc_object_t challenge = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(challenge, "v", 1); xpc_dictionary_set_string(challenge, "op", "challenge");
    xpc_dictionary_set_data(challenge, "challenge", admission->challenge, sizeof(admission->challenge));
    xpc_connection_send_message(peer, challenge); xpc_release(challenge);
    xpc_retain(peer);
    admission->timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(admission->timer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
    dispatch_source_set_cancel_handler(admission->timer, ^{ xpc_release(peer); });
    dispatch_source_set_event_handler(admission->timer, ^{
        xpc_connection_cancel(peer); stop_admission_timer(admission);
    });
    dispatch_resume(admission->timer);
}

static bool reserve_connection(void) {
    if (atomic_fetch_add(&connections, 1) < 8) return true;
    atomic_fetch_sub(&connections, 1);
    return false;
}

static void service_peer(xpc_connection_t peer) {
    /* Bound accepted and pending listeners before retaining or queuing them. */
    if (!reserve_connection()) {
        xpc_connection_set_event_handler(peer, ^(xpc_object_t object) { (void)object; });
        xpc_connection_resume(peer); xpc_connection_cancel(peer); return;
    }
    xpc_retain(peer);
    dispatch_async(dispatch_get_main_queue(), ^{
        service_peer_serial(peer);
        xpc_release(peer);
    });
}

static bool bundle_string(CFStringRef key, char *destination, size_t capacity) {
    CFTypeRef value = CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), key);
    return value && CFGetTypeID(value) == CFStringGetTypeID() &&
           CFStringGetCString(value, destination, capacity, kCFStringEncodingUTF8);
}

void evx_xpc_service_main(void) {
    char role[32]; char host_identifier[256];
    if (CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), CFSTR("EVXAuthorityRoot")) ||
        !bundle_string(CFSTR("EVXAuthorityHostIdentifier"), host_identifier, sizeof(host_identifier)) ||
        evx_xpc_authority_directory(host_identifier, server.policy.authority_root, sizeof(server.policy.authority_root)) ||
        !bundle_string(CFSTR("CFBundleIdentifier"), server.policy.identifier, sizeof(server.policy.identifier)) ||
        !bundle_string(CFSTR("EVXClientRequirement"), server.policy.client_requirement, sizeof(server.policy.client_requirement)) ||
        !bundle_string(CFSTR("EVXWorkerSHA256"), server.policy.worker_digest, sizeof(server.policy.worker_digest)) ||
        !bundle_string(CFSTR("EVXRole"), role, sizeof(role))) _Exit(2);
    if (server.policy.authority_root[0] != '/' || !server.policy.authority_root[1] ||
        server.policy.authority_root[strlen(server.policy.authority_root) - 1] == '/' || geteuid() == 0) _Exit(2);
    if (!strcmp(role, "guest")) server.policy.mode = "apple-run";
    else if (!strcmp(role, "compiler")) server.policy.mode = "apple-compile";
    else if (!strcmp(role, "file")) {
        server.policy.mode = "apple-file";
        if (container_directory(server.policy.identifier, "EVXWorkspace", server.policy.workspace, sizeof(server.policy.workspace))) _Exit(2);
    }
    else _Exit(2);
    CFURLRef url = CFBundleCopyExecutableURL(CFBundleGetMainBundle());
    char executable[PATH_MAX];
    if (!url || !CFURLGetFileSystemRepresentation(url, true, (UInt8 *)executable, sizeof(executable))) _Exit(2);
    CFRelease(url);
    char *directory = strrchr(executable, '/');
    if (!directory) _Exit(2);
    *directory = '\0';
    int written = snprintf(server.policy.worker_path, sizeof(server.policy.worker_path), "%s/evx-worker-apple", executable);
    if (written < 0 || (size_t)written >= sizeof(server.policy.worker_path)) _Exit(2);
    xpc_main(service_peer);
}
