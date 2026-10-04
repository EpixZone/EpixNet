/* Unit tests of production protocol and package validation. XPC transport,
 * process creation and signature services are controlled at their OS boundary;
 * dictionaries, descriptors, paths, hashes and policy checks remain real.
 * Signed/native acceptance suites separately verify those OS boundaries. */
#include <assert.h>
#include <Block.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <libproc.h>
#include <setjmp.h>
#include <spawn.h>
#include <sys/wait.h>
#include <xpc/xpc.h>
#include <unistd.h>

static void (^transport_handler)(xpc_object_t);
static bool client_transport;
static bool cancelled_connection;
static bool reject_identity;
static bool fail_signature;
static int spawned;
static int exit_status;
static jmp_buf exit_target;
static CFDictionaryRef signing_fixture;
static CFDictionaryRef bundle_fixture;
static CFURLRef executable_fixture;

static void transport_event(xpc_connection_t peer, void (^handler)(xpc_object_t)) {
    (void)peer;
    if (transport_handler) Block_release(transport_handler);
    transport_handler = Block_copy(handler);
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) { (void)event; });
}
static int transport_identity(xpc_connection_t peer, const char *requirement) {
    (void)peer; assert(requirement); return reject_identity ? -1 : 0;
}
static void transport_resume(xpc_connection_t peer) { xpc_connection_resume(peer); }
static void transport_cancel(xpc_connection_t peer) { xpc_connection_cancel(peer); cancelled_connection = true; }
static pid_t transport_pid(xpc_connection_t peer) { (void)peer; return getpid(); }
static void transport_send(xpc_connection_t peer, xpc_object_t request);
static void transport_main(void (*callback)(xpc_connection_t)) { (void)callback; longjmp(exit_target, 1); }
static void expected_exit(int status) { exit_status = status; longjmp(exit_target, 1); }
static int process_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                         const posix_spawnattr_t *attributes, char *const argv[], char *const env[]) {
    (void)actions; (void)attributes;
    assert(path && argv[0] && argv[1] && !argv[2]);
    assert(env[0]); *pid = getpid(); ++spawned; return 0;
}
static pid_t process_wait(pid_t pid, int *status, int options, struct rusage *usage) {
    (void)options; *status = 0; memset(usage, 0, sizeof(*usage)); return pid;
}
static int process_signal(pid_t pid, int signal) { (void)pid; (void)signal; return 0; }
static int process_observe(int pid, int flavor, uint64_t arg, void *out, int size) {
    (void)pid; (void)flavor; (void)arg; memset(out, 0, (size_t)size); return size;
}
static OSStatus signature_self(SecCSFlags flags, SecCodeRef *out) {
    (void)flags; *out = (SecCodeRef)CFRetain(CFSTR("fixture-self")); return fail_signature ? -1 : 0;
}
static OSStatus signature_static(SecCodeRef code, SecCSFlags flags, SecStaticCodeRef *out) {
    (void)code; (void)flags; *out = (SecStaticCodeRef)CFRetain(CFSTR("fixture-code")); return 0;
}
static OSStatus signature_valid(SecCodeRef code, SecCSFlags flags, SecRequirementRef requirement) {
    (void)code; (void)flags; (void)requirement; return 0;
}
static OSStatus signature_static_valid(SecStaticCodeRef code, SecCSFlags flags, SecRequirementRef requirement) {
    (void)code; (void)flags; (void)requirement; return 0;
}
static OSStatus signature_info(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef *out) {
    (void)code; (void)flags; *out = CFRetain(signing_fixture); return 0;
}
static OSStatus signature_path(SecStaticCodeRef code, SecCSFlags flags, CFURLRef *out) {
    (void)code; (void)flags; *out = CFRetain(executable_fixture); return 0;
}
static OSStatus signature_requirement(CFStringRef expression, SecCSFlags flags, SecRequirementRef *out) {
    (void)flags; *out = (SecRequirementRef)CFRetain(expression); return 0;
}
static CFTypeRef bundle_value(CFBundleRef bundle, CFStringRef key) { (void)bundle; return CFDictionaryGetValue(bundle_fixture, key); }
static CFURLRef bundle_executable(CFBundleRef bundle) { (void)bundle; return CFRetain(executable_fixture); }

#define xpc_connection_set_event_handler transport_event
#define xpc_connection_set_peer_code_signing_requirement transport_identity
#define xpc_connection_resume transport_resume
#define xpc_connection_cancel transport_cancel
#define xpc_connection_send_message transport_send
#define xpc_connection_get_pid transport_pid
#define xpc_main transport_main
#define posix_spawn process_spawn
#define wait4 process_wait
#define kill process_signal
#define killpg process_signal
#define proc_pidinfo process_observe
#define _Exit expected_exit
#define CFBundleGetValueForInfoDictionaryKey bundle_value
#define CFBundleCopyExecutableURL bundle_executable
#define SecCodeCopySelf signature_self
#define SecCodeCopyStaticCode signature_static
#define SecCodeCheckValidity signature_valid
#define SecStaticCodeCheckValidity signature_static_valid
#define SecCodeCopySigningInformation signature_info
#define SecCodeCopyPath signature_path
#define SecRequirementCreateWithString signature_requirement
#include "../../../crates/evx-supervisor/native/apple_xpc.c"
#include "../../../crates/evx-supervisor/native/apple_package.c"

static xpc_object_t sample(uint64_t sequence, uint64_t state) {
    xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(result, "v", 1);
    xpc_dictionary_set_uint64(result, "state", state);
    xpc_dictionary_set_uint64(result, "pid", getpid());
    xpc_dictionary_set_uint64(result, "rss", 1024);
    xpc_dictionary_set_uint64(result, "peak", 2048);
    xpc_dictionary_set_uint64(result, "cpu_ns", 1000);
    xpc_dictionary_set_uint64(result, "sequence", sequence);
    xpc_dictionary_set_int64(result, "exit", 0);
    return result;
}
static xpc_object_t message(const char *op) {
    xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(result, "v", 1);
    xpc_dictionary_set_string(result, "op", op);
    return result;
}
static void transport_send(xpc_connection_t peer, xpc_object_t request) {
    (void)peer;
    if (!client_transport) return;
    const char *op = xpc_dictionary_get_string(request, "op");
    xpc_object_t reply;
    if (!strcmp(op, "hello")) {
        reply = message("challenge"); unsigned char nonce[32] = {42};
        xpc_dictionary_set_data(reply, "challenge", nonce, sizeof(nonce));
    } else if (!strcmp(op, "start")) { reply = sample(1, 1); }
    else { assert(!strcmp(op, "stop")); return; }
    transport_handler(reply); xpc_release(reply);
}
static void digest_file(const char *path, char digest[65]) {
    int fd = open(path, O_RDONLY); assert(fd >= 0);
    struct stat info; assert(!fstat(fd, &info)); unsigned char hash[32];
    assert(hash_worker(fd, &info, hash)); close(fd);
    for (unsigned i = 0; i < 32; ++i) snprintf(digest + i * 2, 3, "%02x", hash[i]);
}
static void client_tests(const char *root) {
    client_transport = true;
    struct client *client = evx_xpc_open("org.epix.fixture", "identifier fixture", root, 0, 0, 1, 2);
    assert(client && client->sample.state == 1);
    struct evx_xpc_observation snapshot;
    evx_xpc_snapshot(client, &snapshot); assert(snapshot.pid == getpid());
    evx_xpc_stop(client); evx_xpc_release(client);
    reject_identity = true;
    assert(!evx_xpc_open("org.epix.fixture", "identifier fixture", root, 0, 0, 1, 2));
    reject_identity = false;
    assert(!evx_xpc_open("org.epix.fixture", "identifier fixture", "/missing-evx-authority", 0, 0, 1, 2));
    struct client invalid = {0}; uint64_t sequence = 0;
    xpc_object_t malformed = message("challenge");
    client_event(&invalid, &sequence, malformed); assert(invalid.sample.state == -1);
    xpc_release(malformed);
    invalid = (struct client){0}; malformed = message("challenge");
    xpc_dictionary_set_data(malformed, "challenge", "x", 1);
    client_event(&invalid, &sequence, malformed); assert(invalid.sample.state == -1);
    xpc_release(malformed);
    client_transport = false;
}
static void server_tests(const char *root, const char *worker) {
    assert(strlcpy(server.policy.authority_root, root, sizeof(server.policy.authority_root)) < sizeof(server.policy.authority_root));
    strlcpy(server.policy.identifier, "org.epix.fixture", sizeof(server.policy.identifier));
    strlcpy(server.policy.worker_path, worker, sizeof(server.policy.worker_path));
    server.policy.mode = "apple-run";
    digest_file(worker, server.policy.worker_digest);
    xpc_connection_t peer = xpc_connection_create("org.epix.fixture", NULL);
    atomic_fetch_add(&connections, 1);
    service_peer_serial(peer);
    struct admission *admission = xpc_connection_get_context(peer);
    xpc_object_t request = message("hello"); service_request(peer, admission, request); xpc_release(request);
    assert(admission->hello);
    int directory = secure_directory(root, true); assert(directory >= 0);
    char filename[65]; int authority = create_authority(directory, admission->challenge, server.policy.identifier, filename);
    assert(authority >= 0);
    int pipes[3][2]; for (int i = 0; i < 3; ++i) assert(!pipe(pipes[i]));
    request = message("start");
    xpc_dictionary_set_uint64(request, "access", 0);
    xpc_dictionary_set_fd(request, "authority", authority);
    xpc_dictionary_set_fd(request, "input", pipes[0][0]);
    xpc_dictionary_set_fd(request, "output", pipes[1][1]);
    xpc_dictionary_set_fd(request, "error", pipes[2][1]);
    assert(accept_authority(request, peer, admission));
    admission->challenge[0] ^= 1; assert(!accept_authority(request, peer, admission)); admission->challenge[0] ^= 1;
    assert(!fchmod(authority, 0644)); assert(!accept_authority(request, peer, admission)); assert(!fchmod(authority, 0600));
    assert(accept_authority(request, peer, admission));
    assert(admission->hello && !admission->consumed);
    assert(!server.peer || server.reaped);
    service_request(peer, admission, request);
    assert(spawned == 1 && admission->consumed);
    assert(!linkat(directory, filename, directory, "linked", 0)); assert(!accept_authority(request, peer, admission)); unlinkat(directory, "linked", 0);
    xpc_object_t stop = message("stop"); service_request(peer, admission, stop); xpc_release(stop);
    assert(server.stopping); poll_child(); assert(server.reaped && server.exit_code == 0);
    service_request(peer, admission, request); assert(cancelled_connection);
    service_request(peer, admission, (xpc_object_t)XPC_ERROR_CONNECTION_INVALID); assert(server.child == 0);
    xpc_release(request);
    request = xpc_dictionary_create(NULL, NULL, 0); service_request(peer, admission, request); xpc_release(request);
    close(authority); unlinkat(directory, filename, 0); close(directory);
    for (int i = 0; i < 3; ++i) { close(pipes[i][0]); close(pipes[i][1]); }
    // Private workspace leases reject a second owner and preserve directory mode.
    snprintf(server.policy.workspace, sizeof(server.policy.workspace), "%s/workspace", root);
    int lease = workspace_lease(); assert(lease >= 0); assert(workspace_lease() < 0); close(lease);
    rmdir(server.policy.workspace); cancel_idle_exit();
    xpc_release(peer);
    peer = xpc_connection_create("org.epix.fixture", NULL);
    reject_identity = true; atomic_fetch_add(&connections, 1); service_peer_serial(peer); reject_identity = false;
    xpc_release(peer);
}
static CFMutableDictionaryRef dictionary(void) {
    return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}
static void package_tests(const char *worker) {
    CFMutableDictionaryRef plist = dictionary(); CFMutableDictionaryRef signing = dictionary();
    const char *team = "ABCDEFGHIJ"; struct evx_package_policy policy;
    CFDictionarySetValue(plist, CFSTR("EVXExecutionProfile"), CFSTR("apple-xpc-fixture"));
    CFDictionarySetValue(plist, CFSTR("CFBundleIdentifier"), CFSTR("org.epix.fixture"));
    CFDictionarySetValue(plist, CFSTR("EVXServiceManifest"), CFSTR("evx-services.json"));
    CFDictionarySetValue(plist, CFSTR("EVXServiceManifestSHA256"), CFSTR("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CFDictionarySetValue(plist, CFSTR("EVXReleaseTeamIdentifier"), CFSTR("ABCDEFGHIJ"));
    CFDictionarySetValue(signing, kSecCodeInfoPList, plist);
    CFDictionarySetValue(signing, kSecCodeInfoIdentifier, CFSTR("org.epix.fixture"));
    CFDictionarySetValue(signing, kSecCodeInfoTeamIdentifier, CFSTR("ABCDEFGHIJ"));
    int flags = kSecCodeSignatureAdhoc | kSecCodeSignatureRuntime;
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &flags);
    CFDictionarySetValue(signing, kSecCodeInfoFlags, number); CFRelease(number);
    signing_fixture = signing;
    executable_fixture = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)worker, strlen(worker), false);
    assert(!evx_apple_package_policy(true, "", &policy));
    assert(!strcmp(policy.identifier, "org.epix.fixture"));
    CFDictionarySetValue(plist, CFSTR("EVXExecutionProfile"), CFSTR("apple-xpc-developer-id"));
    assert(!evx_apple_package_policy(false, team, &policy));
    assert(evx_apple_package_policy(false, "BAD", &policy));
    assert(evx_apple_package_policy(false, "abcdefghij", &policy));
    assert(evx_apple_package_policy(false, "KLMNOPQRST", &policy));
    CFDictionarySetValue(plist, CFSTR("EVXServiceManifest"), CFSTR("../evx-services.json"));
    assert(evx_apple_package_policy(false, team, &policy));
    fail_signature = true; assert(evx_apple_package_policy(false, team, &policy)); fail_signature = false;
    assert(evx_apple_package_policy(false, team, NULL));
    // The service accepts only signed fixed role metadata, never an authority override.
    bundle_fixture = plist;
    CFDictionarySetValue(plist, CFSTR("EVXAuthorityHostIdentifier"), CFSTR("org.epix.fixture"));
    CFDictionarySetValue(plist, CFSTR("EVXClientRequirement"), CFSTR("identifier fixture"));
    CFDictionarySetValue(plist, CFSTR("EVXWorkerSHA256"), CFSTR("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    for (unsigned i = 0; i < 3; ++i) {
        CFStringRef roles[] = {CFSTR("guest"), CFSTR("compiler"), CFSTR("file")};
        CFDictionarySetValue(plist, CFSTR("EVXRole"), roles[i]); exit_status = 0;
        if (!setjmp(exit_target)) evx_xpc_service_main(); assert(exit_status == 0);
    }
    CFDictionarySetValue(plist, CFSTR("EVXRole"), CFSTR("invalid"));
    if (!setjmp(exit_target)) evx_xpc_service_main(); assert(exit_status == 2);
    CFDictionarySetValue(plist, CFSTR("EVXAuthorityRoot"), CFSTR("/tmp"));
    if (!setjmp(exit_target)) evx_xpc_service_main(); assert(exit_status == 2);
    CFRelease(executable_fixture); CFRelease(signing); CFRelease(plist);
}
int main(void) {
    char root[] = "/private/tmp/evx-boundaries-XXXXXX"; assert(mkdtemp(root));
    char worker[PATH_MAX]; snprintf(worker, sizeof(worker), "%s/worker", root);
    int fd = open(worker, O_WRONLY | O_CREAT | O_EXCL, 0700); assert(fd >= 0);
    assert(write(fd, "fixture", 7) == 7); close(fd);
    client_tests(root); server_tests(root, worker); package_tests(worker);
    unlink(worker); rmdir(root);
    if (transport_handler) Block_release(transport_handler);
    puts("protocol and package boundaries passed"); return 0;
}
