#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>

/* Run inside the actual Firefox executable so AppArmor applies its normal
 * executable-path rule. Exit before Firefox starts or opens a profile.
 * These calls must be separate: Ubuntu can permit creating a user namespace
 * while denying the capabilities needed inside it. */
__attribute__((constructor)) static void check_namespace(void) {
    _exit(unshare(CLONE_NEWUSER) == 0 && unshare(CLONE_NEWPID) == 0 ? 42 : 43);
}
