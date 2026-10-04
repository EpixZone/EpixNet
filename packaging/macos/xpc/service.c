/* The signed fixture deliberately echoes bytes without compiling or executing
 * them. Never package this listener as the production EVX worker. */
#include "protocol.h"
#include <dispatch/dispatch.h>
#include <stdlib.h>

#ifdef EVX_FIXTURE_INHERITED_SANDBOX
#include "sandbox-parent.h"
#endif

#ifndef EVX_CLIENT_REQUIREMENT
#error EVX_CLIENT_REQUIREMENT must pin the fixture client
#endif
#ifndef EVX_SERVICE_ROLE
#error EVX_SERVICE_ROLE must select exactly one role
#endif

static void accept_peer(xpc_connection_t peer) {
    /* XPC validates the signed peer for every incoming message. Install the
     * requirement before resume, without inspecting caller-supplied fields. */
    if (xpc_connection_set_peer_code_signing_requirement(
            peer, EVX_CLIENT_REQUIREMENT) != 0) {
        xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
            (void)event;
        });
        xpc_connection_resume(peer);
        xpc_connection_cancel(peer);
        return;
    }
    dispatch_queue_t queue = dispatch_queue_create("org.epixnet.evx.fixture.peer", NULL);
    xpc_connection_set_target_queue(peer, queue);
    dispatch_release(queue);
    __block uint64_t sequence = 1;
    __block size_t total = 0;
    __block bool denied = false;
    xpc_connection_set_event_handler(peer, ^(xpc_object_t frame) {
        if (xpc_get_type(frame) == XPC_TYPE_ERROR) {
#ifdef EVX_FIXTURE_SURVIVE_DISCONNECT
            return;
#else
            _Exit(0);
#endif
        }
        size_t length = 0;
#ifdef EVX_FIXTURE_SCOPED_FD
        int scoped_fd = xpc_dictionary_dup_fd(frame, "scoped");
        xpc_object_t checked = xpc_copy(frame);
        xpc_dictionary_set_value(checked, "scoped", NULL);
#else
        xpc_object_t checked = frame;
#endif
        bool accepted = !denied && sequence <= EVX_XPC_FRAME_COUNT &&
            evx_xpc_frame(checked, EVX_SERVICE_ROLE, sequence, &length) &&
            length <= EVX_XPC_TOTAL_LIMIT - total;
#ifdef EVX_FIXTURE_SCOPED_FD
        xpc_release(checked);
        accepted = accepted && scoped_fd >= 0;
#endif
        xpc_object_t reply = xpc_dictionary_create_reply(frame);
        if (!reply) {
            denied = true;
            return;
        }
        if (accepted) {
            total += length;
#ifdef EVX_FIXTURE_INHERITED_SANDBOX
            char output[128];
            if (!sandbox_child_probe(output, sizeof(output),
#ifdef EVX_FIXTURE_SCOPED_FD
                                     scoped_fd
#else
                                     -1
#endif
                                     )) {
                xpc_dictionary_set_string(reply, "error", "child fixture failed");
            } else {
                evx_xpc_put_frame(reply, EVX_SERVICE_ROLE, sequence++, output, strlen(output));
            }
#else
            size_t ignored = 0;
            const void *body = xpc_dictionary_get_data(frame, "body", &ignored);
            evx_xpc_put_frame(reply, EVX_SERVICE_ROLE, sequence++, body, length);
#endif
        } else {
            denied = true;
            xpc_dictionary_set_string(reply, "error", "transport denied");
        }
        xpc_connection_send_message(peer, reply);
        xpc_release(reply);
#ifdef EVX_FIXTURE_SCOPED_FD
        close(scoped_fd);
#endif
    });
    xpc_connection_resume(peer);
}

int main(void) {
    /* Not a lifecycle implementation: launchd may reuse this process. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        _Exit(0);
    });
    xpc_main(accept_peer);
}
