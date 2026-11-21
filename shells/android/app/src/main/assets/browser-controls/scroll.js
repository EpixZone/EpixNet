/* This builtin receives one visibility flag. It never forwards page messages to Android. */
(() => {
    "use strict";
    if (window !== window.top) return;
    const attribute = "data-epix-native-chrome-hidden";
    let port = null;
    const clear = () => document.documentElement.removeAttribute(attribute);
    const connect = () => {
        if (port) return;
        const next = browser.runtime.connectNative("epix_browser_controls");
        port = next;
        next.onMessage.addListener(message => {
            if (port !== next || typeof message?.hidden !== "boolean") return;
            if (message.hidden) document.documentElement.setAttribute(attribute, "true");
            else clear();
        });
        next.onDisconnect.addListener(() => {
            if (port !== next) return;
            port = null;
            clear();
        });
    };
    window.addEventListener("pagehide", () => {
        const previous = port;
        port = null;
        clear();
        previous?.disconnect();
    });
    window.addEventListener("pageshow", connect);
    connect();
})();
