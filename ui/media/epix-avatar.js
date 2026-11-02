// Vendored by xites. EpixNet owns the shared thumbnails; the original profile
// URL stays usable in standalone pages and on nodes without this command.
(function (root) {
  "use strict";
  var bindings = new WeakMap();
  var requests = new WeakMap();
  var capabilities = new WeakMap();

  function eligible(source, size) {
    if (typeof source !== "string" || source.length > 2048 || !Number.isInteger(size) || size < 1 || size > 128) return false;
    try {
      var url = new URL(source);
      return /^https?:$/.test(url.protocol) && !url.username && !url.password;
    } catch {
      // Relative and legacy image paths use the existing display path.
      return false;
    }
  }

  function displayUrl(source, size) {
    if (!eligible(source, size)) return source;
    var url = new URL(source);
    if (!/(^|\.)gravatar\.com$/i.test(url.hostname) ||
        !/^\/avatar\/(?:[a-f\d]{32}|[a-f\d]{64})(?:\.jpg)?\/?$/i.test(url.pathname)) return source;
    url.searchParams.delete("size");
    url.searchParams.set("s", String(size));
    return url.href;
  }

  function wrapperOrigin(info) {
    if (info?.version !== 1 || typeof info.origin !== "string") return null;
    try {
      var url = new URL(info.origin);
      return /^https?:$/.test(url.protocol) && info.origin === url.origin ? url.origin : null;
    } catch {
      // Invalid or missing capability metadata selects ordinary image display.
      return null;
    }
  }

  function wrapperFor(frame) {
    if (capabilities.has(frame)) return capabilities.get(frame);
    var check = new Promise(function (resolve) {
      var timer = setTimeout(function () { capabilities.delete(frame); resolve(null); }, 900);
      function reply(info) { clearTimeout(timer); resolve(wrapperOrigin(info)); }
      try {
        var result = frame.cmd("wrapperAvatarThumbnailVersion", {}, reply);
        if (result && typeof result.then === "function") result.then(reply, function () { reply(null); });
      } catch {
        // A disconnected or legacy bridge may throw before invoking its callback.
        reply(null);
      }
    });
    capabilities.set(frame, check);
    return check;
  }

  function get(source, size, frame) {
    frame = frame || root.Page;
    if (root.parent === root || !eligible(source, size) || !frame || typeof frame.cmd !== "function") return Promise.resolve(null);
    var pending = requests.get(frame);
    if (!pending) { pending = new Map(); requests.set(frame, pending); }
    var key = JSON.stringify([source, size]);
    if (pending.has(key)) return pending.get(key);
    var request = wrapperFor(frame).then(function (origin) {
      if (!origin || typeof MessageChannel !== "function") return null;
      return new Promise(function (resolve) {
        // WindowProxy survives navigation. A transferred port delivers the
        // image only to the document that actually asked for it.
        var channel = new MessageChannel();
        function finish(png) {
          clearTimeout(timer);
          channel.port1.close();
          resolve(typeof png === "string" && png.length <= 100000 &&
            /^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(png) ? png : null);
        }
        var timer = setTimeout(function () { finish(null); }, 16000);
        channel.port1.onmessage = function (event) { finish(event.data?.thumbnail); };
        try {
          root.parent.postMessage({cmd: "wrapperGetAvatarThumbnail", id: 0,
            wrapper_nonce: frame.wrapper_nonce, params: {url: source, size: size}}, origin, [channel.port2]);
        } catch (_) { channel.port2.close(); finish(null); }
      });
    }).finally(function () { pending.delete(key); });
    pending.set(key, request);
    return request;
  }

  function paint(element, source, background) {
    if (background) {
      // Serialize a single CSS string even for legacy relative URLs.
      var escaped = source.replace(/["\\\x00-\x1f\x7f]/g, function (ch) {
        return "\\" + ch.codePointAt(0).toString(16) + " ";
      });
      element.style.backgroundImage = source ? 'url("' + escaped + '")' : "";
    } else if (source) {
      element.setAttribute("referrerpolicy", "no-referrer");
      element.setAttribute("src", source);
    } else {
      element.removeAttribute("src");
    }
  }

  function bind(element, source, size, options) {
    source = typeof source === "string" ? source : "";
    var background = !!options?.background;
    var previous = bindings.get(element);
    if (previous && previous.source === source && previous.size === size && previous.background === background) return previous.done;
    var current = {source: source, size: size, background: background};
    bindings.set(element, current);
    if (previous || !source) paint(element, "", previous ? previous.background : background);
    if (!source) { current.done = Promise.resolve(); return current.done; }
    current.done = get(source, size, options?.frame).then(function (thumbnail) {
      if (bindings.get(element) === current) paint(element, thumbnail || displayUrl(source, size), background);
    });
    return current.done;
  }

  root.EpixAvatar = {get: get, bind: bind};
})(window);
