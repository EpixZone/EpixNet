// Runs in a node-provided, opaque sandbox. Only this document owns the
// decoding canvas. An untrusted xite cannot choose the pixels stored for a URL.
(function () {
  "use strict";
  var MAX_BYTES = 5 * 1024 * 1024;
  var channel = new MessageChannel();
  var token = location.hash.slice(1);
  if (parent === window || !/^[a-f0-9]{32}$/.test(token)) return;

  function rasterType(bytes) {
    var str = function (i, n) { return String.fromCharCode.apply(null, bytes.subarray(i, i + n)); };
    if (str(0, 8) === "\x89PNG\r\n\x1a\n") return "image/png";
    if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return "image/jpeg";
    if (str(0, 6) === "GIF87a" || str(0, 6) === "GIF89a") return "image/gif";
    if (str(0, 4) === "RIFF" && str(8, 4) === "WEBP") return "image/webp";
    if (str(4, 4) === "ftyp" && /^(avif|avis)$/.test(str(8, 4))) return "image/avif";
    return null;
  }

  async function download(url, signal) {
    var response = await fetch(url, {mode: "cors", credentials: "omit", redirect: "error",
      cache: "no-store", referrerPolicy: "no-referrer", signal: signal});
    var policy = response.headers.get("cache-control") || "";
    if (!response.ok || response.type !== "cors" || /(?:^|,)\s*no-store\b/i.test(policy) ||
        !response.body || Number(response.headers.get("content-length")) > MAX_BYTES) throw Error("Image unavailable");
    var reader = response.body.getReader(), length = 0, parts = [];
    try {
      while (true) {
        var part = await reader.read();
        if (part.done) break;
        length += part.value.byteLength;
        if (length > MAX_BYTES) { await reader.cancel(); throw Error("Image too large"); }
        parts.push(part.value);
      }
    } finally { reader.releaseLock(); }
    var bytes = new Uint8Array(length), offset = 0;
    for (var chunk of parts) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    var type = rasterType(bytes);
    if (!type) throw Error("Unsupported image");
    return new Blob([bytes], {type: type});
  }

  async function pixels(source, size, signal) {
    var url = new URL(source);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password ||
        !Number.isInteger(size) || size < 1 || size > 128) throw Error("Invalid image");
    if (/(^|\.)gravatar\.com$/i.test(url.hostname) &&
        /^\/avatar\/(?:[a-f\d]{32}|[a-f\d]{64})(?:\.jpg)?\/?$/i.test(url.pathname)) {
      url.searchParams.delete("size");
      url.searchParams.set("s", String(size));
    }
    var local = URL.createObjectURL(await download(url.href, signal));
    try {
      var image = new Image();
      await new Promise(function (resolve, reject) {
        image.onload = resolve; image.onerror = reject; image.src = local;
      });
      var w = image.naturalWidth, h = image.naturalHeight, side = Math.min(w, h);
      if (!side || w * h > 32 * 1024 * 1024) throw Error("Image too large");
      var sample = document.createElement("canvas");
      sample.width = sample.height = Math.min(512, side);
      var ctx = sample.getContext("2d");
      ctx.imageSmoothingQuality = "high";
      ctx.drawImage(image, Math.floor((w - side) / 2), Math.floor((h - side) / 2), side, side, 0, 0, sample.width, sample.height);
      if (sample.width > size) {
        var result = document.createElement("canvas");
        result.width = result.height = size;
        await pica({features: ["js"]}).resize(sample, result, {filter: "lanczos3"});
        sample = result;
      }
      return sample.getContext("2d").getImageData(0, 0, sample.width, sample.height);
    } finally { URL.revokeObjectURL(local); }
  }

  channel.port1.onmessage = async function (event) {
    channel.port1.onmessage = null; // one source per frame
    var abort = new AbortController();
    var timer = setTimeout(function () { abort.abort(); }, 8500);
    try {
      var image = await pixels(event.data.url, event.data.size, abort.signal);
      channel.port1.postMessage({width: image.width, rgba: image.data.buffer}, [image.data.buffer]);
    } catch (_) { channel.port1.postMessage(null); }
    finally { clearTimeout(timer); channel.port1.close(); }
  };
  // Give the parent a private port. Never send jobs or pixel data through a
  // WindowProxy, which outlives its document when a frame navigates.
  parent.postMessage({epixAvatarProcessor: token}, "*", [channel.port2]);
})();
