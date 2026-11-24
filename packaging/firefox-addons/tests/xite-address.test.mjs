import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { configureXiteAddresses } from "../xite-address.sys.mjs";

test("only an unrestricted address-bar EPIX address gets a local navigation result", (t) => {
  class UrlbarResult { constructor(options) { Object.assign(this, options); } }
  const original = t.mock.fn(() => "Firefox result");
  const provider = { matchUnknownUrl: original };
  const modules = {
    "moz-src:///browser/components/urlbar/UrlbarProviderHeuristicFallback.sys.mjs": {
      UrlbarProviderHeuristicFallback: provider,
    },
    "moz-src:///browser/components/urlbar/UrlbarUtils.sys.mjs": {
      UrlbarUtils: { RESULT_TYPE: { URL: 1 }, RESULT_SOURCE: { OTHER_LOCAL: 2 } },
    },
    "chrome://browser/content/urlbar/UrlbarResult.mjs": { UrlbarResult },
  };
  globalThis.ChromeUtils = { importESModule: (url) => modules[url] };
  globalThis.Services = { scriptloader: { loadSubScript(url, scope) {
    assert.equal(url, "resource://epix-addon-installer/epix-address.js");
    const script = new URL("../../../crates/epix-browser/assets/epix-address.js", import.meta.url);
    runInNewContext(readFileSync(script, "utf8"), scope, { filename: script.href });
  } } };
  t.after(() => { delete globalThis.ChromeUtils; delete globalThis.Services; });
  configureXiteAddresses();

  const address = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
  const context = { searchString: address, sapName: "urlbar" };
  const url = "https://" + address + ".epix/";
  for (const value of [address, address.toUpperCase()]) {
    const result = provider.matchUnknownUrl({ ...context, searchString: value });
    assert.ok(result instanceof UrlbarResult);
    assert.deepEqual(result.payload, { title: url, url });
    assert.equal(result.heuristic, true);
  }
  assert.equal(original.mock.callCount(), 0);

  const cases = [
    { searchString: "ordinary query" }, { searchString: "? " + address },
    { searchString: "search " + address }, { searchString: address + " nearby" },
    { searchString: "https://example.test/?q=" + address }, { searchString: address + ".epix" },
    { searchString: "epix1bookclubmembership2026" }, { searchString: address.slice(0,-1) + "q" },
    { searchString: address.toUpperCase().replace("K", "K") },
    { searchString: address.replace("epix", "Epix") }, { searchString: "epix1" + "i".repeat(38) },
    { searchString: "epix1" + "q".repeat(38) }, { searchString: null },
    { searchString: "epix1q" }, { searchString: "epix1" + "q".repeat(81) },
    { sapName: "searchbar" }, { sapName: "urlbar-handoff" },
    { searchMode: { engineName: "Search" } }, { restrictSource: 0 }, { restrictToken: { value: "?" } },
  ];
  for (const change of cases) {
    const query = { ...context, ...change };
    assert.equal(provider.matchUnknownUrl(query), "Firefox result");
    const last = original.mock.calls.at(-1);
    assert.equal(last.this, provider);
    assert.equal(last.arguments[0], query);
  }
});
