import assert from "node:assert/strict";
import { test } from "node:test";
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
  t.after(() => { delete globalThis.ChromeUtils; });
  configureXiteAddresses();

  const address = "epix1" + "q".repeat(38);
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
