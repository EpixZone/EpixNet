// Firefox uses this heuristic for both suggestions and immediate Enter. Its
// fast path only calls built-in providers. Keep Firefox's alternative search
// action and every other provider, restriction and input source intact.
export function configureXiteAddresses() {
  const { UrlbarProviderHeuristicFallback } = ChromeUtils.importESModule(
    "moz-src:///browser/components/urlbar/UrlbarProviderHeuristicFallback.sys.mjs"
  );
  const { UrlbarUtils } = ChromeUtils.importESModule(
    "moz-src:///browser/components/urlbar/UrlbarUtils.sys.mjs"
  );
  const { UrlbarResult } = ChromeUtils.importESModule(
    "chrome://browser/content/urlbar/UrlbarResult.mjs"
  );
  const validator = {};
  Services.scriptloader.loadSubScript("resource://epix-addon-installer/epix-address.js", validator);
  const original = UrlbarProviderHeuristicFallback.matchUnknownUrl;
  if (typeof original !== "function") {
    throw new Error("Firefox address bar heuristic is unavailable");
  }
  UrlbarProviderHeuristicFallback.matchUnknownUrl = function (context) {
    const address = context.searchString;
    if (context.sapName === "urlbar" && !context.searchMode &&
        context.restrictSource == null && !context.restrictToken &&
        validator.isEpixXiteAddress(address)) {
      const url = "https://" + address.toLowerCase() + ".epix/";
      return new UrlbarResult({
        type: UrlbarUtils.RESULT_TYPE.URL,
        source: UrlbarUtils.RESULT_SOURCE.OTHER_LOCAL,
        heuristic: true,
        payload: { title: url, url },
      });
    }
    return original.call(this, context);
  };
}
