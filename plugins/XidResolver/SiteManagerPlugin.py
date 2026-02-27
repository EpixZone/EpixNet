import logging
import re
import json
import time

from Config import config
from Plugin import PluginManager
from util.Flag import flag

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
except ImportError:
    from urllib2 import urlopen, Request, URLError

allow_reload = False

log = logging.getLogger("XidResolverPlugin")

# Cache: keyed by "name.tld", stores {"address": site_address, "timestamp": float}
_resolve_cache = {}
# Reverse cache: keyed by site_address, stores "name.tld"
_reverse_cache = {}
RESOLVE_CACHE_TTL = 30

# EPIXNET DNS record type (private-use range per RFC 6895)
EPIXNET_RECORD_TYPE = 65280


def _fetch_json(url, timeout=10):
    try:
        req = Request(url)
        req.add_header("Accept", "application/json")
        resp = urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode("utf-8"))
    except (URLError, ValueError, IOError) as e:
        log.debug("xID RPC fetch failed for %s: %s" % (url, e))
        return None


def _get_rpc_url():
    return getattr(config, "chain_rpc_url", "https://api.epix.zone").rstrip("/")


def _resolve_epix_name(tld, name):
    """Query the xID chain for the EPIXNET DNS record of a name.

    Returns the EpixNet site address string, or None.
    """
    cache_key = "%s.%s" % (name, tld)
    now = time.time()
    cached = _resolve_cache.get(cache_key)
    if cached and (now - cached["timestamp"]) < RESOLVE_CACHE_TTL:
        return cached["address"]

    rpc_url = _get_rpc_url()

    # First check name exists
    data = _fetch_json("%s/xid/v1/resolve/%s/%s" % (rpc_url, tld, name))
    if not data or not data.get("record"):
        _resolve_cache[cache_key] = {"address": None, "timestamp": now}
        return None

    # Get DNS records and look for EPIXNET type (65280)
    dns_data = _fetch_json("%s/xid/v1/dns/%s/%s" % (rpc_url, tld, name))
    site_address = None
    if dns_data and dns_data.get("records"):
        for record in dns_data["records"]:
            if int(record.get("record_type", 0)) == EPIXNET_RECORD_TYPE:
                site_address = record.get("value", "").strip()
                break

    _resolve_cache[cache_key] = {"address": site_address, "timestamp": now}
    if site_address:
        _reverse_cache[site_address] = cache_key

    if site_address:
        log.debug("Resolved %s to %s" % (cache_key, site_address))
    else:
        log.debug("Name %s exists but has no EPIXNET record" % cache_key)

    return site_address


@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):

    def isEpixDomain(self, address):
        return re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]+$", address) and address.endswith(".epix")

    def resolveEpixDomain(self, domain):
        domain = domain.lower()
        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return None
        name, tld = parts
        return _resolve_epix_name(tld, name)

    def resolveDomain(self, domain):
        return self.resolveEpixDomain(domain) or super(SiteManagerPlugin, self).resolveDomain(domain)

    def isDomain(self, address):
        return self.isEpixDomain(address) or super(SiteManagerPlugin, self).isDomain(address)

    def load(self, *args, **kwargs):
        super(SiteManagerPlugin, self).load(*args, **kwargs)
        # Populate reverse cache from content.json "domain" fields
        count = 0
        for address, site in self.sites.items():
            content = site.content_manager.contents.get("content.json")
            if content and content.get("domain"):
                domain = content["domain"].lower()
                if domain.endswith(".epix"):
                    _reverse_cache[address] = domain
                    count += 1
        if count:
            log.debug("Loaded %d domain reverse mappings from sites" % count)

    def reverseLookupDomain(self, address):
        """Return the .epix domain for a site address, or None."""
        return _reverse_cache.get(address)


def clearXidCaches():
    """Clear all xID-related caches (resolver + chain attestation + SiteManager domain cache)."""
    count = len(_resolve_cache)
    _resolve_cache.clear()
    _reverse_cache.clear()

    # Clear ChainAttestation caches if loaded
    try:
        from plugins.ChainAttestation import ChainAttestationPlugin
        ChainAttestationPlugin._name_cache.clear()
        ChainAttestationPlugin._attestation_cache.clear()
        ChainAttestationPlugin._digest_cache.update({"digest": None, "height": 0, "timestamp": 0})
    except Exception:
        pass

    # Clear SiteManager's @Cached domain resolution caches
    from Site import SiteManager as SM
    sm = SM.site_manager
    if sm:
        for method_name in ("isDomainCached", "resolveDomainCached"):
            method = getattr(sm, method_name, None)
            if method and hasattr(method, "emptyCache"):
                method.emptyCache()

    log.info("xID caches cleared (%d resolver entries)" % count)
    return count


@PluginManager.registerTo("UiWebsocket")
class UiWebsocketPlugin(object):
    @flag.admin
    def actionXidClearCache(self, to):
        count = clearXidCaches()
        self.response(to, {"cleared": count})
