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

# Cache: keyed by "name.tld", stores {"address": site_address, "timestamp": float, "attested": bool}
_resolve_cache = {}
# Reverse cache: keyed by site_address, stores "name.tld" (only from attested resolutions)
_reverse_cache = {}
RESOLVE_CACHE_TTL = 30
# Attested resolutions are trusted longer since they're backed by 2/3 validator consensus
ATTESTED_CACHE_TTL = 300

# EPIXNET DNS record type (private-use range per RFC 6895)
EPIXNET_RECORD_TYPE = 65280

# Expected chain ID prefix — must start with "epix_" to be the real Epix chain.
EXPECTED_CHAIN_ID_PREFIX = "epix_"

# Chain ID verification state
_chain_id_verified = None
_chain_id_cache = {"chain_id": None, "timestamp": 0}
CHAIN_ID_CACHE_TTL = 300

# Attested snapshot cache: stores all EPIXNET domain->address mappings from a finalized snapshot
# {"digest": str, "mappings": {domain: address}, "timestamp": float}
_attested_snapshot = {"digest": None, "mappings": {}, "timestamp": 0}
SNAPSHOT_CACHE_TTL = 60


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


def _verify_chain_id():
    """Verify the RPC endpoint is serving the real Epix chain."""
    global _chain_id_verified
    now = time.time()
    if (now - _chain_id_cache["timestamp"]) < CHAIN_ID_CACHE_TTL and _chain_id_verified is not None:
        return _chain_id_verified

    rpc_url = _get_rpc_url()
    data = _fetch_json("%s/cosmos/base/tendermint/v1beta1/node_info" % rpc_url)
    chain_id = None
    if data and data.get("default_node_info"):
        chain_id = data["default_node_info"].get("network", "")

    _chain_id_cache["chain_id"] = chain_id
    _chain_id_cache["timestamp"] = now

    if chain_id and chain_id.startswith(EXPECTED_CHAIN_ID_PREFIX):
        _chain_id_verified = True
        log.debug("Chain ID verified: %s" % chain_id)
    else:
        _chain_id_verified = False
        log.warning("Chain ID verification failed: got '%s', expected prefix '%s'" % (chain_id, EXPECTED_CHAIN_ID_PREFIX))

    return _chain_id_verified


def _fetch_attested_snapshot():
    """Fetch the state snapshot and verify it's attested by 2/3+ validators.

    Returns the snapshot mappings dict {domain: address} if finalized, or None.
    Uses the ChainAttestation plugin's functions when available.

    The snapshot is fetched first, then its digest is verified against attestations.
    This avoids race conditions where the digest changes between separate RPC calls.
    Retries up to 3 times if the digest changes mid-pagination.
    """
    now = time.time()
    if _attested_snapshot["digest"] and (now - _attested_snapshot["timestamp"]) < SNAPSHOT_CACHE_TTL:
        return _attested_snapshot["mappings"]

    rpc_url = _get_rpc_url()

    for attempt in range(3):
        # 1. Fetch the first page of the snapshot to get the current digest
        snap_data = _fetch_json("%s/xid/v1/state_snapshot" % rpc_url)
        if not snap_data:
            return None

        digest = snap_data.get("digest", "")
        if not digest:
            return None

        # If we already have this digest cached, just refresh the timestamp
        if digest == _attested_snapshot["digest"]:
            _attested_snapshot["timestamp"] = now
            return _attested_snapshot["mappings"]

        # 2. Check if this digest is finalized (attested by 2/3+ validators)
        att_data = _fetch_json("%s/xid/v1/attestations?digest=%s" % (rpc_url, digest))
        if not att_data or not att_data.get("finalized"):
            return None

        # 3. Extract EPIXNET DNS mappings from already-fetched first page + remaining pages
        mappings = {}
        digest_changed = False

        # Process first page (already fetched)
        for domain_snap in snap_data.get("domains", []):
            record = domain_snap.get("record", {})
            name = record.get("name", "")
            tld = record.get("tld", "")
            if not name or not tld:
                continue

            domain_key = "%s.%s" % (name, tld)
            for dns_rec in domain_snap.get("dns_records", []):
                if int(dns_rec.get("record_type", 0)) == EPIXNET_RECORD_TYPE:
                    site_addr = dns_rec.get("value", "").strip()
                    if site_addr:
                        mappings[domain_key] = site_addr
                    break

        # Fetch remaining pages
        pagination = snap_data.get("pagination", {})
        next_key = pagination.get("next_key")
        page = 1
        while next_key and page < 100:
            url = "%s/xid/v1/state_snapshot?pagination.key=%s" % (rpc_url, next_key)
            snap_data = _fetch_json(url)
            if not snap_data:
                break

            # Verify digest hasn't changed mid-pagination
            if snap_data.get("digest", "") != digest:
                log.debug("Digest changed mid-pagination (attempt %d), retrying" % (attempt + 1))
                digest_changed = True
                break

            for domain_snap in snap_data.get("domains", []):
                record = domain_snap.get("record", {})
                name = record.get("name", "")
                tld = record.get("tld", "")
                if not name or not tld:
                    continue

                domain_key = "%s.%s" % (name, tld)
                for dns_rec in domain_snap.get("dns_records", []):
                    if int(dns_rec.get("record_type", 0)) == EPIXNET_RECORD_TYPE:
                        site_addr = dns_rec.get("value", "").strip()
                        if site_addr:
                            mappings[domain_key] = site_addr
                        break

            pagination = snap_data.get("pagination", {})
            next_key = pagination.get("next_key")
            page += 1

        if digest_changed:
            continue  # Retry from scratch

        # Store the attested snapshot
        _attested_snapshot["digest"] = digest
        _attested_snapshot["mappings"] = mappings
        _attested_snapshot["timestamp"] = now

        # Populate caches from attested data
        for domain_key, site_addr in mappings.items():
            _resolve_cache[domain_key] = {"address": site_addr, "timestamp": now, "attested": True}
            _reverse_cache[site_addr] = domain_key

        log.info("Loaded attested snapshot: %d EPIXNET mappings (digest: %s...)" % (len(mappings), digest[:16]))
        return mappings

    log.warning("Failed to fetch consistent snapshot after 3 attempts")
    return None


def _resolve_epix_name(tld, name):
    """Query the xID chain for the EPIXNET DNS record of a name.

    Verification priority:
    1. Attested snapshot (2/3 validator consensus) — strongest proof
    2. Direct RPC query with chain ID verification — fallback

    Returns the EpixNet site address string, or None.
    """
    cache_key = "%s.%s" % (name, tld)
    now = time.time()
    cached = _resolve_cache.get(cache_key)
    if cached:
        ttl = ATTESTED_CACHE_TTL if cached.get("attested") else RESOLVE_CACHE_TTL
        if (now - cached["timestamp"]) < ttl:
            return cached["address"]

    # Try attested snapshot first (strongest verification)
    attested_mappings = _fetch_attested_snapshot()
    if attested_mappings is not None:
        site_address = attested_mappings.get(cache_key)
        _resolve_cache[cache_key] = {"address": site_address, "timestamp": now, "attested": True}
        if site_address:
            _reverse_cache[site_address] = cache_key
            log.debug("Resolved %s to %s (attested)" % (cache_key, site_address))
        return site_address

    # Fallback: direct RPC query with chain ID verification
    if not _verify_chain_id():
        return None

    rpc_url = _get_rpc_url()

    data = _fetch_json("%s/xid/v1/resolve/%s/%s" % (rpc_url, tld, name))
    if not data or not data.get("record"):
        _resolve_cache[cache_key] = {"address": None, "timestamp": now, "attested": False}
        return None

    dns_data = _fetch_json("%s/xid/v1/dns/%s/%s" % (rpc_url, tld, name))
    site_address = None
    if dns_data and dns_data.get("records"):
        for record in dns_data["records"]:
            if int(record.get("record_type", 0)) == EPIXNET_RECORD_TYPE:
                site_address = record.get("value", "").strip()
                break

    _resolve_cache[cache_key] = {"address": site_address, "timestamp": now, "attested": False}
    if site_address:
        _reverse_cache[site_address] = cache_key
        log.debug("Resolved %s to %s (chain ID verified, not attested)" % (cache_key, site_address))
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

    def reverseLookupDomain(self, address):
        """Return the verified .epix domain for a site address, or None.

        Only returns domains verified against the chain — either from an
        attested snapshot (2/3 validator consensus) or a chain-ID-verified
        forward resolution that confirmed domain -> address.
        """
        # Already verified via forward resolution or attested snapshot
        cached = _reverse_cache.get(address)
        if cached:
            return cached

        # Check if the site claims a domain in content.json
        site = self.sites.get(address)
        if not site:
            return None
        content = site.content_manager.contents.get("content.json")
        if not content or not content.get("domain"):
            return None

        domain = content["domain"].lower()
        if not domain.endswith(".epix"):
            return None

        # Verify against chain: resolve the claimed domain and check it points here
        resolved = self.resolveEpixDomain(domain)
        if resolved == address:
            return domain

        log.debug("Domain claim %s by %s failed chain verification (resolved to %s)" % (domain, address, resolved))
        return None


def clearXidCaches():
    """Clear all xID-related caches (resolver + chain attestation + SiteManager domain cache)."""
    global _chain_id_verified
    count = len(_resolve_cache)
    _resolve_cache.clear()
    _reverse_cache.clear()
    _chain_id_verified = None
    _chain_id_cache.update({"chain_id": None, "timestamp": 0})
    _attested_snapshot.update({"digest": None, "mappings": {}, "timestamp": 0})

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
