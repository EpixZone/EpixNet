##
##  Copyright (c) 2022 caryoscelus
##
##  epixnet is free software: you can redistribute it and/or modify it under the
##  terms of the GNU General Public License as published by the Free Software
##  Foundation, either version 3 of the License, or (at your option) any later version.
##
##  epixnet is distributed in the hope that it will be useful, but
##  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
##  FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
##  details.
##
## You should have received a copy of the GNU General Public License along with
## epixnet. If not, see <https://www.gnu.org/licenses/>.
##

import json
import re
import time
from Plugin import PluginManager

GATEWAY_BANNER_HTML = """
<style>
/* Banner sits above the iframe but below the wrapper's UI chrome
   (notifications z=999, fixbutton z=999, popups z=9999) so error/warning
   toasts and the menu stay clickable on top of the banner area. */
#epix-gateway-banner {
    position: fixed; top: 0; left: 0; right: 0; z-index: 1;
    height: 38px;
    background: #0d1117; color: #e6edf3;
    font: 13px/38px -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    text-align: center; padding: 0 16px;
    box-sizing: border-box;
}
#epix-gateway-banner strong { color: #f0f6fc; font-weight: 600; }
#epix-gateway-banner a {
    color: #fff; background: #238636; text-decoration: none;
    padding: 5px 12px; border-radius: 4px; margin-left: 10px;
    font-weight: 600; transition: background 0.15s;
}
#epix-gateway-banner a:hover { background: #2ea043; }
#inner-iframe { top: 38px !important; height: calc(100% - 38px) !important; }
</style>
<div id="epix-gateway-banner">
    <strong>Public gateway - read-only.</strong>
    Install EpixNet to use your own identity, browse the full network, and host sites.
    <a href="https://epixnet.io/#download" target="_blank" rel="noopener">Get EpixNet</a>
</div>
</body>
</html>
"""

# based on the code from Multiuser plugin
@PluginManager.registerTo("UiRequest")
class NoNewSites(object):
    def __init__(self, *args, **kwargs):
        return super(NoNewSites, self).__init__(*args, **kwargs)

    def actionWrapper(self, path, extra_headers=None):
        match_address = re.match("/(media/)?(?P<address>[A-Za-z0-9\._-]+)(?P<inner_path>/.*|$)", path)
        reserved_names = [
            'Config',
            'Plugins',
            'Stats',
            'StatsJson',
            'Benchmark',
        ]
        # Match either the reserved name on its own or with trailing slash —
        # but not as a prefix of a longer name (e.g. "Stats" shouldn't swallow
        # "StatsJson"). The (?=/|$) lookahead enforces that.
        match_reserved = re.match(f"/({'|'.join(map(re.escape, reserved_names))})(?=/|$)", path)
        if not match_address and not match_reserved:
            self.sendHeader(500)
            return self.formatError("Plugin error", "No match for address found")

        addr = match_address.group("address")

        if not self.server.site_manager.get(addr) and not match_reserved:
            self.sendHeader(404)
            return self.formatError("Not Found", "Adding new sites disabled", details=False)
        return super(NoNewSites, self).actionWrapper(path, extra_headers)

    # Lightweight public stats endpoint for the marketing site header.
    # Avoids the full /Stats debug page (which iterates live sockets and
    # crashes on closed file descriptors). Cached for 30s.
    _stats_json_cache = {"at": 0, "body": None}

    def actionStatsJson(self):
        import main
        from Config import config

        now = time.time()
        cache = NoNewSites._stats_json_cache
        if cache["body"] is None or now - cache["at"] > 30:
            try:
                fs = main.file_server
                sites = list(self.server.sites.values())

                # Sum per-site peer counts. peers_total counts every peer this
                # node has ever heard of for any site (the "known" pool).
                # peers_connected counts peers we have an active connection
                # to right now. Iterating site.peers (a dict) is safe — we
                # never touch peer.connection.sock, so no Bad-fd risk like
                # the upstream /Stats page has.
                peers_total = 0
                peers_connected = 0
                for site in sites:
                    site_peers = list(site.peers.values())
                    peers_total += len(site_peers)
                    for peer in site_peers:
                        conn = peer.connection
                        if conn and conn.connected:
                            peers_connected += 1

                payload = {
                    "version": config.version,
                    "sites": len(sites),
                    "peers_total": peers_total,
                    "peers_connected": peers_connected,
                    "connections": len(fs.connections),
                    "bytes_recv": fs.bytes_recv,
                    "bytes_sent": fs.bytes_sent,
                    "port_opened": bool(fs.port_opened),
                }
            except Exception as e:
                payload = {"error": str(e)}
            cache["body"] = json.dumps(payload).encode("utf8")
            cache["at"] = now

        # CORS is added by nginx (location = /StatsJson) so the marketing
        # site can fetch this from a different origin. Keep it out of here
        # so we don't end up with two Access-Control-Allow-Origin headers.
        self.sendHeader(200, content_type="application/json")
        # WSGI requires an iterable of bytes. Returning raw bytes makes
        # gevent's pywsgi iterate byte-by-byte and crash with
        # "TypeError: object of type 'int' has no len()".
        return [cache["body"]]

    # Inject the public-gateway banner into every wrapper page.
    def renderWrapper(self, *args, **kwargs):
        try:
            import logging
            body = super(NoNewSites, self).renderWrapper(*args, **kwargs)
            logging.info("NoNewSites.renderWrapper: body type=%s len=%s" % (type(body).__name__, len(body) if body else 'n/a'))
            if isinstance(body, bytes):
                return re.sub(rb"</body>\s*</html>\s*$",
                              GATEWAY_BANNER_HTML.encode("utf8"),
                              body)
            return re.sub(r"</body>\s*</html>\s*$", GATEWAY_BANNER_HTML, body)
        except Exception as e:
            import logging
            logging.error("NoNewSites.renderWrapper FAILED: %r" % e)
            return body
