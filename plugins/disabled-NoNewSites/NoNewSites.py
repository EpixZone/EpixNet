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

import re
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
            'Benchmark',
        ]
        match_reserved = re.match(f"/({'|'.join(reserved_names)})/?", path)
        if not match_address and not match_reserved:
            self.sendHeader(500)
            return self.formatError("Plugin error", "No match for address found")

        addr = match_address.group("address")

        if not self.server.site_manager.get(addr) and not match_reserved:
            self.sendHeader(404)
            return self.formatError("Not Found", "Adding new sites disabled", details=False)
        return super(NoNewSites, self).actionWrapper(path, extra_headers)

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
