import logging
import re
import time

from Config import config
from Plugin import PluginManager

allow_reload = False  # No reload supported

log = logging.getLogger("EpixnamePlugin")


@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):
    site_epixname = None
    db_domains = {}
    db_domains_modified = None

    def load(self, *args, **kwargs):
        super(SiteManagerPlugin, self).load(*args, **kwargs)
        if not self.get(config.bit_resolver):
            self.need(config.bit_resolver)  # Need EpixName site

    # Return: True if the address is .bit domain
    def isBitDomain(self, address):
        return re.match(r"(.*?)([A-Za-z0-9_-]+\.bit)$", address)

    # Resolve domain
    # Return: The address or None
    def resolveBitDomain(self, domain):
        domain = domain.lower()
        if not self.site_epixname:
            self.site_epixname = self.need(config.bit_resolver)

        site_epixname_modified = self.site_epixname.content_manager.contents.get("content.json", {}).get("modified", 0)
        if not self.db_domains or self.db_domains_modified != site_epixname_modified:
            self.site_epixname.needFile("data/names.json", priority=10)
            s = time.time()
            try:
                self.db_domains = self.site_epixname.storage.loadJson("data/names.json")
            except Exception as err:
                log.error("Error loading names.json: %s" % err)

            log.debug(
                "Domain db with %s entries loaded in %.3fs (modification: %s -> %s)" %
                (len(self.db_domains), time.time() - s, self.db_domains_modified, site_epixname_modified)
            )
            self.db_domains_modified = site_epixname_modified
        return self.db_domains.get(domain)

    # Turn domain into address
    def resolveDomain(self, domain):
        return self.resolveBitDomain(domain) or super(SiteManagerPlugin, self).resolveDomain(domain)

    # Return: True if the address is domain
    def isDomain(self, address):
        return self.isBitDomain(address) or super(SiteManagerPlugin, self).isDomain(address)


@PluginManager.registerTo("ConfigPlugin")
class ConfigPlugin(object):
    def createArguments(self):
        group = self.parser.add_argument_group("Epixname plugin")
        group.add_argument(
            "--bit-resolver", help="EpixNet site to resolve .bit domains (deprecated)",
            default="epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t", metavar="address"
        )

        return super(ConfigPlugin, self).createArguments()
