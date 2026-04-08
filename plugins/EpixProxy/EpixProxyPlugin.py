import os
import sys
import atexit
import logging
import subprocess

from Plugin import PluginManager
from Config import config

log = logging.getLogger("EpixProxy")


@PluginManager.registerTo("UiRequest")
class UiRequestPlugin(object):
    def route(self, path):
        if path == "/proxy.pac":
            return self.actionProxyPac()
        return super().route(path)

    def actionProxyPac(self):
        pac_content = """function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.epix")) {
        return "PROXY 127.0.0.1:%d; DIRECT";
    }
    return "DIRECT";
}
""" % config.ui_port
        self.sendHeader(content_type="application/x-ns-proxy-autoconfig")
        return iter([pac_content.encode("utf8")])


@PluginManager.registerTo("UiServer")
class UiServerPlugin(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if getattr(config, "epix_proxy", "auto") != "off":
            self.allow_trans_proxy = True


@PluginManager.registerTo("Actions")
class ActionsPlugin(object):
    def main(self):
        proxy_mode = getattr(config, "epix_proxy", "auto")
        if proxy_mode != "off":
            self._proxy_previous = {}
            self._proxy_configured = False
            self._setup_system_proxy()
            if self._proxy_configured:
                atexit.register(self._cleanup_system_proxy)
        return super().main()

    def _setup_system_proxy(self):
        pac_url = "http://127.0.0.1:%d/proxy.pac" % config.ui_port
        loud = (getattr(config, "epix_proxy", "auto") == "on")

        if sys.platform == "win32":
            self._setup_windows_proxy(pac_url, loud)
        elif sys.platform == "darwin":
            self._setup_macos_proxy(pac_url, loud)
        else:
            self._setup_linux_proxy(pac_url, loud)

    def _run_cmd(self, cmd, loud=False):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0, result.stdout.strip()
        except FileNotFoundError:
            if loud:
                log.warning("Command not found: %s" % cmd[0])
            return False, ""
        except Exception as err:
            if loud:
                log.warning("Command failed: %s (%s)" % (cmd, err))
            return False, ""

    # --- Linux ---

    def _setup_linux_proxy(self, pac_url, loud):
        # Try GNOME/GTK (gsettings)
        if self._setup_gnome_proxy(pac_url, loud):
            return
        # Try KDE
        if self._setup_kde_proxy(pac_url, loud):
            return

        if loud:
            log.warning(
                "Could not auto-configure system proxy. "
                "Set your browser's PAC URL to: %s" % pac_url
            )
        else:
            log.info(
                "Auto proxy setup not available. "
                "For native .epix domains, set browser PAC URL to: %s" % pac_url
            )

    def _setup_gnome_proxy(self, pac_url, loud):
        # Check if gsettings is available
        ok, _ = self._run_cmd(["which", "gsettings"])
        if not ok:
            return False

        # Save previous settings
        ok, prev_mode = self._run_cmd(
            ["gsettings", "get", "org.gnome.system.proxy", "mode"]
        )
        if not ok:
            return False

        _, prev_url = self._run_cmd(
            ["gsettings", "get", "org.gnome.system.proxy", "autoconfig-url"]
        )

        self._proxy_previous["gnome_mode"] = prev_mode
        self._proxy_previous["gnome_url"] = prev_url

        # Set PAC URL
        ok, _ = self._run_cmd(
            ["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", pac_url]
        )
        if not ok:
            return False

        ok, _ = self._run_cmd(
            ["gsettings", "set", "org.gnome.system.proxy", "mode", "auto"]
        )
        if not ok:
            return False

        self._proxy_configured = True
        log.info("GNOME proxy configured: %s" % pac_url)
        return True

    def _setup_kde_proxy(self, pac_url, loud):
        kioslaverc = os.path.expanduser("~/.config/kioslaverc")
        if not os.path.isfile(kioslaverc):
            return False

        try:
            with open(kioslaverc, "r") as f:
                content = f.read()
        except Exception:
            return False

        # Save original content for restoration
        self._proxy_previous["kde_content"] = content

        # Parse and update proxy settings
        import configparser
        kio_config = configparser.ConfigParser()
        kio_config.read(kioslaverc)

        if not kio_config.has_section("Proxy Settings"):
            kio_config.add_section("Proxy Settings")

        self._proxy_previous["kde_proxy_type"] = kio_config.get(
            "Proxy Settings", "ProxyType", fallback=""
        )
        self._proxy_previous["kde_proxy_url"] = kio_config.get(
            "Proxy Settings", "Proxy Config Script", fallback=""
        )

        kio_config.set("Proxy Settings", "ProxyType", "2")  # 2 = PAC
        kio_config.set("Proxy Settings", "Proxy Config Script", pac_url)

        try:
            with open(kioslaverc, "w") as f:
                kio_config.write(f)
            self._proxy_configured = True
            log.info("KDE proxy configured: %s" % pac_url)
            return True
        except Exception as err:
            log.debug("KDE proxy setup failed: %s" % err)
            return False

    # --- Windows ---

    def _setup_windows_proxy(self, pac_url, loud):
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)

            # Save previous AutoConfigURL
            try:
                prev_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                self._proxy_previous["win_url"] = prev_url
            except FileNotFoundError:
                self._proxy_previous["win_url"] = None

            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
            winreg.CloseKey(key)

            self._proxy_configured = True
            log.info("Windows proxy configured: %s" % pac_url)
        except Exception as err:
            if loud:
                log.warning("Windows proxy setup failed: %s" % err)
            else:
                log.info(
                    "Auto proxy setup failed. "
                    "For native .epix domains, set browser PAC URL to: %s" % pac_url
                )

    # --- macOS ---

    def _setup_macos_proxy(self, pac_url, loud):
        # Find active network service
        ok, output = self._run_cmd(["networksetup", "-listallnetworkservices"])
        if not ok:
            if loud:
                log.warning("macOS proxy setup failed: networksetup not available")
            return

        services = [
            line for line in output.split("\n")
            if line and not line.startswith("*") and not line.startswith("An asterisk")
        ]

        configured_any = False
        for service in services:
            # Save previous PAC URL
            ok, prev_info = self._run_cmd(
                ["networksetup", "-getautoproxyurl", service]
            )
            if ok:
                self._proxy_previous.setdefault("macos_services", {})[service] = prev_info

            ok, _ = self._run_cmd(
                ["networksetup", "-setautoproxyurl", service, pac_url]
            )
            if ok:
                configured_any = True
                log.info("macOS proxy configured for %s: %s" % (service, pac_url))

        if configured_any:
            self._proxy_configured = True
        elif loud:
            log.warning("macOS proxy setup failed for all network services")

    # --- Cleanup ---

    def _cleanup_system_proxy(self):
        if not self._proxy_configured:
            return

        log.info("Cleaning up system proxy settings...")

        if sys.platform == "win32":
            self._cleanup_windows_proxy()
        elif sys.platform == "darwin":
            self._cleanup_macos_proxy()
        else:
            self._cleanup_linux_proxy()

    def _cleanup_linux_proxy(self):
        # Restore GNOME settings
        if "gnome_mode" in self._proxy_previous:
            prev_mode = self._proxy_previous["gnome_mode"].strip("'")
            prev_url = self._proxy_previous.get("gnome_url", "''").strip("'")
            self._run_cmd(
                ["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", prev_url]
            )
            self._run_cmd(
                ["gsettings", "set", "org.gnome.system.proxy", "mode", prev_mode]
            )
            log.info("GNOME proxy settings restored")

        # Restore KDE settings
        if "kde_content" in self._proxy_previous:
            kioslaverc = os.path.expanduser("~/.config/kioslaverc")
            try:
                with open(kioslaverc, "w") as f:
                    f.write(self._proxy_previous["kde_content"])
                log.info("KDE proxy settings restored")
            except Exception as err:
                log.warning("KDE proxy cleanup failed: %s" % err)

    def _cleanup_windows_proxy(self):
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)

            prev_url = self._proxy_previous.get("win_url")
            if prev_url is not None:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, prev_url)
            else:
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass

            winreg.CloseKey(key)
            log.info("Windows proxy settings restored")
        except Exception as err:
            log.warning("Windows proxy cleanup failed: %s" % err)

    def _cleanup_macos_proxy(self):
        services = self._proxy_previous.get("macos_services", {})
        for service, prev_info in services.items():
            # Parse previous info to check if PAC was enabled
            if "No" in prev_info or not prev_info:
                self._run_cmd(
                    ["networksetup", "-setautoproxystate", service, "off"]
                )
            else:
                # Extract previous URL from the output
                for line in prev_info.split("\n"):
                    if line.startswith("URL:"):
                        prev_url = line.split(":", 1)[1].strip()
                        if prev_url:
                            self._run_cmd(
                                ["networksetup", "-setautoproxyurl", service, prev_url]
                            )
                        break
        log.info("macOS proxy settings restored")


@PluginManager.registerTo("ConfigPlugin")
class ConfigPlugin(object):
    def createArguments(self):
        group = self.parser.add_argument_group("EpixProxy plugin")
        group.add_argument(
            '--epix-proxy',
            help='Native .epix domain proxy (auto/on/off)',
            default='auto',
            choices=['auto', 'on', 'off']
        )
        return super().createArguments()
