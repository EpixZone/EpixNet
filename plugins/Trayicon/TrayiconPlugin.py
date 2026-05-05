import os
import sys
import atexit
import time

from Plugin import PluginManager
from Config import config
from Translate import Translate

allow_reload = False  # No source reload supported in this plugin


plugin_dir = os.path.dirname(__file__)

if "_" not in locals():
    _ = Translate(plugin_dir + "/languages/")


def _has_console():
    """Check if a console window is available (Windows only)."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return ctypes.windll.kernel32.GetConsoleWindow() != 0
    except Exception:
        return False


def _hide_console():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass


def _show_console():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
    except Exception:
        pass


def _get_startup_folder():
    """Get Windows Startup folder path. Returns None on non-Windows."""
    if sys.platform != "win32":
        return None
    try:
        from .lib import winfolders
        return winfolders.get(winfolders.STARTUP)
    except Exception:
        return None


@PluginManager.registerTo("Actions")
class ActionsPlugin(object):

    def main(self):
        try:
            import pystray
            import pystray._base
            from PIL import Image
        except ImportError as err:
            print("Trayicon plugin: pystray or Pillow not installed (%s), skipping tray icon." % err)
            super(ActionsPlugin, self).main()
            return

        # pystray runs on a real OS thread and uses queue.Queue for signaling.
        # gevent.monkey.patch_all() replaces queue.Queue with a cooperative
        # version that only works inside a gevent hub, which causes LoopExit
        # when pystray's setup thread blocks on .get(). Swap in the unpatched
        # stdlib Queue on pystray's own queue module reference.
        try:
            import gevent.monkey
            real_queue_cls = gevent.monkey.get_original("queue", "Queue")
            pystray._base.queue.Queue = real_queue_cls
        except Exception as err:
            print("Trayicon plugin: failed to restore stdlib queue.Queue: %s" % err)

        import threading
        import main

        self.main = main
        self.console = False

        icon_path = os.path.join(plugin_dir, "trayicon.ico")

        # Set AppUserModelID so Windows toasts are attributed to EpixNet
        # instead of "Python". The friendly display name and icon are
        # registered once per user under HKCU so the toast shows "EpixNet".
        if sys.platform == "win32":
            aumid = "EpixZone.EpixNet"
            try:
                import winreg
                key_path = r"Software\Classes\AppUserModelId\%s" % aumid
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "EpixNet")
                    if os.path.exists(icon_path):
                        winreg.SetValueEx(key, "IconUri", 0, winreg.REG_SZ, icon_path)
            except Exception as err:
                print("Trayicon plugin: failed to register AUMID display name: %s" % err)
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(aumid)
            except Exception as err:
                print("Trayicon plugin: failed to set AppUserModelID: %s" % err)

        # Load icon image
        try:
            icon_image = Image.open(icon_path)
        except Exception as err:
            print("Trayicon plugin: Failed to load icon %s: %s" % (icon_path, err))
            super(ActionsPlugin, self).main()
            return

        ui_ip = config.ui_ip if config.ui_ip != "*" else "127.0.0.1"
        if ":" in ui_ip:
            ui_ip = "[" + ui_ip + "]"
        self._epixnet_url = "http://%s:%s/%s" % (ui_ip, config.ui_port, config.homepage)

        # Build menu
        menu_items = [
            pystray.MenuItem(
                lambda item: self.titleIp(),
                None, enabled=False
            ),
            pystray.MenuItem(
                lambda item: self.titleConnections(),
                None, enabled=False
            ),
            pystray.MenuItem(
                lambda item: self.titleTransfer(),
                None, enabled=False
            ),
        ]

        # Console toggle (Windows only)
        if _has_console():
            menu_items.append(
                pystray.MenuItem(
                    lambda item: _["Show console window"],
                    self._on_toggle_console,
                    checked=lambda item: self.console
                )
            )

        # Autorun toggle (Windows only)
        if sys.platform == "win32":
            menu_items.append(
                pystray.MenuItem(
                    lambda item: _["Start EpixNet when Windows starts"],
                    self._on_toggle_autorun,
                    checked=lambda item: self.isAutorunEnabled()
                )
            )

        menu_items.append(pystray.Menu.SEPARATOR)
        menu_items.append(pystray.MenuItem(
            _["EpixNet X"],
            lambda icon, item: self.opensite("https://x.com/zone_epix")
        ))
        menu_items.append(pystray.MenuItem(
            _["EpixNet Github"],
            lambda icon, item: self.opensite("https://github.com/EpixZone/EpixNet")
        ))
        menu_items.append(pystray.MenuItem(
            _["Report bug/request feature"],
            lambda icon, item: self.opensite("https://github.com/EpixZone/EpixNet/issues")
        ))
        menu_items.append(pystray.Menu.SEPARATOR)
        menu_items.append(pystray.MenuItem(
            _["!Open EpixNet"].lstrip("!"),
            lambda icon, item: self.opensite(self._epixnet_url),
            default=True
        ))
        menu_items.append(pystray.Menu.SEPARATOR)
        menu_items.append(pystray.MenuItem(
            _["Quit"],
            self._on_quit
        ))

        self.icon = pystray.Icon(
            "epixnet",
            icon=icon_image,
            title="EpixNet %s" % config.version,
            menu=pystray.Menu(*menu_items)
        )

        @atexit.register
        def hideIcon():
            try:
                self.icon.stop()
            except Exception as err:
                print("Error removing trayicon: %s" % err)

        import gevent
        hub = gevent.get_hub()
        self._quit_async = hub.loop.async_()
        self._quit_async.start(lambda: gevent.spawn_later(0.1, self.quitServers))

        # Run pystray in a real OS thread (pystray is not gevent compatible)
        self._icon_thread = threading.Thread(target=self.icon.run, name="Trayicon", daemon=True)
        self._icon_thread.start()

        # Periodically rebuild the menu so dynamic labels (IP, connections,
        # transfer) reflect the current server state.  The menu is built once
        # by pystray at startup — before the file_server exists — so without
        # this the labels stay frozen at their initial "no data" values.
        def _menu_refresh_loop():
            while self._icon_thread.is_alive():
                time.sleep(5)
                try:
                    self.icon.update_menu()
                except Exception:
                    pass
        self._menu_refresh_thread = threading.Thread(
            target=_menu_refresh_loop, name="TrayiconMenuRefresh", daemon=True
        )
        self._menu_refresh_thread.start()

        super(ActionsPlugin, self).main()
        try:
            self.icon.stop()
        except Exception:
            pass
        try:
            self._quit_async.stop()
        except Exception:
            pass

    def _on_quit(self, icon, item):
        self.icon.stop()
        self._quit_async.send()

    def _on_toggle_console(self, icon, item):
        if self.console:
            _hide_console()
            self.console = False
        else:
            _show_console()
            self.console = True

    def _on_toggle_autorun(self, icon, item):
        if self.isAutorunEnabled():
            os.unlink(self.getAutorunPath())
        else:
            open(self.getAutorunPath(), "wb").write(self.formatAutorun().encode("utf8"))

    def quit(self):
        self._on_quit(None, None)

    def quitServers(self):
        ui_server = getattr(self.main, "ui_server", None)
        file_server = getattr(self.main, "file_server", None)
        if ui_server is not None:
            ui_server.stop()
        if file_server is not None:
            file_server.stop()

    def opensite(self, url):
        import webbrowser
        webbrowser.open(url, new=0)

    def announce(self, message, title=""):
        """Show an OS notification toast via the tray icon."""
        icon = getattr(self, "icon", None)
        if icon is None or not getattr(icon, "visible", False):
            return
        try:
            # Bypass pystray's title fallback (which uses self.title) so
            # toasts don't show a redundant EpixNet heading above the body.
            if sys.platform == "win32" and hasattr(icon, "_message"):
                from pystray import _win32 as pystray_win32
                icon._message(
                    pystray_win32.win32.NIM_MODIFY,
                    pystray_win32.win32.NIF_INFO,
                    szInfo=message,
                    szInfoTitle=title or "",
                )
            else:
                icon.notify(message, title or None)
        except Exception as err:
            print("Trayicon announce error: %s" % err)

    def titleIp(self):
        file_server = getattr(self.main, "file_server", None)
        if file_server is None:
            return "IP: - "
        title = "IP: %s " % ", ".join(file_server.ip_external_list)
        if any(file_server.port_opened):
            title += _["(active)"]
        else:
            title += _["(passive)"]
        return title

    def titleConnections(self):
        file_server = getattr(self.main, "file_server", None)
        if file_server is None:
            return _["Connections: %s"] % 0
        title = _["Connections: %s"] % len(file_server.connections)
        return title

    def titleTransfer(self):
        file_server = getattr(self.main, "file_server", None)
        if file_server is None:
            return _["Received: %.2f MB | Sent: %.2f MB"] % (0.0, 0.0)
        title = _["Received: %.2f MB | Sent: %.2f MB"] % (
            float(file_server.bytes_recv) / 1024 / 1024,
            float(file_server.bytes_sent) / 1024 / 1024
        )
        return title

    def getAutorunPath(self):
        startup = _get_startup_folder()
        if not startup:
            return None
        return "%s\\epixnet.cmd" % startup

    def formatAutorun(self):
        args = sys.argv[:]

        if not getattr(sys, 'frozen', False):  # Not frozen
            args.insert(0, sys.executable)
            cwd = os.getcwd()
        else:
            cwd = os.path.dirname(sys.executable)

        ignored_args = [
            "--open_browser", "default_browser",
            "--dist_type", "bundle_win64"
        ]

        if sys.platform == 'win32':
            args = ['"%s"' % arg for arg in args if arg and arg not in ignored_args]
        cmd = " ".join(args)

        # Dont open browser on autorun
        cmd = cmd.replace("start.py", "epixnet.py").strip()
        cmd += ' --open_browser ""'

        return "\r\n".join([
            '@echo off',
            'chcp 65001 > nul',
            'set PYTHONIOENCODING=utf-8',
            'cd /D \"%s\"' % cwd,
            'start "" %s' % cmd
        ])

    def isAutorunEnabled(self):
        path = self.getAutorunPath()
        if not path:
            return False
        return os.path.isfile(path) and open(path, "rb").read().decode("utf8") == self.formatAutorun()
