#!/usr/bin/env python3
"""Release checks reject incomplete, uncommitted and incorrectly pinned bundles."""
import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("wallet_check", pathlib.Path(__file__).with_name("check-mobile-wallet.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WalletReleaseChecks(unittest.TestCase):
    def test_development_and_release_have_distinct_requirements(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "shells").mkdir()
            (root / "shells/wallet-ext.rev").write_text("a" * 12)
            previous = module.ROOT
            module.ROOT = root
            self.addCleanup(setattr, module, "ROOT", previous)
            for name in ("manifest.json", "mobile.html", "mobile-register.html", "mobileProvider.bundle.js"):
                (root / name).write_text("fixture")
            info = {"schema": 1, "providerProtocol": 1, "revision": "a" * 40,
                    "modifiedSource": True, "termsURL": "", "privacyURL": "", "analyticsConfigured": False}
            def save():
                (root / "epix-mobile-build.json").write_text(json.dumps(info))
            save()
            self.assertFalse(module.check(root))
            self.assertEqual(len(module.check(root, True)), 3)
            info.update(modifiedSource=False, termsURL="https://operator.test/terms", privacyURL="https://operator.test/privacy")
            save()
            self.assertFalse(module.check(root, True))
            for value in (True, None, "false"):
                info["analyticsConfigured"] = value
                save()
                self.assertTrue(any("analyticsConfigured" in error for error in module.check(root, True)))
            del info["analyticsConfigured"]
            save()
            self.assertTrue(any("analyticsConfigured" in error for error in module.check(root, True)))
            info["analyticsConfigured"] = False
            info["revision"] = "b" * 40
            save()
            self.assertTrue(any("revision" in error for error in module.check(root, True)))
            (root / "mobileProvider.bundle.js").unlink()
            self.assertTrue(any("asset" in error for error in module.check(root)))


if __name__ == "__main__":
    unittest.main()
