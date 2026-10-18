import os

from .base import BaseScanner

LICENSE_NAMES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "COPYING.md"]


class LicenseScanner(BaseScanner):
    name = "license"

    def scan(self, repo_path):
        for name in LICENSE_NAMES:
            fpath = os.path.join(repo_path, name)
            if os.path.isfile(fpath):
                return [{"type": "license", "found": True, "file": name}]
        return [{"type": "license", "found": False, "severity": "medium", "issue": "no license file"}]
