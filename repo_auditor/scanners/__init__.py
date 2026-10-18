from .secrets import SecretsScanner
from .dependencies import DependencyScanner
from .files import FileScanner
from .license import LicenseScanner
from .config import ConfigScanner

ALL_SCANNERS = [
    SecretsScanner,
    DependencyScanner,
    FileScanner,
    LicenseScanner,
    ConfigScanner,
]
