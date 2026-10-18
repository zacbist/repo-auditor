from abc import ABC, abstractmethod


class BaseScanner(ABC):
    name = "base"

    @abstractmethod
    def scan(self, repo_path):
        pass
