"""High-level client exposing every filescan.io API endpoint."""

from filescanio.config import load_settings, resolve_base_url
from filescanio.groups.feed import FeedGroup
from filescanio.groups.files import FilesGroup
from filescanio.groups.misc import MiscGroup
from filescanio.groups.reports import ReportsGroup
from filescanio.groups.reputation import ReputationGroup
from filescanio.groups.scan import ScanGroup
from filescanio.groups.similarity import SimilarityGroup
from filescanio.groups.system import SystemGroup
from filescanio.groups.threatintel import ThreatIntelGroup
from filescanio.groups.users import UsersGroup
from filescanio.http import Transport
from filescanio.transport import DEFAULT_TIMEOUT


class FileScanClient:
    """Client for the filescan.io API.

    The API key and the base URL are each resolved independently from the
    arguments, the environment, or the local config file, in that order.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not (api_key or "").strip():
            api_key = load_settings().api_key
        self._transport = Transport(
            api_key=api_key or "",
            base_url=(base_url or "").strip() or resolve_base_url(),
            timeout=timeout,
        )
        self.scan = ScanGroup(self._transport)
        self.reports = ReportsGroup(self._transport)
        self.files = FilesGroup(self._transport)
        self.similarity = SimilarityGroup(self._transport)
        self.system = SystemGroup(self._transport)
        self.users = UsersGroup(self._transport)
        self.feed = FeedGroup(self._transport)
        self.misc = MiscGroup(self._transport)
        self.reputation = ReputationGroup(self._transport)
        self.threatintel = ThreatIntelGroup(self._transport)

    def close(self) -> None:
        """Close the underlying HTTP transport."""
        self._transport.close()

    def __enter__(self) -> FileScanClient:
        """Return the client for use as a context manager."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the client when leaving the context manager."""
        self.close()
