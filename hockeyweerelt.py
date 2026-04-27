import aiohttp
import asyncio
import logging
import uuid
from datetime import datetime
import hashlib
import time
import re
from typing import Any, Optional
from urllib.parse import urljoin
import json

_LOGGER = logging.getLogger(__name__)


class Crypto:
    @staticmethod
    def generate_signature(
        url_path: str,
        params: dict,
        timestamp: int,
        device_uuid: str,
    ) -> str:
        """
        Generate a SHA-1 request signature.

        Args:
            url_path:    e.g. "/api/test"
            params:      query parameters, e.g. {"foo": "bar"}
            timestamp:   Unix timestamp, e.g. int(time.time())
            device_uuid: registered device UUID

        Returns:
            Hex-encoded SHA-1 digest.
        """
        clean_path = re.sub(r"[^a-zA-Z0-9\-/]+", "", url_path)

        cleaned_params: list[str] = []
        for key, value in params.items():
            if key:
                clean_key = re.sub(r"[^a-zA-Z0-9\-/=]+", "", key)
                clean_value = re.sub(r"[^a-zA-Z0-9\-/=]+", "", str(value))
                cleaned_params.append(f"{clean_key}={clean_value}")

        query_string = "".join(cleaned_params)
        reversed_uuid = device_uuid[::-1] if device_uuid else ""
        payload = f"{timestamp}{clean_path}{query_string}{reversed_uuid}"

        return hashlib.sha1(payload.encode("utf-8")).hexdigest()


class Api:
    base_url = "https://app.hockeyweerelt.nl"
    _default_headers = {"Accept": "application/json"}

    def __init__(self, session: Optional[aiohttp.ClientSession] = None) -> None:
        self._external_session = session is not None
        self.session = session or aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        self.headers: dict[str, str] = self._default_headers.copy()
        self.uuid: Optional[str] = None

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "Api":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if not self._external_session:
            await self.session.close()

    # ------------------------------------------------------------------
    # Factory — always initialises the device before returning
    # ------------------------------------------------------------------

    @classmethod
    async def create(cls, session: Optional[aiohttp.ClientSession] = None) -> "Api":
        """Preferred constructor: creates *and* initialises the API client."""
        api = cls(session)
        await api.init()
        return api

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Register this device and store the authorisation token."""
        self.uuid = str(uuid.uuid4())
        r = await self._post(
            "/device/register", params={"os": "Web", "uuid": self.uuid}
        )
        self.headers["X-HAPI-Authorization"] = r["token"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_init(self) -> None:
        if self.uuid is None:
            raise RuntimeError(
                "Api is not initialised. "
                "Use 'await Api.create()' or call 'await api.init()' first."
            )

    def _build_headers(self, path: str, params: dict) -> dict[str, str]:
        self._require_init()
        t = int(time.time())
        headers = self.headers.copy()
        headers["X-HAPI-Signature"] = Crypto.generate_signature(
            path,
            params,
            t,
            self.uuid,  # type: ignore[arg-type]
        )
        headers["X-HAPI-Timestamp"] = str(t)
        return headers

    def _unwrap(self, response: Any) -> Any:
        """Return response["data"] when present, otherwise the raw response."""
        if isinstance(response, dict) and "data" in response:
            return response["data"]
        return response

    async def _fetch(self, path: str, params: Optional[dict] = None) -> Any:
        params = dict(params or {})
        headers = self._build_headers(path, params)
        url = urljoin(self.base_url, path)

        try:
            async with self.session.get(url, params=params, headers=headers) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientResponseError as e:
            _LOGGER.error("GET %s returned %s: %s", path, e.status, e.message)
            raise
        except aiohttp.ClientError as e:
            _LOGGER.error("GET %s failed: %s", path, e)
            raise

    async def _post(
        self, path: str, params: Optional[dict] = None, data: Optional[dict] = None
    ) -> Any:
        params = params or {}
        headers = self._build_headers(path, params)
        url = urljoin(self.base_url, path)

        try:
            async with self.session.post(
                url, params=params, json=data, headers=headers
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientResponseError as e:
            _LOGGER.error("POST %s returned %s: %s", path, e.status, e.message)
            raise
        except aiohttp.ClientError as e:
            _LOGGER.error("POST %s failed: %s", path, e)
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_clubs(self) -> list:
        return self._unwrap(await self._fetch("/clubs"))

    async def get_club_info(self, club_id: int | str) -> dict:
        return self._unwrap(await self._fetch(f"/clubs/{club_id}"))

    async def get_club_teams(self, club_id: int | str) -> list:
        """Return the teams list embedded in the club detail response."""
        club = self._unwrap(await self._fetch(f"/clubs/{club_id}"))
        return club.get("teams", [])

    async def get_poule_team(self, poule_id: int | str, team_id: int | str) -> dict:
        """Return the full poule context for a team (standings + all matches)."""
        return self._unwrap(await self._fetch(f"/poules/{poule_id}/teams/{team_id}"))

    async def get_team_matches(self, team_id: int | str, poule_id: int | str) -> list:
        """Return all matches in the poule that involve the given team."""
        data = await self.get_poule_team(poule_id, team_id)
        all_matches: list = data.get("poule", {}).get("matches", [])
        team_id_int = int(team_id)
        return [
            m
            for m in all_matches
            if m["home"]["id"] == team_id_int or m["away"]["id"] == team_id_int
        ]

    async def get_next_team_match(
        self, team_id: int | str, poule_id: int | str | None
    ) -> dict | None:
        """Return the next scheduled match for the team, or None if there are none."""

        if poule_id is None:
            matches = await self.get_matches_for_teams([team_id])
        else:
            matches = await self.get_team_matches(team_id, poule_id)
        upcoming = [m for m in matches if m.get("status") in ("scheduled", "announced")]
        if not upcoming:
            return None
        return min(upcoming, key=lambda m: m["date"])

    async def custom(self, url_path: str, params: dict | None = None):
        """Make a custom API call to any endpoint, with optional query parameters and JSON body."""
        return self._unwrap(await self._fetch(url_path, params=params))

    async def get_matches_for_teams(self, team_ids: list[int]) -> list:
        params = [("team_id[]", tid) for tid in team_ids]
        return self._unwrap(await self._fetch("/matches/team", params=params))

    async def get_team_poules(self, club_id, team_id: int) -> list:
        club_data = await self.get_club_info(club_id)
        teams = club_data.get("teams", [])
        team = next((t for t in teams if t["id"] == team_id), None)
        if not team:
            raise ValueError("Team not found")

        poule_id = team.get("recent_poule_id")
        teaminfo = await self.get_poule_team(poule_id, team_id)
        return teaminfo.get("team", {}).get("poules", {})


# ----------------------------------------------------------------------
# Quick smoke-test
# ----------------------------------------------------------------------

if __name__ == "__main__":

    async def main() -> None:
        async with await Api.create() as api:
            poules = await api.get_team_poules("HH11AR3", 24687)
            print(poules)
            return

            clubs = await api.get_clubs()
            if not clubs:
                print("No clubs returned.")
                return

            first_club = clubs[0]
            print("First club:", first_club)

            club_id = first_club["federation_reference_id"]
            club_info = await api.get_club_info(club_id)
            print("Club info:", club_info)

            teams = await api.get_club_teams(club_id)
            if teams:
                team = teams[1]

                team_id = team["id"]
                poule_id = team["recent_poule_id"]
                print(f"\nFetching matches for team {team['name']} in poule {poule_id}")

                next_match = await api.get_next_team_match(team_id, poule_id)
                print("Next match:", next_match)

                all_matches = await api.get_team_matches(team_id, poule_id)
                print(f"Total matches this season: {len(all_matches)}")

    async def repl():
        async with await Api.create() as api:
            while True:
                inp = input("Enter url path: ")
                if inp.lower() in {"exit", "quit"}:
                    break
                try:
                    s = inp.split("?")
                    if len(s) == 2:
                        url_path, query = s
                        params = dict(q.split("=") for q in query.split("&"))
                    else:
                        url_path = inp
                        params = None
                    api_response = await api.custom(url_path, params=params)
                    print("Response: ", json.dumps(api_response, indent=2))
                    print()
                except Exception as e:
                    print("Error: ", e)
                    print()

    asyncio.run(main())
