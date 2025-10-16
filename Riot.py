# Riot.py

import os
import time
import traceback
from base64 import b64encode, b64decode
from json import loads
from functools import lru_cache
from typing import Any

# Local Imports
from utils import Utils
from Logger import Logger


class Auth:
    def __init__(self, logger):
        self.logger = logger

        self.headers = None
        self.headers_console = None

        self.accessToken = None
        self.entitlementToken = None
        self.puuid = None
        self.port = None
        self.encoded_pass = None

        self.account_name = None
        self.account_tag = None

        self.utils = Utils(logger)

        self.api_request = self.utils.api_request

        # Cache for client version and platform data
        self._client_version = None
        self._platform_data = None

    def get_userdata_from_token(self) -> tuple[str, str]:
        r = self.api_request("GET", "https://auth.riotgames.com/userinfo",
                             headers={"Authorization": f"Bearer {self.accessToken}"})
        try:
            self.account_name = r.json()["acct"]["game_name"]
            self.account_tag = r.json()["acct"]["tag_line"]
            return self.account_name, self.account_tag
        except Exception as e:
            traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
            self.logger.log(3, f"Failed to get account name/tag: {traceback_str}")
            return "None", "None"

    def _get_user_data_from_riot_client(self):
        try:
            # get lockfile password
            file_path = os.getenv("localappdata")
            lockfile_data = None
            try:
                with open(f"{file_path}\\Riot Games\\Riot Client\\Config\\lockfile", "r") as f:
                    lockfile_data = f.read()
            except:
                print("Riot Client isn't logged into an account!\nRetrying!")
                return None

            if lockfile_data is None:
                return None

            # Base 64 encode the password
            password = b64encode(f"riot:{str(lockfile_data.split(':')[3])}".encode("ASCII")).decode()
            self.encoded_pass = password
            # Get the port the WS is running on
            port = str(lockfile_data.split(":")[2])
            self.port = port
            if password is not None:
                # Make secure connection with the WS
                # Get user login tokens
                try:
                    with self.api_request("GET",
                                          f"https://127.0.0.1:{port}/entitlements/v1/token",
                                          headers={"authorization": f"Basic {password}", "accept": "*/*",
                                                   "Host": f"127.0.0.1:{port}"}, verify=False
                                          ) as r:
                        return_data = r.json()
                        print(return_data)
                except Exception:
                    print("Please make sure Riot Client is open!")
                    return None
                if "accessToken" in return_data and "token" in return_data and "subject" in return_data:
                    return return_data["accessToken"], return_data["token"], return_data["subject"]
                else:
                    return None
            else:
                raise Exception("Riot Client Login Password Not Found!")
        except Exception as e:
            print("Please make sure you are logged into a Riot Account!")
            traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
            # Safely handle return_data which might be unbound
            return_data_str = str(locals().get('return_data', 'N/A'))
            self.logger.log(1, f"Log In Failed!\nData: {return_data_str}\nTraceback: {traceback_str}")
            return None

    def log_in(self) -> bool:
        user_data = self._get_user_data_from_riot_client()

        if user_data is not None:
            self.accessToken = user_data[0]
            self.entitlementToken = user_data[1]
            self.puuid = user_data[2]

            self.get_headers()

            self.get_userdata_from_token()

            return True
        return False

    def get_headers(self):
        # Cache client version to avoid repeated API calls
        if self._client_version is None:
            r = self.api_request("GET", "https://valorant-api.com/v1/version")
            self._client_version = r.json()["data"]["riotClientVersion"]

        # Cache platform data to avoid recreating it
        if self._platform_data is None:
            self._platform_data = "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9"

        headers_pc = {
            "X-Riot-Entitlements-JWT": f"{self.entitlementToken}",
            "Authorization": f"Bearer {self.accessToken}",
            "X-Riot-ClientPlatform": self._platform_data,
            "X-Riot-ClientVersion": self._client_version,
            "Content-Type": "application/json"
        }
        headers_console = {
            "X-Riot-Entitlements-JWT": f"{self.entitlementToken}",
            "Authorization": f"Bearer {self.accessToken}",
            "X-Riot-ClientPlatform": self._platform_data,
            "X-Riot-ClientVersion": self._client_version
        }

        self.headers = headers_pc.copy()
        self.headers_console = headers_console.copy()

class Client:
    def __init__(self, logger, api_request, port, encoded_pass, headers):
        self.logger = logger
        self.api_request = api_request
        self.port = port
        self.password = encoded_pass
        self.headers = headers

        # Local Imports
        import utils as utilss
        self.utils = utilss.Utils(logger)

    def get_user_store(self, puuid: str):
        store_url = f"https://pd.na.a.pvp.net/store/v3/storefront/{puuid}"
        response = self.api_request("POST", store_url, headers=self.headers, data={})
        store_data = response.json()
        return store_data

    def get_user_current_state(self, puuid: str, presences_data: dict | None = None) -> int:
        """
            This function takes a player uuid, Then it translates it the user's current state.

            Parameters:
            puuid (str): The desired player's UUID.
            presences_data *Optional* (dict|None): The presence data of the user.

            Returns:
                int
                    -1: Error
                    0: Not in Valorant
                    1: In Menus
                    2: In Menus Queueing
                    3: Pregame
                    4: In-Game
                    5: Unknown State
            """
        try:
            import requests
            try:
                requests.packages.urllib3.disable_warnings()  # noqa
            except AttributeError:
                # urllib3 might not be available in this way, try alternative
                try:
                    import urllib3
                    urllib3.disable_warnings()
                except ImportError:
                    pass  # Continue without disabling warnings
        except ImportError:
            self.logger.log(1, "Requests package error. Failed to disable warnings.")
        try:
            if presences_data is None:
                with self.api_request("GET", f"https://127.0.0.1:{self.port}/chat/v4/presences",
                                      headers={"authorization": f"Basic {self.password}", "accept": "*/*",
                                               "Host": f"127.0.0.1:{self.port}"}, verify=False) as r:
                    data = r.json()
            else:
                data = presences_data

            all_user_data = data["presences"]
            for user in all_user_data:
                if user["puuid"] == puuid and user["activePlatform"] == "windows":
                    # Check if the player is playing Valorant. If not, return 0
                    if str(user["product"]).lower() != "valorant":
                        return 0

                    encoded_user_data: str = user["private"]
                    decoded_user_data = loads(b64decode(encoded_user_data))
                    state = decoded_user_data["matchPresenceData"]["sessionLoopState"]
                    party_state = decoded_user_data["partyPresenceData"]["partyState"]
                    if state == "MENUS":
                        if party_state == "DEFAULT":
                            return 1
                        elif party_state == "MATCHMAKING":
                            return 2
                        elif party_state == "MATCHMADE_GAME_STARTING":
                            return 3
                    elif state == "PREGAME":
                        return 3
                    elif state == "INGAME":
                        return 4
                    else:
                        return 5
        except Exception as e:
            traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
            self.logger.log(1, traceback_str)
        return -1

    @lru_cache(maxsize=256)
    def get_match_history(self, puuid: str, gamemode: str | None = None):
        # stats_used_game_mode = config_main.get("stats_used_game_mode", "ALL").lower()
        search = ""
        stats_used_game_mode = "same"
        if stats_used_game_mode != "all":
            if stats_used_game_mode == "same" and gamemode is not None:
                search = f"&queue={gamemode}"
            elif stats_used_game_mode != "same":
                search = f"&queue={stats_used_game_mode}"

        headers = self.headers
        url = f"https://pd.na.a.pvp.net/match-history/v1/history/{puuid}?endIndex={10}{search}"

        response = self.api_request("GET", url, headers=headers)
        history = response.json().get("History", [])
        return history

    @lru_cache(maxsize=4096)
    def get_match_details(self, match_id: str, platform: str = "PC"):
        headers = self.headers
        match_url = f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}"

        while True:
            match_response = self.api_request("GET", match_url, headers=headers)
            if match_response.status_code == 429:
                self.logger.log(2, f"Rate limited fetching match {match_id}")
            elif match_response.status_code == 200:
                return match_response.json()
            else:
                self.logger.log(1, f"Error fetching match {match_id}: {match_response.status_code}")
                return None

    def get_player_data_from_uuid(self, user_id: str, cache: dict, platform: str = "PC", gamemode: str | None = None):
        # Check the cache first to avoid redundant processing
        if user_id in cache:
            return {}, cache

        kills = 0
        deaths = 0
        wins = []
        partyIDs = {}
        headshot = []
        search = ""

        try:
            history = self.get_match_history(user_id, gamemode)

            save_match_data = None
            for i in history:
                match_id = i["MatchID"]
                match_data = self.get_match_details(match_id, platform)

                if match_data is None:
                    continue  # Skip if match data couldn't be retrieved

                player_data = match_data.get("players", [])

                for match in player_data:
                    if str(match["subject"]) == str(user_id):
                        partyId = match["partyId"]

                        if save_match_data is None:
                            if partyId not in partyIDs:
                                partyIDs[partyId] = [match["subject"]]
                            elif match["subject"] not in partyIDs[partyId]:
                                partyIDs[partyId].append(match["subject"])
                            save_match_data = player_data

                        team = match["teamId"]
                        game_team_id = match_data["teams"][0]["teamId"]
                        won = match_data["teams"][0]["won"] if game_team_id == team else match_data["teams"][1]["won"]
                        wins.append(True if won else False)
                        kills += match["stats"]["kills"]
                        deaths += match["stats"]["deaths"]

                        #agent = self.get_agent_data_from_id(match["characterId"])  # TODO | Unused

                headshot.append(round(self.utils.get_headshot_percent(match_data)[str(user_id)]))
            try:
                avg = sum(headshot) / len(headshot)
            except ZeroDivisionError:
                avg = 0

            kd_ratio = self.utils.calculate_kd(kills, deaths)
            cache[user_id] = (kd_ratio, wins, round(avg))

            return partyIDs, cache

        except Exception as e:
            traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
            self.logger.log(1, traceback_str)
            print(f"Error: {e}")
            cache[user_id] = (-1, ['Error'], -1)
            return {}, cache

    @lru_cache(maxsize=4096)
    def get_player_card_from_uuid(self, uuid: str) -> dict | None:
        #print(f"Cache not working | {uuid}")
        # Fully execute the API request, then return the data.
        response = self._fetch_player_card(uuid)
        return response

    @lru_cache(maxsize=4096)
    def _fetch_player_card(self, uuid: str) -> dict | None:
        with self.api_request("GET", f"https://valorant-api.com/v1/playercards/{uuid}") as r:
            if r.status_code == 404:
                return None
            else:
                return r.json()["data"]

    @lru_cache(maxsize=1024)
    def get_player_title_from_uuid(self, uuid: str) -> dict | None:
        with self.api_request("GET", f"https://valorant-api.com/v1/playertitles/{uuid}") as r:
            if r.status_code == 404:
                return None
            else:
                return r.json()["data"]

    @lru_cache(maxsize=1024)
    def get_mapdata_from_id(self, map_id: str) -> str | None:
        with self.api_request("GET", f"https://valorant-api.com/v1/maps") as r:
            maps = r.json()["data"]
        for map_data in maps:
            if map_data["mapUrl"] == map_id:
                return map_data['displayName']
        return None

    @lru_cache(maxsize=1024)
    def get_agent_data_from_id(self, agent_id: str) -> tuple[str, str, str] | tuple[str, None, None]:
        r = self.api_request("GET", f"https://valorant-api.com/v1/agents/{agent_id}")
        if r.status_code == 200:
            data = r.json()["data"]
            agent_name: str = data["displayName"]
            agent_icon_url: str = data["displayIconSmall"]

            agent_icon_raw: str = self.api_request("GET", f"{agent_icon_url}", headers=self.headers).content

            return agent_name, agent_icon_url, agent_icon_raw
        return "Unknown", None, None

class Shop:
    def __init__(self, auth: Auth, logger: Logger):
        self.auth = auth
        self.logger = logger
        self.api_request = auth.utils.api_request

        # Cache for expensive API calls
        self._all_skins_cache = None
        self._content_tiers_cache = {}
        self._storefront_cache = {}
        self._wallet_cache = None

    def get_daily_shop(self) -> list[dict[str, Any]]:
        """
        Fetches daily shop offers with detailed skin information.
        Returns a list of dictionaries, each containing skin details.
        """
        store_data = self._get_storefront()
        skins_panel = store_data.get("SkinsPanelLayout", {})
        offers = skins_panel.get("SingleItemStoreOffers", [])

        # Get all skins reference data once
        all_skins = self._get_all_skins_reference()

        shop_items = []
        for offer in offers:
            skin_id = str(offer.get("OfferID", ""))
            price = offer.get("Cost", {}).get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", 0)
            skin_info = self._get_skin_details(skin_id, all_skins)
            skin_info["price"] = price
            shop_items.append(skin_info)
        return shop_items

    def _get_skin_details(self, skin_id: str, all_skins: list[dict]) -> dict[str, Any]:
        """
        Fetches detailed information for a single skin offer.
        """
        skin_response = self.api_request("GET", f"https://valorant-api.com/v1/weapons/skinlevels/{skin_id}")
        skin_data = skin_response.json().get("data", {})

        name = skin_data.get("displayName", "Unknown")
        image = skin_data.get("displayIcon", "")
        video = skin_data.get("streamedVideo", "")

        rarity = self._get_skin_rarity(name, all_skins)
        return {
            "id": skin_id,
            "name": name,
            "image": image,
            "video": video,
            "rarity": rarity
        }

    def _get_skin_rarity(self, skin_name: str, all_skins: list[dict]) -> dict[str, str]:
        """
        Determines the rarity of a skin by matching its name in the reference data.
        Uses cached content tiers for better performance.
        """
        for data in all_skins:
            if data.get("displayName", "").lower() == skin_name.lower():
                tier_uuid = data.get("contentTierUuid", "")
                if tier_uuid:
                    # Check cache first
                    if tier_uuid not in self._content_tiers_cache:
                        tier_response = self.api_request("GET", f"https://valorant-api.com/v1/contenttiers/{tier_uuid}")
                        self._content_tiers_cache[tier_uuid] = tier_response.json().get("data", {})

                    tier_data = self._content_tiers_cache[tier_uuid]
                    return {
                        "name": tier_data.get("devName", ""),
                        "color": tier_data.get("highlightColor", ""),
                        "icon": tier_data.get("displayIcon", "")
                    }
        return {"name": "Unknown", "color": "", "icon": ""}

    def _get_all_skins_reference(self) -> list[dict]:
        """
        Retrieves a reference list of all skins data.
        """
        if self._all_skins_cache is None:
            response = self.api_request("GET", "https://valorant-api.com/v1/weapons/skins/")
            self._all_skins_cache = response.json().get("data", [])
        return self._all_skins_cache

    def _get_storefront(self) -> dict:
        # Use puuid as cache key since storefront is user-specific
        cache_key = self.auth.puuid
        if cache_key not in self._storefront_cache:
            store_url = f"https://pd.na.a.pvp.net/store/v3/storefront/{self.auth.puuid}"
            response = self.api_request("POST", store_url, headers=self.auth.headers, data={})
            if response.status_code == 200:
                self._storefront_cache[cache_key] = response.json()
            else:
                self.logger.log(1, f"Failed to fetch storefront for {self.auth.puuid}: {response.status_code}")
                self._storefront_cache[cache_key] = {}

        return self._storefront_cache[cache_key]

    def _get_wallet(self) -> dict:
        if self._wallet_cache is None:
            wallet_url = f"https://pd.na.a.pvp.net/store/v1/wallet/{self.auth.puuid}"
            response = self.api_request("GET", wallet_url, headers=self.auth.headers)
            if response.status_code == 200:
                self._wallet_cache = response.json()
            else:
                self.logger.log(1, f"Failed to fetch wallet: {response.status_code}")
                self._wallet_cache = {}
        return self._wallet_cache

    def get_currency(self) -> dict[str, int]:
        """
        Returns a dictionary of currency balances: VP, RP, KC.
        """
        wallet = self._get_wallet().get("Balances", {})
        if wallet:
            vp = int(wallet.get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", 0))
            rp = int(wallet.get("e59aa87c-4cbf-517a-5983-6e81511be9b7", 0))
            kc = int(wallet.get("85ca954a-41f2-ce94-9b45-8ca3dd39a00d", 0))
            return {"VP": vp, "RP": rp, "KC": kc}
        return {"VP": 0, "RP": 0, "KC": 0}
