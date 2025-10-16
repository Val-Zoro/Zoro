# Loader.py
import threading
from functools import lru_cache
from typing import Any

import requests

request_semaphore = threading.Semaphore(3)  # Increased from 2 to 3 for better performance

class Loader:
	def __init__(self, headers, logger, puuid, port, encoded_pass, auth):
		self.headers = headers
		self.logger = logger
		self.puuid = puuid
		self.port = port
		self.encoded_pass = encoded_pass

		self.auth = auth

		self.pregame_data = None
		self.parties = None

		from Riot import Client
		from utils import Utils

		self.utils = Utils(self.logger)
		self.api_request = self.utils.api_request
		self.client = Client(logger, self.api_request, self.port, self.encoded_pass, self.headers)

		self.GAME_MODES = {
			"unrated": "Unrated",
			"competitive": "Competitive",
			"swiftplay": "Swiftplay",
			"spikerush": "Spikerush",
			"deathmatch": "Deathmatch",
			"ggteam": "Escalation",
			"hurm": "Team Deathmatch"
		}

		self.RANK_MAPPING = {
				3: "Iron 1",
				4: "Iron 2",
				5: "Iron 3",
				6: "Bronze 1",
				7: "Bronze 2",
				8: "Bronze 3",
				9: "Silver 1",
				10: "Silver 2",
				11: "Silver 3",
				12: "Gold 1",
				13: "Gold 2",
				14: "Gold 3",
				15: "Plat 1",
				16: "Plat 2",
				17: "Plat 3",
				18: "Diamond 1",
				19: "Diamond 2",
				20: "Diamond 3",
				21: "Ascendant 1",
				22: "Ascendant 2",
				23: "Ascendant 3",
				24: "Immortal 1",
				25: "Immortal 2",
				26: "Immortal 3",
				27: "Radiant"
			}

		self.DEV_PUUID_LIST = ["fe5714d7-344c-5453-90f0-9a72d8bdd947"]
		self.input_task = None

		self.temp_game_cache = {}
		self.cache = {}
		self.card_cache = {}
		self.title_cache = {}

	def clear_caches(self):
		"""Clear all caches to free memory and ensure fresh data."""
		self.get_userdata_from_id.cache_clear()
		self.get_rank_from_uuid.cache_clear()
		self.get_player_card_cached.cache_clear()
		self.get_player_title_cached.cache_clear()
		self.get_card_image_cached.cache_clear()

	def optimize_for_speed(self):
		"""Apply speed optimizations to the loader."""
		# Clear caches to ensure fresh data
		self.clear_caches()

		# Pre-warm commonly used caches
		if hasattr(self, 'DEV_PUUID_LIST') and self.DEV_PUUID_LIST:
			for puuid in self.DEV_PUUID_LIST:
				# Pre-warm user data cache
				self.get_userdata_from_id_cached(puuid, self.puuid)
				# Pre-warm rank data cache
				self.get_rank_from_uuid_cached(puuid, return_tier_also=True)

	def batch_fetch_user_data(self, user_ids: list, host_player_uuid: str | None = None):
		"""Batch fetch user data for multiple users efficiently."""
		results = {}
		for user_id in user_ids:
			try:
				user_data = self.get_userdata_from_id_cached(user_id, host_player_uuid)
				results[user_id] = user_data
			except Exception as e:
				self.logger.log(2, f"Error fetching user data for {user_id}: {str(e)}")
				results[user_id] = ("Unknown", False)
		return results

	def batch_fetch_rank_data(self, user_ids: list, platform: str = "PC", return_tier_also: bool = False):
		"""Batch fetch rank data for multiple users efficiently."""
		results = {}
		for user_id in user_ids:
			try:
				rank_data = self.get_rank_from_uuid_cached(user_id, platform, return_tier_also)
				results[user_id] = rank_data
			except Exception as e:
				self.logger.log(2, f"Error fetching rank data for {user_id}: {str(e)}")
				if return_tier_also:
					results[user_id] = ("Unranked", "0", "0")
				else:
					results[user_id] = "Unranked"
		return results

	def wait_for_data_fetching(self, threads_list, timeout: int = 5):
		"""Wait for data fetching threads to complete with timeout."""
		import time
		start_time = time.time()

		for thread in threads_list:
			if thread.is_alive():
				remaining_time = timeout - (time.time() - start_time)
				if remaining_time > 0:
					thread.join(timeout=remaining_time)
				else:
					self.logger.log(2, "Data fetching timeout reached")
					break

	def cleanup_threads(self):
		"""Clean up completed threads from the active threads list."""
		if hasattr(self, '_active_threads'):
			self._active_threads = [t for t in self._active_threads if t.is_alive()]

	def is_data_cached(self, data_type: str, identifier: str) -> bool:
		"""Check if specific data is already cached to avoid redundant API calls."""
		if data_type == "user":
			return identifier in self.cache and self.cache[identifier] is not None
		elif data_type == "rank":
			return identifier in self.cache and self.cache[identifier] is not None
		elif data_type == "card":
			return identifier in self.card_cache
		elif data_type == "title":
			return identifier in self.title_cache
		return False

	def get_cached_data(self, data_type: str, identifier: str):
		"""Get cached data if available."""
		if data_type == "user" or data_type == "rank":
			return self.cache.get(identifier)
		elif data_type == "card":
			return self.card_cache.get(identifier)
		elif data_type == "title":
			return self.title_cache.get(identifier)
		return None

	def run_optimized(self):
		"""Run the loader with all optimizations applied."""
		try:
			# Apply speed optimizations
			self.optimize_for_speed()

			# Run the main logic
			result = self.run()

			# Clean up threads
			self.cleanup_threads()

			return result
		except Exception as e:
			self.logger.log(1, f"Error in optimized run: {str(e)}")
			# Fallback to regular run
			return self.run()

	def process_party_members(self, party_data):
		"""Process party members with optimized data fetching and caching."""
		processed_members = []

		# Pre-fetch all required data in batches to reduce API calls
		member_subjects = [str(member["Subject"]) for member in party_data["Members"]]

		# Batch fetch user data for all members
		user_data_batch = self.batch_fetch_user_data(member_subjects, self.puuid)

		# Batch fetch rank data for all members
		rank_data_batch = self.batch_fetch_rank_data(member_subjects, return_tier_also=True)

		# Batch fetch card and title data for all members
		card_data_batch = {}
		title_data_batch = {}
		for member in party_data["Members"]:
			subject = str(member["Subject"])
			card_id = member["PlayerIdentity"]["PlayerCardID"]
			title_id = member["PlayerIdentity"]["PlayerTitleID"]

			# Cache card data
			if subject not in card_data_batch:
				card_data = self.get_player_card_cached(card_id)
				if card_data and card_data.get('largeArt'):
					card_img_data = self.get_card_image_cached(card_data['largeArt'])
					card_data_batch[subject] = card_img_data
				else:
					card_data_batch[subject] = None

			# Cache title data
			if subject not in title_data_batch:
				title_data = self.get_player_title_cached(title_id)
				title_data_batch[subject] = title_data.get("titleText", "") if title_data else ""

		# Process each member with cached data
		for member in party_data["Members"]:
			subject = str(member["Subject"])
			name, is_user = user_data_batch.get(subject, ("Unknown", False))
			rank, tier, rr = rank_data_batch.get(subject, ("Unknown", "0", "0"))

			# Update member data
			member["Rank"] = rank
			member["Tier"] = tier
			member["RR"] = rr
			member["is_user"] = is_user
			member["PlayerIdentity"]["AccountName"] = name
			member["PlayerIdentity"]["RawPlayerCard"] = card_data_batch.get(subject)
			member["PlayerIdentity"]["PlayerTitle"] = title_data_batch.get(subject, "")

			processed_members.append(member)

		return processed_members

	def run(self):
		# Check if on valorant

		user_state = self.client.get_user_current_state(self.puuid)

		if 1 > user_state or user_state > 4:
			return {"state": {"id": 0, "text": "Not Online"}}

		elif user_state == 1:
			party_data = self.fetch_party_data(self.fetch_party_id())
			if party_data:
				processed_members = self.process_party_members(party_data)
				party_data["Members"] = processed_members
				return {"state": {"id": 1, "text": "In menu"}, "party": {"id": party_data["ID"],
																		 "Members": party_data["Members"],
																		 "state": party_data["State"],
																		 "accessibility": party_data["Accessibility"],
																		 "mode":  self.GAME_MODES.get(party_data["MatchmakingData"]["QueueID"].lower(), str(party_data["MatchmakingData"]["QueueID"]))}}
			else:
				return {"state": {"id": 0, "text": "Not Online"}}

		elif user_state == 2:
			party_data = self.fetch_party_data(self.fetch_party_id())
			if party_data:
				processed_members = self.process_party_members(party_data)
				party_data["Members"] = processed_members
				return {"state": {"id": 2, "text": "Queueing"},
						"party": {"id": party_data["ID"],
								  "Members": party_data["Members"],
								  "state": party_data["State"],
								  "accessibility": party_data["Accessibility"],
								  "mode": self.GAME_MODES.get(party_data["MatchmakingData"]["QueueID"].lower(),
																  str(party_data["MatchmakingData"]["QueueID"]))}}
			else:
				return {"state": {"id": 0, "text": "Not Online"}}

		elif user_state == 3:
			data = self.get_pregame_data(self.cache, self.parties)
			if data is not None:
				pregame_data, self.cache, self.parties = data
				return {"state": {"id": 3, "text": "Pregame"}, "data": pregame_data}
			else:
				game_data = self.get_ingame_data(self.cache, self.parties)
				return {"state": {"id": 4, "text": "Ingame"}, "data": game_data}
		elif user_state == 4:
			game_data = self.get_ingame_data(self.cache, self.parties)
			return {"state": {"id": 4, "text": "Ingame"}, "data": game_data}
		return None

	def handle_api_error(self, error: Exception, context: str, fallback_value=None):
		"""Handle API errors with proper logging and fallback values."""
		self.logger.log(2, f"API Error in {context}: {str(error)}")
		return fallback_value

	def safe_api_request(self, method: str, url: str, headers: dict | None = None, data=None, context: str = "API Request"):
		"""Make API requests with proper error handling and fallbacks."""
		try:
			response = self.api_request(method, url, headers=headers or self.headers, data=data)
			if response.status_code in [200, 201, 202]:
				return response
			else:
				self.logger.log(2, f"API {method} {url} failed with status {response.status_code}")
				return None
		except Exception as e:
			self.handle_api_error(e, f"{context} ({method} {url})")
			return None

	def fetch_party_id(self):
		"""Fetch the party ID for the current user with improved error handling."""
		try:
			with self.api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(self.puuid)}",
								  headers=self.headers) as r:
				if r.status_code == 400:
					error_data = r.json()
					is_console = str(error_data.get("errorCode")) == "PLAYER_PLATFORM_TYPE_MISMATCH"
					if is_console:
						with self.api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(self.puuid)}",
											  headers=self.headers) as r2:
							return r2.json().get('CurrentPartyID')
					else:
						self.logger.log(1,
										f"Error fetching party details. Error: {error_data}")
						return None
				elif r.status_code == 404:
					return None
				else:
					return r.json().get('CurrentPartyID')
		except Exception as e:
			self.logger.log(1, f"Exception in fetch_party_id: {str(e)}")
			return None

	def fetch_party_data(self, party_id: str | None) -> dict[str, Any]:
		"""Fetch the details of a party using its ID with resilient error handling."""
		if not party_id:
			return {}
		url = f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}"
		try:
			response = requests.get(url, headers=self.headers, timeout=5.0)
			response.raise_for_status()
			return response.json()
		except requests.RequestException as exc:
			self.logger.log(2, f"Failed to fetch party data for {party_id}: {exc}")
			return {}


	@lru_cache(maxsize=1024)
	def get_userdata_from_id(self, user_id: str, host_player_uuid: str | None = None) -> tuple[str, bool]:
		host_player = "Unknown"

		req = self.api_request("PUT", f"https://pd.na.a.pvp.net/name-service/v2/players", headers=self.headers,
							   data=[user_id])
		if req.status_code == 200:
			user_info = req.json()[0]
			user_name = f"{user_info['GameName']}#{user_info['TagLine']}"
			if host_player_uuid is not None:
				if user_id == host_player_uuid:
					host_player = f"(You) {user_name}"
					return host_player, True
				else:
					host_player = user_name
			else:
				host_player = user_name
		elif req.status_code == 429:
			self.logger.log(2, "Rate Limited | get_userdata_from_id")
		else:
			self.logger.log(1, f"Error in get_userdata_from_id | {req.status_code} | {req.json()}")
			return "null", False

		return host_player, False

	def get_userdata_from_id_cached(self, user_id: str, host_player_uuid: str | None = None) -> tuple[str, bool]:
		"""Cached version of get_userdata_from_id for batch processing."""
		return self.get_userdata_from_id(user_id, host_player_uuid)

	@lru_cache(maxsize=6)
	def get_rank_from_uuid(self, user_id: str, platform: str = "PC", return_tier_also: bool = False) -> str | tuple[str, str, str]:
		rank_tier = 0
		rank_rr = 0

		if platform == "PC":
			r = self.api_request("GET",
								 f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=competitive&endIndex=1",
								 headers=self.headers)
			try:
				rank_tier = r.json()["Matches"][0]["TierAfterUpdate"]
				rank_rr = r.json()["Matches"][0]["RankedRatingAfterUpdate"]
			except:
				if return_tier_also:
					return "Unranked", "0", "0"
		elif platform == "CONSOLE":
			r = self.api_request("GET",
								 f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=console_competitive&endIndex=1",
								 headers=self.headers)
			try:
				rank_tier = r.json()["Matches"][0]["TierAfterUpdate"]
				rank_rr = r.json()["Matches"][0]["RankedRatingAfterUpdate"]
			except:
				return "Error", "-1", "-1"

		if rank_tier == 0:
			rank = "Unranked"
		else:
			rank = self.RANK_MAPPING.get(int(rank_tier), "Unknown")
		if return_tier_also:
			return rank, str(rank_tier), str(rank_rr)
		return rank

	def get_rank_from_uuid_cached(self, user_id: str, platform: str = "PC", return_tier_also: bool = False) -> str | tuple[str, str, str]:
		"""Cached version of get_rank_from_uuid for batch processing."""
		return self.get_rank_from_uuid(user_id, platform, return_tier_also)

	@lru_cache(maxsize=512)
	def get_player_card_cached(self, card_id: str):
		"""Cached version of get_player_card_from_uuid."""
		return self.client.get_player_card_from_uuid(card_id)

	@lru_cache(maxsize=512)
	def get_player_title_cached(self, title_id: str):
		"""Cached version of get_player_title_from_uuid."""
		return self.client.get_player_title_from_uuid(title_id)

	@lru_cache(maxsize=128)
	def get_card_image_cached(self, card_url: str):
		"""Cached version of card image fetching."""
		try:
			card_response = self.api_request("GET", card_url, headers=self.headers)
			return getattr(card_response, 'content', b'')
		except:
			return None

	def get_pregame_data(self, cache: dict | None = None, partys: dict | None = None):
		if partys is None:
			partys = {}
		if cache is None:
			cache = {}

		def fetch_player_data(player_id, platform):
			nonlocal partys, cache
			with request_semaphore:
				party_data, new_cache = self.client.get_player_data_from_uuid(player_id, cache or {}, platform)
				partys = self.utils.add_parties(partys, party_data)
				if cache is not None:
					cache.update(new_cache)
			return None

		r = self.api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/players/{self.puuid}",
		                     headers=self.headers)
		if r.status_code != 404 and r.status_code != 400:
			pregame_data = r.json()
			if pregame_data["MatchID"]:
				with self.api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{pregame_data['MatchID']}",
								 headers=self.headers) as r:
					match_data = r.json()

				# Split into what is needed
				map_name = self.client.get_mapdata_from_id(match_data["MapID"])
				gamemode_name = match_data["QueueID"]
				data = {"map": map_name, "gamemode": gamemode_name, "players": [], "enemy_lock_count": match_data["EnemyTeamLockCount"], "enemy_total_count": match_data["EnemyTeamSize"]}

				party_exists = []
				party_number = 1
				for player in match_data["AllyTeam"]["Players"]:
					subject = player["Subject"]
					name, is_user = self.get_userdata_from_id_cached(subject, self.puuid)
					rank, tier, rr = self.get_rank_from_uuid_cached(subject, return_tier_also=True)

					agent_id = player["CharacterID"]

					if agent_id != "":
						agent_name, _, agent_icon_raw = self.client.get_agent_data_from_id(agent_id)
					else:
						agent_name = "None"
						agent_icon_raw = None

					# Get player stats - only fetch if not already cached
					if not cache.get(subject):
						thread = threading.Thread(target=fetch_player_data, args=(subject, "PC"))
						thread.start()
						# Store thread reference for potential waiting
						if not hasattr(self, '_active_threads'):
							self._active_threads = []
						self._active_threads.append(thread)

					"""for party_id, members in partys.items():
						if len(members) > 1:
							if player["Subject"] in members:
								for existing_party in party_exists:
									if existing_party[0] == party_id:
										#party_symbol = get_party_symbol(int(existing_party[1]), True)
										break
								else:
									party_exists.append([party_id, party_number])
									#party_symbol = get_party_symbol(int(party_number), True)
									party_number += 1
									break"""
					# print("parties:", party_exists, partys, cache)

					kd, wins, hs = cache.get(player["Subject"], (None, None, None))
					player_data = { "name": name,
									"puuid": player["Subject"],
									"agent": agent_name,
					                "agent_icon": agent_icon_raw,
									"agent_state": player["CharacterSelectionState"],
					                "is_user": is_user,
									"tier": tier,
									"rank": rank,
									"level": player["PlayerIdentity"]["AccountLevel"],
					                # "player_card": card_img_data, | UNUSED
					                "kd": kd,
					                "hs": hs,
					                "match_history": wins,
					                "party_data": party_number
								   }
					data["players"].append(player_data)
				return data, cache, partys
			print("Error: No MatchID found in pregame data.")
			return None, cache, partys
		else:
			if self.auth.log_in():
				# Avoid redundant recursive calls by using a different approach
				return self.get_pregame_data(cache, partys)
			return None, cache, partys


	def get_ingame_data(self, cache: dict | None = None, partys: dict | None = None):
		if cache is None:
			cache = {}
		if partys is None:
			partys = {}

		def fetch_player_data(player_id, platform):
			nonlocal partys, cache
			with request_semaphore:
				party_data, new_cache = self.client.get_player_data_from_uuid(player_id, cache or {}, platform)
				partys = self.utils.add_parties(partys, party_data)
				if cache is not None:
					cache.update(new_cache)
			return None

		r = self.api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{self.puuid}",
		                     headers=self.headers)
		if r.status_code != 404 and r.status_code != 400:
			pregame_data = r.json()
			if pregame_data.get("MatchID") is not None:
				with self.api_request("GET",
				                      f"https://glz-na-1.na.a.pvp.net/core-game/v1/matches/{pregame_data['MatchID']}",
				                      headers=self.headers) as r:
					match_data = r.json()

				try:
					gamemode_name = str(match_data["MatchmakingData"]["QueueID"]).capitalize()
					is_solo = False
				except TypeError:
					gamemode_name = match_data["ProvisioningFlow"]
					if gamemode_name == "ShootingRange":
						gamemode_name = "Shooting Range"
					if gamemode_name == "ReplayNewPlayerExperience":
						gamemode_name = "Tutorial"
					is_solo = True

				# Split into what is needed
				map_name = self.client.get_mapdata_from_id(match_data["MapID"]) if not is_solo else "The Range"

				data = {"map": map_name, "gamemode": gamemode_name, "players": []}

				party_exists = []
				party_number = len(partys) + 1

				for player in match_data["Players"]:
					subject = player["Subject"]
					name, is_user = self.get_userdata_from_id_cached(subject, self.puuid)
					rank, tier, rr = self.get_rank_from_uuid_cached(subject, return_tier_also=True)

					agent_id = player["CharacterID"]

					if agent_id != "":
						agent_name, _, agent_icon_raw = self.client.get_agent_data_from_id(agent_id)
					else:
						agent_name = "None"
						agent_icon_raw = None

					# Get player stats - only fetch if not already cached
					if not cache.get(subject):
						thread = threading.Thread(target=fetch_player_data, args=(subject, "PC"))
						thread.start()
						# Store thread reference for potential waiting
						if not hasattr(self, '_active_threads'):
							self._active_threads = []
						self._active_threads.append(thread)

					"""for party_id, members in partys.items():
						if len(members) > 1:
							if player["Subject"] in members:
								for existing_party in party_exists:
									if existing_party[0] == party_id:
										# party_symbol = get_party_symbol(int(existing_party[1]), True)
										break
								else:
									party_exists.append([party_id, party_number])
									# party_symbol = get_party_symbol(int(party_number), True)
									party_number += 1
									break"""
					# print("parties:", party_exists, partys, cache)

					kd, wins, hs = cache.get(player["Subject"], (None, None, None))
					player_data = {"name": name,
					               "puuid": player["Subject"],
					               "team": player["TeamID"],
					               "agent": agent_name,
					               "agent_icon": agent_icon_raw,
					               "is_user": is_user,
					               "tier": tier,
					               "rank": rank,
					               "level": player["PlayerIdentity"]["AccountLevel"],
					               # "player_card": card_img_data, | UNUSED
					               "kd": kd,
					               "hs": hs,
					               "match_history": wins,
					               "party_data": party_number
					               }
					data["players"].append(player_data)
				return data
			return None
		else:
			print("Trying to re-auth...")
			if self.auth.log_in():
				print("Re-auth successful, retrying...")
				# Avoid redundant recursive calls by using a different approach
				return self.get_ingame_data(cache, partys)
			return None
