# utils.py

import hashlib
import os
import time
from json import dumps, dump, load
import webbrowser
import requests
from colorama import Style

DATA_PATH = "data"
DEBUG = False
DEBUG_MODE = False
SAVE_DATA = False

class FakeResponse:
	"""Mimics a requests.Response object for debugging."""

	def __init__(self, json_data, status_code=200):
		self._json_data = json_data
		self.status_code = status_code

	def json(self):
		return self._json_data

	def text(self):
		return dumps(self._json_data, indent=4)

	def __enter__(self):
		"""Allows use in 'with' statements."""
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		"""Ensures no errors occur when used in a 'with' statement."""
		pass

class Utils:
	def __init__(self, logger):
		self.logger = logger

	@staticmethod
	def generate_filename(method, url, params=None, data=None):
		"""Generates a structured filename inside categorized folders."""

		# Extract endpoint path (e.g., "/stats/player" -> "stats/player")
		endpoint_path = url.replace("https://", "").strip("/")

		# Replace special characters in folder names
		safe_path = endpoint_path.replace("/", "_").replace(":", "_").replace("?", "_")  # Convert "stats/player" to "stats_player"

		# Hash request details to ensure unique filenames
		hash_input = f"{method}_{url}_{dumps(params, sort_keys=True)}_{dumps(data, sort_keys=True)}"
		hashed = hashlib.md5(hash_input.encode()).hexdigest()

		# Create directory for this request type
		folder_path = os.path.join(DATA_PATH, safe_path)
		os.makedirs(folder_path, exist_ok=True)

		return os.path.join(folder_path, f"{hashed}.json")

	@staticmethod
	def get_rate_limit_wait_time(response):
		"""Extracts wait time from rate limit headers if available."""
		reset_time = response.headers.get("Retry-After")
		if reset_time:
			wait_time = int(reset_time)
			return wait_time
		return None  # No rate limit header found

	def handle_rate_limit(self, response, url, method="GET", headers=None, params=None, data=None, json=None, verify=None):
		"""Handles rate limiting with exponential backoff and API headers."""
		wait_time = self.get_rate_limit_wait_time(response)
		if wait_time:
			if DEBUG:
				print(f"Rate limited! Retrying in {wait_time} seconds...")
			time.sleep(wait_time)
			return requests.request(method, url, params=params, json=json or data, headers=headers, verify=verify)

		return response  # No rate limit header, fallback to exponential backoff

	def api_request(self, method, url, params=None, data=None, headers=None, json=None, verify=None):
		"""Handles API requests and switches to debug mode if enabled."""
		OVERRIDE_RESPONSES = {}
		requests.packages.urllib3.disable_warnings()  # noqa


		if DEBUG_MODE:
			file_path = self.generate_filename(method, url, params, data)
			# Check for any overridden responses first.
			for base_url, response_data in OVERRIDE_RESPONSES.items():
				if url.startswith(base_url):
					return FakeResponse(response_data, response_data.get("status", 404))
			# If a stored response exists, load and return it.
			if os.path.exists(file_path):
				with open(file_path, "r") as file:
					stored_response = load(file)
				return FakeResponse(stored_response)
			else:
				print(f"No stored response for {url} - {method}. Making API request...")

		# Prepare the real request data.
		if data is None and json is not None:
			data = json
		try:
			response = requests.request(method, url, params=params, json=data, headers=headers, verify=verify)
		except requests.exceptions.ConnectionError:
			self.logger.log(1, f"Connection error for {url} - {method}")
			return FakeResponse({"message": "Failed to connect."}, 404)

		if response.status_code == 200:
			# Save the response if enabled.
			if SAVE_DATA:
				try:
					response_data = response.json()
					self.save_response(file_path, response_data)
				except requests.exceptions.JSONDecodeError:
					if DEBUG:
						print(f"Failed to decode JSON response for {url} - {method}.")
			return response

		elif response.status_code == 429:
			return self.handle_rate_limit(response, url, method, headers, params, data, json, verify)

		else:
			if response.status_code != 404:
				self.logger.log(2, f"API returned '{response.status_code}' from request '{response.url}'\n"
								   f"Using params: '{str(params)}', and data/json: {str(data) + ' // ' + str(json)}'\n")
				if DEBUG:
					print(f"API Error: {response.status_code}")
			return response

	@staticmethod
	def add_parties(partys, new_parties):
		for party_id, new_players in new_parties.items():
			if party_id in partys:
				# Add new players to the existing party, ensuring no duplicates
				partys[party_id].extend(new_players)
				partys[party_id] = list(set(partys[party_id]))  # Remove duplicates
			else:
				# Create a new party with the new players
				partys[party_id] = new_players
		return partys

	@staticmethod
	def get_headshot_percent(match_data: dict) -> dict[str, float | int]:
		def update_damage_stats(damage_dict, main_player, damage_info, host_only_mode=False):
			if not host_only_mode:
				if main_player not in damage_dict:
					damage_dict[main_player] = {"legshots": 0, "bodyshots": 0, "headshots": 0}

				damage_dict[main_player]["legshots"] += damage_info["legshots"]
				damage_dict[main_player]["bodyshots"] += damage_info["bodyshots"]
				damage_dict[main_player]["headshots"] += damage_info["headshots"]

			else:
				damage_dict["legshots"] += damage_info["legshots"]
				damage_dict["bodyshots"] += damage_info["bodyshots"]
				damage_dict["headshots"] += damage_info["headshots"]

			return damage_dict

		all_players = match_data['players']
		damage_stats = {}
		players_headshot_percent = {}

		for player in all_players:
			player_uuid = player["subject"]

			for round_stats in match_data["roundResults"]:
				# Player by Player
				for player_stat in round_stats["playerStats"]:
					# Who did the damage
					main_player = player_stat["subject"]
					try:
						# Info on that damage, damage by damage
						for hit in player_stat["damage"]:
							# Update damage stats
							damage_stats = update_damage_stats(damage_stats, main_player, hit)
					except KeyError:
						# If no damage is done to any player from that player by round
						pass
			other_damage_stats = damage_stats.get(player_uuid, {"legshots": 0, "bodyshots": 0, "headshots": 0})
			total_shots = other_damage_stats["legshots"] + other_damage_stats["bodyshots"] + other_damage_stats[
				"headshots"]
			if total_shots > 0:
				headshot_percentage = (other_damage_stats["headshots"] / total_shots) * 100
			else:
				headshot_percentage = 0
			players_headshot_percent[str(player_uuid)] = headshot_percentage
		return players_headshot_percent

	@staticmethod
	def get_rank_name_from_tier(tier: int, basic=False):
		"""Returns the rank name based on the tier."""
		if tier == 0:
			rank = "Unranked"
		else:
			rank_mapping = {
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
			rank = rank_mapping.get(int(tier), "Unknown Rank")
			if basic:
				rank = rank.split(" ")[0]
		return rank

	@staticmethod
	def calculate_kd(kills, deaths):
		if deaths == 0:
			return kills  # Stop div of zero
		return round(kills / deaths, 2)

	@staticmethod
	def save_response(file_path, data):
		"""Saves the API response for future debugging."""
		os.makedirs(DATA_PATH, exist_ok=True)
		with open(file_path, "w") as file:
			dump(data, file, indent=4)

	@staticmethod
	def color_text(text, color):
		"""Apply color to the text."""
		return f"{color}{text}{Style.RESET_ALL}"

	@staticmethod
	def download_image(url):
		"""Download image from a URL and return bytes."""
		try:
			response = requests.get(url)
			response.raise_for_status()
			return response.content
		except Exception as e:
			print(f"Failed to download image: {e}")
			return b""

	@staticmethod
	def open_url(url):
		"""Open a URL in the default web browser."""
		webbrowser.open(url)
