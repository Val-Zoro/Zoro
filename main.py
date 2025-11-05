VERSION = "v2.5.0"

import asyncio
import threading
import time
import os
import traceback
import sys
import colorama
import requests
import hashlib
import tkinter
import argparse
import nest_asyncio
import configparser

from math import tanh
from typing import Any, Dict, Optional, Tuple, List, Callable, Mapping, Sequence
from json import dump, dumps, loads, load
from platform import system, version
# from wmi import WMI | Removed to avoid dependency issues on non-Windows systems
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from io import StringIO
from colorama import Fore, Style
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry  # noqa | Ignore, should work fine
from urllib3 import disable_warnings
from PIL import Image, ImageTk
from datetime import datetime, timedelta
from pypresence import Presence
from contextlib import suppress
from functools import lru_cache
from collections import deque
from dataclasses import dataclass
from pathlib import Path


from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import pretty
from rich.text import Text
from rich.columns import Columns

from rich.live import Live
from rich.spinner import Spinner

from tkinter import ttk, messagebox

console = Console()
pretty.install()

DEBUG = False
DEBUG_MODE = False
SAVE_DATA = False

val_token = ""
val_access_token = ""
val_entitlements_token = ""
val_uuid = ""
region = ""

internal_api_headers = {}
internal_api_headers_console = {}

password = ""
port = ""

MAX_CONCURRENT_REQUESTS = 2
request_semaphore = threading.Semaphore(MAX_CONCURRENT_REQUESTS)

input_task = None


async def stop_input_listener() -> None:
        """Cancel the active input listener task if one is running."""
        global input_task

        if input_task is not None and not input_task.done():
                input_task.cancel()
                with suppress(asyncio.CancelledError):
                        await input_task
        input_task = None

GAME_MODES = {
	"unrated": "Unrated",
	"competitive": "Competitive",
	"swiftplay": "Swiftplay",
	"spikerush": "Spikerush",
	"deathmatch": "Deathmatch",
	"ggteam": "Escalation",
	"hurm": "Team Deathmatch"
}

CONFIG_FILE = "config.ini"  # Name / Path for the config file
CLIENT_ID = 1354365908054708388  # For discord RPC

DEV_PUUID_LIST = ["fe5714d7-344c-5453-90f0-9a72d8bdd947"]  # Private Dev PUUIDs for marking devs in-game


DATA_PATH = "data"
if not os.path.exists(DATA_PATH):
	os.mkdir(DATA_PATH)

pub_key = ("-----BEGIN PUBLIC KEY-----\n"
		   "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqIKYJWIl6Wif397yi3P+\n"
		   "YnVZ9ExhGvuUpECU+BhpnJkP1pHJldurnKfpIdGhsiTblzlFvMS5y3wdKNmtpIW7\n"
		   "8KVC8bL7FwLShmMBQNkEL4GvZfgGHYbAlJOXOiWuqDk/CS28ccZyEzAkxT4WY4H2\n"
		   "BWVVBPax72ksJL2oMOxYJVZg2w3P3LbWNfcrgAC1/HPVzmuYka0IDo9TevbCwccC\n"
		   "yNS3GlJ6g4E7yp8RIsFyEoq7DueHuK+zkvgpmb5eLRg8Ssq9t6bCcnx6Sl2hb4n/\n"
		   "5OmRNvohCFM3WpP1vAdNxrsQT8uSuExbH4g7uDT/l5+ZdpxytzEzGdvPezmPiXhL\n"
		   "5QIDAQAB\n"
		   "-----END PUBLIC KEY-----")

BANNER = """
██╗   ██╗ █████╗ ██╗      ██████╗ ██████╗  █████╗ ███╗   ██╗████████╗    ███████╗ ██████╗ ██████╗  ██████╗ 
██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝    ╚══███╔╝██╔═══██╗██╔══██╗██╔═══██╗
██║   ██║███████║██║     ██║   ██║██████╔╝███████║██╔██╗ ██║   ██║         ███╔╝ ██║   ██║██████╔╝██║   ██║
╚██╗ ██╔╝██╔══██║██║     ██║   ██║██╔══██╗██╔══██║██║╚██╗██║   ██║        ███╔╝  ██║   ██║██╔══██╗██║   ██║
 ╚████╔╝ ██║  ██║███████╗╚██████╔╝██║  ██║██║  ██║██║ ╚████║   ██║       ███████╗╚██████╔╝██║  ██║╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
"""


class Logger:
	def __init__(self, app_name: str, file_name: str, file_ending: str = ".log"):
		self.app_name = app_name
		self.file_name = file_name
		self.file_ending = file_ending

		self.VERSION = "v1.6.5"

		self.LEVELS = {1: f"Error",
					   2: f"Warning",
					   3: f"Info",
					   4: f"Debug"}
		self.MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
		self.LOG_TIME_INTERVAL = timedelta(days=1)  # 1 day

		self.key = None
		self.hwid = None

	def __get_sys_hwid(self):
		# 	c = WMI()
		# 	self.hwid = c.Win32_ComputerSystemProduct()[0].UUID, c.Win32_BaseBoard()[0].SerialNumber
		self.hwid = ("Unknown", "Unknown")

	def _encrypt_message(self, message: str) -> str:
		try:
			cipher_rsa = PKCS1_OAEP.new(self.key)
		except Exception:
			raise (ValueError(f"[Logger] Public key not loaded, cannot encrypt log message."))

		aes_key = get_random_bytes(16)

		cipher_aes = AES.new(aes_key, AES.MODE_CBC)

		encrypted_message = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))

		encrypted_aes_key = cipher_rsa.encrypt(aes_key)

		encrypted_message = b64encode(encrypted_aes_key + cipher_aes.iv + encrypted_message).decode('utf-8')

		return encrypted_message

	@staticmethod
	def _timestamp():
		return datetime.now()

	def _format_message(self, level: int, message: str) -> str:
		level_name = self.LEVELS.get(level, "Unknown")
		timestamp_str = self._timestamp().strftime("%Y-%m-%d %H:%M:%S")
		return f"{timestamp_str} - {level_name}: {message}"

	def _get_log_filename(self, hit_mix_size: bool = False) -> str:
		now = self._timestamp()
		if not hit_mix_size:
			return f"{self.file_name}_{now.strftime('%Y-%m-%d')}{self.file_ending}"
		else:
			return f"{self.file_name}_{now.strftime('%Y-%m-%d-%H%M%S')}{self.file_ending}"

	def _is_file_large(self, full_log_file_name: str) -> bool:
		return os.path.exists(full_log_file_name) and os.path.getsize(full_log_file_name) >= self.MAX_FILE_SIZE

	def _log_file_header(self):
		return (f"\n"
				f"============================================================\n"
				f"Application Name:    {self.app_name}\n"
				f"Version:             {self.VERSION}\n"
				f"Log File Created:    {self._timestamp()}\n"
				f"Log Levels:          [DEBUG | INFO | WARNING | ERROR]\n"
				f"------------------------------------------------------------\n"
				f"Hostname:            [Null]\n"
				f"Operating System:    [{system()}, {version()}]\n"
				f"HWID:                {self.hwid}\n"
				f"------------------------------------------------------------\n"
				f"Log Format:          [Timestamp] [Log Level] [Message]\n\n"
				f"============================================================\n\n"
				f"Log Start:\n")

	def load_public_key(self, key: str):
		self.key = RSA.import_key(key)

	def log(self, level: int, message: str) -> int:
		if level not in self.LEVELS:
			return -1  # Invalid level

		current_time = self._timestamp()
		log_filename = self._get_log_filename()

		if "/" in log_filename:
			file_path = log_filename.split("/")[0]
			if not os.path.exists(file_path):
				os.mkdir(file_path)

		# Check if the file needs to be rotated
		if self._is_file_large(log_filename):
			log_filename = self._get_log_filename(True)
		elif os.path.exists(log_filename) and (
				current_time - datetime.fromtimestamp(os.path.getmtime(log_filename))) > self.LOG_TIME_INTERVAL:
			log_filename = self._get_log_filename(False)

		try:
			self.__get_sys_hwid()

			# Prepare formatted message once
			_formatted = self._format_message(level, message)

			if DEBUG:
				console.print(_formatted)

			if os.path.exists(log_filename):
				with open(log_filename, "a") as f:
					f.write(self._encrypt_message(_formatted) + "\n")
			else:
				with open(log_filename, "w") as f:
					f.write(self._encrypt_message(self._log_file_header()) + "\n")
					f.write(self._encrypt_message(_formatted) + "\n")

		except IOError as e:
			console.print(f"Error writing to log file: {e}")
			return -2  # File I/O error

		return 1  # Success


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


def generate_filename(method, url, params=None, data=None):
	"""Generates a structured filename inside categorized folders."""

	# Extract endpoint path (e.g., "/stats/player" -> "stats/player")
	endpoint_path = url.replace("https://", "").strip("/")

	# Replace special characters in folder names
	safe_path = endpoint_path.replace("/", "_").replace(":", "_").replace("?",
																		  "_")  # Convert "stats/player" to "stats_player"

	# Hash request details to ensure unique filenames
	hash_input = f"{method}_{url}_{dumps(params, sort_keys=True)}_{dumps(data, sort_keys=True)}"
	hashed = hashlib.sha256(hash_input.encode()).hexdigest()

	# Create directory for this request type
	folder_path = os.path.join(DATA_PATH, safe_path)
	os.makedirs(folder_path, exist_ok=True)

	return os.path.join(folder_path, f"{hashed}.json")


def get_rate_limit_wait_time(response):
	"""Extracts wait time from rate limit headers if available."""
	reset_time = response.headers.get("Retry-After")
	if reset_time:
		wait_time = int(reset_time)
		return wait_time
	return None  # No rate limit header found


def handle_rate_limit(response, url, method="GET", headers=None, params=None, data=None, json=None, verify=None):
	"""Handles rate limiting with exponential backoff and API headers."""
	wait_time = get_rate_limit_wait_time(response)
	if wait_time:
		if DEBUG:
			logger.log(4, f"Rate limited! Retrying in {wait_time} seconds...")
		time.sleep(wait_time)
		# Reuse a shared session with timeout
		return SESSION.request(method, url, params=params, json=json or data, headers=headers, verify=verify,
							   timeout=REQUEST_TIMEOUT)

	return response  # No rate limit header, fallback to exponential backoff


def api_request(method, url, params=None, data=None, headers=None, json=None, verify=None):
	"""Handles API requests and switches to debug mode if enabled."""

	OVERRIDE_RESPONSES = {
		"https://glz-na-1.na.a.pvp.net/core-game/": {"status": 404},  # Stop from connecting to the data core game
		"https://glz-na-1.na.a.pvp.net/pregame/": {"status": 404},  # Stop from connecting to the data per game
	}

	disable_warnings()  # noqa

	if DEBUG_MODE:
		file_path = generate_filename(method, url, params, data)
		for base_url, response_data in OVERRIDE_RESPONSES.items():
			if url.startswith(base_url):
				return FakeResponse(response_data, response_data.get("status", 404))
		# Load stored response
		if os.path.exists(file_path):
			with open(file_path, "r") as file:
				response_data = load(file)
			return FakeResponse(response_data)  # Return a fake response object
		else:
			console.print(f"No stored response for {url} - {method}")

	# If not in debug mode, make a real API request
	if data is None and json is not None:
		data = json
	# Reuse shared session with connection pooling and timeouts
	response = SESSION.request(method, url, params=params, json=data, headers=headers, verify=verify,
							   timeout=REQUEST_TIMEOUT)

	if response.status_code == 200:
		if SAVE_DATA:
			response_data = response.json()
			file_path = generate_filename(method, url, params, data)
			save_response(file_path, response_data)  # Store for debugging
		return response
	elif response.status_code == 429:
		return handle_rate_limit(response, url, method, headers, params, data, json, verify)
	else:
		if response.status_code != 404:
			logger.log(2,
					   f"API returned '{response.status_code}' from request '{response.url}'\nUsing params: '{str(params)}, Using data/json: {str(data) + ' // ' + str(json)}'\n")
			if DEBUG:
				console.print(f"API Error: {response.status_code}")
		return response


def save_response(file_path, data):
	"""Saves the API response for future debugging."""
	os.makedirs(DATA_PATH, exist_ok=True)
	with open(file_path, "w") as file:
		dump(data, file, indent=4)


async def get_user_data_from_riot_client() -> tuple[str, str, str] | None:
	global password, port

	try:

		# get lockfile password
		file_path = os.getenv("localappdata")
		try:
			with open(f"{file_path}\\Riot Games\\Riot Client\\Config\\lockfile", "r") as f:
				lockfile_data = f.read()
		except:
			console.print("Riot Client isn't logged into an account!")
			return None
		# Base 64 encode the password
		password = b64encode(f"riot:{str(lockfile_data.split(':')[3])}".encode("ASCII")).decode()
		# Get the port the WS is running on
		port = str(lockfile_data.split(":")[2])

		return_data = {}

		if password is not None:
			# Make secure connection with the WS
			# Get user login tokens
			try:
				with api_request("GET",
								 f"https://127.0.0.1:{port}/entitlements/v1/token",
								 headers={"authorization": f"Basic {password}", "accept": "*/*",
										  "Host": f"127.0.0.1:{port}"}, verify=False
								 ) as r:
					return_data = r.json()
			except Exception:
				console.print("Please make sure Riot Client is open!")
			return return_data["accessToken"], return_data["token"], return_data["subject"]
		else:
			raise Exception("Riot Client Login Password Not Found!")
	except Exception as e:
		console.print(color_text("Please make sure you are logged into a Riot Account!", Fore.CYAN))
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, f"Log In Failed!\nData: {return_data}\nTraceback: {traceback_str}")
	return None


async def log_in() -> bool:
	global val_token, val_access_token, val_entitlements_token, val_uuid
	user_data = await get_user_data_from_riot_client()

	if user_data is not None:
		val_token = "Bearer"
		val_access_token = user_data[0]
		val_entitlements_token = user_data[1]
		val_uuid = user_data[2]

		get_headers()

		return True
	return False


def get_headers():
	global internal_api_headers, internal_api_headers_console

	r = api_request("GET", "https://valorant-api.com/v1/version")
	client_version = r.json()["data"]["riotClientVersion"]

	headers_pc = {
		"X-Riot-Entitlements-JWT": f"{val_entitlements_token}",
		"Authorization": f"Bearer {val_access_token}",
		"X-Riot-ClientPlatform": "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
		"X-Riot-ClientVersion": client_version,
		"Content-Type": "application/json"
	}
	headers_console = {
		"X-Riot-Entitlements-JWT": f"{val_entitlements_token}",
		"Authorization": f"Bearer {val_access_token}",
		"X-Riot-ClientPlatform": "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
		"X-Riot-ClientVersion": client_version
	}

	internal_api_headers = headers_pc.copy()
	internal_api_headers_console = headers_console.copy()


class ToolTip:
	"""
	Basic tooltip that appears on mouse hover.
	Usage:
		tooltip = ToolTip(widget, text="Some info")
	"""

	def __init__(self, widget, text, bg="#2a2a2a", fg="white"):
		self.widget = widget
		self.text = text
		self.tooltip_window = None
		self.bg = bg
		self.fg = fg
		widget.bind("<Enter>", self.show_tooltip)
		widget.bind("<Leave>", self.hide_tooltip)

	def show_tooltip(self, event=None):
		if self.tooltip_window or not self.text:
			return
		x = self.widget.winfo_rootx() + 20
		y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
		self.tooltip_window = tw = tkinter.Toplevel(self.widget)
		tw.wm_overrideredirect(True)
		tw.wm_geometry(f"+{x}+{y}")

		label = tkinter.Label(
			tw,
			text=self.text,
			justify="left",
			background=self.bg,
			foreground=self.fg,
			relief="solid",
			borderwidth=1,
			font=("Helvetica", 9, "normal")
		)
		label.pack(ipadx=5, ipady=3)

	def hide_tooltip(self, event=None):
		if self.tooltip_window:
			self.tooltip_window.destroy()
			self.tooltip_window = None


image_cache = {}


def load_image(url, size=None):
	"""Load and optionally resize an image from a URL using caching."""
	if url in image_cache:
		img = image_cache[url]
	else:
		try:
			img = Image.open(requests.get(url, stream=True).raw)
			image_cache[url] = img
		except Exception as e:
			console.print(f"Error loading image from {url}: {e}")
			return None
	if size:
		img = img.resize(size, Image.Resampling.LANCZOS)
	return img


class ValorantShopChecker:
	def __init__(self):
		self.val_uuid = val_uuid
		self.data_path = "data"
		self.internal_api_headers = internal_api_headers
		self.logger = logger
		self.dark_mode = True

	async def run(self):
		"""
		Main method to load the shop data, process the API responses,
		and display the GUI with the collected information.
		"""
		# await log_in()

		try:
			# -----------------------------------------------------------
			# Set up API headers and fetch store data
			# -----------------------------------------------------------
			get_headers()
			store_url = f"https://pd.na.a.pvp.net/store/v3/storefront/{self.val_uuid}"
			response = api_request("POST", store_url, headers=self.internal_api_headers, data={})
			store_data = response.json()

			# Save the raw store data to a file for debugging/auditing
			if DEBUG:
				with open(f"{self.data_path}/data.json", "w") as file:
					dump(store_data, file, indent=4)

			# -----------------------------------------------------------
			# Fetch and extract wallet data
			# -----------------------------------------------------------
			wallet_url = f"https://pd.na.a.pvp.net/store/v1/wallet/{self.val_uuid}"
			wallet_response = api_request("GET", wallet_url, headers=self.internal_api_headers)
			wallet_data = wallet_response.json()
			balances = wallet_data.get("Balances", {})

			# Valorant Points, Radianite Points, Kingdom Credits and their icons
			vp = balances.get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", 0)
			rp = balances.get("e59aa87c-4cbf-517a-5983-6e81511be9b7", 0)
			kc = balances.get("85ca954a-41f2-ce94-9b45-8ca3dd39a00d", 0)

			vp_icon = "https://media.valorant-api.com/currencies/85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741/displayicon.png"
			rp_icon = "https://media.valorant-api.com/currencies/e59aa87c-4cbf-517a-5983-6e81511be9b7/displayicon.png"
			kc_icon = "https://media.valorant-api.com/currencies/85ca954a-41f2-ce94-9b45-8ca3dd39a00d/displayicon.png"

			# -----------------------------------------------------------
			# Process Bundle Data
			# -----------------------------------------------------------
			bundles_uuid = []
			bundle_prices = []
			bundle_items = {}
			bundle_duration = None  # Default value if no bundles are found
			featured_bundle = store_data.get('FeaturedBundle', {})

			if 'Bundles' in featured_bundle:
				for bundle in featured_bundle['Bundles']:
					bundle_uuid = bundle.get('DataAssetID', '')
					bundles_uuid.append(bundle_uuid)

					bundle_items[bundle_uuid] = []

					# Calculate total discounted price from all items in the bundle
					bundle_prices.append((bundle.get("TotalBaseCost", {"85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741": -1}).get(
						"85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", -1), bundle.get("TotalDiscountedCost", {
						"85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741": -1}).get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", -1)))

					# Get a reference list of all skins data
					all_skins_response = api_request("GET", "https://valorant-api.com/v1/weapons/skins/")
					all_skins_data = all_skins_response.json().get("data", [])

					# Get all items in the bundle.
					for itemOffer in bundle["ItemOffers"]:
						is_skin = False

						item_uuid = itemOffer["Offer"]["OfferID"]
						item_type_uuid = itemOffer["Offer"]["Rewards"][0]["ItemTypeID"]
						item_cost = itemOffer["Offer"]["Cost"]["85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741"]
						# Check what item it is
						# If Weapon Skin
						if item_type_uuid == "e7c63390-eda7-46e0-bb7a-a6abdacd2433":
							item_data = api_request("GET",
													f"https://valorant-api.com/v1/weapons/skinlevels/{item_uuid}").json()
							is_skin = True
						# If Buddy
						elif item_type_uuid == "dd3bf334-87f3-40bd-b043-682a57a8dc3a":
							item_data = api_request("GET",
													f"https://valorant-api.com/v1/buddies/levels/{item_uuid}").json()
						# If Spray
						elif item_type_uuid == "d5f120f8-ff8c-4aac-92ea-f2b5acbe9475":
							item_data = api_request("GET", f"https://valorant-api.com/v1/sprays/{item_uuid}").json()
						# If Player Card
						elif item_type_uuid == "3f296c07-64c3-494c-923b-fe692a4fa1bd":
							item_data = api_request("GET",
													f"https://valorant-api.com/v1/playercards/{item_uuid}").json()
						# If Player Title
						elif item_type_uuid == "de7caa6b-adf7-4588-bbd1-143831e786c6":
							item_data = api_request("GET",
													f"https://valorant-api.com/v1/playertitles/{item_uuid}").json()
						else:
							item_data = {"data": {"displayName": "null",
												  "displayIcon": "https://img.icons8.com/liquid-glass/48/no-image.png"}}  # FIXME | Replace with an image not null
						#console.print(item_data)
						if item_data.get("status", 404) == 200 and item_data.get("data"):
							item_name: str = item_data["data"]["displayName"]
							try:
								item_icon: str = item_data["data"].get(
									"displayIcon")  # TODO | Add fallback image if none
							except KeyError:
								item_icon = ""  # TODO | Add fallback image if none
						else:
							item_name = "Unknown"
							item_icon = ""  # TODO | Add fallback image if none
						skin_rarity = []
						if is_skin and item_data.get("status", 404) == 200:
							for data in all_skins_data:
								if data.get("displayName", "").lower() == item_name.lower():
									tier_uuid = data.get("contentTierUuid", "")
									if tier_uuid:
										tier_response = api_request("GET",
																	f"https://valorant-api.com/v1/contenttiers/{tier_uuid}")
										tier_data = tier_response.json().get("data", {})
										skin_rarity = [
											tier_data.get("devName", ""),
											tier_data.get("highlightColor", ""),
											tier_data.get("displayIcon", "")
										]
										break
						else:
							skin_rarity = ["N/A", "4A4A4A", "https://img.icons8.com/liquid-glass/48/no-image.png"]
						bundle_items[bundle_uuid].append((item_name, item_icon, item_cost, skin_rarity))

					# Assuming all bundles share the same duration, take the last one
					bundle_duration = bundle.get("DurationRemainingInSeconds")

			# -----------------------------------------------------------
			# Process Daily Shop Skins Data
			# -----------------------------------------------------------
			skins_panel = store_data.get("SkinsPanelLayout", {})
			skin_duration = skins_panel.get("SingleItemOffersRemainingDurationInSeconds")
			daily_shop_offers = skins_panel.get("SingleItemStoreOffers", [])

			skin_ids = []
			skin_prices = []
			for offer in daily_shop_offers:
				skin_id = str(offer.get("OfferID", ''))
				skin_ids.append(skin_id)

				# Get cost from the wallet currency (Valorant Points)
				cost = offer.get("Cost", {}).get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", 0)
				skin_prices.append(str(cost))

			# -----------------------------------------------------------
			# Retrieve Detailed Skin Information
			# -----------------------------------------------------------
			skin_names = []
			skin_images = []
			skin_videos = []
			skin_rarity = []

			# Get a reference list of all skins data
			all_skins_response = api_request("GET", "https://valorant-api.com/v1/weapons/skins/")
			all_skins_data = all_skins_response.json().get("data", [])

			for skin_id in skin_ids:
				skin_response = api_request("GET", f"https://valorant-api.com/v1/weapons/skinlevels/{skin_id}")
				skin_data = skin_response.json().get('data', {})

				name = skin_data.get('displayName', 'Unknown')
				skin_names.append(name)
				skin_images.append(skin_data.get('displayIcon', ''))
				skin_videos.append(skin_data.get('streamedVideo', ''))

				# Determine skin rarity by matching the skin name in the reference data
				rarity_found = False
				for data in all_skins_data:
					if data.get("displayName", "").lower() == name.lower():
						tier_uuid = data.get("contentTierUuid", "")
						if tier_uuid:
							tier_response = api_request("GET", f"https://valorant-api.com/v1/contenttiers/{tier_uuid}")
							tier_data = tier_response.json().get("data", {})
							skin_rarity.append((
								tier_data.get("devName", ""),
								tier_data.get("highlightColor", ""),
								tier_data.get("displayIcon", "")
							))
							rarity_found = True
							break
				if not rarity_found:
					skin_rarity.append(("Unknown", "", ""))

			# -----------------------------------------------------------
			# Retrieve Bundle Details (Names and Images)
			# -----------------------------------------------------------
			current_bundles = []
			bundles_images = []
			for bundle_uuid in bundles_uuid:
				bundle_response = api_request("GET", f"https://valorant-api.com/v1/bundles/{bundle_uuid}")
				bundle_data = bundle_response.json().get('data', {})
				current_bundles.append((bundle_data.get('displayName', 'Unknown'), bundle_uuid))
				bundles_images.append(bundle_data.get('displayIcon', ''))

			# -----------------------------------------------------------
			# Process Night Market Data
			# -----------------------------------------------------------
			bonus_store = store_data.get('BonusStore', {})
			nm_duration = bonus_store.get('BonusStoreRemainingDurationInSeconds')
			bonus_offers = bonus_store.get('BonusStoreOffers', [])

			# Capture base vs discount prices and the corresponding skin ids
			nm_prices = []  # list of (base, discount)
			nm_skin_ids = []
			for offer in bonus_offers:
				rewards = offer.get('Offer', {}).get('Rewards', []) or []
				skin_id = rewards[0].get('ItemID') if rewards else None
				if skin_id:
					nm_skin_ids.append(skin_id)
				base_cost_map = offer.get('Offer', {}).get('Cost', {}) or {}
				disc_cost_map = offer.get('DiscountCosts', {}) or {}
				# Prefer VP currency id, otherwise take first
				vp_id = "85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741"
				base = base_cost_map.get(vp_id)
				if base is None and base_cost_map:
					base = next(iter(base_cost_map.values()))
				disc = disc_cost_map.get(vp_id)
				if disc is None and disc_cost_map:
					disc = next(iter(disc_cost_map.values()))
				nm_prices.append((base or 0, disc or 0))

			nm_offers = []
			nm_images = []
			for skin_id in nm_skin_ids:
				nm_response = api_request("GET", f"https://valorant-api.com/v1/weapons/skinlevels/{skin_id}")
				nm_data = nm_response.json().get('data', {})
				nm_offers.append(nm_data.get('displayName', 'Unknown'))
				nm_images.append(nm_data.get('displayIcon', ''))

			# -----------------------------------------------------------
			# Display the GUI with the collected data
			# -----------------------------------------------------------
			await self.display_gui(
				vp, vp_icon,
				rp, rp_icon,
				kc, kc_icon,
				current_bundles, bundles_images, bundle_prices, bundle_duration, bundle_items,
				skin_names, skin_images, skin_videos, skin_prices, skin_duration, skin_rarity,
				nm_offers, nm_prices, nm_images, nm_duration
			)

		except Exception as e:
			error_trace = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			self.logger.log(1, error_trace)
			console.print(f"Error: {error_trace}")

	async def display_gui(
			self,
			vp, vp_icon, rp, rp_icon, kc, kc_icon,
			current_bundles, bundles_images, bundle_prices, bundle_duration, bundle_items,
			skin_names, skin_images, skin_videos, skin_prices, skin_duration, skin_rarity,
			nm_offers, nm_prices, nm_images, nm_duration
	):
		# -------------------- Theme Colors & Fonts --------------------
		DARK_BG = "#1E1E1E"
		LIGHT_BG = "#F5F6F8"
		DARK_CARD_BG = "#232427"
		LIGHT_CARD_BG = "#FFFFFF"
		ACCENT_COLOR = "#FF4654"  # Valorant accent
		TEXT_DARK = "#0F1113"
		TEXT_LIGHT = "#FFFFFF"

		TITLE_FONT = ("Segoe UI", 26, "bold")
		HEADER_FONT = ("Segoe UI", 14, "bold")
		LABEL_FONT = ("Segoe UI", 11)
		PRICE_FONT = ("Segoe UI", 12, "bold")
		BUTTON_FONT = ("Segoe UI", 10, "bold")
		TIMER_FONT = ("Segoe UI", 10, "italic")

		# -------------------- Utility Functions --------------------
		def format_duration(seconds):
			days = seconds // (24 * 3600)
			seconds %= (24 * 3600)
			hours = seconds // 3600
			seconds %= 3600
			minutes = seconds // 60
			seconds %= 60
			return f"{days}d {hours}h {minutes}m {seconds}s"

		def fixed_resize(image, width, height):
			original_width, original_height = image.size
			ratio = min(width / original_width, height / original_height)
			new_size = (int(original_width * ratio), int(original_height * ratio))
			return image.resize(new_size, Image.Resampling.LANCZOS)

		# Color helpers and number formatting
		def _clamp(n: int) -> int:
			return max(0, min(255, n))

		def _hex_to_rgb(c: str):
			c = (c or "").strip()
			if c.startswith("#"):
				c = c[1:]
			if len(c) >= 6:
				try:
					return tuple(int(c[i:i+2], 16) for i in (0, 2, 4))
				except Exception:
					return (255, 255, 255)
			return (255, 255, 255)

		def _rgb_to_hex(rgb):
			return '#%02x%02x%02x' % rgb

		def lighten(color: str, factor: float = 0.12) -> str:
			r, g, b = _hex_to_rgb(color)
			lr = _clamp(int(r + (255 - r) * factor))
			lg = _clamp(int(g + (255 - g) * factor))
			lb = _clamp(int(b + (255 - b) * factor))
			return _rgb_to_hex((lr, lg, lb))

		def fmt_num(n) -> str:
			try:
				return f"{int(n):,}"
			except Exception:
				return str(n)

		# -------------------- Setup Root & Style --------------------
		root = tkinter.Tk()
		root.title("Valorant Shop Checker")
		root.minsize(1024, 720)
		root.configure(bg=DARK_BG if self.dark_mode else LIGHT_BG)
		style = ttk.Style()
		style.theme_use("clam")

		# Configure overall padding and grid weight for responsiveness.
		root.grid_rowconfigure(0, weight=1)
		root.grid_columnconfigure(0, weight=1)

		# -------------------- Load Theme Icons --------------------
		sun_icon_url = "https://raw.githubusercontent.com/Saucywan/IconAssets/71ca8de7336c6a03ad319cabd9580b8e83fe6e3c/sun.png"
		moon_icon_url = "https://raw.githubusercontent.com/Saucywan/IconAssets/71ca8de7336c6a03ad319cabd9580b8e83fe6e3c/moon.png"
		sun_icon = moon_icon = None
		for url, var in [(sun_icon_url, "sun_icon"), (moon_icon_url, "moon_icon")]:
			img = load_image(url, (24, 24))
			if img:
				if url == sun_icon_url:
					sun_icon = ImageTk.PhotoImage(img)
				else:
					moon_icon = ImageTk.PhotoImage(img)

		# -------------------- Global Card List for Theme Updates --------------------
		cards = []
		theme_btn = None  # Placeholder for theme toggle button

		# -------------------- Hover Effects for Cards --------------------
		def add_hover_effect(widget, normal_bg, hover_bg):
			def on_enter(event):
				widget.configure(bg=hover_bg)
				for child in widget.winfo_children():
					try:
						child.configure(bg=hover_bg)
					except Exception:
						pass

			def on_leave(event):
				new_card_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
				widget.configure(bg=new_card_bg)

				for child in widget.winfo_children():
					try:
						child.configure(bg=new_card_bg)
						if isinstance(child, tkinter.Label):
							child.configure(fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK)
					except Exception:
						pass

			widget.bind("<Enter>", on_enter)
			widget.bind("<Leave>", on_leave)

		# -------------------- Theme Toggle Function --------------------
		def switch_theme(lock: bool = False):
			nonlocal theme_btn
			if not lock:
				self.dark_mode = not self.dark_mode

			if self.dark_mode:
				# Dark Mode configuration
				root.configure(bg=DARK_BG)
				style.configure("TFrame", background=DARK_BG)
				style.configure("TLabel", background=DARK_BG, foreground=TEXT_LIGHT, font=LABEL_FONT)
				style.configure("Title.TLabel", font=TITLE_FONT, foreground=TEXT_LIGHT, background=DARK_BG)
				style.configure("TLabelframe", background=DARK_BG, borderwidth=0)
				style.configure("TLabelframe.Label", background=DARK_BG, foreground=TEXT_LIGHT, font=HEADER_FONT)
				style.configure("TButton", background=DARK_CARD_BG, foreground=TEXT_LIGHT, font=BUTTON_FONT, padding=[12,6])
				style.configure("Timer.TLabel", foreground="#CCCCCC", background=DARK_BG, font=TIMER_FONT)
				style.configure("TNotebook", background=DARK_BG, borderwidth=0)
				style.configure("TNotebook.Tab", background=DARK_CARD_BG, foreground="#CCCCCC", borderwidth=0,
								padding=[10, 5])
				style.map("TNotebook.Tab", background=[("selected", "#444444")], foreground=[("selected", TEXT_LIGHT)])


			else:
				# Light Mode configuration
				root.configure(bg=LIGHT_BG)
				style.configure("TFrame", background=LIGHT_BG)
				style.configure("TLabel", background=LIGHT_BG, foreground=TEXT_DARK, font=LABEL_FONT)
				style.configure("Title.TLabel", font=TITLE_FONT, foreground=TEXT_DARK, background=LIGHT_BG)
				style.configure("TLabelframe", background=LIGHT_BG, borderwidth=0)
				style.configure("TLabelframe.Label", background=LIGHT_BG, foreground=TEXT_DARK, font=HEADER_FONT)
				style.configure("TButton", background="#e0e0e0", foreground=TEXT_DARK, font=BUTTON_FONT, padding=[12,6])
				style.configure("Timer.TLabel", foreground="#333", background=LIGHT_BG, font=TIMER_FONT)
				style.configure("TNotebook", background=LIGHT_BG, borderwidth=0)
				style.configure("TNotebook.Tab", background="#e0e0e0", foreground=TEXT_DARK, borderwidth=0,
								padding=[10, 5])
				style.map("TNotebook.Tab", background=[("selected", "#d0d0d0")], foreground=[("selected", "#000000")])

			# Update all card backgrounds and child widget colors
			new_card_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
			new_text_fg = TEXT_LIGHT if self.dark_mode else TEXT_DARK
			for card in cards:
				card.configure(bg=new_card_bg)
				for child in card.winfo_children():
					try:
						child.configure(bg=new_card_bg)
						if isinstance(child, tkinter.Label):
							child.configure(fg=new_text_fg)
					except Exception:
						pass

			# Update theme toggle button icon if loaded
			if theme_btn is not None and sun_icon and moon_icon:
				if self.dark_mode:
					theme_btn.config(image=sun_icon)
					theme_btn.image = sun_icon
				else:
					theme_btn.config(image=moon_icon)
					theme_btn.image = moon_icon

		# -------------------- HEADER SECTION --------------------
		header_frame = ttk.Frame(root)
		header_frame.pack(fill="x", pady=(20, 10), padx=20)

		title_label = ttk.Label(header_frame, text="Valorant Shop Checker", style="Title.TLabel")
		title_label.pack(side="left", padx=(0, 20))

		async def refresh():
			console.print("Refresh clicked!")
			refresh_btn.config(text="Refreshing...", state="disabled")
			await self.run()
			refresh_btn.config(text="Refresh", state="normal")

		refresh_btn = ttk.Button(header_frame, text="Refresh", command=lambda: asyncio.run(refresh()))
		refresh_btn.pack(side="right", padx=5)

		theme_btn = ttk.Button(header_frame, command=switch_theme)
		theme_btn.pack(side="right", padx=5)

		# Initialize theme (lock mode to set initial colors without toggling)
		switch_theme(lock=True)

		# Keyboard shortcuts: R refresh, T theme
		root.bind("r", lambda e: asyncio.run(refresh()))
		root.bind("R", lambda e: asyncio.run(refresh()))
		root.bind("t", lambda e: switch_theme())
		root.bind("T", lambda e: switch_theme())

		# -------------------- POINTS SECTION --------------------
		points_frame = ttk.Frame(root)
		points_frame.pack(fill="x", pady=10, padx=20)

		def create_points_badge(parent, icon_url, amount, label_text):
			badge_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
			badge = tkinter.Frame(parent, bg=badge_bg, bd=0, relief="flat")
			badge.pack(side="left", padx=6)
			inner = tkinter.Frame(badge, bg=badge_bg)
			inner.pack(padx=10, pady=6)
			try:
				icon_img = load_image(icon_url, (22, 22))
				if icon_img:
					photo = ImageTk.PhotoImage(icon_img)
					lbl_icon = tkinter.Label(inner, image=photo, bg=badge_bg)
					lbl_icon.image = photo
					lbl_icon.pack(side="left", padx=(0, 6))
				else:
					raise Exception("No image")
			except Exception as e:
				console.print(f"Icon load error: {e}")
				tkinter.Label(inner, text="?", width=2, bg=badge_bg, fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK).pack(side="left")
			amount_lbl = tkinter.Label(inner, text=fmt_num(amount), font=("Segoe UI", 12, "bold"),
									 fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK, bg=badge_bg)
			amount_lbl.pack(side="left")
			ToolTip(badge, text=f"{label_text}: {fmt_num(amount)}")
			return badge

		create_points_badge(points_frame, vp_icon, vp, "Valorant Points")
		create_points_badge(points_frame, rp_icon, rp, "Radianite Points")
		create_points_badge(points_frame, kc_icon, kc, "Kingdom Credits")

		# -------------------- NOTEBOOK (TABS) --------------------
		notebook = ttk.Notebook(root)
		notebook.pack(fill="both", expand=True, padx=20, pady=10)

		# -------------------- BUNDLE DETAILS POPUP FUNCTION --------------------
		def show_bundle_details(bundle_uuid, bundle_name):
			items = bundle_items.get(bundle_uuid)
			if not items:
				messagebox.showerror("Error", "No details available for this bundle.")
				return

			details_window = tkinter.Toplevel(root)
			details_window.title(f"Bundle Details - {bundle_name}")
			details_window.minsize(500, 400)

			canvas = tkinter.Canvas(details_window, bg=DARK_BG if self.dark_mode else LIGHT_BG)
			scrollbar = ttk.Scrollbar(details_window, orient="vertical", command=canvas.yview)
			scrollable_frame = ttk.Frame(canvas)

			scrollable_frame.bind(
				"<Configure>",
				lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
			)

			canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
			canvas.configure(yscrollcommand=scrollbar.set)

			canvas.pack(side="left", fill="both", expand=True)
			scrollbar.pack(side="right", fill="y")

			for item in items:
				item_name, item_icon_url, item_cost, item_rarity = item
				card_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
				item_frame = tkinter.Frame(scrollable_frame, bg=card_bg, bd=1, relief="solid")
				item_frame.pack(padx=10, pady=10, fill="x")

				try:
					icon_img = load_image(item_icon_url, (50, 50))
					if icon_img:
						icon_img = fixed_resize(icon_img, 50, 50)
						icon_photo = ImageTk.PhotoImage(icon_img)
						icon_label = tkinter.Label(item_frame, image=icon_photo, bg=card_bg)
						icon_label.image = icon_photo
						icon_label.pack(side="left", padx=10, pady=10)
					else:
						raise Exception("No icon")
				except Exception:
					tkinter.Label(item_frame, text="No Icon", bg=card_bg).pack(side="left", padx=10, pady=10)

				details_frame = tkinter.Frame(item_frame, bg=card_bg)
				details_frame.pack(side="left", fill="x", expand=True)

				tkinter.Label(details_frame, text=item_name, font=("Helvetica", 12, "bold"),
							  bg=card_bg, fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK).pack(anchor="w")
				tkinter.Label(details_frame, text=f"Cost: {item_cost} VP", font=("Helvetica", 10),
							  bg=card_bg, fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK).pack(anchor="w")

				if item_rarity and len(item_rarity) >= 3:
					rarity_name, highlight_color, display_icon_url = item_rarity
					if len(highlight_color) != 6:
						highlight_color = "#" + highlight_color[0:-2]
					rarity_frame = tkinter.Frame(details_frame, bg=highlight_color)
					rarity_frame.pack(anchor="w", pady=(5, 0))
					try:
						rarity_img = load_image(display_icon_url, (16, 16))
						if rarity_img:
							rarity_img = rarity_img.resize((16, 16), Image.Resampling.LANCZOS)
							rarity_photo = ImageTk.PhotoImage(rarity_img)
							rarity_icon_label = tkinter.Label(rarity_frame, image=rarity_photo, bg=highlight_color)
							rarity_icon_label.image = rarity_photo
							rarity_icon_label.pack(side="left", padx=(0, 2))
					except Exception as e:
						console.print("Error loading rarity icon in popup:", e)
					tkinter.Label(rarity_frame, text=rarity_name, font=("Helvetica", 8, "bold"),
								  bg=highlight_color, fg="white").pack(side="left", padx=(0, 2))

		# -------------------- ITEM CARD CREATION FUNCTION --------------------
		def create_item_card(parent, image_url, title, price, img_width, img_height,
							 card_bg, text_fg, rarity=None,
							 compare_prices=False, is_bundle=False, bundle_uuid=None, bundle_name=None,
							 video_url=None):
			if is_bundle:
				card_frame = tkinter.Frame(parent, bg=card_bg, bd=0)
				card_frame.configure(highlightthickness=1, highlightbackground="#CCCCCC", padx=10, pady=10)
			else:
				card_frame = tkinter.Frame(parent, bg=card_bg, bd=1, relief="solid")
			cards.append(card_frame)

			add_hover_effect(card_frame, card_bg, lighten(card_bg, 0.06))

			# For bundles, add a “BUNDLE” badge.
			if is_bundle:
				badge_frame = tkinter.Frame(card_frame, bg=card_bg)
				badge_frame.pack(anchor="nw", padx=5, pady=5)
				badge = tkinter.Label(badge_frame, text="BUNDLE", bg=ACCENT_COLOR, fg=TEXT_DARK,
									  font=("Helvetica", 8, "bold"))
				badge.pack()

			if rarity:
				rarity_name, highlight_color, display_icon_url = rarity
				if len(highlight_color) != 6:
					highlight_color = "#" + highlight_color[0:-2]
				rarity_frame = tkinter.Frame(card_frame, bg=highlight_color)
				rarity_frame.pack(anchor="ne", padx=5, pady=5)
				try:
					rarity_img = load_image(display_icon_url, (16, 16))
					if rarity_img:
						rarity_img = rarity_img.resize((16, 16), Image.Resampling.LANCZOS)
						rarity_photo = ImageTk.PhotoImage(rarity_img)
						rarity_icon_label = tkinter.Label(rarity_frame, image=rarity_photo, bg=highlight_color)
						rarity_icon_label.image = rarity_photo
						rarity_icon_label.pack(side="left", padx=(0, 2))
				except Exception as e:
					console.print("Error loading rarity icon:", e)
				tkinter.Label(rarity_frame, text=rarity_name, bg=highlight_color, fg="white",
							  font=("Helvetica", 8, "bold")).pack(side="left")

			try:
				item_image = load_image(image_url)
				if item_image:
					if img_width and img_height:
						item_image = fixed_resize(item_image, img_width, img_height)
					else:
						item_image = fixed_resize(item_image, 250, 130)
					img = ImageTk.PhotoImage(item_image)
					img_label = tkinter.Label(card_frame, image=img, bg=card_bg)
					img_label.image = img
					img_label.pack(pady=(15, 5))
				else:
					raise Exception("Image not available")
			except Exception as e:
				console.print(f"Image load error: {e}")
				tkinter.Label(card_frame, text="Image not available", bg=card_bg, fg=text_fg).pack(pady=10)

			tkinter.Label(card_frame, text=title, font=("Segoe UI", 12, "bold"), fg=text_fg, bg=card_bg).pack(
				pady=(5, 0))
			if compare_prices:
				base_price, discount_price = price
				price_frame = tkinter.Frame(card_frame, bg=card_bg)
				price_frame.pack(pady=(5, 10))
				tkinter.Label(price_frame, text=f"{fmt_num(base_price)} VP", font=("Segoe UI", 10, "overstrike"),
							  fg="#E06B74", bg=card_bg).pack(side="left", padx=(0, 6))
				tkinter.Label(price_frame, text=f"{fmt_num(discount_price)} VP", font=("Segoe UI", 12, "bold"),
							  fg=text_fg, bg=card_bg).pack(side="left")
				try:
					if base_price and discount_price and base_price > discount_price:
						pct = int(round((base_price - discount_price) / float(base_price) * 100))
						tkinter.Label(price_frame, text=f" -{pct}%", font=("Segoe UI", 10, "bold"),
									  fg=ACCENT_COLOR, bg=card_bg).pack(side="left", padx=(6,0))
				except Exception:
					pass
			else:
				tkinter.Label(card_frame, text=f"Price: {fmt_num(price)} VP", font=("Segoe UI", 10),
							  fg=text_fg, bg=card_bg).pack(pady=(5, 10))

			# Tooltip
			ToolTip(card_frame, text=f"{title}\nPrice: {fmt_num((price[1] if compare_prices else price))} VP")

			if is_bundle and bundle_uuid is not None and bundle_name is not None:
				def on_click(event):
					show_bundle_details(bundle_uuid, bundle_name)

				card_frame.bind("<Button-1>", on_click)
				for child in card_frame.winfo_children():
					child.bind("<Button-1>", on_click)

			return card_frame

		# -------------------- SECTION CREATION FUNCTION --------------------
		def create_section(parent_frame, title, items, images, prices, duration,
						   img_width, img_height, rarities=None, is_bundle: bool = False,
						   compare_prices: bool = False, videos=None):
			section_frame = ttk.Labelframe(parent_frame, text=title)
			section_frame.pack(pady=10, padx=10, anchor="center", fill="x")

			timer_frame = ttk.Frame(section_frame)
			timer_frame.pack(fill="x", padx=10, pady=5)
			timer_label = tkinter.Label(timer_frame, text=f"Expires in: {format_duration(duration)}",
									 bg=DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG,
									 fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK,
									 font=TIMER_FONT)
			timer_label.pack(side="left", padx=(0,8), pady=2)

			items_frame = ttk.Frame(section_frame)
			items_frame.pack(padx=10, pady=10, fill="both", expand=True)

			# Responsive grid: build cards once, layout on resize
			cards_local = []

			def build_cards():
				if cards_local:
					return
				for idx in range(len(items)):
					card_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
					text_fg = TEXT_LIGHT if self.dark_mode else TEXT_DARK
					rarity = rarities[idx] if rarities is not None else None
					bundle_uuid = items[idx][1] if is_bundle else None
					bundle_name = items[idx][0] if is_bundle else None
					vid = None
					if videos and idx < len(videos):
						vid = videos[idx] or None
					card = create_item_card(
						items_frame,
						images[idx],
						items[idx] if not is_bundle else f"Bundle {items[idx][0]}",
						prices[idx],
						img_width=img_width,
						img_height=img_height,
						card_bg=card_bg,
						text_fg=text_fg,
						rarity=rarity,
						compare_prices=compare_prices,
						is_bundle=is_bundle,
						bundle_uuid=bundle_uuid,
						bundle_name=bundle_name,
						video_url=vid,
					)
					cards_local.append(card)

			def layout_cards(event=None):
				build_cards()
				for c in cards_local:
					c.grid_forget()
				width = max(items_frame.winfo_width(), 1)
				min_w = 420 if is_bundle else 260
				pad = 20
				cols = max(1, min(6, width // (min_w + pad)))
				for i in range(cols):
					items_frame.grid_columnconfigure(i, weight=1)
				for i, c in enumerate(cards_local):
					r = i // cols
					col = i % cols
					c.grid(row=r, column=col, padx=10, pady=10, sticky="nsew")

			items_frame.bind("<Configure>", layout_cards)
			root.after(50, layout_cards)

			return timer_label, duration

		# -------------------- Create Tabs and Sections --------------------
		def create_tab(tab_name):
			frame = ttk.Frame(notebook)
			notebook.add(frame, text=tab_name)
			return frame

		bundles_tab = create_tab("Bundles")
		bundles_timer_label = None
		total_bundles_duration = bundle_duration
		if current_bundles:
			bundles_timer_label, total_bundles_duration = create_section(
				bundles_tab,
				"Bundles",
				current_bundles,
				bundles_images,
				bundle_prices,
				bundle_duration,
				img_width=400,
				img_height=220,
				is_bundle=True,
				compare_prices=True
			)

		skins_tab = create_tab("Daily Skins")
		skins_timer_label = None
		total_skins_duration = skin_duration
		if skin_names:
			skins_timer_label, total_skins_duration = create_section(
				skins_tab,
				"Daily Skins",
				skin_names,
				skin_images,
				skin_prices,
				skin_duration,
				img_width=0,
				img_height=0,
				rarities=skin_rarity,
				videos=skin_videos
			)

		nm_tab = create_tab("Night Market")
		nm_timer_label = None
		total_nm_duration = nm_duration if nm_duration else 0
		if nm_offers:
			nm_timer_label, total_nm_duration = create_section(
				nm_tab,
				"Night Market",
				nm_offers,
				nm_images,
				nm_prices,
				nm_duration,
				img_width=300,
				img_height=140,
				compare_prices=True
			)
		else:
			ttk.Label(nm_tab, text="Night Market is currently not available.").pack(pady=20)

		# -------------------- STATUS BAR --------------------
		status_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
		status = tkinter.Frame(root, bg=status_bg)
		status.pack(side="bottom", fill="x", padx=0, pady=0)
		from datetime import datetime
		stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		status_lbl = tkinter.Label(status, text=f"Last updated: {stamp}", bg=status_bg,
								  fg=TEXT_LIGHT if self.dark_mode else TEXT_DARK, font=("Segoe UI", 9))
		status_lbl.pack(side="right", padx=12, pady=6)

		# -------------------- Timers Update Loop --------------------
		remaining_bundle = total_bundles_duration
		remaining_skin = total_skins_duration
		remaining_nm = total_nm_duration
		after_id = None

		def update_timers():
			nonlocal remaining_bundle, remaining_skin, remaining_nm, after_id
			if not root.winfo_exists():
				return
			try:
				if current_bundles and bundles_timer_label:
					if remaining_bundle > 0:
						remaining_bundle -= 1
						bundles_timer_label.config(text=f"Expires in: {format_duration(remaining_bundle)}")
					else:
						bundles_timer_label.config(text="Expired")
				if skin_names and skins_timer_label:
					if remaining_skin > 0:
						remaining_skin -= 1
						skins_timer_label.config(text=f"Expires in: {format_duration(remaining_skin)}")
					else:
						skins_timer_label.config(text="Expired")
				if nm_offers and nm_timer_label:
					if remaining_nm > 0:
						remaining_nm -= 1
						nm_timer_label.config(text=f"Expires in: {format_duration(remaining_nm)}")
					else:
						nm_timer_label.config(text="Expired")
			except tkinter.TclError:
				return
			after_id = root.after(1000, update_timers)

		def on_closing():
			if after_id is not None:
				try:
					root.after_cancel(after_id)
				except tkinter.TclError:
					pass
			root.destroy()

		root.protocol("WM_DELETE_WINDOW", on_closing)
		update_timers()
		root.mainloop()


class NotificationManager:
	def __init__(self):
		self.notifications = []
		self.console = console
		self._recent_notifications = deque()
		self._recent_lookup = set()

	def has_notifications(self):
		return len(self.notifications) >= 1

	def _prune_recent(self, now: float) -> None:
		while self._recent_notifications and self._recent_notifications[0][1] <= now:
			expired_notification, _ = self._recent_notifications.popleft()
			self._recent_lookup.discard(expired_notification)

	def add_notification(self, notification: str, *, dedupe: bool = False, dedupe_ttl: float = 3.0) -> bool:
		"""Add a notification."""
		if dedupe:
			now = time.monotonic()
			self._prune_recent(now)
			if notification in self._recent_lookup:
				return False
			expiry = now + max(dedupe_ttl, 0.0)
			self._recent_lookup.add(notification)
			self._recent_notifications.append((notification, expiry))
			while len(self._recent_notifications) > 128:
				expired_notification, _ = self._recent_notifications.popleft()
				self._recent_lookup.discard(expired_notification)

		self.notifications.insert(0, notification)
		return True

	def remove_notification(self, notification: str):
		"""Remove a notification if it exists."""
		if notification in self.notifications:
			self.notifications.remove(notification)

	def clear_notifications(self):
		"""Clear all notifications."""
		self.notifications.clear()
		self._recent_notifications.clear()
		self._recent_lookup.clear()

	def get_display(self):
		"""
		Display the notifications using Rich Console.
		The most recent notification appears first.
		"""
		if not self.notifications:
			return None

		# Combine notifications into a single text block
		content = "\n".join(self.notifications)
		# Create a Panel with a title and styled border
		panel = Panel(
			Text.from_markup(content),
			border_style="yellow",
			expand=False
		)
		return panel


class ValorantPerformanceScorer:
	"""
	Fast 0–100 match performance scorer for Valorant using multi-factor signals.

	What it does
	- Produces a per-match score in [0, 100], centered at 50 (≈ average).
	- ~30 indicates a bad game, ~70 a good game, 90+ excellent; 100 is reachable in elite games.
	- Uses several components beyond K/D and blends them with tunable weights.

	Components (all centered at 50 via a symmetric log-odds mapping)
	- kd:             K vs D using log-odds (handles zero deaths cleanly)                 [default weight 0.45]
	- openers:        First-kills vs first-deaths by round                                [0.20]
	- adr:            Damage per round vs team average (excludes self)                    [0.15]
	- multikill:      Multi-kill impact (sum(max(0, kills_in_round-1)) per round) vs team [0.10]
	- econ:           Economy-weighted frags (weights kills/deaths by loadout advantage)  [0.05]
	- objective:      Plants+defuses vs team average                                      [0.05]
	- behavior penalty (optional): AFK, stayed in spawn, friendly fire                   (subtracted)

	Fine-tuning parameters (init arguments)
	- weights: dict[str, float] (default: {"kd":0.45,"openers":0.20,"adr":0.15,"multikill":0.10,"econ":0.05,"objective":0.05})
	  • How much each component moves the final score. Will be normalized to sum to 1.
	  • Increase kd for a simpler K/D-dominant score; increase adr/openers for team-impact sensitivity.

	- temperature: float (default 0.9, typical range 0.75–1.2)
	  • Controls steepness of the logistic mapping (per-component).
	  • Lower < 1 makes curves steeper, making high/low performances push closer to 0/100.
	  • Raise toward 1.0–1.1 to be more conservative (scores cluster more around 50).

	- smoothing: dict[str, float] (default: {"kd":0.5,"openers":0.5,"adr":1.0,"multikill":0.05,"econ":0.5,"objective":0.5})
	  • Pseudocounts (c) added to both “sides” in each component to stabilize small samples.
	  • Recommended ranges:
		- kd/openers/econ/objective: c ∈ [0.25, 2.0]
		- adr: c ∈ [0.5, 10.0] (ADR is continuous; larger c softens extremes)
		- multikill: c ∈ [0.01, 0.25] (events per round are sparse; small c keeps sensitivity)

	- econ_adv_scale: float (default 4000.0; range ~2000–8000)
	  • Scale for relative loadout advantage in tanh((adv)/econ_adv_scale).
	  • Smaller → stronger effect from smaller loadout differences.

	- econ_weight_amp: float (default 0.25; range ~0.1–0.5)
	  • Amplitude of economy weighting; kill/death weight = 1 ± amp * tanh(...)
	  • Larger amp → bigger reward for “upset” kills and softer penalty for disadvantaged deaths.

	- apply_behavior_penalty: bool (default True)
	  • Whether to subtract behavior penalties from the blended score.

	- penalty_scales: dict[str, float] (defaults: {"afk":3.0, "spawn":0.5, "ff":0.01})
	  • Scale factors for behavior signals:
		- afk adds 3.0 points penalty per AFK round (capped by penalty_caps["afk"])
		- spawn adds 0.5 points per “stayed in spawn” round (cap by penalty_caps["spawn"])
		- ff adds 0.01 points per damage point of friendly fire outgoing (cap by penalty_caps["ff"])
	  • Increase if you want stronger punishment for negative behavior.

	- penalty_caps: dict[str, float] (defaults: {"afk":10.0,"spawn":6.0,"ff":4.0})
	  • Caps per sub-component before summing (total penalty is sum of capped sub-penalties).
	  • Keeps penalties bounded and predictable.

	Usage
	- scorer = ValorantPerformanceScorer()
	- scorer.prepare(match_json_dict)
	- score = scorer.score_player(subject)                 # float 0–100
	- score, breakdown = scorer.score_player(subject, explain=True)
	- scores = scorer.score_all()                          # dict[subject] -> score
	- scores, breakdowns = scorer.score_all(explain=True)  # dicts

	Performance notes
	- prepare() pre-indexes the match once. All subsequent scoring is O(1) per player.
	- No heavy libraries; single pass over kills and O(players + rounds) precomputation.
	"""

	__slots__ = (
		# Config
		"weights", "temperature", "inv_t", "smoothing",
		"econ_adv_scale", "econ_weight_amp",
		"apply_behavior_penalty", "penalty_scales", "penalty_caps",
		# Cached match
		"match", "players_by_subject", "subjects",
		"team_of", "team_members",
		# Per-subject raw stats/caches
		"kills", "deaths", "rounds_played",
		"adr", "team_adr_sum", "team_adr_count",
		"ipr", "team_ipr_sum", "team_ipr_count",
		"objectives", "team_obj_sum", "team_obj_count",
		"open_for", "open_against",
		"w_kill", "w_death",
		"behavior_penalty_by_subject",
	)

	def __init__(
			self,
			*,
			weights: Optional[Dict[str, float]] = None,
			temperature: float = 0.9,
			smoothing: Optional[Dict[str, float]] = None,
			econ_adv_scale: float = 4000.0,
			econ_weight_amp: float = 0.25,
			apply_behavior_penalty: bool = True,
			penalty_scales: Optional[Dict[str, float]] = None,
			penalty_caps: Optional[Dict[str, float]] = None,
	) -> None:
		# Defaults
		if weights is None:
			weights = {
				"kd": 0.45,
				"openers": 0.20,
				"adr": 0.15,
				"multikill": 0.10,
				"econ": 0.05,
				"objective": 0.05,
			}
		s = sum(weights.values()) or 1.0
		self.weights = {k: (v / s) for k, v in weights.items()}

		self.temperature = float(temperature)
		self.inv_t = 1.0 / self.temperature if self.temperature != 0 else 1.0  # safe

		if smoothing is None:
			smoothing = {"kd": 0.5, "openers": 0.5, "adr": 1.0, "multikill": 0.05, "econ": 0.5, "objective": 0.5}
		self.smoothing = dict(smoothing)

		self.econ_adv_scale = float(econ_adv_scale)
		self.econ_weight_amp = float(econ_weight_amp)

		self.apply_behavior_penalty = bool(apply_behavior_penalty)
		self.penalty_scales = penalty_scales or {"afk": 3.0, "spawn": 0.5, "ff": 0.01}
		self.penalty_caps = penalty_caps or {"afk": 10.0, "spawn": 6.0, "ff": 4.0}

		# Caches (initialized in prepare)
		self.match: Optional[Dict[str, Any]] = None
		self.players_by_subject: Dict[str, Dict[str, Any]] = {}
		self.subjects: List[str] = []
		self.team_of: Dict[str, str] = {}
		self.team_members: Dict[str, List[str]] = {}
		self.kills: Dict[str, float] = {}
		self.deaths: Dict[str, float] = {}
		self.rounds_played: Dict[str, int] = {}
		self.adr: Dict[str, float] = {}
		self.team_adr_sum: Dict[str, float] = {}
		self.team_adr_count: Dict[str, int] = {}
		self.ipr: Dict[str, float] = {}
		self.team_ipr_sum: Dict[str, float] = {}
		self.team_ipr_count: Dict[str, int] = {}
		self.objectives: Dict[str, float] = {}
		self.team_obj_sum: Dict[str, float] = {}
		self.team_obj_count: Dict[str, int] = {}
		self.open_for: Dict[str, float] = {}
		self.open_against: Dict[str, float] = {}
		self.w_kill: Dict[str, float] = {}
		self.w_death: Dict[str, float] = {}
		self.behavior_penalty_by_subject: Dict[str, float] = {}

	# -----------------------------
	# Public API
	# -----------------------------

	def prepare(self, match: Dict[str, Any]) -> None:
		"""
		Pre-index the match once. Call this before scoring.

		Optimizations:
		- Single pass over players to cache basics (kills/deaths/rounds/adr team sums, behavior).
		- Build round->subject->loadoutValue map once for economy weighting.
		- Single pass over kills to compute: first-kills per round, weighted frags, and multikill counts.
		"""
		self.match = match

		# Players and teams
		players = [p for p in match.get("players", []) if not p.get("isObserver", False)]
		self.players_by_subject = {p.get("subject"): p for p in players}
		self.subjects = [p.get("subject") for p in players]
		self.team_of = {p.get("subject"): p.get("teamId") for p in players}
		self.team_members = {}
		for p in players:
			team = p.get("teamId")
			subj = p.get("subject")
			if team is None or subj is None:
				continue
			self.team_members.setdefault(team, []).append(subj)

		# Basic stats and ADR
		self.kills.clear()
		self.deaths.clear()
		self.rounds_played.clear()
		self.adr.clear()
		self.team_adr_sum.clear()
		self.team_adr_count.clear()

		for p in players:
			subj = p.get("subject")
			st = p.get("stats") or {}
			k = float(st.get("kills", 0) or 0)
			d = float(st.get("deaths", 0) or 0)
			r = int(st.get("roundsPlayed", 0) or 0)
			self.kills[subj] = k
			self.deaths[subj] = d
			self.rounds_played[subj] = r

			# ADR from roundDamage
			total_damage = 0.0
			for rd in p.get("roundDamage", []) or []:
				total_damage += float(rd.get("damage", 0) or 0)
			adr = (total_damage / r) if r > 0 else 0.0
			self.adr[subj] = adr

			team = self.team_of.get(subj)
			if team:
				self.team_adr_sum[team] = self.team_adr_sum.get(team, 0.0) + adr
				self.team_adr_count[team] = self.team_adr_count.get(team, 0) + (1 if r > 0 else 0)

		# Objectives (plants + defuses) and per-team totals
		self.objectives.clear()
		self.team_obj_sum.clear()
		self.team_obj_count.clear()
		for rr in match.get("roundResults", []) or []:
			planter = rr.get("bombPlanter")
			defuser = rr.get("bombDefuser")
			if planter:
				self.objectives[planter] = self.objectives.get(planter, 0.0) + 1.0
			if defuser:
				self.objectives[defuser] = self.objectives.get(defuser, 0.0) + 1.0

		for subj in self.subjects:
			team = self.team_of.get(subj)
			if team:
				v = float(self.objectives.get(subj, 0.0))
				self.team_obj_sum[team] = self.team_obj_sum.get(team, 0.0) + v
				self.team_obj_count[team] = self.team_obj_count.get(team, 0) + 1

		# Behavior penalties precomputed
		self.behavior_penalty_by_subject.clear()
		if self.apply_behavior_penalty:
			for p in players:
				subj = p.get("subject")
				bf = p.get("behaviorFactors") or {}
				afk_rounds = float(bf.get("afkRounds", 0.0) or 0.0)
				stayed_spawn = float(bf.get("stayedInSpawnRounds", 0.0) or 0.0)
				ff_out = float(bf.get("friendlyFireOutgoing", 0.0) or 0.0)

				s_afk = min(self.penalty_caps.get("afk", 10.0), self.penalty_scales.get("afk", 3.0) * afk_rounds)
				s_spawn = min(self.penalty_caps.get("spawn", 6.0), self.penalty_scales.get("spawn", 0.5) * stayed_spawn)
				s_ff = min(self.penalty_caps.get("ff", 4.0), self.penalty_scales.get("ff", 0.01) * ff_out)
				self.behavior_penalty_by_subject[subj] = float(s_afk + s_spawn + s_ff)
		else:
			for subj in self.subjects:
				self.behavior_penalty_by_subject[subj] = 0.0

		# Economy by round -> subject -> loadoutValue
		econ_by_round: Dict[int, Dict[str, float]] = {}
		for rr in match.get("roundResults", []) or []:
			rnum = int(rr.get("roundNum", 0) or 0)
			econ_map: Dict[str, float] = {}
			pes = rr.get("playerEconomies") or []
			if pes:
				for pe in pes:
					subj = pe.get("subject")
					if subj is None:
						continue
					econ_map[subj] = float(pe.get("loadoutValue", 0.0) or 0.0)
			else:
				# Fallback to playerStats if playerEconomies missing
				for ps in rr.get("playerStats", []) or []:
					subj = ps.get("subject")
					econ = ps.get("economy") or {}
					if subj is None:
						continue
					econ_map[subj] = float(econ.get("loadoutValue", 0.0) or 0.0)
			econ_by_round[rnum] = econ_map

		# Kills pass: compute openers, w_kill/death, per-player per-round kill counts (for multikill)
		self.open_for.clear()
		self.open_against.clear()
		self.w_kill.clear()
		self.w_death.clear()
		per_player_round_kills: Dict[str, Dict[int, int]] = {}
		earliest_kill_in_round: Dict[int, Tuple[int, str, str]] = {}  # round -> (roundTime, killer, victim)

		amp = self.econ_weight_amp
		scale = self.econ_adv_scale

		for e in match.get("kills", []) or []:
			r = int(e.get("round", e.get("roundNum", 0)) or 0)
			killer = e.get("killer")
			victim = e.get("victim")

			# Opening duel tracking without sorting: store earliest by roundTime
			rt = int(e.get("roundTime", 0) or 0)
			cur = earliest_kill_in_round.get(r)
			if cur is None or rt < cur[0]:
				earliest_kill_in_round[r] = (rt, killer, victim)

			# Econ-weighted frags (if econ info available; else adv=0 → weight ~1)
			econ = econ_by_round.get(r) or {}
			lk = float(econ.get(killer, 0.0) or 0.0)
			lv = float(econ.get(victim, 0.0) or 0.0)

			# Kill weight for the killer: more weight if victim had higher loadout
			adv_kill = (lv - lk) / scale if scale != 0 else 0.0
			w_k = 1.0 + amp * tanh(adv_kill)
			# Death weight for the victim: less penalty if they died to a much higher loadout
			adv_death = (lk - lv) / scale if scale != 0 else 0.0
			w_d = 1.0 + amp * tanh(adv_death)

			if killer:
				self.w_kill[killer] = self.w_kill.get(killer, 0.0) + w_k
			if victim:
				self.w_death[victim] = self.w_death.get(victim, 0.0) + w_d

			# Multikill counts per round
			if killer:
				dct = per_player_round_kills.get(killer)
				if dct is None:
					dct = {}
					per_player_round_kills[killer] = dct
				dct[r] = dct.get(r, 0) + 1

		# Opening-duel tallies from earliest_kill_in_round
		for _, killer, victim in earliest_kill_in_round.values():
			if killer:
				self.open_for[killer] = self.open_for.get(killer, 0.0) + 1.0
			if victim:
				self.open_against[victim] = self.open_against.get(victim, 0.0) + 1.0

		# Multikill impact per round (impact points = max(0, kills_in_round - 1))
		self.ipr.clear()
		self.team_ipr_sum.clear()
		self.team_ipr_count.clear()
		for subj in self.subjects:
			rmap = per_player_round_kills.get(subj) or {}
			impact_points = 0
			for cnt in rmap.values():
				if cnt > 1:
					impact_points += (cnt - 1)
			rounds = self.rounds_played.get(subj, 0) or 0
			ipr = (impact_points / rounds) if rounds > 0 else 0.0
			self.ipr[subj] = ipr

			team = self.team_of.get(subj)
			if team:
				self.team_ipr_sum[team] = self.team_ipr_sum.get(team, 0.0) + ipr
				self.team_ipr_count[team] = self.team_ipr_count.get(team, 0) + (1 if rounds > 0 else 0)

		# Ensure all dicts have all subjects with zero defaults to avoid KeyErrors later
		for subj in self.subjects:
			self.open_for.setdefault(subj, 0.0)
			self.open_against.setdefault(subj, 0.0)
			self.w_kill.setdefault(subj, 0.0)
			self.w_death.setdefault(subj, 0.0)
			self.objectives.setdefault(subj, 0.0)
			self.behavior_penalty_by_subject.setdefault(subj, 0.0)

	def score_player(self, subject: str, *, explain: bool = False) -> Tuple[float, Optional[Dict[str, Any]]]:
		"""
		Score one player by subject.
		Returns (score, breakdown) if explain=True, else (score, None).
		"""
		if self.match is None:
			raise RuntimeError("Call prepare(match) before scoring.")

		if subject not in self.players_by_subject:
			return 0.0, {"error": f"subject {subject} not found"} if explain else (0.0,
																				   None)  # type: ignore[return-value]

		# Component scores
		s_kd, kd_info = self._comp_kd(subject)
		s_open, open_info = self._comp_openers(subject)
		s_adr, adr_info = self._comp_adr(subject)
		s_mk, mk_info = self._comp_multikill(subject)
		s_econ, econ_info = self._comp_econ(subject)
		s_obj, obj_info = self._comp_objective(subject)

		w = self.weights
		base = (
				w["kd"] * s_kd +
				w["openers"] * s_open +
				w["adr"] * s_adr +
				w["multikill"] * s_mk +
				w["econ"] * s_econ +
				w["objective"] * s_obj
		)

		pen = self.behavior_penalty_by_subject.get(subject, 0.0) if self.apply_behavior_penalty else 0.0
		final = self._clamp(base - pen)

		if not explain:
			return round(final, 2), None

		breakdown = {
			"final": round(final, 2),
			"base_score": round(base, 2),
			"penalty": round(pen, 2),
			"weights": dict(self.weights),
			"temperature": self.temperature,
			"smoothing": dict(self.smoothing),
			"components": {
				"kd": {"score": round(s_kd, 2), **kd_info, "weight": w["kd"]},
				"openers": {"score": round(s_open, 2), **open_info, "weight": w["openers"]},
				"adr": {"score": round(s_adr, 2), **adr_info, "weight": w["adr"]},
				"multikill": {"score": round(s_mk, 2), **mk_info, "weight": w["multikill"]},
				"econ": {"score": round(s_econ, 2), **econ_info, "weight": w["econ"]},
				"objective": {"score": round(s_obj, 2), **obj_info, "weight": w["objective"]},
			}
		}
		return round(final, 2), breakdown

	def score_all(self, *, explain: bool = False) -> Tuple[Dict[str, float], Optional[Dict[str, Dict[str, Any]]]]:
		"""
		Score all players in the prepared match.
		Returns (scores, breakdowns) if explain=True, else (scores, None).
		"""
		if self.match is None:
			raise RuntimeError("Call prepare(match) before scoring.")

		scores: Dict[str, float] = {}
		breakdowns: Dict[str, Dict[str, Any]] = {} if explain else None

		for subj in self.subjects:
			s, br = self.score_player(subj, explain=explain)
			scores[subj] = s
			if explain and br is not None and isinstance(breakdowns, dict):
				breakdowns[subj] = br

		return scores, breakdowns

	# -----------------------------
	# Component scorers (use cached raw stats)
	# -----------------------------

	def _comp_kd(self, subject: str) -> Tuple[float, Dict[str, Any]]:
		k = self.kills.get(subject, 0.0)
		d = self.deaths.get(subject, 0.0)
		c = self.smoothing.get("kd", 0.5)
		score = self._logistic_from_pair(k, d, c)
		return score, {"kills": k, "deaths": d}

	def _comp_openers(self, subject: str) -> Tuple[float, Dict[str, Any]]:
		ofor = self.open_for.get(subject, 0.0)
		oagn = self.open_against.get(subject, 0.0)
		c = self.smoothing.get("openers", 0.5)
		score = self._logistic_from_pair(ofor, oagn, c)
		return score, {"opening_kills": ofor, "opening_deaths": oagn}

	def _comp_adr(self, subject: str) -> Tuple[float, Dict[str, Any]]:
		my_adr = self.adr.get(subject, 0.0)
		team = self.team_of.get(subject)
		if not team:
			return 50.0, {"adr": my_adr, "team_avg": 0.0}
		team_sum = self.team_adr_sum.get(team, 0.0)
		team_cnt = self.team_adr_count.get(team, 0)
		# Average ADR of teammates excluding self
		# If team_cnt <= 1 or denom 0, treat neutral (50)
		denom = max(team_cnt - (1 if self.rounds_played.get(subject, 0) > 0 else 0), 0)
		peer_sum = team_sum - my_adr if self.rounds_played.get(subject, 0) > 0 else team_sum
		team_avg = (peer_sum / denom) if denom > 0 else 0.0
		if team_avg <= 0:
			return 50.0, {"adr": my_adr, "team_avg": 0.0}
		c = self.smoothing.get("adr", 1.0)
		score = self._logistic_from_ratio(my_adr, team_avg, c)
		return score, {"adr": my_adr, "team_avg": team_avg}

	def _comp_multikill(self, subject: str) -> Tuple[float, Dict[str, Any]]:
		my_ipr = self.ipr.get(subject, 0.0)
		team = self.team_of.get(subject)
		if not team:
			return 50.0, {"impact_per_round": my_ipr, "team_avg": 0.0}
		team_sum = self.team_ipr_sum.get(team, 0.0)
		team_cnt = self.team_ipr_count.get(team, 0)
		# Average IPR of teammates excluding self
		has_rounds = 1 if self.rounds_played.get(subject, 0) > 0 else 0
		denom = max(team_cnt - has_rounds, 0)
		peer_sum = team_sum - (my_ipr if has_rounds else 0.0)
		team_avg = (peer_sum / denom) if denom > 0 else 0.0
		if team_avg <= 0:
			return 50.0, {"impact_per_round": my_ipr, "team_avg": 0.0}
		c = self.smoothing.get("multikill", 0.05)
		score = self._logistic_from_ratio(my_ipr, team_avg, c)
		return score, {"impact_per_round": my_ipr, "team_avg": team_avg}

	def _comp_econ(self, subject: str) -> Tuple[float, Dict[str, Any]]:
		wk = self.w_kill.get(subject, 0.0)
		wd = self.w_death.get(subject, 0.0)
		c = self.smoothing.get("econ", 0.5)
		score = self._logistic_from_pair(wk, wd, c)
		return score, {"weighted_kills": wk, "weighted_deaths": wd, "amp": self.econ_weight_amp,
					   "scale": self.econ_adv_scale}

	def _comp_objective(self, subject: str) -> Tuple[float, Dict[str, Any]]:
		my_obj = self.objectives.get(subject, 0.0)
		team = self.team_of.get(subject)
		if not team:
			return 50.0, {"objectives": my_obj, "team_avg": 0.0}
		team_total = self.team_obj_sum.get(team, 0.0)
		team_cnt = self.team_obj_count.get(team, 0)
		denom = max(team_cnt - 1, 0)
		peer_sum = team_total - my_obj
		team_avg = (peer_sum / denom) if denom > 0 else 0.0
		if team_avg <= 0:
			return 50.0, {"objectives": my_obj, "team_avg": 0.0}
		c = self.smoothing.get("objective", 0.5)
		score = self._logistic_from_ratio(my_obj, team_avg, c)
		return score, {"objectives": my_obj, "team_avg": team_avg}

	# -----------------------------
	# Math helpers
	# -----------------------------

	def _logistic_from_pair(self, win: float, loss: float, c: float) -> float:
		"""
		0–100 score from a (win, loss) pair using log-odds with smoothing c and temperature t.
		Equivalent to: 100 / (1 + 2^(-log2((win+c)/(loss+c)) / t))
		Computed as: 100 * (win+c)^(1/t) / [(win+c)^(1/t) + (loss+c)^(1/t)]
		"""
		a = (win + c) ** self.inv_t
		b = (loss + c) ** self.inv_t
		denom = a + b
		return 100.0 * (a / denom) if denom > 0.0 else 50.0

	def _logistic_from_ratio(self, x: float, y: float, c: float) -> float:
		"""
		0–100 score from a performance ratio x vs y using the same transform as _logistic_from_pair.
		"""
		a = (x + c) ** self.inv_t
		b = (y + c) ** self.inv_t
		denom = a + b
		return 100.0 * (a / denom) if denom > 0.0 else 50.0

	@staticmethod
	def _clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
		return lo if x < lo else hi if x > hi else x


def calculate_kd(kills: int, deaths: int) -> float | int:
	if deaths == 0:
		return kills  # Stop div of zero
	return round(kills / deaths, 2)

class ConfigValidationError(ValueError):
	"""Raised when a configuration value cannot be parsed or validated."""


@dataclass(frozen=True)
class ConfigValidationIssue:
	section: str
	key: str
	message: str
	reverted_to: str | None = None


@dataclass(frozen=True)
class ConfigOption:
	key: str
	default: Any
	description: Sequence[str]
	value_type: str = "str"
	min_value: int | None = None
	max_value: int | None = None
	normalizer: Callable[[str], str] | None = None

	def render_default(self) -> str:
		return self._render_value(self.default)

	def normalize(self, raw_value: str) -> str:
		value = raw_value.strip()
		if not value and self.value_type != "str":
			raise ConfigValidationError("Value cannot be empty.")
		if self.normalizer:
			return self.normalizer(value)
		if self.value_type == "bool":
			return self._normalize_bool(value)
		if self.value_type == "int":
			return self._normalize_int(value)
		return value

	def _normalize_bool(self, value: str) -> str:
		mapping = {
			"true": True,
			"1": True,
			"yes": True,
			"on": True,
			"false": False,
			"0": False,
			"no": False,
			"off": False,
		}
		key = value.lower()
		if key not in mapping:
			raise ConfigValidationError("Expected a boolean value (true/false).")
		return self._render_value(mapping[key])

	def _normalize_int(self, value: str) -> str:
		try:
			parsed = int(value)
		except ValueError as exc:
			raise ConfigValidationError("Expected an integer value.") from exc
		if self.min_value is not None and parsed < self.min_value:
			raise ConfigValidationError(
				f"Value must be greater than or equal to {self.min_value}."
			)
		if self.max_value is not None and parsed > self.max_value:
			raise ConfigValidationError(
				f"Value must be less than or equal to {self.max_value}."
			)
		return self._render_value(parsed)

	def _render_value(self, value: Any) -> str:
		if self.value_type == "bool":
			return "true" if bool(value) else "false"
		if self.value_type == "int":
			return str(int(value))
		return str(value)


@dataclass(frozen=True)
class ConfigSection:
	name: str
	options: Sequence[ConfigOption]
	description: Sequence[str] = ()


@dataclass(frozen=True)
class ConfigLoadResult:
	config: configparser.ConfigParser
	issues: Sequence[ConfigValidationIssue]
	created: bool


class ConfigManager:
	def __init__(self, path: Path | str, sections: Sequence[ConfigSection]):
		self.path = Path(path)
		self.sections = tuple(sections)

	def load(self) -> ConfigLoadResult:
		created = False
		if not self.path.exists():
			parser = self._build_defaults_parser()
			self._write_with_comments(parser)
			created = True

		parser = self._read()
		issues: list[ConfigValidationIssue] = []
		dirty = created

		for section in self.sections:
			if not parser.has_section(section.name):
				parser.add_section(section.name)
				issues.append(
					ConfigValidationIssue(
						section=section.name,
						key="*",
						message="Section missing in file; populated with defaults.",
					)
				)
				dirty = True

			for option in section.options:
				existing = parser.get(section.name, option.key, fallback=None)
				if existing is None:
					new_value = option.render_default()
					parser.set(section.name, option.key, new_value)
					issues.append(
						ConfigValidationIssue(
							section=section.name,
							key=option.key,
							message="Missing entry; default applied.",
							reverted_to=new_value,
						)
					)
					dirty = True
					continue

				try:
					normalized = option.normalize(existing)
				except ConfigValidationError as exc:
					normalized = option.render_default()
					parser.set(section.name, option.key, normalized)
					issues.append(
						ConfigValidationIssue(
							section=section.name,
							key=option.key,
							message=str(exc),
							reverted_to=normalized,
						)
					)
					dirty = True
				else:
					if normalized != existing.strip():
						parser.set(section.name, option.key, normalized)
						dirty = True

		if dirty:
			self._write_with_comments(parser)

		return ConfigLoadResult(config=parser, issues=issues, created=created)

	def _build_defaults_parser(self) -> configparser.ConfigParser:
		parser = configparser.ConfigParser()
		for section in self.sections:
			parser.add_section(section.name)
			for option in section.options:
				parser.set(section.name, option.key, option.render_default())
		return parser

	def _read(self) -> configparser.ConfigParser:
		parser = configparser.ConfigParser()
		parser.read(self.path, encoding="utf-8")
		return parser

	def _write_with_comments(self, parser: configparser.ConfigParser) -> None:
		lines: list[str] = []
		managed_sections = {section.name for section in self.sections}

		for index, section in enumerate(self.sections):
			if index:
				lines.append("\n")
			for line in section.description:
				lines.append(f"; {line}\n")
			lines.append(f"[{section.name}]\n")

			items = {
				key: value
				for key, value in parser.items(section.name, raw=True)
				if parser.has_option(section.name, key)
			}

			for option in section.options:
				for line in option.description:
					lines.append(f"; {line}\n")
				value = parser.get(section.name, option.key, fallback=option.render_default())
				lines.append(f"{option.key} = {value}\n\n")
				items.pop(option.key.lower(), None)

			if items:
				lines.append("; Additional options preserved by ConfigManager\n")
				for key in sorted(items):
					lines.append(f"{key} = {items[key]}\n")
				lines.append("\n")

		for section_name in parser.sections():
			if section_name not in managed_sections:
				lines.append(f"[{section_name}]\n")
				for key, value in parser.items(section_name, raw=True):
					lines.append(f"{key} = {value}\n")
				lines.append("\n")

		self.path.write_text("".join(lines).rstrip() + "\n", encoding="utf-8")


def build_main_config_manager(
	path: Path | str, game_modes: Mapping[str, str]
) -> ConfigManager:
	pretty_modes = [f"{code} ({name})" for code, name in sorted(game_modes.items())]
	valid_mode_list = ["ALL", "SAME"] + sorted(game_modes.keys())

	def normalize_game_mode(value: str) -> str:
		trimmed = value.strip()
		lowered = trimmed.lower()
		if lowered == "all":
			return "ALL"
		if lowered == "same":
			return "SAME"
		if lowered in game_modes:
			return lowered
		raise ConfigValidationError(
			f"Value '{trimmed}' is not a recognized game mode. "
			f"Valid options: {', '.join(valid_mode_list)}."
		)

	sections: Sequence[ConfigSection] = (
		ConfigSection(
			name="Main",
			description=(
				"Primary configuration for Valorant Zoro. Edit values to customize behaviour.",
			),
			options=(
				ConfigOption(
					key="amount_of_matches_for_player_stats",
					default=10,
					value_type="int",
					min_value=1,
					max_value=20,
					description=(
						"Number of matches to aggregate before computing player statistics.",
						"Allowed range: 1-20. Default = 10.",
					),
				),
				ConfigOption(
					key="stats_used_game_mode",
					default="ALL",
					description=(
						"Queue to source player statistics from.",
						"Use ALL for every match, SAME for the active queue, or specify a queue code.",
						"Valid queue codes: " + ", ".join(pretty_modes),
						"Default = ALL.",
					),
					normalizer=normalize_game_mode,
				),
				ConfigOption(
					key="use_discord_rich_presence",
					default=False,
					value_type="bool",
					description=(
						"Enable Discord Rich Presence integration.",
						"Set to true to publish session details to your profile.",
						"Default = false.",
					),
				),
				ConfigOption(
					key="advanced_missing_agents",
					default=False,
					value_type="bool",
					description=(
						"Enable beta features for advanced missing agent detection in pregame.",
						"Default = false.",
					),
				),
			),
		),
	)

	return ConfigManager(path, sections)


@lru_cache(maxsize=128)
def get_userdata_from_id(user_id: str, host_player_uuid: str | None = None) -> tuple[str, bool]:
	req = api_request("PUT", f"https://pd.na.a.pvp.net/name-service/v2/players", headers=internal_api_headers,
					  data=[user_id])
	if req.status_code == 200:
		user_info = req.json()[0]
		user_name = f"{user_info['GameName']}#{user_info['TagLine']}"
		is_self = host_player_uuid is not None and user_id == host_player_uuid
		return user_name, is_self
	elif req.status_code == 429:
		logger.log(2, "Rate Limited | get_userdata_from_id")
	else:
		logger.log(1, f"Error in get_userdata_from_id | {req.status_code} | {req.json()}")
		return "null", False
	return "null", False


SELF_BADGE_RICH = "[bold white on blue] YOU [/]"
SELF_BADGE_PLAIN = "[YOU]"


def format_player_label(name: str, is_self: bool, *, rich: bool = True) -> str:
	if not is_self:
		return name
	badge = SELF_BADGE_RICH if rich else SELF_BADGE_PLAIN
	return f"{badge} {name}"


@lru_cache(maxsize=128)
def get_agent_data_from_id(agent_id: str) -> str:
	r = api_request("GET", f"https://valorant-api.com/v1/agents/{agent_id}")
	agent_name = r.json()["data"]["displayName"]
	return agent_name


@lru_cache(maxsize=128)
def get_agent_role(agent_id: str) -> str:
	"""
	Return the agent's role display name (Controller, Duelist, Initiator, Sentinel).
	"""
	try:
		r = api_request("GET", f"https://valorant-api.com/v1/agents/{agent_id}")
		data = r.json().get("data", {})
		return (data.get("role") or {}).get("displayName", "Unknown")
	except Exception:
		return "Unknown"


@lru_cache(maxsize=1)
def get_all_agents_by_role() -> Dict[str, List[str]]:
	"""
	Fetch all playable agents once and bucket them by role.
	"""
	result: Dict[str, List[str]] = {"Controller": [], "Duelist": [],
									"Initiator": [], "Sentinel": []}
	try:
		r = api_request("GET", "https://valorant-api.com/v1/agents?isPlayableCharacter=true")
		for ag in r.json().get("data", []):
			role = (ag.get("role") or {}).get("displayName", "Unknown")
			name = ag.get("displayName", "Unknown")
			if role in result:
				result[role].append(name)
	except Exception:
		pass
	return result


# Static utility classification for advanced view
_AGENT_UTILITY_TAG: Dict[str, str] = {
	# Flashers
	"Phoenix": "Flash",
	"Yoru": "Flash",
	"Breach": "Flash",
	"Skye": "Flash",
	"KAY/O": "Flash",
	"Gekko": "Flash",
	"Reyna": "Flash",
	"Vyse": "Flash",
	# Smokers / Controllers
	"Brimstone": "Smoke",
	"Omen": "Smoke",
	"Astra": "Smoke",
	"Viper": "Smoke",
	"Harbor": "Smoke",
	"Clove": "Smoke"
}

def categorize_agent_utility(agent_name: str) -> str:
	return _AGENT_UTILITY_TAG.get(agent_name, "Other")


@lru_cache(maxsize=128)
def get_mapdata_from_id(map_id: str) -> str | None:
	r = api_request("GET", f"https://valorant-api.com/v1/maps")
	maps = r.json()["data"]
	for map_data in maps:
		if map_data["mapUrl"] == map_id:
			return map_data['displayName']
	return None


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


def get_headshot_percent(match_data: dict) -> dict[str, float | int]:
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
		total_shots = other_damage_stats["legshots"] + other_damage_stats["bodyshots"] + other_damage_stats["headshots"]
		if total_shots > 0:
			headshot_percentage = (other_damage_stats["headshots"] / total_shots) * 100
		else:
			headshot_percentage = 0
		players_headshot_percent[str(player_uuid)] = headshot_percentage
	return players_headshot_percent


def generate_match_report(match_stats: dict, host_player_uuid: str, compact_mode: bool = False) -> str:
	"""
	Generate a formatted match report for the host player.

	Parameters:
		match_stats (dict): The match details are returned from the API.
		host_player_uuid (str): The UUID of the host player.
		compact_mode (bool): If True, output only key info in one line.

	Returns:
		list[str]: A list of strings representing the report lines.
				   In compact mode, the list will contain a single string.
	"""
	# Retrieve host player data from match_stats
	host_player = next(
		(p for p in match_stats.get("players", []) if p.get("subject") == host_player_uuid),
		None
	)
	if host_player is None:
		return "No data available for host player."

	# Basic stats for host player
	# user_name = get_userdata_from_id(host_player['subject'])[0]
	agent_name = get_agent_data_from_id(host_player['characterId'])
	stats = host_player.get("stats", {})
	kd = calculate_kd(stats.get("kills", 0), stats.get("deaths", 0))

	# Determine win/loss status based on team data
	win_status = "N/A"
	teams = match_stats.get("teams", [])
	host_team = host_player.get("teamId", "")
	for team in teams:
		if team.get("teamId") == host_team:
			win_status = "Win" if team.get("won", False) else "Loss"
			break

	# Calculate damage stats to determine headshot percentage (host only)
	damage_stats = {"legshots": 0, "bodyshots": 0, "headshots": 0}
	for round_stats in match_stats.get("roundResults", []):
		for player_stat in round_stats.get("playerStats", []):
			if player_stat.get("subject") == host_player_uuid:
				for hit in player_stat.get("damage", []):
					damage_stats = update_damage_stats(damage_stats, host_player_uuid, hit, True)
	total_shots = damage_stats["legshots"] + damage_stats["bodyshots"] + damage_stats["headshots"]
	headshot_percentage = (damage_stats["headshots"] / total_shots * 100) if total_shots > 0 else 0

	# Get the map name using your existing helper (fallback to "Unknown")
	map_name = get_mapdata_from_id(match_stats["matchInfo"].get("mapId", "Unknown"))

	overall_color = "green" if win_status == "Win" else "red"
	kd_color = "bright_green" if kd >= 1.0 else "bright_red"
	hs_color = "bright_green" if headshot_percentage >= 20 else "bright_red"
	scorer = ValorantPerformanceScorer()
	scorer.prepare(match_stats)
	player_score, _ = scorer.score_player(host_player_uuid, explain=False)
	if compact_mode:
		compact_report = (
			f"[{overall_color}]"  # Start overall color
			f"[Map: {map_name}] "
			f"[Agent: {agent_name}] "
			f"[Result: {win_status}] "
			f"[Score: {player_score}] "
			f"[HS%: [{hs_color}]{round(headshot_percentage, 2)}%[/{hs_color}]] "
			f"[KD: [{kd_color}]{kd}[/{kd_color}]]"
			f"[/{overall_color}]"  # End overall color
		)
		return compact_report
	"""
	# Otherwise, generate a detailed multi-line report with sections.
	border = overall_color + "=" * 50 + Style.RESET_ALL
	report = []
	report.append(border)
	report.append(overall_color + "MATCH REPORT".center(50) + Style.RESET_ALL)
	report.append(border)
	report.append("")
	report.append(overall_color + f"Player: (You) {user_name} ({agent_name})".center(50) + Style.RESET_ALL)
	report.append("-" * 50)
	report.append(f"Score    : {stats.get('score', 'N/A')}")
	report.append(f"Kills    : {stats.get('kills', 0)}")
	report.append(f"Deaths   : {stats.get('deaths', 0)}")
	report.append(f"Assists  : {stats.get('assists', 0)}")
	report.append(f"KD Ratio : {kd_color}{kd}{Style.RESET_ALL}")
	report.append(f"Result   : {overall_color}{win_status}{Style.RESET_ALL}")
	report.append("")
	report.append("Damage Breakdown:".center(50))
	report.append(f"  Total Shots : {total_shots}")
	report.append(f"  Leg Shots   : {damage_stats['legshots']}")
	report.append(f"  Body Shots  : {damage_stats['bodyshots']}")
	report.append(f"  Head Shots  : {damage_stats['headshots']}")
	report.append(f"  Headshot %% : {hs_color}{headshot_percentage:.2f}%{Style.RESET_ALL}")
	report.append("")
	report.append(border)

	return report
	"""
	return "null"


@lru_cache(maxsize=10)
def get_rank_from_uuid(user_id: str, platform: str = "PC"):
	rank_tier = -1

	if platform == "PC":
		r = api_request("GET", f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=competitive",
						headers=internal_api_headers)
		try:
			rank_tier = int(r.json()["Matches"][0]["TierAfterUpdate"])
		except:
			return "Unranked"
	elif platform == "CONSOLE":
		r = api_request("GET",
						f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=console_competitive",
						headers=internal_api_headers_console)
		try:
			rank_tier = int(r.json()["Matches"][0]["TierAfterUpdate"])
		except:
			# If the user plays no comp match
			return "Unranked"

	if rank_tier == 0:
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
		rank = rank_mapping.get(int(rank_tier), "Unknown Rank")
	return rank


def create_session():
	session = requests.Session()
	retry = Retry(
		total=3,  # Total number of retries
		read=5,  # Number of retries on read errors
		connect=5,  # Number of retries on connection errors
		backoff_factor=1,  # Backoff factor to apply between attempts
		status_forcelist=[500, 502, 503, 504],  # Retry on these status codes
	)
	adapter = HTTPAdapter(max_retries=retry)
	session.mount('https://', adapter)
	return session


# Shared HTTP session and default timeouts for efficiency
REQUEST_TIMEOUT = (5, 15)  # (connect timeout, read timeout)
SESSION = create_session()


@lru_cache(maxsize=256)
def get_match_details(match_id: str, platform: str = "PC"):
	headers = internal_api_headers if platform == "PC" else internal_api_headers_console
	match_url = f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}"

	while True:
		match_response = api_request("GET", match_url, headers=headers)
		if match_response.status_code == 429:
			logger.log(2, f"Rate limited fetching match {match_id}")
		elif match_response.status_code == 200:
			return match_response.json()
		else:
			logger.log(1, f"Error fetching match {match_id}: {match_response.status_code}")
			return None


def get_player_data_from_uuid(user_id: str, cache: dict, platform: str = "PC", gamemode: str = None):
	kills = 0
	deaths = 0
	wins = []
	partyIDs = {}
	headshot = []
	search = ""

	try:
		stats_used_game_mode = config_main.get("stats_used_game_mode", "ALL").lower()
		if stats_used_game_mode != "all":
			if stats_used_game_mode == "same" and gamemode is not None:
				search = f"&queue={gamemode}"
			elif stats_used_game_mode != "same":
				search = f"&queue={stats_used_game_mode}"

		headers = internal_api_headers if platform == "PC" else internal_api_headers_console
		url = f"https://pd.na.a.pvp.net/match-history/v1/history/{user_id}?endIndex={int(config_main.get('amount_of_matches_for_player_stats', '10'))}{search}"

		response = api_request("GET", url, headers=headers)

		history = response.json().get("History", [])

		save_match_data = None
		for i in history:
			time.sleep(3)  # TODO | Remove someday
			match_id = i["MatchID"]
			match_data = get_match_details(match_id, platform)

			if match_data is None:
				continue  # Skip if match data couldn't be retrieved

			player_data = match_data.get("players", [])
			player_score = []
			performance = ValorantPerformanceScorer()
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
					wins.append("[green]■[/green]" if won else "[red]■[/red]")
					kills += match["stats"]["kills"]
					deaths += match["stats"]["deaths"]

					performance.prepare(match_data)
					player_score.append(performance.score_player(user_id)[0])

					# agent = get_agent_data_from_id(match["characterId"])  # TODO | Unused
			avg_score = sum(player_score) / len(player_score) if len(player_score) > 0 else 0
			headshot.append(round(get_headshot_percent(match_data)[str(user_id)]))

			avg_headshot = sum(headshot) / len(headshot) if len(headshot) > 0 else 0

		if len(history) == 0:
			cache[user_id] = (-1, ['No Matches'], -1, -1)
			return {}, cache

		kd_ratio = calculate_kd(kills, deaths)
		try:
			cache[user_id] = (kd_ratio, wins, round(avg_headshot), avg_score)
		except ReferenceError:
			logger.log(2, "get_player_data_from_uuid ReferenceError on avg_headshot | avg_score")
			cache[user_id] = (kd_ratio, wins, 0, avg_score)

		return partyIDs, cache

	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
		cache[user_id] = (-1, ['Error'], -1, -1)
		return {}, cache


def get_rank_color(rank: str, use_rich_markup: bool = False):
	"""Return colored text for a rank, with Radiant being multicolored."""
	if not use_rich_markup:
		# Define color codes
		RANK_COLORS = {
			"Iron": "\033[90m",  # Gray
			"Bronze": "\033[38;5;130m",  # Orange/Brown
			"Silver": "\033[37m",  # Light Gray/White
			"Gold": "\033[33m",  # Yellow
			"Plat": "\033[36m",  # Cyan
			"Diamond": "\033[35m",  # Magenta
			"Ascendant": "\033[38;5;82m",  # Bright Green
			"Immortal": f"\033[31m",  # Red
			"Radiant": "\033[38;5;196mR\033[38;5;202ma\033[38;5;226md\033[38;5;82mi\033[36ma\033[38;5;33mn\033[38;5;201mt"  # Rainbow (Multi-Colored)
		}

		RESET = "\033[0m"  # Reset color to default

		# If the rank is Radiant, apply the multicolored effect
		if "Radiant" in rank.capitalize():
			return f"[{RANK_COLORS['Radiant']}]{RESET}"

		# For other ranks, return the appropriate color
		for rank_name, color in RANK_COLORS.items():
			if rank_name.capitalize() in rank.capitalize():
				return f"{color}[{rank}]{RESET}"

		# Default return for unknown ranks
		return f"\033[90m[{rank}]{RESET}"  # No color, default text
	else:
		RANK_COLORS = {
			"Iron": "grey50",
			"Bronze": "orange4",
			"Silver": "white",
			"Gold": "yellow",
			"Plat": "cyan",
			"Diamond": "magenta",
			"Ascendant": "green3",
			"Immortal": "red",
		}

		rank_cap = rank.capitalize()

		# Handle "Radiant" with multicolor effect
		if "Radiant" in rank_cap:
			return "[#ff0000]R[/][#ff7f00]a[/][#ffff00]d[/][#00ff00]i[/][#0000ff]a[/][#4b0082]n[/][#8f00ff]t[/]"

		# For other ranks, loop through the dictionary
		for rank_name, color in RANK_COLORS.items():
			if rank_name.capitalize() in rank_cap:
				return f"[{color}][{rank}][/{color}]"

		# Default return for unknown ranks
		return f"[grey50][{rank}][/grey50]"


def get_user_current_state(puuid: str, presences_data: dict = None) -> int:
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
	requests.packages.urllib3.disable_warnings()  # noqa
	try:
		if presences_data is None:
			with api_request("GET", f"https://127.0.0.1:{port}/chat/v4/presences",
							 headers={"authorization": f"Basic {password}", "accept": "*/*",
									  "Host": f"127.0.0.1:{port}"}, verify=False) as r:
				data = r.json()
		else:
			data = presences_data

		all_user_data = data["presences"]
		for user in all_user_data:
			if user["puuid"] == puuid:
				# Check if the player is playing Valorant. If not, return 0
				if str(user["product"]).lower() != "valorant":
					#console.print(f"State: {0}")
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
				else:  # Unknown State
					return 5
	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
	if DEBUG:
		console.print(f"State of {puuid}: {-1}")
	return -1


def get_current_game_score(puuid: str) -> tuple[int, int]:
	requests.packages.urllib3.disable_warnings()  # noqa
	all_user_data = "null"
	decoded_user_data = "null"

	try:
		data = api_request("GET", f"https://127.0.0.1:{port}/chat/v4/presences",
						   headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"},
						   verify=False).json()

		all_user_data = data["presences"]
		for user in all_user_data:
			if user["puuid"] == puuid:
				encoded_user_data: str = user["private"]
				decoded_user_data = loads(b64decode(encoded_user_data))
				allyTeamScore = decoded_user_data["partyOwnerMatchScoreAllyTeam"]
				enemyTeamScore = decoded_user_data["partyOwnerMatchScoreEnemyTeam"]
				return allyTeamScore, enemyTeamScore
	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
	logger.log(1,
			   f"Returning -1, -1 for current game score!\nData PUUID: {puuid}\n All_User_Data: {all_user_data}\nDecoded_User_Data: {decoded_user_data}")
	return -1, -1


def get_party_symbol(number: int, use_markup: bool = False) -> str:
	party_symbol = "★"
	if use_markup:
		# Using Rich-supported color names (or hex values)
		party_colors = [
			"red",  # originally ANSI 196
			"orange3",  # originally ANSI 208
			"yellow",  # originally ANSI 226
			"green",  # originally ANSI 46
			"blue",  # originally ANSI 21
			"magenta",  # originally ANSI 201
			"cyan",  # originally ANSI 51
			"deeppink",  # originally ANSI 200
			"purple",  # originally ANSI 93
			"chartreuse3",  # originally ANSI 118
		]
		color = party_colors[number - 1]
		# Return a string with Rich markup that will color the star.
		return f"[{color}]{party_symbol}[/{color}] "
	else:
		party_colours = [
			"\033[38;5;196m",  # Red
			"\033[38;5;208m",  # Orange
			"\033[38;5;226m",  # Yellow
			"\033[38;5;46m",  # Green
			"\033[38;5;21m",  # Blue
			"\033[38;5;201m",  # Magenta
			"\033[38;5;51m",  # Cyan
			"\033[38;5;200m",  # Pink
			"\033[38;5;93m",  # Bright Purple
			"\033[38;5;118m",  # Lime Green
		]
		reset = "\033[0m"
		coloured_party_symbol = f"{party_colours[number - 1]}{party_symbol}{reset} "
		return coloured_party_symbol


DISPATCHED_MATCH_REPORTS: set[str] = set()
_DISPATCHED_REPORT_ORDER: deque[str] = deque()


async def match_report(match_id: str):
	"""
		Polls the match details endpoint until the match data is available,
		processes the data, and then calls the console notification.
	"""
	# Poll every 5 seconds until match data is available.
	while True:
		response = api_request("GET", f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}",
							   headers=internal_api_headers)
		if response.status_code == 200:
			match_data = response.json()
			break
		await asyncio.sleep(5)

	# Process the match data to calculate statistics.
	summary = generate_match_report(match_data, val_uuid, True)

	# Display the notification on the console.
	if summary and summary != "null":
		Notification.add_notification(summary, dedupe=True, dedupe_ttl=10.0)


def dispatch_match_report_once(match_id: str) -> bool:
	match_key = str(match_id)
	if not match_key:
		return False
	if match_key in DISPATCHED_MATCH_REPORTS:
		return False

	DISPATCHED_MATCH_REPORTS.add(match_key)
	_DISPATCHED_REPORT_ORDER.append(match_key)
	while len(_DISPATCHED_REPORT_ORDER) > 50:
		old_id = _DISPATCHED_REPORT_ORDER.popleft()
		DISPATCHED_MATCH_REPORTS.discard(old_id)

	asyncio.create_task(match_report(match_key))
	return True


LOOP_THROTTLE_INITIAL = 1.0
LOOP_THROTTLE_MIN = 0.6
LOOP_THROTTLE_MAX = 2.0
LOOP_THROTTLE_INCREASE = 0.2
LOOP_THROTTLE_DECREASE = 0.25


class LoopThrottler:
	"""Adaptive sleep helper for console loops."""

	def __init__(self, initial: float = LOOP_THROTTLE_INITIAL):
		self._interval = initial

	def record_iteration(self, state_changed: bool) -> None:
		if state_changed:
			# Move an interval toward the responsive floor when content updates.
			self._interval = max(LOOP_THROTTLE_MIN, self._interval - LOOP_THROTTLE_DECREASE)
		else:
			# Drift toward the ceiling when nothing meaningful changed.
			self._interval = min(LOOP_THROTTLE_MAX, self._interval + LOOP_THROTTLE_INCREASE)

	async def sleep(self) -> None:
		await asyncio.sleep(self._interval)


async def run_in_game(cache: dict = None, partys: dict = None):
	if cache is None:
		cache = {}

	console.print("Loading...")

	# Fetch match ID
	while True:
		try:
			r = api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}",
							headers=internal_api_headers)
			if r.status_code == 200:
				match_id = r.json()["MatchID"]
				break
			else:
				if 3 <= get_user_current_state(str(val_uuid)) <= 4:
					await asyncio.sleep(0.5)
				else:
					return None
		except:
			await asyncio.sleep(0.5)

	got_players = False
	player_data = {}
	player_name_cache = []
	team_blue_player_list = {}
	team_red_player_list = {}
	user_team_id = None
	if partys is None:
		partys = {}

	throttler = LoopThrottler()
	last_signature = None
	match_report_dispatched = False

	def fetch_player_data(player_id, platform):
		nonlocal partys, cache
		with request_semaphore:
			party_data, cache = get_player_data_from_uuid(player_id, cache, platform)
			partys = add_parties(partys, party_data)
		return None

	if config_main.get("use_discord_rich_presence", "").lower() == "true":
		RPC.update(
			state="In-Game",
			details=f"Loading...",
			large_image="valorant",
			large_text="Valorant Zoro",
			party_size=[1, 5],
			start=int(time.time()),
		)

	host_player_agent = None

	while True:
		state_changed = False
		exit_after_render = False
		exit_sleep = 0
		try:
			# Get match data
			with api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/matches/{match_id}",
							 headers=internal_api_headers) as r:
				if r.status_code == 400:
					logger.log(2,
							   f"Login may have expired! Re-logging in.\n Tried to get in-game match data. MATCH_ID -> {match_id}")
					await log_in()
				elif r.status_code == 404:
					return None
				else:
					match_data = r.json()
			mode_name = "null"
			gamemode_name = "null"
			if match_data["State"] not in ("CLOSED", "POST_GAME"):
				map_id = match_data["MapID"]
				try:
					gamemode_name = str(match_data["MatchmakingData"]["QueueID"]).capitalize()
					mode_name = GAME_MODES.get(gamemode_name.lower(), gamemode_name)
					is_solo = False
				except TypeError:
					gamemode_name = match_data["ProvisioningFlow"]
					if gamemode_name == "ShootingRange":
						gamemode_name = "Shooting Range"
					if gamemode_name == "ReplayNewPlayerExperience":
						gamemode_name = "Tutorial"
					is_solo = True
				map_name = get_mapdata_from_id(map_id) if not is_solo else "The Range"

				if config_main.get("use_discord_rich_presence", "").lower() == "true":
					RPC.update(
						state=f"In-Game",
						details=f"{map_name} | {mode_name.capitalize()} | {host_player_agent.capitalize() if host_player_agent is not None else ''}",
						large_image="valorant",
						large_text="Valorant Zoro",
						party_size=[1, 5],
					)

				# Build a header string
				header = f"[green]Map:[/green] {map_name}\n[cyan]Game mode:[/cyan] {mode_name}\n\n"

				# (Populate player lists once)
				if not got_players:
					threads = []
					for player in match_data["Players"]:
						player_id = player["PlayerIdentity"]["Subject"]
						team_id = player["TeamID"]
						is_level_hidden = player["PlayerIdentity"]["HideAccountLevel"]
						player_lvl = str(player["PlayerIdentity"]["AccountLevel"]) if not is_level_hidden else "--"
						agent_name = get_agent_data_from_id(player['CharacterID'])
						host_player, is_user = get_userdata_from_id(player_id, val_uuid)
						host_player = format_player_label(host_player, is_user)
						if is_user:
							user_team_id = team_id.lower()
							host_player_agent = agent_name
						player_name_cache.append(host_player)

						# Fetch player data asynchronously
						if "console" in gamemode_name:
							rank = get_rank_from_uuid(str(player_id), "CONSOLE")
							thread = threading.Thread(target=fetch_player_data, args=(player_id, "CONSOLE"))
						else:
							rank = get_rank_from_uuid(str(player_id))
							thread = threading.Thread(target=fetch_player_data, args=(player_id, "PC"))
						threads.append(thread)
						thread.start()

						if team_id.lower() == "blue":
							team_blue_player_list[host_player] = (agent_name, player_lvl, rank, player_id)
						elif team_id.lower() == "red":
							team_red_player_list[host_player] = (agent_name, player_lvl, rank, player_id)

						player_data[host_player] = cache.get(str(player_id), ("Loading", "-", "Loading", "-"))

				# Refresh player data (if needed)
				count = 0
				party_exists = []
				party_number = 1
				for player in match_data["Players"]:
					player_id = player["PlayerIdentity"]["Subject"]
					player_data[str(player_name_cache[count])] = cache.get(str(player_id),
																		   ("Loading", "-", "Loading", "-"))
					count += 1

				def format_kd_value(value: Any) -> str:
					if value is None:
						return "--"
					if isinstance(value, (int, float)):
						if value < 0:
							return "--"
						return f"{value:.2f}"
					if isinstance(value, str):
						return value if value not in ("", "-") else "--"
					return "--"

				def format_hs_value(value: Any) -> str:
					if value is None:
						return "--"
					if isinstance(value, (int, float)):
						if value < 0:
							return "--"
						return f"{int(round(value))}%"
					if isinstance(value, str):
						normalized = value.strip()
						if normalized in ("", "-", "--"):
							return "--"
						if normalized.lower() == "loading":
							return "Loading"
						return normalized if normalized.endswith("%") else f"{normalized}%"
					return "--"

				def format_recent_matches(value: Any) -> str:
					if isinstance(value, list):
						if not value:
							return "--"
						if len(value) == 1:
							return value[0]
						return "".join(str(item) for item in value)
					if isinstance(value, str):
						return value if value not in ("", "-") else "--"
					return "--"

				def build_team_rows(team_players: dict[str, tuple[str, str, str, str]]) -> list[dict[str, str]]:
					nonlocal party_number
					rows: list[dict[str, str]] = []
					for user_name, data in team_players.items():
						party_symbol = ""
						for party_id, members in partys.items():
							if len(members) > 1 and str(data[3]) in members:
								for existing_party in party_exists:
									if existing_party[0] == party_id:
										party_symbol = get_party_symbol(int(existing_party[1]), True)
										break
								else:
									party_exists.append([party_id, party_number])
									party_symbol = get_party_symbol(int(party_number), True)
									party_number += 1
									break
						kd, wins, hs, _ = player_data.get(user_name, ("Loading", "-", "Loading", "-"))
						rows.append(
							{
								"party": party_symbol,
								"level": data[1],
								"rank": data[2],
								"player": user_name,
								"agent": data[0],
								"kd": format_kd_value(kd),
								"hs": format_hs_value(hs),
								"recent": format_recent_matches(wins),
							}
						)
					return rows

				def build_team_table(rows: list[dict[str, str]], *, header_color: str) -> Table:
					table = Table(
						show_header=True,
						header_style=f"bold {header_color}",
						pad_edge=False,
						expand=True,
					)
					table.add_column("Party", style=header_color, no_wrap=True)
					table.add_column("Level", style=header_color, no_wrap=True)
					table.add_column("Rank", no_wrap=True)
					table.add_column("Player", overflow="fold")
					table.add_column("Agent", style="cyan", no_wrap=True)
					table.add_column("KD", style="magenta", justify="right", no_wrap=True)
					table.add_column("HS%", style="magenta", justify="right", no_wrap=True)
					table.add_column("Recent", style="magenta")

					for row in rows:
						level_value = row["level"]
						level_text = (
							f"LVL {level_value}"
							if level_value not in ("", "-", "--", "None")
							else "LVL --"
						)
						level_markup = f"[{header_color}]{level_text}[/{header_color}]"
						agent_value = row["agent"]
						agent_markup = (
							f"[italic]{agent_value}[/]"
							if agent_value not in ("-", "--", "Unknown")
							else agent_value
						)
						table.add_row(
							row["party"],
							level_markup,
							get_rank_color(row["rank"], True),
							row["player"],
							agent_markup,
							row["kd"],
							row["hs"],
							row["recent"],
						)
					return table

				team_blue_rows = build_team_rows(team_blue_player_list)
				team_red_rows = build_team_rows(team_red_player_list)

				actual_user_team = user_team_id or "blue"
				if actual_user_team == "red":
					own_team_rows = team_red_rows
					opponent_rows = team_blue_rows
					own_team_actual = "Red"
					opponent_actual = "Blue"
				else:
					own_team_rows = team_blue_rows
					opponent_rows = team_red_rows
					own_team_actual = "Blue"
					opponent_actual = "Red"

				if user_team_id is None:
					own_team_title = "Your Team"
					opponent_title = "Opponents"
				else:
					own_team_title = f"Your Team ({own_team_actual})"
					opponent_title = f"Opponents ({opponent_actual})"

				own_team_panel = Panel(
					build_team_table(own_team_rows, header_color="blue"),
					title=own_team_title,
					border_style="blue",
					padding=(0, 1),
				)
				opponent_panel = Panel(
					build_team_table(opponent_rows, header_color="red"),
					title=opponent_title,
					border_style="red",
					padding=(0, 1),
				)

				score = get_current_game_score(val_uuid)
				render_header = f"{header}[yellow]Score:[/yellow] {score[0]} | {score[1]}\n"

				scoreboard_lines = []
				try:
					with api_request("GET", f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}",
									 headers=internal_api_headers) as re_match_stats:
						match_stats = re_match_stats.json()

					total_rounds = match_stats["teams"][0]["roundsPlayed"]
					team_1_rounds = match_stats["teams"][0]["roundsWon"]
					team_2_rounds = match_stats["teams"][1]["roundsWon"]

					scoreboard_lines.append(f"[yellow]Total Rounds:[/yellow] {total_rounds}")
					scoreboard_lines.append(f"[yellow]Score:[/yellow] {team_1_rounds}  |  {team_2_rounds}")

					if not match_report_dispatched:
						asyncio.create_task(match_report(match_id))
						match_report_dispatched = True
					exit_after_render = True
					exit_sleep = 3
				except Exception:
					pass

				render_payload = {
					"header": render_header,
					"own_team_label": own_team_title,
					"opponent_label": opponent_title,
					"own_team_rows": own_team_rows,
					"opponent_rows": opponent_rows,
					"scoreboard": scoreboard_lines
				}
				# Hash the render payload so we only redraw when meaningful data changes.
				signature = hashlib.sha1(dumps(render_payload, sort_keys=True).encode("utf-8")).hexdigest()
				state_changed = signature != last_signature
				if state_changed:
					last_signature = signature
					console.clear()
					clear_console()
					console.print(render_header, markup=True)
					console.print(Columns([own_team_panel, opponent_panel], expand=True, equal=True))
					for line in scoreboard_lines:
						console.print(line)

				got_players = True

			else:
				if not match_report_dispatched:
					asyncio.create_task(match_report(match_id))
					match_report_dispatched = True
				exit_after_render = True

			# Feed throttler with whether we rendered a new frame.
			throttler.record_iteration(state_changed)
			if exit_after_render:
				if exit_sleep:
					await asyncio.sleep(exit_sleep)
				return
			await throttler.sleep()

		except KeyboardInterrupt:
			sys.exit(1)
		except Exception as e:
			await log_in()
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			console.print("Error Logged!")


def print_buffered(buffer):
	"""Print content from a buffer without clearing the screen."""
	sys.stdout.write(buffer.getvalue())
	sys.stdout.flush()


def add_parties(partys, new_parties):
	if DEBUG:
		with open(f"{DATA_PATH}/partys_thing.json", "a") as file:
			dump(partys, file, indent=4)
	for party_id, new_players in new_parties.items():
		if party_id in partys:
			# Add new players to the existing party, ensuring no duplicates
			partys[party_id].extend(new_players)
			partys[party_id] = list(set(partys[party_id]))  # Remove duplicates
		else:
			# Create a new party with the new players
			partys[party_id] = new_players
	return partys


async def with_spinner(message, coro):
	with Live(Spinner("dots", text=message), refresh_per_second=12):
		return await coro


async def run_pregame(data: dict):
	console.print("Match FOUND! Getting match details")

	got_rank = False
	got_map_and_gamemode = False
	player_data = {}
	threads = []
	rank_list = {}

	cache = {}
	partys = {}
	throttler = LoopThrottler()
	last_signature = None

	def fetch_player_data(player_id, platform):
		nonlocal cache, partys
		with request_semaphore:
			party_data, cache = get_player_data_from_uuid(player_id, cache, platform)
			partys = add_parties(partys, party_data)
		return None

	if config_main.get("use_discord_rich_presence", "").lower() == "true":
		RPC.update(
			state="In Agent Select",
			details="Loading...",
			large_image="valorant",
			large_text="Valorant Zoro",
			party_size=[1, 5],
			start=int(time.time()),
		)

	while True:
		state_changed = False
		try:
			buffer = StringIO()
			with api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{data['MatchID']}",
							 headers=internal_api_headers) as r:
				match_data = r.json()
				if DEBUG:
					with open(f"{DATA_PATH}/pre_match_data.json", "w") as f:
						dump(match_data, f, indent=4)

			if not got_map_and_gamemode:
				map_name = get_mapdata_from_id(match_data["MapID"])
				gamemode_name = match_data["QueueID"]
				if config_main.get("use_discord_rich_presence", "").lower() == "true":
					RPC.update(
						state="In Agent Select",
						details=f"{map_name} | {gamemode_name.capitalize()}",
						start=int(time.time()),
						party_size=[1, 5],
					)

				got_map_and_gamemode = True

			buffer.write(f"[bright_white]{'=' * 30}[/bright_white]\n")
			buffer.write(f"[green]Map: {map_name}[/green]\n")
			buffer.write(f"[cyan]Game Mode: {str(gamemode_name).capitalize()}[/cyan]\n")
			buffer.write(f"[bright_white]{'=' * 30}\n\n[/bright_white]")

			# our_team_colour = match_data["AllyTeam"]["TeamID"]

			party_number = 1
			party_exists = []

			# Track which agents have been selected so far
			selected_agent_ids: List[str] = []

			for ally_player in match_data["AllyTeam"]["Players"]:
				user_name, is_user = get_userdata_from_id(ally_player["PlayerIdentity"]["Subject"], val_uuid)
				user_name = format_player_label(user_name, is_user)

				is_level_hidden = ally_player["PlayerIdentity"]["HideAccountLevel"]
				if not is_level_hidden:
					player_level = str(ally_player["PlayerIdentity"]["AccountLevel"])
				else:
					player_level = "--"
				party_symbol = ""

				state = ally_player["CharacterSelectionState"]

				try:
					agent_name = get_agent_data_from_id(ally_player["CharacterID"])
					if agent_name != "None" and ally_player["CharacterID"]:
						selected_agent_ids.append(ally_player["CharacterID"])
					if is_user:
						if config_main.get("use_discord_rich_presence", "").lower() == "true":
							RPC.update(
								state="In Agent Select",
								details=f"{map_name} | {gamemode_name.capitalize()} | ({'H' if state.lower() == 'selected' else 'L'}) {agent_name.capitalize()}",
								party_size=[1, 5],
							)
				except Exception:
					agent_name = "None"

				if not got_rank:
					if "console" in gamemode_name:
						rank = get_rank_from_uuid(str(ally_player["PlayerIdentity"]["Subject"]), "CONSOLE")
						rank_list[str(user_name)] = str(rank)
						thread = threading.Thread(target=fetch_player_data,
												  args=(ally_player["PlayerIdentity"]["Subject"], "CONSOLE"))
					else:
						rank = get_rank_from_uuid(str(ally_player["PlayerIdentity"]["Subject"]))
						rank_list[str(user_name)] = str(rank)
						thread = threading.Thread(target=fetch_player_data,
												  args=(ally_player["PlayerIdentity"]["Subject"], "PC"))
					threads.append(thread)
					thread.start()

				state = ally_player["CharacterSelectionState"]

				rank = rank_list.get(str(user_name), "Failed")

				# Ensure the rank color is applied correctly
				for party_id, members in partys.items():
					if len(members) > 1:
						if ally_player["PlayerIdentity"]["Subject"] in members:
							for existing_party in party_exists:
								if existing_party[0] == party_id:
									party_symbol = get_party_symbol(int(existing_party[1]), True)
									break
							else:
								party_exists.append([party_id, party_number])
								party_symbol = get_party_symbol(int(party_number), True)
								party_number += 1
								break

				state_display = {
					"": "(Picking)",
					"selected": "(Hovering)",
					"locked": "(Locked)"
				}.get(state, "(Unknown)")

				state_color = {
					"": "yellow",
					"selected": "blue",
					"locked": "green"
				}.get(state, "red")

				buffer.write(
					f"{party_symbol}[{state_color}][LVL {player_level}][/{state_color}] {get_rank_color(rank, True)} {user_name}: {agent_name} {state_display}\n"
				)

				kd, wins, avg, score = cache.get(str(ally_player["PlayerIdentity"]["Subject"]),
										  ("Loading", "-", "Loading", "-"))
				buffer.write(f"[magenta]  Player KD: {kd} | Headshot: {avg}% | Score: {score}[/magenta]\n")
				buffer.write(f"[bright_magenta]  Past Matches: {''.join(wins)}[/bright_magenta]\n\n")

			# -------------------------------------------------------
			# Missing agents panel
			# -------------------------------------------------------
			all_by_role = get_all_agents_by_role()
			selected_roles = {get_agent_role(aid) for aid in selected_agent_ids}
			missing_output_lines: List[str] = []

			for role, agents in all_by_role.items():
				if role in ("Unknown", ""):
					continue
				# Skip role already covered
				if role in selected_roles:
					continue
				# Remove agents already picked
				missing_agents = [a for a in agents if a not in [get_agent_data_from_id(i) for i in selected_agent_ids]]
				if not missing_agents:
					continue

				if ADVANCED_MISSING_AGENTS:
					# subgroup by utility
					by_util: Dict[str, List[str]] = {"Flash": [], "Smoke": [], "Both": [], "Other": []}
					for ag in missing_agents:
						by_util[categorize_agent_utility(ag)].append(ag)

					missing_output_lines.append(f"[white]{role}:[/white]")
					for util_key in ("Flash", "Smoke", "Both", "Other"):
						util_agents = by_util[util_key]
						if util_agents:
							names_str = ", ".join(util_agents)
							missing_output_lines.append(f"  [cyan]{util_key}:[/cyan] {names_str}")
				else:
					names_str = ", ".join(missing_agents)
					missing_output_lines.append(f"[white]{role}:[/white] {names_str}")

			if missing_output_lines:
				buffer.write("[yellow]Missing Agents[/yellow]\n")
				buffer.write("\n".join(missing_output_lines) + "\n\n")

			got_rank = True
			buffer.write(
				f"[red]Enemy team: {match_data['EnemyTeamLockCount']}/{match_data['EnemyTeamSize']} LOCKED[/red]\n")
			transitioning = False
			if match_data["PhaseTimeRemainingNS"] == 0:
				buffer.write(f"[cyan]In Loading Phase[/cyan]\n")
				transitioning = True

			render_output = buffer.getvalue()
			# Hash the panel content so we only redraw when the payload changes.
			signature = hashlib.sha1(render_output.encode("utf-8")).hexdigest()
			if signature != last_signature:
				state_changed = True
				last_signature = signature
				clear_console()
				console.print(render_output, markup=True)

			# Feed the adaptive throttler (flagging transitions as changes).
			throttler.record_iteration(state_changed or transitioning)
			if transitioning:
				break
			await throttler.sleep()
		except KeyboardInterrupt:
			sys.exit(1)
		except KeyError:
			return
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			console.print("Error Logged!")

	logger.log(3, "Loading pregame -> in-game")
	await run_in_game(cache, partys)


def clear_console():
	os.system("cls" if os.name == "nt" else "clear")


def color_text(text, color):
	"""Apply color to the text."""
	return f"{color}{text}{Style.RESET_ALL}"


async def toggle_ready_state(party_id: str, is_ready: bool):
	url = f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}/members/{val_uuid}/setReady"
	data = {"ready": is_ready}

	try:
		response = api_request("POST", url, json=data, headers=internal_api_headers)
		if response.status_code == 200:
			console.print(f"Ready state set to: {is_ready}")
			return True
		else:
			console.print(f"Failed to toggle ready state")
			logger.log(2,
					   f"Failed to toggle ready state. Status Code: {response.status_code}, Response: {response.text}")
			return False
	except Exception as e:
		console.print(f"Failed to toggle ready state")
		if DEBUG:
			logger.log(2, f"Failed to toggle ready state. Error: {e}")
		return False


def quit_game():
	player_state = get_user_current_state(val_uuid)
	if player_state == 3:
		with api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/players/{val_uuid}",
						 headers=internal_api_headers) as r:
			if r.status_code == 200:
				match_id = r.json()["MatchID"]
				api_request("POST", f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{match_id}/quit",
							headers=internal_api_headers)
	elif player_state == 4:
		with api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}",
						 headers=internal_api_headers) as r:
			if r.status_code == 200:
				match_id = r.json()["MatchID"]
				api_request("POST",
							f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}/disassociate/{match_id}",
							headers=internal_api_headers)


async def listen_for_input(party_id: str):
	is_ready = True  # Start with the default ready state
	console.print("Enter a command: ")

	while True:
		try:
			user_input = await asyncio.to_thread(input, "> ")  # Non-blocking input
			user_input: str = user_input.strip().lower()

			if user_input == "r":
				is_ready = not is_ready
				await toggle_ready_state(party_id, is_ready)
			elif user_input.lower() in ["cls", "clear"]:
				clear_console()
			elif "party" in user_input.lower():
				clear_console()
				console.print("Loading Party...")
				logger.log(4, "Calling get_party from user input")
				await get_party()
			elif "store" in user_input.lower():
				await ValorantShop.run()
			elif user_input.lower() in ["quit", "leave"]:
				console.print("Leaving game...")
				quit_game()
			elif user_input.lower() in ["friends", "friend", "f"]:
				clear_console()
				console.print("Fetching friend states...")
				friend_states = await get_friend_states()
				if friend_states:
					console.print("\n".join(friend_states))
				else:
					console.print("No friends found or unable to fetch friend states.")
			elif user_input.lower() in ["help", "h", "?"]:
				table = Table(show_header=False, box=None, show_lines=True, row_styles=["red", "dim"])
				table.add_row("r", "Toggle Ready State", end_section=True)
				table.add_row("clear/cls", "Clear Console", end_section=True)
				table.add_row("party", "Show Party Details", end_section=True)
				table.add_row("store", "Open Valorant Store Interface", end_section=True)
				table.add_row("quit/leave", "Quit Current Game", end_section=True)
				table.add_row("friends/f", "Show Friend States", end_section=True)
				table.add_row("help/h/?", "Show This Help Message", end_section=True)
				console.print(table, style="cyan")
			if DEBUG:
				if user_input.lower()[0] == "-":
					pass


		except asyncio.CancelledError:
			break
		except Exception as e:
			console.print(f"Error in input listener: {e}")
			break


async def get_friend_states() -> list[str]:
	requests.packages.urllib3.disable_warnings()  # noqa
	friend_list = []
	try:
		with api_request("GET", f"https://127.0.0.1:{port}/chat/v4/presences",
						 headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"},
						 verify=False) as r:
			data = r.json()
		all_user_data = data["presences"]
		for user in all_user_data:
			if user["activePlatform"] is not None and user["private"] is not None:
				if str(user["puuid"]) != str(val_uuid):
					state = get_user_current_state(user["puuid"], data)
					"""
					-1: Error
					0: Not in Valorant
					1: In Menus
					2: In Menus Queueing
					3: Pregame
					4: In-Game
					5: Unknown State
					"""
					state_str = "In Menu" if state == 1 else "Queueing" if state == 2 else "Pre-game" if state == 3 else "In-game" if state == 4 else "Unknown-4" if state == 5 else "Unknown-5"
					full_str = f"{user['game_name']}#{user['game_tag']}: {state_str}"
					friend_list.append(full_str)
	except Exception:
		console.print("Please make sure Riot Client is open!")
		return []

	return friend_list


async def get_party(got_rank: dict = None):
	"""Fetch and display party details in Valorant."""
	global input_task
	buffer = StringIO()
	last_rendered_content = ""
	input_task = None  # Task for input handling
	got_rank = got_rank or {}

	logger.log(3, "Loading Party... ")

	if config_main.get("use_discord_rich_presence", "").lower() == "true":
		RPC.update(
			state="In Menu",
			details="Valorant Match Tracker",
			large_image="valorant",
			large_text="Valorant Zoro",
			party_size=[1, 5],
			start=int(time.time()),
		)

	while True:
		return_code = await check_if_user_in_pregame()
		if return_code:
			last_rendered_content = ""
			clear_console()

			if config_main.get("use_discord_rich_presence", "").lower() == "true":
				RPC.update(
					state="In Menu",
					details="Valorant Match Tracker",
					large_image="valorant",
					large_text="Valorant Zoro",
					party_size=[1, 5],
					start=int(time.time()),
				)

		try:
			buffer.truncate(0)
			buffer.seek(0)

			# Build the dynamic party section.
			message_list = ["[cyan]----- Party -----[/cyan]\n"]
			party_id = await fetch_party_id()

			if party_id:
				party_data = await fetch_party_data(party_id)

				if input_task is None or input_task.done():
					input_task = asyncio.create_task(listen_for_input(party_id))

				message_list.extend(parse_party_data(party_data, got_rank))
				party_section = "".join(message_list)

				if Notification.has_notifications():
					notification_display = Notification.get_display()
					new_screen_content = notification_display.renderable + party_section
				else:
					new_screen_content = party_section
					notification_display = None

				if new_screen_content != last_rendered_content:
					clear_console()
					if Notification.has_notifications():
						console.print(notification_display, markup=True)
					console.print("\n" + party_section, markup=True)
					last_rendered_content = new_screen_content

				await asyncio.sleep(0.5)
			else:
				render_no_party_message(buffer, last_rendered_content)
				await stop_input_listener()
				await asyncio.sleep(3.5)
				return -1
		except KeyboardInterrupt:
			sys.exit(1)
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, f"Error: {traceback_str}")


async def fetch_party_id():
	"""Fetch the party ID for the current user."""
	with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}",
					 headers=internal_api_headers) as r:
		if r.status_code == 400:
			is_console = str(r.json().get("errorCode")) == "PLAYER_PLATFORM_TYPE_MISMATCH"
			if is_console:
				with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}",
								 headers=internal_api_headers_console) as r2:
					return r2.json().get('CurrentPartyID')
			else:
				logger.log(1,
						   f"Error fetching party details. Dumping Data:\n{r.json()}\nParameters: {str(val_uuid)}, {internal_api_headers}, {internal_api_headers_console}")
				return None
		elif r.status_code == 404:
			return None
		else:
			return r.json().get('CurrentPartyID')


async def fetch_party_data(party_id):
	"""Fetch the details of a party using its ID."""
	r = api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}", headers=internal_api_headers)
	return r.json()


def parse_party_data(party_data, got_rank):
	"""Parse party data and prepare messages for rendering."""
	messages = []
	is_queueing = party_data.get("State")
	if is_queueing == "MATCHMAKING":
		messages.append("[yellow]Queueing![/yellow]\n")

	game_mode = str(party_data.get("MatchmakingData", {}).get("QueueID", "Unknown")).lower()
	game_mode = GAME_MODES.get(game_mode.lower(), str(game_mode))
	messages.append(f"[green]Mode: {game_mode}[/green]\n\n")

	for member in party_data.get("Members", []):
		player_name, is_user = get_userdata_from_id(str(member["Subject"]), val_uuid)
		if member["Subject"] in DEV_PUUID_LIST:
			player_name += " [hot_pink][[/hot_pink][red]DEV[/red][hot_pink]][/hot_pink]"
		is_leader = member.get("IsOwner", False)
		player_lvl = member["PlayerIdentity"].get("AccountLevel", "-1")

		color = "yellow" if is_user else ("bright_red" if is_leader else "white")
		leader_text = "[Leader] " if is_leader else ""

		if member["Subject"] not in got_rank:
			player_rank_str = get_rank_color(get_rank_from_uuid(str(member['Subject'])), True)
			got_rank[str(member["Subject"])] = player_rank_str
		else:
			player_rank_str = got_rank[str(member["Subject"])]

		messages.append(f"[{color}]{leader_text}[LVL {player_lvl}] {player_name} {player_rank_str}[/{color}]\n")
	return messages


def render_no_party_message(buffer: StringIO, last_rendered_content: str):
	"""Render a message when no party is found."""
	clear_console()
	if config_main.get("use_discord_rich_presence", "").lower() == "true":
		RPC.clear()
	new_message = color_text("Valorant is not running for that user!\n", Fore.RED)
	if new_message != last_rendered_content:
		buffer.write(new_message)
		print_buffered(buffer)


async def check_if_user_in_pregame(send_message: bool = False) -> bool:
	if send_message:
		console.print("\n\nChecking if player is in match")

	state = get_user_current_state(val_uuid)
	if state == 3:
		try:
			# Try pregame
			r = api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/players/{val_uuid}",
							headers=internal_api_headers)
			if r.status_code != 404:
				data = r.json()
				if data["MatchID"]:
					clear_console()
					logger.log(3, "Loading check_pregame -> pregame")
					Notification.clear_notifications()
					await run_pregame(data)
					return True
			elif r.status_code == 400:
				logger.log(3, "Loading check_pregame -> log_in")
				await log_in()
			else:
				# Not in pre-game error?
				await asyncio.sleep(1)
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, f"Error: {traceback_str}")
	elif state == 4:
		# Try playing in-game
		try:
			r = api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}",
							headers=internal_api_headers)
			return_code = r.status_code
			if return_code == 200:
				clear_console()
				logger.log(3, "Loading check_pregame -> in_game")
				Notification.clear_notifications()
				await run_in_game()
				return True
			elif return_code == 400:
				logger.log(3, "Loading check_pregame -> log_in")
				await log_in()
			else:
				return False
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, f"Error: {traceback_str}")

	return False


def get_userdata_from_token() -> tuple[str, str]:
	r = api_request("GET", "https://auth.riotgames.com/userinfo",
					headers={"Authorization": f"Bearer {val_access_token}"})
	try:
		account_name = r.json()["acct"]["game_name"]
		account_tag = r.json()["acct"]["tag_line"]
		return account_name, account_tag
	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(3, f"Failed to get account name/tag: {traceback_str}")
		return "None", "None"


def main_display():
	"""Display the main banner and version information."""
	banner = Panel(
		f"[cyan bold]{BANNER}[/cyan bold]",
		title="Welcome",
		title_align="left",
		border_style="blue",
	)
	console.print(banner)

	version_info = f"[bold cyan]Version:[/bold cyan] [green]{VERSION}[/green]"
	console.print(version_info)


def _print_exit_message() -> None:
	console.print("[bold yellow]Exiting...[/bold yellow]")


async def display_logged_in_status(name: str) -> None:
	"""Display the logged-in status with a welcome message."""
	console.clear()
	main_display()
	console.print(f"\n[bold green]You have been logged in! Welcome, {name.capitalize()}[/bold green]")


async def display_friend_states(friend_states: list) -> None:
	"""Display the friend states in a formatted table."""
	if not friend_states:
		console.print("[bold red]No friends online.[/bold red]")
	else:
		table = Table(title="Friend States", show_header=True, header_style="bold magenta")
		table.add_column("Friend", style="cyan")
		table.add_column("Status", style="green")
		for friend_state in friend_states:
			friend_name, status = friend_state.split(":")
			table.add_row(friend_name, status)
		console.print(table)


async def main() -> bool:
	global ValorantShop, Notification, RPC
	clear_console()
	main_display()
	console.print("[yellow]One moment while we sign you in...[/yellow]\n")

	try:
		logged_in = await with_spinner("Logging in...", log_in())
	except KeyboardInterrupt:
		_print_exit_message()
		return False

	if logged_in:
		try:
			name, tag = get_userdata_from_token()
		except KeyboardInterrupt:
			_print_exit_message()
			return False
		logger.log(3, f"Using Version: {VERSION} || Logged in as: {name}#{tag}")

		ValorantShop = ValorantShopChecker()
		Notification = NotificationManager()

		while True:
			try:
				await display_logged_in_status(name)

				# Fetch and display friend states dynamically
				friend_states = await get_friend_states()
				await display_friend_states(friend_states)

				state = get_user_current_state(val_uuid)
				if state != 3 and state != 4:
					console.print("\n(1) Valorant Shop, (2) In-Game Loader\n")
					user_input = input().strip()
					if user_input == "1":
						await with_spinner("Loading Store...", ValorantShop.run())
					elif user_input == "2":
						while True:
							logged_in = await log_in()
							if logged_in:
								await check_if_user_in_pregame()
								logger.log(4, "Calling get_party from main")
								if await get_party() == -1:
									break
							else:
								await asyncio.sleep(2.5)
								console.clear()
					else:
						console.print("[bold red]Invalid input. Please try again.[/bold red]")
						await asyncio.sleep(1.5)
				else:
					while True:
						logged_in = await log_in()
						if logged_in:
							await check_if_user_in_pregame()
							logger.log(4, "Calling get_party from auto-main")
							await get_party()
						else:
							await asyncio.sleep(2.5)
							console.clear()
			except KeyboardInterrupt:
				_print_exit_message()
				return False
			except EOFError:
				_print_exit_message()
				return False
			except Exception as e:
				traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
				logger.log(1, traceback_str)
				console.print(f"[bold red]An Error Has Happened![/bold red]\n{traceback_str}")
				await asyncio.sleep(2)
	else:
		console.print("[bold red]Failed to log in. Retrying in 5 seconds...[/bold red]")
	await asyncio.sleep(5)
	return True


if __name__ == "__main__":
	parser = argparse.ArgumentParser(add_help=True)
	parser.add_argument("--debug", action="store_true", help="Enable debug mode")
	parser.add_argument("--no-rpc", action="store_true", help="Disable Discord Rich Presence")
	parser.add_argument("--version", action="store_true", help="Show version and exit")
	args = parser.parse_args()

	if args.version:
		console.print(f"Valorant Zoro Version: {VERSION}")
		sys.exit(0)

	config_manager = build_main_config_manager(CONFIG_FILE, GAME_MODES)
	config_result = config_manager.load()
	config = config_result.config
	config_main = config["Main"]

	# Preserve existing flags behavior
	if args.debug:
		DEBUG = True
	if args.no_rpc:
		config_main["use_discord_rich_presence"] = "false"

	ADVANCED_MISSING_AGENTS: bool = config_main.get("advanced_missing_agents", "false").strip().lower() == "true"

	# Common initialization before launching UI/CLI
	clear_console()
	colorama.init(autoreset=True)
	logger = Logger("Zoro", "logs/Zoro", ".log")
	logger.load_public_key(pub_key)

	if DEBUG:
		logger.log(4, "Debug mode enabled")

	if config_result.created:
		console.print(Panel(f"Created default configuration at '{CONFIG_FILE}'.", style="bold green"))

	if config_result.issues:
		console.rule("[bold yellow]Configuration Adjustments[/bold yellow]")
		for issue in config_result.issues:
			key_path = f"{issue.section}.{issue.key}" if issue.key != "*" else issue.section
			console.print(f"[yellow]{key_path}[/yellow]: {issue.message}")
			if issue.reverted_to is not None:
				console.print(f"  Using value: {issue.reverted_to}")
		console.print(Panel("Update the config file to apply your preferred values.", style="bold yellow"))
		if sys.stdin and sys.stdin.isatty():
			input("Press enter to continue...")
	elif DEBUG:
		console.print(Panel("Configuration loaded successfully.", style="bold green"))
		time.sleep(1)

	RPC = None
	if not args.no_rpc:
		try:
			nest_asyncio.apply()
			RPC = Presence(CLIENT_ID)
			RPC.connect()
		except Exception as e:
			logger.log(2, f"Error initializing Discord RPC: {e}")
			RPC = None

	while True:
		try:
			should_continue = asyncio.run(main())
		except KeyboardInterrupt:
			_print_exit_message()
			break
		if not should_continue:
			break
