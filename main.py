VERSION = "v2.4.2"

import asyncio
import threading
import time
import os
import configparser
import traceback
import sys
import colorama
import requests
import ssl
import hashlib
import tkinter
import tkinter.messagebox

from json import dump, dumps, loads, load
from platform import system, version
from wmi import WMI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from io import StringIO
from colorama import Fore, Style
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry  # noqa | Ignore, should work fine
from PIL import Image, ImageTk
from datetime import datetime, timedelta
from pypresence import Presence
from functools import lru_cache

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import pretty
from rich.text import Text
from rich.columns import Columns

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

GAME_MODES = {
	"unrated": "Unrated",
	"competitive": "Competitive",
	"swiftplay": "Swiftplay",
	"spikerush": "Spikerush",
	"deathmatch": "Deathmatch",
	"ggteam": "Escalation",
	"hurm": "Team Deathmatch"
}

CONFIG_FILE = "config.ini"
CLIENT_ID = 1354365908054708388

DEV_PUUID_LIST = ["fe5714d7-344c-5453-90f0-9a72d8bdd947"]


def create_default_config():
	"""Creates a default config file."""
	raw_config_data = (
			'[Main]\n'
			'; Amount of matches to look at before using that data for player stats\n'
			'; Wins / Loss | KD, HS%, ETC\n'
			'; Default = 10\n'
			'amount_of_matches_for_player_stats = 10\n'
			'\n'
			'; What game-mode should these stats be taken from\n'
			'; Valid values: "ALL", "SAME", or one of the following\n; ' +
			"\n; ".join([f"{code} ({name})" for code, name in GAME_MODES.items()]) + '\n'
																					 '; Default = "ALL"\n'
																					 'stats_used_game_mode = ALL\n'
	)
	with open(CONFIG_FILE, "w") as file:
		file.write(raw_config_data)
	console.print(Panel("Default config file created.", style="bold green"))
	time.sleep(5)


# Create a default config file if it doesn't exist.
if not os.path.exists(CONFIG_FILE):
	create_default_config()

# Read the config file.
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Ensure the expected section is present.
if "Main" not in config:
	console.print(Panel("Config file is missing the 'Main' section. Recreating default config.", style="bold red"))
	create_default_config()
	config.read(CONFIG_FILE)

config_main = config["Main"]


def validate_and_fix_config(config_main):
	"""
	Validates each configuration value and reverts only the problematic ones to default values.

	Validations:
	  - 'amount_of_matches_for_player_stats' must be an integer between 1 and 20.
	  - 'stats_used_game_mode' must be 'ALL', 'SAME', or one of the allowed game mode codes.
	"""
	changes_made = False

	# Validate amount_of_matches_for_player_stats.
	default_amount = 10
	amt_str = config_main.get("amount_of_matches_for_player_stats", str(default_amount))
	try:
		amt = int(amt_str)
		if not (1 <= amt <= 20):
			console.rule("[bold red]Configuration Warning[/bold red]")
			console.print(f"[red]Error:[/red] 'amount_of_matches_for_player_stats' is set to [bold]{amt}[/bold].")
			console.print("  It must be an integer between 1 and 20. Reverting to default (10).")
			config_main["amount_of_matches_for_player_stats"] = str(default_amount)
			changes_made = True
	except ValueError:
		console.rule("[bold red]Configuration Warning[/bold red]")
		console.print(f"[red]Error:[/red] 'amount_of_matches_for_player_stats' value '{amt_str}' is not a valid integer.")
		console.print("  Reverting to default (10).")
		config_main["amount_of_matches_for_player_stats"] = str(default_amount)
		changes_made = True

	# Validate stats_used_game_mode.
	default_mode = "ALL"
	mode_str = config_main.get("stats_used_game_mode", default_mode).strip()
	mode_lower = mode_str.lower()
	valid_modes = ["all", "same"] + list(GAME_MODES.keys())
	if mode_lower not in valid_modes:
		pretty_options = ["ALL", "SAME"] + [f"{code} ({name})" for code, name in GAME_MODES.items()]
		console.rule("[bold red]Configuration Warning[/bold red]")
		console.print(f"[red]Error:[/red] 'stats_used_game_mode' is set to [bold]'{mode_str}'[/bold].")
		console.print("  It must be one of the following:")
		console.print("    " + ", ".join(pretty_options))
		console.print(f"  Reverting to default ({default_mode}).")
		config_main["stats_used_game_mode"] = default_mode
		changes_made = True
	else:
		# Normalize the value: use uppercase for special keywords; game modes stay lowercase.
		if mode_lower in ["all", "same"]:
			config_main["stats_used_game_mode"] = mode_lower.upper()
		else:
			config_main["stats_used_game_mode"] = mode_lower

	# If any corrections were made, update the config file.
	if changes_made:
		console.print(Panel("Please update the config file to permanently fix the issue!", style="bold yellow"))
		input("Press enter to continue...")


validate_and_fix_config(config_main)

if DEBUG:
	console.print(Panel("Config file validated successfully.", style="bold green"))
	time.sleep(1)

# config_main = {"stats_used_game_mode": "Same", "amount_of_matches_for_player_stats": "10", "debug": False}

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

		self.VERSION = "v1.6.0"

		self.LEVELS = {1: f"{Fore.RED}Error{Fore.RESET}",
					   2: f"{Fore.YELLOW}Warning{Fore.RESET}",
					   3: f"{Fore.BLUE}Info{Fore.RESET}",
					   4: f"{Fore.LIGHTWHITE_EX}Debug{Fore.RESET}"}
		self.MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
		self.LOG_TIME_INTERVAL = timedelta(days=1)  # 1 day

		self.key = None
		self.hwid = None

	def __get_sys_hwid(self):
		try:
			c = WMI()
			self.hwid = c.Win32_ComputerSystemProduct()[0].UUID, c.Win32_BaseBoard()[0].SerialNumber
		except:
			pass

	def _encrypt_message(self, message: str) -> str:
		cipher_rsa = PKCS1_OAEP.new(self.key)

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
		return f"{Fore.CYAN}{timestamp_str}{Style.RESET_ALL} - {level_name}: {message}"

	def _get_log_filename(self, hit_mix_size: bool = False) -> str:
		now = self._timestamp()
		if not hit_mix_size:
			return f"{self.file_name}_{now.strftime('%Y-%m-%d')}{self.file_ending}"
		else:
			return f"{self.file_name}_{now.strftime('%Y-%m-%d-%H%M%S')}{self.file_ending}"

	def _is_file_large(self, full_log_file_name: str) -> bool:
		return os.path.exists(full_log_file_name) and os.path.getsize(full_log_file_name) >= self.MAX_FILE_SIZE

	def _log_file_header(self):
		return (f"\n{Fore.LIGHTWHITE_EX}"
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
				f"Log Start:{Fore.RESET}\n")

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
		if self._is_file_large(log_filename) or (os.path.exists(log_filename) and (current_time - datetime.fromtimestamp(os.path.getmtime(log_filename))) > self.LOG_TIME_INTERVAL):
			log_filename = self._get_log_filename()  # Ensure new file name is generated

		try:
			self.__get_sys_hwid()

			if os.path.exists(log_filename):
				with open(log_filename, "a") as f:
					f.write(self._encrypt_message(self._format_message(level, message)) + "\n")
			else:
				with open(log_filename, "w") as f:
					f.write(self._encrypt_message(self._log_file_header()) + "\n")
					f.write(self._encrypt_message(self._format_message(level, message)) + "\n")

		except IOError as e:
			print(f"Error writing to log file: {e}")
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
	safe_path = endpoint_path.replace("/", "_").replace(":", "_").replace("?", "_")  # Convert "stats/player" to "stats_player"

	# Hash request details to ensure unique filenames
	hash_input = f"{method}_{url}_{dumps(params, sort_keys=True)}_{dumps(data, sort_keys=True)}"
	hashed = hashlib.md5(hash_input.encode()).hexdigest()

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
			print(f"Rate limited! Retrying in {wait_time} seconds...")
		time.sleep(wait_time)
		return requests.request(method, url, params=params, json=json or data, headers=headers, verify=verify)

	return response  # No rate limit header, fallback to exponential backoff


def api_request(method, url, params=None, data=None, headers=None, json=None, verify=None):
	"""Handles API requests and switches to debug mode if enabled."""

	OVERRIDE_RESPONSES = {
		"https://glz-na-1.na.a.pvp.net/core-game/": {"status": 404},  # Stop from connecting to the data core game
		"https://glz-na-1.na.a.pvp.net/pregame/": {"status": 404},  # Stop from connecting to the data per game
	}

	requests.packages.urllib3.disable_warnings()  # noqa

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
			print(f"No stored response for {url} - {method}")

	# If not in debug mode, make real API request
	if data is None and json is not None:
		data = json
	response = requests.request(method, url, params=params, json=data, headers=headers, verify=verify)

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
			logger.log(2, f"API returned '{response.status_code}' from request '{response.url}'\nUsing params: '{str(params)}, Using data/json: {str(data) + ' // ' + str(json)}'\n")
			if DEBUG:
				print(f"API Error: {response.status_code}")
		return response


def save_response(file_path, data):
	"""Saves the API response for future debugging."""
	os.makedirs(DATA_PATH, exist_ok=True)
	with open(file_path, "w") as file:
		dump(data, file, indent=4)


def convert_time(sec):
	days = sec // (24 * 3600)
	sec %= (24 * 3600)
	hours = sec // 3600
	sec %= 3600
	minutes = sec // 60
	sec %= 60
	return "%d:%02d:%02d:%02d" % (days, hours, minutes, sec)


def create_riot_auth_ssl_ctx() -> ssl.SSLContext:
	import ctypes
	from typing import Optional
	import contextlib
	import warnings

	ssl_ctx = ssl.create_default_context()

	# https://github.com/python/cpython/issues/88068
	addr = id(ssl_ctx) + sys.getsizeof(object())
	ssl_ctx_addr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_void_p)).contents

	libssl: Optional[ctypes.CDLL] = None
	if sys.platform.startswith("win32"):
		for dll_name in (
				"libssl-3.dll",
				"libssl-3-x64.dll",
				"libssl-1_1.dll",
				"libssl-1_1-x64.dll",
		):
			with contextlib.suppress(FileNotFoundError, OSError):
				libssl = ctypes.CDLL(dll_name)
				break
	elif sys.platform.startswith(("linux", "darwin")):
		libssl = ctypes.CDLL(ssl._ssl.__file__)  # type: ignore

	if libssl is None:
		raise NotImplementedError(
			"Failed to load libssl. Your platform or distribution might be unsupported, please open an issue."
		)

	with warnings.catch_warnings():
		warnings.filterwarnings("ignore", category=DeprecationWarning)
		ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # deprecated since 3.10
	ssl_ctx.set_alpn_protocols(["http/1.1"])
	ssl_ctx.options |= 1 << 19  # SSL_OP_NO_ENCRYPT_THEN_MAC
	ssl_ctx.options |= 1 << 14  # SSL_OP_NO_TICKET
	# setting SSL_CTRL_SET_SIGALGS_LIST
	# setting SSL_CTRL_SET_GROUPS_LIST
	libssl.SSL_CTX_ctrl(ssl_ctx_addr, 92, 0, ":".join(
		(
			"x25519",
			"secp256r1",
			"secp384r1",
		)
	).encode())

	# print([cipher["name"] for cipher in ssl_ctx.get_ciphers()])
	return ssl_ctx


async def get_user_data_from_riot_client():
	global password, port

	try:

		# get lockfile password
		file_path = os.getenv("localappdata")
		try:
			with open(f"{file_path}\\Riot Games\\Riot Client\\Config\\lockfile", "r") as f:
				lockfile_data = f.read()
		except:
			print("Riot Client isn't logged into an account!\nRetrying!")
		# Base 64 encode the password
		password = b64encode(f"riot:{str(lockfile_data.split(':')[3])}".encode("ASCII")).decode()
		# Get the port the WS is running on
		port = str(lockfile_data.split(":")[2])
		if password is not None:
			# Make secure connection with the WS
			# Get user login tokens
			try:
				with api_request("GET",
								 f"https://127.0.0.1:{port}/entitlements/v1/token",
								 headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, verify=False
								 ) as r:
					return_data = r.json()
			except Exception:
				print("Please make sure Riot Client is open!")
				return None
			return return_data["accessToken"], return_data["token"], return_data["subject"]
		else:
			raise Exception("Riot Client Login Password Not Found!")
	except Exception as e:
		print(color_text("Please make sure you are logged into a Riot Account!", Fore.CYAN))
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, f"Log In Failed!\nData: {return_data}\nTraceback: {traceback_str}")


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
			print(f"Error loading image from {url}: {e}")
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
		print("Loading Shop...")
		await log_in()

		try:
			# -----------------------------------------------------------
			# Set up API headers and fetch store data
			# -----------------------------------------------------------
			get_headers()
			store_url = f"https://pd.na.a.pvp.net/store/v3/storefront/{self.val_uuid}"
			response = api_request("POST", store_url, headers=self.internal_api_headers, data={})
			store_data = response.json()

			# Save the raw store data to a file for debugging/auditing
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
					bundle_prices.append((bundle.get("TotalBaseCost", {"85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741": -1}).get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", -1), bundle.get("TotalDiscountedCost", {"85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741": -1}).get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", -1)))

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
							item_data = api_request("GET", f"https://valorant-api.com/v1/weapons/skinlevels/{item_uuid}").json()
							is_skin = True
						# If Buddy
						elif item_type_uuid == "dd3bf334-87f3-40bd-b043-682a57a8dc3a":
							item_data = api_request("GET", f"https://valorant-api.com/v1/buddies/levels/{item_uuid}").json()
						# If Spray
						elif item_type_uuid == "d5f120f8-ff8c-4aac-92ea-f2b5acbe9475":
							item_data = api_request("GET", f"https://valorant-api.com/v1/sprays/{item_uuid}").json()
						# If Player Card
						elif item_type_uuid == "3f296c07-64c3-494c-923b-fe692a4fa1bd":
							item_data = api_request("GET", f"https://valorant-api.com/v1/playercards/{item_uuid}").json()
						# If Player Title
						elif item_type_uuid == "de7caa6b-adf7-4588-bbd1-143831e786c6":
							item_data = api_request("GET", f"https://valorant-api.com/v1/playertitles/{item_uuid}").json()
						else:
							item_data = {"data": {"displayName": "null", "displayIcon": "null"}}  # FIXME | Replace with an image not null
						item_name: str = item_data["data"]["displayName"]
						item_icon: str = item_data["data"]["displayIcon"]
						skin_rarity = []
						if is_skin:
							for data in all_skins_data:
								if data.get("displayName", "").lower() == item_name.lower():
									tier_uuid = data.get("contentTierUuid", "")
									if tier_uuid:
										tier_response = api_request("GET", f"https://valorant-api.com/v1/contenttiers/{tier_uuid}")
										tier_data = tier_response.json().get("data", {})
										skin_rarity = [
											tier_data.get("devName", ""),
											tier_data.get("highlightColor", ""),
											tier_data.get("displayIcon", "")
										]
										break

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

			nm_prices = []
			nm_skin_ids = []
			for offer in bonus_offers:
				# Append discount costs from the offer
				discount_costs = offer.get('DiscountCosts', {}).values()
				nm_prices.extend(discount_costs)

				# Append skin IDs from offer rewards
				rewards = offer.get('Offer', {}).get('Rewards', [])
				for reward in rewards:
					nm_skin_ids.append(reward.get('ItemID'))

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
				skin_names, skin_images, skin_prices, skin_duration, skin_rarity,
				nm_offers, nm_prices, nm_images, nm_duration
			)

		except Exception as e:
			error_trace = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			self.logger.log(1, error_trace)
			print(f"Error: {error_trace}")

	async def display_gui(
			self,
			vp, vp_icon, rp, rp_icon, kc, kc_icon,
			current_bundles, bundles_images, bundle_prices, bundle_duration, bundle_items,
			skin_names, skin_images, skin_prices, skin_duration, skin_rarity,
			nm_offers, nm_prices, nm_images, nm_duration
	):
		# -------------------- Theme Colors & Fonts --------------------
		DARK_BG = "#1E1E1E"
		LIGHT_BG = "#f0f0f0"
		DARK_CARD_BG = "#2a2a2a"
		LIGHT_CARD_BG = "#fafafa"
		ACCENT_COLOR = "#ffcc00"  # For badges and accents
		TEXT_DARK = "#1a1a1a"
		TEXT_LIGHT = "#FFFFFF"

		TITLE_FONT = ("Helvetica", 32, "bold")
		HEADER_FONT = ("Helvetica", 16, "bold")
		LABEL_FONT = ("Helvetica", 12)
		PRICE_FONT = ("Helvetica", 12, "bold")
		BUTTON_FONT = ("Helvetica", 10, "bold")
		TIMER_FONT = ("Helvetica", 10, "italic")

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
				widget.configure(bg="#7c7c7c")
				for child in widget.winfo_children():
					try:
						child.configure(bg="#7c7c7c")
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
				style.configure("TButton", background=DARK_CARD_BG, foreground=TEXT_LIGHT, font=BUTTON_FONT)
				style.configure("Timer.TLabel", foreground="#CCCCCC", background=DARK_BG, font=TIMER_FONT)
				style.configure("TNotebook", background=DARK_BG, borderwidth=0)
				style.configure("TNotebook.Tab", background=DARK_CARD_BG, foreground="#CCCCCC", borderwidth=0, padding=[10, 5])
				style.map("TNotebook.Tab", background=[("selected", "#444444")], foreground=[("selected", TEXT_LIGHT)])


			else:
				# Light Mode configuration
				root.configure(bg=LIGHT_BG)
				style.configure("TFrame", background=LIGHT_BG)
				style.configure("TLabel", background=LIGHT_BG, foreground=TEXT_DARK, font=LABEL_FONT)
				style.configure("Title.TLabel", font=TITLE_FONT, foreground=TEXT_DARK, background=LIGHT_BG)
				style.configure("TLabelframe", background=LIGHT_BG, borderwidth=0)
				style.configure("TLabelframe.Label", background=LIGHT_BG, foreground=TEXT_DARK, font=HEADER_FONT)
				style.configure("TButton", background="#e0e0e0", foreground=TEXT_DARK, font=BUTTON_FONT)
				style.configure("Timer.TLabel", foreground="#333", background=LIGHT_BG, font=TIMER_FONT)
				style.configure("TNotebook", background=LIGHT_BG, borderwidth=0)
				style.configure("TNotebook.Tab", background="#e0e0e0", foreground=TEXT_DARK, borderwidth=0, padding=[10, 5])
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
			print("Refresh clicked!")
			refresh_btn.config(text="Refreshing...", state="disabled")
			await self.run()
			refresh_btn.config(text="Refresh", state="normal")

		refresh_btn = ttk.Button(header_frame, text="Refresh", command=lambda: asyncio.run(refresh()))
		refresh_btn.pack(side="right", padx=5)

		theme_btn = ttk.Button(header_frame, command=switch_theme)
		theme_btn.pack(side="right", padx=5)

		# Initialize theme (lock mode to set initial colors without toggling)
		switch_theme(lock=True)

		# -------------------- POINTS SECTION --------------------
		points_frame = ttk.Frame(root)
		points_frame.pack(fill="x", pady=10, padx=20)

		def create_points_section(frame, icon_url, amount):
			try:
				icon_img = load_image(icon_url, (32, 32))
				if icon_img:
					photo = ImageTk.PhotoImage(icon_img)
					lbl_icon = ttk.Label(frame, image=photo)
					lbl_icon.image = photo
					lbl_icon.pack(side="left", padx=(0, 5))
				else:
					raise Exception("No image")
			except Exception as e:
				print(f"Icon load error: {e}")
				ttk.Label(frame, text="Icon", width=4).pack(side="left", padx=(0, 5))
			ttk.Label(frame, text=str(amount), font=("Helvetica", 14)).pack(side="left", padx=(0, 20))

		create_points_section(points_frame, vp_icon, vp)
		create_points_section(points_frame, rp_icon, rp)
		create_points_section(points_frame, kc_icon, kc)

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
						print("Error loading rarity icon in popup:", e)
					tkinter.Label(rarity_frame, text=rarity_name, font=("Helvetica", 8, "bold"),
								  bg=highlight_color, fg="white").pack(side="left", padx=(0, 2))

		# -------------------- ITEM CARD CREATION FUNCTION --------------------
		def create_item_card(parent, image_url, title, price, img_width, img_height,
							 card_bg, text_fg, rarity=None,
							 is_bundle=False, bundle_uuid=None, bundle_name=None):
			if is_bundle:
				card_frame = tkinter.Frame(parent, bg=card_bg, bd=0)
				card_frame.configure(highlightthickness=1, highlightbackground="#CCCCCC", padx=10, pady=10)
			else:
				card_frame = tkinter.Frame(parent, bg=card_bg, bd=1, relief="solid")
			cards.append(card_frame)

			add_hover_effect(card_frame, card_bg, ACCENT_COLOR)

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
					print("Error loading rarity icon:", e)
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
				print(f"Image load error: {e}")
				tkinter.Label(card_frame, text="Image not available", bg=card_bg, fg=text_fg).pack(pady=10)

			tkinter.Label(card_frame, text=title, font=("Helvetica", 12, "bold"), fg=text_fg, bg=card_bg).pack(pady=(5, 0))
			if is_bundle:
				base_price, discount_price = price
				price_frame = tkinter.Frame(card_frame, bg=card_bg)
				price_frame.pack(pady=(5, 10))
				tkinter.Label(price_frame, text=f"{base_price} VP", font=("Helvetica", 10, "overstrike"),
							  fg="red", bg=card_bg).pack(side="left", padx=(0, 5))
				tkinter.Label(price_frame, text=f"{discount_price} VP", font=("Helvetica", 12, "bold"),
							  fg=text_fg, bg=card_bg).pack(side="left")
			else:
				tkinter.Label(card_frame, text=f"Price: {price} VP", font=("Helvetica", 10),
							  fg=text_fg, bg=card_bg).pack(pady=(5, 10))

			# Tooltip
			ToolTip(card_frame, text=f"{title}\nPrice: {price} VP")

			if is_bundle and bundle_uuid is not None and bundle_name is not None:
				def on_click(event):
					show_bundle_details(bundle_uuid, bundle_name)

				card_frame.bind("<Button-1>", on_click)
				for child in card_frame.winfo_children():
					child.bind("<Button-1>", on_click)

			return card_frame

		# -------------------- SECTION CREATION FUNCTION --------------------
		def create_section(parent_frame, title, items, images, prices, duration,
						   img_width, img_height, rarities=None, is_bundle: bool = False):
			section_frame = ttk.Labelframe(parent_frame, text=title)
			section_frame.pack(pady=10, padx=10, anchor="center", fill="x")

			timer_frame = ttk.Frame(section_frame)
			timer_frame.pack(fill="x", padx=10, pady=5)
			timer_label = ttk.Label(timer_frame, text=f"Expires in: {format_duration(duration)}", style="Timer.TLabel")
			timer_label.pack(side="left")

			items_frame = ttk.Frame(section_frame)
			items_frame.pack(padx=10, pady=10, fill="both", expand=True)

			# Set columns based on item type.
			num_columns = 2 if is_bundle else 4
			num_items = len(items)
			num_rows = (num_items + num_columns - 1) // num_columns

			for row in range(num_rows):
				row_count = min(num_columns, num_items - row * num_columns)
				offset = (num_columns - row_count) // 2
				for col in range(row_count):
					idx = row * num_columns + col
					card_bg = DARK_CARD_BG if self.dark_mode else LIGHT_CARD_BG
					text_fg = TEXT_LIGHT if self.dark_mode else TEXT_DARK
					rarity = rarities[idx] if rarities is not None else None
					bundle_uuid = items[idx][1] if is_bundle else None
					bundle_name = items[idx][0] if is_bundle else None
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
						is_bundle=is_bundle,
						bundle_uuid=bundle_uuid,
						bundle_name=bundle_name
					)
					card.grid(row=row, column=offset + col, padx=10, pady=10, sticky="nsew")
					# Allow the card to expand if needed.
					items_frame.grid_columnconfigure(offset + col, weight=1)

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
				is_bundle=True
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
				rarities=skin_rarity
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
				img_height=140
			)
		else:
			ttk.Label(nm_tab, text="Night Market is currently not available.").pack(pady=20)

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

	def has_notifications(self):
		if len(self.notifications) >= 1:
			return True
		else:
			return False

	def add_notification(self, notification: str):
		"""Add a notification."""
		self.notifications.insert(0, notification)

	def remove_notification(self, notification: str):
		"""Remove a notification if it exists."""
		if notification in self.notifications:
			self.notifications.remove(notification)

	def clear_notifications(self):
		"""Clear all notifications."""
		self.notifications = []

	def get_display(self):
		"""
		Display the notifications using Rich Console.
		The most recent notification appears first.
		"""
		if not self.notifications:
			return ""

		# Combine notifications into a single text block
		content = "\n".join(self.notifications)
		# Create a Panel with a title and styled border
		panel = Panel(
			Text.from_markup(content),
			border_style="yellow",
			expand=False
		)
		return panel


def calculate_kd(kills, deaths):
	if deaths == 0:
		return kills  # Stop div of zero
	return round(kills / deaths, 2)


@lru_cache(maxsize=128)
def get_userdata_from_id(user_id: str, host_player_uuid: str | None = None) -> tuple[str, bool]:
	req = api_request("PUT", f"https://pd.na.a.pvp.net/name-service/v2/players", headers=internal_api_headers, data=[user_id])
	if req.status_code == 200:
		user_info = req.json()[0]
		user_name = f"{user_info['GameName']}#{user_info['TagLine']}"
		if host_player_uuid is not None:
			if user_id == host_player_uuid:
				host_player = f"\033[33m(You) {user_name}\033[0m"
				return host_player, True
			else:
				host_player = user_name
		else:
			host_player = user_name
	elif req.status_code == 429:
		logger.log(2, "Rate Limited | get_userdata_from_id")
	else:
		logger.log(1, f"Error in get_userdata_from_id | {req.status_code} | {req.json()}")
		return "null", False

	return host_player, False


@lru_cache(maxsize=128)
def get_agent_data_from_id(agent_id: str) -> str:
	r = api_request("GET", f"https://valorant-api.com/v1/agents/{agent_id}")
	agent_name = r.json()["data"]["displayName"]
	return agent_name


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
		match_stats (dict): The match details returned from the API.
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

	if compact_mode:
		compact_report = (
			f"[{overall_color}]"  # Start overall color
			f"[Map: {map_name}] "
			f"[Agent: {agent_name}] "
			f"[Result: {win_status}] "
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


@lru_cache(maxsize=2)
def get_rank_from_uuid(user_id: str, platform: str = "PC"):
	if platform == "PC":
		r = api_request("GET", f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=competitive", headers=internal_api_headers)
		try:
			rank_tier = r.json()["Matches"][0]["TierAfterUpdate"]
		except:
			return "Unranked"
	elif platform == "CONSOLE":
		r = api_request("GET", f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=console_competitive", headers=internal_api_headers_console)
		try:
			rank_tier = r.json()["Matches"][0]["TierAfterUpdate"]
		except:
			# If no comp match are played by the user
			return "Unranked"

	if str(rank_tier) == "0":
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
		total=5,  # Total number of retries
		read=5,  # Number of retries on read errors
		connect=5,  # Number of retries on connection errors
		backoff_factor=1,  # Backoff factor to apply between attempts
		status_forcelist=[404, 429, 500, 502, 503, 504],  # Retry on these status codes
	)
	adapter = HTTPAdapter(max_retries=retry)
	session.mount('http://', adapter)
	session.mount('https://', adapter)
	return session


@lru_cache(maxsize=256)
def get_match_details(match_id: str, platform: str = "PC"):
	headers = internal_api_headers if platform == "PC" else internal_api_headers_console
	match_url = f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}"

	while True:
		match_response = api_request("GET", match_url, headers=headers)
		if match_response.status_code == 429:
			logger.log(2, f"Rate limited fetching match {match_id}. Retrying in 10 seconds.")
			time.sleep(10)
		elif match_response.status_code == 200:
			return match_response.json()
		else:
			logger.log(1, f"Error fetching match {match_id}: {match_response.status_code}")
			return None


def get_playerdata_from_uuid(user_id: str, cache: dict, platform: str = "PC", gamemode: str = None):
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

		if response.status_code == 429:
			logger.log(2, "Rate Limited fetching match history.")
			while True:
				time.sleep(10)
				response = api_request("GET", url, headers=headers)
				if response.status_code != 429:
					break

		history = response.json().get("History", [])
		time.sleep(5)

		save_match_data = None
		for i in history:
			match_id = i["MatchID"]
			match_data = get_match_details(match_id, platform)

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
					wins.append(Fore.GREEN + "■" if won else Fore.RED + "■")
					kills += match["stats"]["kills"]
					deaths += match["stats"]["deaths"]

					agent = get_agent_data_from_id(match["characterId"])  # TODO | Unused

			headshot.append(round(get_headshot_percent(match_data)[str(user_id)]))
		try:
			avg = sum(headshot) / len(headshot)
		except ZeroDivisionError:
			avg = 0

		kd_ratio = calculate_kd(kills, deaths)
		cache[user_id] = (kd_ratio, wins, round(avg))

		return partyIDs, cache

	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
		print(f"Error: {e}")
		cache[user_id] = (-1, ['Error'], -1)
		return {}, cache


def get_members_of_party_from_uuid(player_id: str):
	player_list = []
	with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(player_id)}", headers=internal_api_headers) as r:
		try:
			if r.status_code == 400:
				is_console = str(r.json()["errorCode"]) == "PLAYER_PLATFORM_TYPE_MISMATCH"
				if is_console:
					with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(player_id)}", headers=internal_api_headers_console) as r2:
						party_id = r2.json()['CurrentPartyID']

			else:
				party_id = r.json()['CurrentPartyID']

		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			print("Error Logged!")

	if party_id is not None:
		with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}", headers=internal_api_headers) as r:
			party_data = r.json()
		for member in party_data["Members"]:
			player_name = get_userdata_from_id(str(member["Subject"]))[0]
			player_list.append(player_name)
	else:
		player_list.clear()
		player_list.append("Player is not in a party. Player could be offline.")
	return player_list, party_id


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
			"Immortal": f"{Fore.LIGHTRED_EX}",  # Red
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
		This function takes a player uuid, Then it translates it the users current state.

		Parameters:
		puuid (str): The desired player's UUID.
		presences_data *Optional* (dict|None):  The presence data of the user.

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
							 headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, verify=False) as r:
				data = r.json()
		else:
			data = presences_data

		all_user_data = data["presences"]
		for user in all_user_data:
			if user["puuid"] == puuid:
				# Check if the player is playing Valorant. If not, return 0
				if str(user["product"]).lower() != "valorant":
					return 0

				encoded_user_data: str = user["private"]
				decoded_user_data = loads(b64decode(encoded_user_data))
				state = decoded_user_data["sessionLoopState"]
				party_state = decoded_user_data["partyState"]
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
		logger.log(1, traceback_str)
	return -1


def get_current_game_score(puuid: str) -> tuple[int, int]:
	requests.packages.urllib3.disable_warnings()  # noqa
	all_user_data = "null"
	decoded_user_data = "null"

	try:
		data = api_request("GET", f"https://127.0.0.1:{port}/chat/v4/presences",
						   headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, verify=False).json()

		all_user_data = data["presences"]
		for user in all_user_data:
			if user["puuid"] == puuid:
				encoded_user_data: str = user["private"]
				decoded_user_data = loads(b64decode(encoded_user_data))
				allyTeamScore = decoded_user_data["partyOwnerMatchScoreAllyTeam"]
				enemyTeamScore = decoded_user_data["partyOwnerMatchScoreEnemyTeam"]
				return allyTeamScore, enemyTeamScore
	except Exception as e:
		print("Error (Score Finding) Logged!")
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
	logger.log(1, f"Returning -1, -1 for current game score!\nData PUUID: {puuid}\n All_User_Data: {all_user_data}\nDecoded_User_Data: {decoded_user_data}")
	return -1, -1


def get_party_symbol(number: int):
	party_symbol = "★"
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


async def match_report(match_id: str):
	"""
		Polls the match details endpoint until the match data is available,
		processes the data, and then calls the console notification.
	"""
	# Poll every 5 seconds until match data is available.
	while True:
		response = api_request("GET", f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}", headers=internal_api_headers)
		if response.status_code == 200:
			match_data = response.json()
			break
		await asyncio.sleep(5)

	# Process the match data to calculate statistics.
	summary: str = generate_match_report(match_data, val_uuid, True)

	# Display the notification on the console.
	Notification.add_notification(summary)


async def run_in_game(cache: dict = None, partys: dict = None):
	if cache is None:
		cache = {}

	print("Loading...")

	# Fetch match ID
	while True:
		try:
			r = api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}", headers=internal_api_headers)
			if r.status_code != 404:
				match_id = r.json()["MatchID"]
				break
			else:
				if 3 <= get_user_current_state(str(val_uuid)) <= 4:
					pass
				else:
					return
		except:
			pass

	got_players = False
	player_data = {}
	player_name_cache = []
	team_blue_player_list = {}
	team_red_player_list = {}
	if partys is None:
		partys = {}

	def fetch_player_data(player_id, platform):
		nonlocal partys, cache
		with request_semaphore:
			party_data, cache = get_playerdata_from_uuid(player_id, cache, platform)
			partys = add_parties(partys, party_data)
		return None

	while True:
		try:
			# Get match data
			with api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/matches/{match_id}",
							 headers=internal_api_headers) as r:
				if r.status_code == 400:
					logger.log(2, f"Login may have expired! Re-logging in.\n Tried to get in-game match data. MATCH_ID -> {match_id}")
					await log_in()
				elif r.status_code == 404:
					return None
				else:
					match_data = r.json()

			if match_data["State"] not in ("CLOSED", "POST_GAME"):
				map_id = match_data["MapID"]
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
				map_name = get_mapdata_from_id(map_id) if not is_solo else "The Range"

				# Build a header string
				header = f"[green]Map:[/green] {map_name}\n[cyan]Game mode:[/cyan] {gamemode_name}\n\n"

				# (Populate player lists once)
				if not got_players:
					threads = []
					for player in match_data["Players"]:
						player_id = player["PlayerIdentity"]["Subject"]
						team_id = player["TeamID"]
						is_level_hidden = player["PlayerIdentity"]["HideAccountLevel"]
						player_lvl = str(player["PlayerIdentity"]["AccountLevel"]) if not is_level_hidden else "--"
						agent_name = get_agent_data_from_id(player['CharacterID'])
						host_player = get_userdata_from_id(player_id, val_uuid)[0]
						player_name_cache.append(host_player)

						# Fetch player data asynchronously
						if "console" in gamemode_name:
							rank = get_rank_from_uuid(str(player_id), "CONSOLE")
							thread = threading.Thread(target=fetch_player_data, args=(player_id, "CONSOLE"))
							threads.append(thread)
							thread.start()
						else:
							rank = get_rank_from_uuid(str(player_id))
							thread = threading.Thread(target=fetch_player_data, args=(player_id, "PC"))
						threads.append(thread)
						thread.start()

						if team_id.lower() == "blue":
							team_blue_player_list[host_player] = (agent_name, player_lvl, rank, player_id)
						elif team_id.lower() == "red":
							team_red_player_list[host_player] = (agent_name, player_lvl, rank, player_id)

						player_data[host_player] = cache.get(str(player_id), ("Loading", "Loading", "Loading"))

				# Refresh player data (if needed)
				count = 0
				party_exists = []
				party_number = 1
				for player in match_data["Players"]:
					player_id = player["PlayerIdentity"]["Subject"]
					player_data[str(player_name_cache[count])] = cache.get(str(player_id), ("Loading", "Loading", "Loading"))
					count += 1

				# Build team display strings using Rich markup
				team_blue_str = ""
				for user_name, data in team_blue_player_list.items():
					party_symbol = ""
					for party_id, members in partys.items():
						if len(members) > 1 and str(data[3]) in members:
							for existing_party in party_exists:
								if existing_party[0] == party_id:
									party_symbol = get_party_symbol(int(existing_party[1]))
									break
							else:
								party_exists.append([party_id, party_number])
								party_symbol = get_party_symbol(int(party_number))
								party_number += 1
								break
					# Using Rich markup for colors
					team_blue_str += f"{party_symbol}[blue][LVL {data[1]}][/blue] {get_rank_color(data[2], True)} {user_name} ({data[0]})\n"
					kd, wins, hs = player_data.get(user_name, ("Loading", "Loading", "Loading"))
					team_blue_str += f"[magenta]Player KD: {kd} | Headshot: {hs}%\nPast Matches: {''.join(wins)}[/magenta]\n\n"

				team_red_str = ""
				for user_name, data in team_red_player_list.items():
					party_symbol = ""
					for party_id, members in partys.items():
						if len(members) > 1 and str(data[3]) in members:
							for existing_party in party_exists:
								if existing_party[0] == party_id:
									party_symbol = get_party_symbol(int(existing_party[1]))
									break
							else:
								party_exists.append([party_id, party_number])
								party_symbol = get_party_symbol(int(party_number))
								party_number += 1
								break
					team_red_str += f"{party_symbol}[red][LVL {data[1]}][/red] {get_rank_color(data[2], True)} {user_name} ({data[0]})\n"
					kd, wins, hs = player_data.get(user_name, ("Loading", "Loading", "Loading"))
					team_red_str += f"[magenta]Player KD: {kd} | Headshot: {hs}%\nPast Matches: {''.join(wins)}[/magenta]\n\n"

				# Create panels for each team
				team_blue_panel = Panel(team_blue_str, title="Team Blue", border_style="blue")
				team_red_panel = Panel(team_red_str, title="Team Red", border_style="red")

				# Get current game score and add to header
				score = get_current_game_score(val_uuid)
				header += f"[yellow]Score:[/yellow] {score[0]} | {score[1]}\n"

				# Clear the console and print header plus side-by-side team panels
				console.clear()
				os.system("cls")
				console.print(header)
				console.print(Columns([team_blue_panel, team_red_panel], expand=True, equal=True))

				got_players = True

				# Optionally, fetch match stats and update additional info...
				try:
					with api_request("GET", f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}",
									 headers=internal_api_headers) as re_match_stats:
						match_stats = re_match_stats.json()

					total_rounds = match_stats["teams"][0]["roundsPlayed"]
					team_1_rounds = match_stats["teams"][0]["roundsWon"]
					team_2_rounds = match_stats["teams"][1]["roundsWon"]

					console.print(f"[yellow]Total Rounds:[/yellow] {total_rounds}")
					console.print(f"[yellow]Score:[/yellow] {team_1_rounds}  |  {team_2_rounds}")

					asyncio.create_task(match_report(match_id))
					await asyncio.sleep(3)
					return

				except Exception:
					pass

				await asyncio.sleep(5)

			else:
				asyncio.create_task(match_report(match_id))
				return

		except KeyboardInterrupt:
			sys.exit(1)
		except Exception as e:
			await log_in()
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			print("Error Logged!")


def print_buffered(buffer):
	"""Print content from a buffer without clearing the screen."""
	sys.stdout.write(buffer.getvalue())
	sys.stdout.flush()


def add_parties(partys, new_parties):
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


async def run_pregame(data: dict):
	print("Match FOUND! Getting match details")
	got_rank = False
	got_map_and_gamemode = False
	player_data = {}
	threads = []
	rank_list = {}
	buffer = StringIO()
	last_rendered_content = ""

	cache = {}
	partys = {}

	def fetch_player_data(player_id, platform):
		nonlocal cache, partys
		with request_semaphore:
			party_data, cache = get_playerdata_from_uuid(player_id, cache, platform)
			partys = add_parties(partys, party_data)
		return None

	while True:
		buffer.truncate(0)
		buffer.seek(0)
		try:
			with api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{data['MatchID']}",
							 headers=internal_api_headers) as r:
				match_data = r.json()
				with open(f"{DATA_PATH}/pre_match_data.json", "w") as f:
					dump(match_data, f, indent=4)

			if not got_map_and_gamemode:
				map_name = get_mapdata_from_id(match_data["MapID"])
				gamemode_name = match_data["QueueID"]
				got_map_and_gamemode = True

			buffer.write(color_text("=" * 30 + "\n", Fore.LIGHTWHITE_EX))
			buffer.write(color_text(f"Map: {map_name}\n", Fore.GREEN))
			buffer.write(color_text(f"Game Mode: {str(gamemode_name).capitalize()}\n", Fore.CYAN))
			buffer.write(color_text("=" * 30 + "\n\n", Fore.LIGHTWHITE_EX))

			our_team_colour = match_data["AllyTeam"]["TeamID"]

			party_number = 1
			party_exists = []

			for ally_player in match_data["AllyTeam"]["Players"]:
				user_name, is_user = get_userdata_from_id(ally_player["PlayerIdentity"]["Subject"], val_uuid)
				is_level_hidden = ally_player["PlayerIdentity"]["HideAccountLevel"]
				if not is_level_hidden:
					player_level = str(ally_player["PlayerIdentity"]["AccountLevel"])
				else:
					player_level = "HIDDEN"
				party_symbol = ""

				try:
					agent_name = get_agent_data_from_id(ally_player["CharacterID"])
				except Exception:
					agent_name = "None"

				if not got_rank:
					if "console" in gamemode_name:
						rank = get_rank_from_uuid(str(ally_player["PlayerIdentity"]["Subject"]), "CONSOLE")
						rank_list[str(user_name)] = str(rank)
						thread = threading.Thread(target=fetch_player_data, args=(ally_player["PlayerIdentity"]["Subject"], "CONSOLE"))
					else:
						rank = get_rank_from_uuid(str(ally_player["PlayerIdentity"]["Subject"]))
						rank_list[str(user_name)] = str(rank)
						thread = threading.Thread(target=fetch_player_data, args=(ally_player["PlayerIdentity"]["Subject"], "PC"))
					threads.append(thread)
					thread.start()

				player_data[user_name] = cache.get(str(ally_player["PlayerIdentity"]["Subject"]), ("Loading", "Loading"))
				state = ally_player["CharacterSelectionState"]

				rank = rank_list.get(str(user_name), "Failed")

				# Ensure the rank color is applied correctly
				for party_id, members in partys.items():
					if len(members) > 1:
						if ally_player["PlayerIdentity"]["Subject"] in members:
							for existing_party in party_exists:
								if existing_party[0] == party_id:
									party_symbol = get_party_symbol(int(existing_party[1]))
									break
							else:
								# Assign new party number
								party_exists.append([party_id, party_number])
								party_symbol = get_party_symbol(int(party_number))
								party_number += 1
								break

				state_display = {
					"": "(Picking)",
					"selected": "(Hovering)",
					"locked": "(Locked)"
				}.get(state, "(Unknown)")

				state_color = {
					"": Fore.YELLOW,
					"selected": Fore.BLUE,
					"locked": Fore.GREEN
				}.get(state, Fore.RED)

				buffer.write(
					f"{party_symbol}{color_text(f'[LVL {player_level}]', state_color)} {get_rank_color(rank)} {user_name}: {agent_name} {state_display}\n"
				)

				kd, wins, avg = cache.get(str(ally_player["PlayerIdentity"]["Subject"]), ("Loading", "Loading", "Loading"))
				buffer.write(color_text(f"  Player KD: {kd} | Headshot: {avg}%\n", Fore.MAGENTA))
				buffer.write(color_text(f"  Past Matches: {''.join(wins)}\n\n", Fore.LIGHTMAGENTA_EX))

			got_rank = True
			buffer.write(color_text(f"Enemy team: {match_data['EnemyTeamLockCount']}/{match_data['EnemyTeamSize']} LOCKED\n", Fore.RED))
			if match_data["PhaseTimeRemainingNS"] == 0:
				buffer.write(color_text("In Loading Phase\n", Fore.CYAN))
				break

			# Render the current buffer content
			current_rendered_content = buffer.getvalue()

			# Only update the screen if content has changed
			if current_rendered_content != last_rendered_content:
				clear_console()
				print(current_rendered_content)
				last_rendered_content = current_rendered_content

			time.sleep(0.5)
		except KeyboardInterrupt:
			sys.exit(1)
		except KeyError:
			return
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			print("Error Logged!")
	logger.log(3, "Loading pregame -> in-game")
	await run_in_game(cache, partys)


def clear_console():
	os.system("cls" if os.name == "nt" else "clear")


def color_text(text, color):
	"""Apply color to the text."""
	return f"{color}{text}{Style.RESET_ALL}"


async def toggle_ready_state(party_id: str, is_ready: bool):
	url = f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}/members/{val_uuid}/setReady"
	headers = internal_api_headers  # Adjust for console if necessary
	data = {"ready": is_ready}

	try:
		response = api_request("POST", url, json=data, headers=headers)
		if response.status_code == 200:
			print(f"Ready state set to: {is_ready}")
			return True
		else:
			print(f"Failed to toggle ready state: {response.status_code} - {response.text}")
			return False
	except Exception as e:
		print(f"Error while toggling ready state: {e}")
		return False


def quit_game():
	player_state = get_user_current_state(val_uuid)
	if player_state == 3:
		with api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/players/{val_uuid}", headers=internal_api_headers) as r:
			if r.status_code == 200:
				match_id = r.json()["MatchID"]
				api_request("POST", f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{match_id}/quit", headers=internal_api_headers)
	elif player_state == 4:
		with api_request("GET", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}", headers=internal_api_headers) as r:
			if r.status_code == 200:
				match_id = r.json()["MatchID"]
				api_request("POST", f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}/disassociate/{match_id}", headers=internal_api_headers)


async def listen_for_input(party_id: str):
	is_ready = True  # Start with the default ready state
	print("Press 'r' to toggle ready state or 'q' to quit.")

	while True:
		try:
			user_input = await asyncio.to_thread(input, "> ")  # Non-blocking input
			user_input: str = user_input.strip().lower()

			if user_input == "r":
				is_ready = not is_ready
				await toggle_ready_state(party_id, is_ready)
			elif user_input == "q":
				print("Exiting input listener...")
				break
			elif user_input.lower() in ["cls", "clear"]:
				clear_console()
			elif "party" in user_input.lower():
				clear_console()
				print("Loading Party...")
				logger.log(4, "Calling get_party from user input")
				await get_party()
			elif "store" in user_input.lower():
				await ValorantShop.run()
			elif "leave" in user_input.lower():
				print("Leaving")
				quit_game()
			if DEBUG:
				if user_input.lower()[0] == "-":
					exec(user_input[1::])

		except Exception as e:
			print(f"Error in input listener: {e}")
			break


async def get_friend_states() -> list[str]:
	requests.packages.urllib3.disable_warnings()  # noqa
	friend_list = []
	try:
		with api_request("GET", f"https://127.0.0.1:{port}/chat/v4/presences",
						 headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, verify=False) as r:
			data = r.json()
		all_user_data = data["presences"]
		for user in all_user_data:
			if user["activePlatform"] is not None:
				if str(user["puuid"]) != str(val_uuid):
					state = get_user_current_state(user["puuid"], data)
					state_str = "In Menu" if state == 1 else "Queueing" if state == 2 else "Pre-game" if state == 3 else "In-game"
					full_str = f"{user['game_name']}#{user['game_tag']}: {state_str}"
					friend_list.append(full_str)
	except Exception:
		print("Please make sure Riot Client is open!")
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

	if config_main.get("use_discord_rich_presence"):
		RPC.connect()
		RPC.update(
			state="In Menu",
			details="Valorant Match Tracker",
			large_image="valorant",
			large_text="Valorant Zoro",
			party_size=[1, 5],
			start=int(time.time()),
		)

	await match_report("e3b681a8-aed3-4e36-8a58-1664b60b2c3d")

	while True:
		return_code = await check_if_user_in_pregame()
		if return_code:
			last_rendered_content = ""
			clear_console()
		try:
			buffer.truncate(0)
			buffer.seek(0)

			# Build the dynamic party section.
			message_list = [color_text("----- Party -----\n", Fore.CYAN)]
			party_id = await fetch_party_id()

			if party_id:
				if input_task is None or input_task.done():
					input_task = asyncio.create_task(listen_for_input(party_id))

				party_data = await fetch_party_data(party_id)
				message_list.extend(parse_party_data(party_data, got_rank))
				party_section = "".join(message_list)

				if Notification.has_notifications():
					new_screen_content = Notification.get_display().renderable + party_section
				else:
					new_screen_content = party_section

				if new_screen_content != last_rendered_content:
					clear_console()
					console.print(Notification.get_display(), markup=True)
					print("\n" + party_section)
					last_rendered_content = new_screen_content

				await asyncio.sleep(0.25)
			else:
				render_no_party_message(buffer, last_rendered_content)
				await asyncio.sleep(3.5)
				return -1
		except KeyboardInterrupt:
			sys.exit(1)
		except Exception as e:
			await handle_exception(e)


async def fetch_party_id():
	"""Fetch the party ID for the current user."""
	with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}", headers=internal_api_headers) as r:
		if r.status_code == 400:
			is_console = str(r.json().get("errorCode")) == "PLAYER_PLATFORM_TYPE_MISMATCH"
			if is_console:
				with api_request("GET", f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}", headers=internal_api_headers_console) as r2:
					return r2.json().get('CurrentPartyID')
			else:
				logger.log(1, "Error fetching party details.")
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
		messages.append(color_text("Queueing!\n", Fore.YELLOW))

	game_mode = str(party_data.get("MatchmakingData", {}).get("QueueID", "Unknown")).lower()
	game_mode = GAME_MODES.get(game_mode.lower(), str(game_mode))
	messages.append(color_text(f"Mode: {game_mode.capitalize()}\n\n", Fore.GREEN))

	for member in party_data.get("Members", []):
		player_name, is_user = get_userdata_from_id(str(member["Subject"]), val_uuid)
		if member["Subject"] in DEV_PUUID_LIST:
			player_name += " [DEV]"  # TODO | Make colour and shit
		is_leader = member.get("IsOwner", False)
		player_lvl = member["PlayerIdentity"].get("AccountLevel", "-1")

		color = Fore.YELLOW if is_user else (Fore.LIGHTRED_EX if is_leader else Fore.WHITE)
		leader_text = "[Leader] " if is_leader else ""

		if member["Subject"] not in got_rank:
			player_rank_str = get_rank_color(get_rank_from_uuid(str(member['Subject'])))
			got_rank[str(member["Subject"])] = player_rank_str
		else:
			player_rank_str = got_rank[str(member["Subject"])]

		messages.append(color_text(f"{leader_text}[LVL {player_lvl}] {player_name} {player_rank_str}\n", color))
	return messages


def render_no_party_message(buffer: StringIO, last_rendered_content: str):
	"""Render a message when no party is found."""
	clear_console()
	new_message = color_text("Valorant is not running for that user!\n", Fore.RED)
	if new_message != last_rendered_content:
		buffer.write(new_message)
		print_buffered(buffer)


async def handle_exception(exception):
	"""Handle exceptions by logging and retrying login."""
	traceback_str = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
	logger.log(1, traceback_str)
	print(color_text(f"An Error Has Happened!\n{traceback_str}", Fore.RED))
	logged_in = await log_in()
	if not logged_in:
		sys.exit(1)


async def check_if_user_in_pregame(send_message: bool = False) -> bool:
	if send_message:
		print("\n\nChecking if player is in match")

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
				time.sleep(1)
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
	r = api_request("GET", "https://auth.riotgames.com/userinfo", headers={"Authorization": f"Bearer {val_access_token}"})
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


async def main() -> None:
	global ValorantShop, Notification, RPC
	clear_console()
	main_display()
	console.print("[yellow]One moment while we sign you in...[/yellow]\n")

	RPC = Presence(CLIENT_ID)

	logged_in = await log_in()
	if logged_in:
		name, tag = get_userdata_from_token()
		logger.log(3, f"Using Version: {VERSION}\nLogged in as: {name}#{tag}")

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
						await ValorantShop.run()
					elif user_input == "2":
						while True:
							logged_in = await log_in()
							if logged_in:
								await check_if_user_in_pregame()
								logger.log(4, "Calling get_party from main")
								if await get_party() == -1:
									break
							else:
								time.sleep(2.5)
								console.clear()
					else:
						console.print("[bold red]Invalid input. Please try again.[/bold red]")
						time.sleep(1.5)
				else:
					while True:
						logged_in = await log_in()
						if logged_in:
							await check_if_user_in_pregame()
							logger.log(4, "Calling get_party from auto-main")
							await get_party()
						else:
							time.sleep(2.5)
							console.clear()
			except KeyboardInterrupt:
				console.print("[bold yellow]Exiting...[/bold yellow]")
				return
			except EOFError:
				console.print("[bold yellow]Exiting...[/bold yellow]")
				return
			except Exception as e:
				traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
				logger.log(1, traceback_str)
				console.print(f"[bold red]An Error Has Happened![/bold red]\n{traceback_str}")
				time.sleep(2)
	else:
		console.print("[bold red]Failed to log in. Retrying in 5 seconds...[/bold red]")
		time.sleep(5)


if __name__ == "__main__":
	clear_console()
	colorama.init(autoreset=True)
	logger = Logger("Valorant Zoro", "logs/ValorantZoro", ".log")
	logger.load_public_key(pub_key)

	while True:
		try:
			asyncio.run(main())
		except KeyboardInterrupt:
			sys.exit(1)
