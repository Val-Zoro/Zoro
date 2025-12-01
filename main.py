import random

VERSION = "v2.5.3-ALPHA"

import argparse
import asyncio
import atexit
import configparser
import hashlib
import os
import sys
import threading
import time
import tkinter
import traceback
from base64 import b64encode, b64decode
from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from io import StringIO
from json import dump, dumps, loads, load
from math import tanh
from pathlib import Path
from platform import system, version
from tempfile import gettempdir
from typing import Any, Dict, Optional, Tuple, List, Callable, Mapping, Sequence, Iterable

import colorama
import nest_asyncio
from Crypto.Cipher import PKCS1_OAEP, AES
# from wmi import WMI | Removed to avoid dependency issues on non-Windows systems
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from PIL import Image
from colorama import Fore, Style
from pypresence import Presence
from requests import Session, get
from requests.adapters import HTTPAdapter
from rich import box, pretty
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from urllib3 import disable_warnings
from urllib3.util.retry import Retry  # noqa | Ignore, should work fine

console = Console()
pretty.install()

DEBUG = False
DEBUG_MODE = False
SAVE_DATA = False
OFFLINE_MODE = False
CLI_DEBUG_OVERRIDE = False
OFFLINE_STATE_MANAGER = None

val_token = ""
val_access_token = ""
val_entitlements_token = ""
val_uuid = ""
region = ""

internal_api_headers = {}
internal_api_headers_console = {}

password = ""
port = ""

party_size = 1

DEFAULT_MENU_ACTION = "manual"
SETUP_COMPLETED = False
STORE_ONLY_MODE = False
VALID_MENU_ACTIONS = {"manual", "shop", "loader"}
SCORECARD_COMMANDS = {"score", "scores", "scorecard", "zscore", "zoro"}
DISCLAIMER_LINES = (
	"Valorant Zoro is a community-maintained client that is not endorsed by Riot Games.",
	"Use of automation or private APIs may violate Riot's terms of service and can lead to account action.",
	"Never share authentication tokens, cookies, or log files that contain personal information.",
	"You accept full responsibility for how you use this software.",
)

MAX_CONCURRENT_REQUESTS = 2
request_semaphore = threading.Semaphore(MAX_CONCURRENT_REQUESTS)

PlayerStatsTuple = tuple[Any, list[str], Any, Any]
PLAYER_STATS_CACHE: dict[str, PlayerStatsTuple] = {}
PLAYER_STATS_PARTY_CACHE: dict[str, dict[str, list[str]]] = {}
PLAYER_STATS_CACHE_EXPIRY: dict[str, float] = {}
PLAYER_STATS_CACHE_TTL = 300  # seconds to reuse prefetched stats between views


@dataclass(frozen=True)
class ZoroScoreEntry:
	match_id: str
	started_at: datetime | None
	map_name: str
	queue_name: str
	agent_name: str
	result: str
	team_rounds: int
	opponent_rounds: int
	rounds_played: int
	kills: int
	deaths: int
	kd_ratio: float
	headshot_percent: float | None
	score: float
	breakdown: Dict[str, Any]


@dataclass(frozen=True)
class BundleItem:
	name: str
	icon_url: str
	cost: int
	rarity: tuple[str, str, str] | None = None
	item_type: str = "Item"


ITEM_TYPE_LABELS: dict[str, str] = {
	"e7c63390-eda7-46e0-bb7a-a6abdacd2433": "Weapon Skin",
	"dd3bf334-87f3-40bd-b043-682a57a8dc3a": "Gun Buddy",
	"d5f120f8-ff8c-4aac-92ea-f2b5acbe9475": "Spray",
	"3f296c07-64c3-494c-923b-fe692a4fa1bd": "Player Card",
	"de7caa6b-adf7-4588-bbd1-143831e786c6": "Player Title",
	"03a572de-4234-31ed-d344-ababa488f981": "Flex"
}

input_task = None

ASYNC_EXCEPTION_HANDLER: Optional[
	Callable[[asyncio.AbstractEventLoop, Dict[str, Any]], None]
] = None


def _prompt_bool(question: str, default: bool) -> bool:
	"""Prompt the user for a yes/no question with a default."""
	if not sys.stdin or not sys.stdin.isatty():
		return default

	default_text = "Y/n" if default else "y/N"
	while True:
		response = input(f"{question} [{default_text}]: ").strip().lower()
		if not response:
			return default
		if response in {"y", "yes"}:
			return True
		if response in {"n", "no"}:
			return False
		console.print("[bold yellow]Please answer with yes or no.[/bold yellow]")


def _prompt_choice(question: str, choices: Mapping[str, str], default_key: str) -> str:
	"""
	Prompt the user to choose from a mapping of keys to descriptions.

	Args:
		question: Text describing what is being selected.
		choices: Mapping of valid input -> human-readable label.
		default_key: Key to use when user presses enter.
	"""
	if not sys.stdin or not sys.stdin.isatty():
		return default_key

	options_display = ", ".join(f"{key} ({label})" for key, label in choices.items())
	prompt_text = f"{question} [{default_key}]: "
	console.print(f"{question}\n  {options_display}")

	while True:
		response = input(prompt_text).strip().lower()
		if not response:
			return default_key
		if response in choices:
			return response
		console.print("[bold yellow]Select one of the listed options.[/bold yellow]")


def _prompt_int(question: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
	"""Prompt the user for an integer value with optional bounds."""
	if not sys.stdin or not sys.stdin.isatty():
		return default

	range_hint = ""
	if minimum is not None and maximum is not None:
		range_hint = f" ({minimum}-{maximum})"
	elif minimum is not None:
		range_hint = f" (>= {minimum})"
	elif maximum is not None:
		range_hint = f" (<= {maximum})"

	while True:
		response = input(f"{question}{range_hint} [{default}]: ").strip()
		if not response:
			return default
		try:
			value = int(response)
		except ValueError:
			console.print("[bold yellow]Enter a whole number.[/bold yellow]")
			continue
		if minimum is not None and value < minimum:
			console.print(f"[bold yellow]Value must be at least {minimum}.[/bold yellow]")
			continue
		if maximum is not None and value > maximum:
			console.print(f"[bold yellow]Value must be at most {maximum}.[/bold yellow]")
			continue
		return value


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
	"hurm": "Team Deathmatch",
	"premier-seasonmatch": "Premier",
	"premier-scrim": "Premier"
}

CONFIG_FILE = "config.ini"  # Name / Path for the config file
CLIENT_ID = 1354365908054708388  # For discord RPC

# ROLES_ID = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUwzWXZkQ0YvZjd5MzdwMFJJem5GZElob2ZiS0VSQ2Yza0lNQ29qNjhUYVcKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ=="
ROLE_URL = "aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9TYXVjeXdhbi80MzgyODA1MzgyMDk3OThjMDBkNjE5MGRhYjlmN2ZlZS9yYXcv"

DATA_PATH = "data"
if not os.path.exists(DATA_PATH) and DEBUG:
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
[dark_red] ▄▄▄▄▄▄▄▄                               [/dark_red]
[red] ▀▀▀▀▀███                               [/red]
[red]     ██▀    ▄████▄    ██▄████   ▄████▄  [/red]
[dark_red]   ▄██▀    ██▀  ▀██   ██▀      ██▀  ▀██ [/dark_red]
[dark_magenta]  ▄██      ██    ██   ██       ██    ██ [/dark_magenta]
[bright_magenta] ███▄▄▄▄▄  ▀██▄▄██▀   ██       ▀██▄▄██▀ [/bright_magenta]
[dark_magenta] ▀▀▀▀▀▀▀▀    ▀▀▀▀     ▀▀         ▀▀▀▀   [/dark_magenta]
"""


class Logger:
	def __init__(self, app_name: str, file_name: str, file_ending: str = ".log"):
		self.app_name = app_name
		self.file_name = file_name
		self.file_ending = file_ending

		self.VERSION = "v1.7.5"

		self.LEVELS = {1: "Error",
		               2: "Warning",
		               3: "Info",
		               4: "Debug"}
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
			raise ValueError("[Logger] Public key not loaded, cannot encrypt log message.")

		aes_key = get_random_bytes(16)

		cipher_aes = AES.new(aes_key, AES.MODE_CBC)

		encrypted_message = cipher_aes.encrypt(pad(message.encode("utf-8"), AES.block_size))

		encrypted_aes_key = cipher_rsa.encrypt(aes_key)

		encrypted_message = b64encode(encrypted_aes_key + cipher_aes.iv + encrypted_message).decode("utf-8")

		return encrypted_message

	@staticmethod
	def _timestamp():
		return datetime.now()

	@staticmethod
	def _coerce_value(value: Any) -> Any:
		if isinstance(value, (str, int, float, bool)) or value is None:
			return value
		if isinstance(value, (list, tuple, set)):
			return [Logger._coerce_value(item) for item in value]
		if isinstance(value, dict):
			return {str(key): Logger._coerce_value(val) for key, val in value.items()}
		return repr(value)

	def _serialize_context(self, context: Mapping[str, Any]) -> str:
		try:
			sanitized = {str(key): self._coerce_value(val) for key, val in context.items()}
			return dumps(sanitized, ensure_ascii=True, default=repr)
		except Exception:
			return repr(context)

	@staticmethod
	def _format_exception_info(exc_info: Any) -> Optional[str]:
		if exc_info is None:
			return None

		if isinstance(exc_info, BaseException):
			return "".join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))

		if isinstance(exc_info, tuple) and len(exc_info) == 3:
			exc_type, exc_value, exc_tb = exc_info
			return "".join(traceback.format_exception(exc_type, exc_value, exc_tb))

		return repr(exc_info)

	def _format_message(self, level: int, message: str, context: Optional[Mapping[str, Any]] = None,
	                    exc_info: Optional[Any] = None) -> str:
		level_name = self.LEVELS.get(level, "Unknown")
		timestamp_str = self._timestamp().strftime("%Y-%m-%d %H:%M:%S")

		details: List[str] = []
		if message:
			details.append(message)

		if context:
			context_payload = self._serialize_context(context)
			details.append(f"context={context_payload}")

		exc_text = self._format_exception_info(exc_info)
		if exc_text:
			details.append(f"exception=\n{exc_text}")

		details.append(f"thread={threading.current_thread().name}")

		formatted_body = "\n".join(details)
		return f"{timestamp_str} - {level_name}: {formatted_body}"

	def _get_log_filename(self) -> str:
		now = self._timestamp()
		return f"{self.file_name}_{now.strftime('%Y-%m-%d')}{self.file_ending}"

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

	def log(self, level: int, message: str, *, context: Optional[Mapping[str, Any]] = None,
	        exc_info: Optional[Any] = None) -> int:
		if level not in self.LEVELS:
			return -1  # Invalid level

		current_time = self._timestamp()
		log_filename = self._get_log_filename()

		if "/" in log_filename:
			file_path = log_filename.split("/")[0]
			if not os.path.exists(file_path):
				os.mkdir(file_path)

		# Check if the file needs to be rotated
		if os.path.exists(log_filename) and (
				current_time - datetime.fromtimestamp(os.path.getmtime(log_filename))) > self.LOG_TIME_INTERVAL:
			log_filename = self._get_log_filename()

		try:
			self.__get_sys_hwid()

			# Prepare a formatted message once
			_formatted = self._format_message(level, message, context=context, exc_info=exc_info)

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

	def debug(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> int:
		return self.log(4, message, context=context)

	def info(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> int:
		return self.log(3, message, context=context)

	def warning(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> int:
		return self.log(2, message, context=context)

	def error(self, message: str, *, context: Optional[Mapping[str, Any]] = None,
	          exc_info: Optional[Any] = None) -> int:
		try:
			return self.log(1, message, context=context, exc_info=exc_info)
		except ImportError:  # Mostly happens when Python is shutting down asynchronously and modules are unloaded
			pass

	def log_exception(self, message: str, exception: BaseException,
	                  *, context: Optional[Mapping[str, Any]] = None, level: int = 1) -> int:
		return self.log(level, message, context=context, exc_info=exception)


logger: Optional["Logger"] = None


def _log_runtime_event(level: int, event: str, message: str, **context: Any) -> None:
	"""
	Safely emit a structured log entry even when the logger has not yet been initialised.
	"""
	logger_obj = globals().get("logger")
	payload = {"event": event, **context}
	if isinstance(logger_obj, Logger):
		logger_obj.log(level, message, context=payload)
	elif DEBUG:
		console.print(f"[dim]{event}[/dim]: {message} {payload}")


def log_debug_event(event: str, message: str, **context: Any) -> None:
	_log_runtime_event(4, event, message, **context)


def log_info_event(event: str, message: str, **context: Any) -> None:
	_log_runtime_event(3, event, message, **context)


def install_global_exception_handlers(app_logger: Logger) -> None:
	"""Ensure uncaught exceptions surface in encrypted logs for diagnostics."""
	global ASYNC_EXCEPTION_HANDLER

	def handle_exception(exc_type, exc_value, exc_traceback):
		if issubclass(exc_type, KeyboardInterrupt):
			sys.__excepthook__(exc_type, exc_value, exc_traceback)
			return
		app_logger.error(
			"Unhandled exception in main thread",
			context={"source": "sys.excepthook"},
			exc_info=(exc_type, exc_value, exc_traceback),
		)

	sys.excepthook = handle_exception

	def threading_exception_handler(args):
		if issubclass(args.exc_type, KeyboardInterrupt):
			return
		app_logger.error(
			"Unhandled exception in background thread",
			context={"thread": getattr(args.thread, "name", "unknown")},
			exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
		)

	threading.excepthook = threading_exception_handler

	def handle_asyncio_exception(loop: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
		context_payload = {key: repr(value) for key, value in context.items() if key != "exception"}
		app_logger.error(
			"Unhandled exception in asyncio task",
			context={"loop_id": id(loop), **context_payload},
			exc_info=context.get("exception"),
		)

	ASYNC_EXCEPTION_HANDLER = handle_asyncio_exception

	try:
		loop = asyncio.get_running_loop()
	except RuntimeError:
		loop = None

	if loop is not None:
		loop.set_exception_handler(handle_asyncio_exception)
	else:
		app_logger.debug(
			"Asyncio loop not running during handler install; handler will be attached when loop starts.",
			context={"thread": threading.current_thread().name},
		)


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
			logger.debug(
				"Rate limited while contacting Riot API",
				context={"retry_in_seconds": wait_time, "url": url, "method": method},
			)
		time.sleep(wait_time)
		# Reuse a shared session with timeout
		return SESSION.request(method, url, params=params, json=json or data, headers=headers, verify=verify,
		                       timeout=REQUEST_TIMEOUT)

	return response  # No rate limit header


def api_request(method, url, params=None, data=None, headers=None, json=None, verify=None, timeout=None, retry=None):
	"""Handles API requests and switches to debug mode if enabled."""

	OVERRIDE_RESPONSES = {
		"https://glz-na-1.na.a.pvp.net/core-game/": {"status": 404},  # Stop from connecting to the data core-game
		"https://glz-na-1.na.a.pvp.net/pregame/": {"status": 404},  # Stop from connecting to the data pre-game
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
	if timeout is None:
		timeout = REQUEST_TIMEOUT

	response = SESSION.request(method, url, params=params, json=data, headers=headers, verify=verify,
	                           timeout=timeout)
	# console.print(f"Response Code: {response.status_code}")

	if response.status_code == 200:
		if SAVE_DATA:
			response_data = response.json()
			file_path = generate_filename(method, url, params, data)
			save_response(file_path, response_data)  # Store for debugging
		return response
	elif response.status_code == 429:
		return handle_rate_limit(response, url, method, headers, params, data, json, verify)
	elif response.status_code == 400:
		asyncio.create_task(log_in())
		return api_request(method, url, params, data, headers, json, verify)
	else:
		if response.status_code != 404:
			error_context = {
				"status_code": response.status_code,
				"url": response.url,
				"method": method,
				"params": repr(params),
				"payload": repr(data if data is not None else json),
			}
			try:
				error_context["response_preview"] = response.text[:400]
			except Exception:
				error_context["response_preview"] = "<unavailable>"
			logger.warning("API request returned non-success status", context=error_context)
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

	return_data: Dict[str, Any] = {}

	try:
		file_path = os.getenv("localappdata")
		lockfile_path = f"{file_path}\\Riot Games\\Riot Client\\Config\\lockfile"
		try:
			with open(lockfile_path, "r") as f:
				lockfile_data = f.read()
		except Exception as lockfile_error:
			console.print("Riot Client isn't logged into an account!")
			logger.error(
				"Failed to read Riot Client lockfile",
				context={"lockfile_path": lockfile_path},
				exc_info=lockfile_error,
			)
			return None

		password = b64encode(f"riot:{str(lockfile_data.split(':')[3])}".encode("ASCII")).decode()
		port = str(lockfile_data.split(":")[2])

		if password is None:
			raise ValueError("Riot Client login password not found")

		try:
			with api_request(
					"GET",
					f"https://127.0.0.1:{port}/entitlements/v1/token",
					headers={
						"authorization": f"Basic {password}",
						"accept": "*/*",
						"Host": f"127.0.0.1:{port}",
					},
					verify=False,
					timeout=(3, 6)
			) as r:
				return_data = r.json()
		except Exception as token_error:
			console.print("Please make sure Riot Client is open!")
			logger.error(
				"Failed to retrieve entitlement tokens from Riot client",
				context={"port": port, "password": password},
				exc_info=token_error,
			)
			return None

		access_token = return_data.get("accessToken")
		entitlements_token = return_data.get("token")
		subject = return_data.get("subject")

		if not all([access_token, entitlements_token, subject]):
			logger.warning(
				"Riot Client returned incomplete token payload",
				context={"keys": list(return_data.keys()), "data": list(return_data.values())},
			)
			return None

		return access_token, entitlements_token, subject

	except Exception as e:
		console.print(color_text("Please make sure you are logged into a Riot Account!", Fore.CYAN))
		logger.error(
			"Log in failed while fetching Riot Client credentials",
			context={"port": port, "has_payload": bool(return_data)},
			exc_info=e,
		)
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


class HeadlessLoadingIndicator:
	"""Minimal loading window for when the console is hidden."""

	def __init__(self, message: str):
		self.message = message
		self._stop_event = threading.Event()
		self._thread: threading.Thread | None = None

	def start(self) -> None:
		if self._thread and self._thread.is_alive():
			return
		self._thread = threading.Thread(target=self._run, daemon=True)
		self._thread.start()

	def _run(self) -> None:
		try:
			import tkinter as tk
		except Exception:
			return
		try:
			root = tk.Tk()
		except Exception:
			return

		root.title("Valorant Zoro")
		root.geometry("320x140")
		root.resizable(False, False)
		try:
			root.iconbitmap("assets/Zoro.ico")
		except Exception:
			pass
		root.attributes("-topmost", True)

		frame = tk.Frame(root, bg="#151618")
		frame.pack(fill="both", expand=True)
		label = tk.Label(
			frame,
			text=self.message,
			font=("Segoe UI", 11, "bold"),
			bg="#151618",
			fg="#FFFFFF",
			wraplength=280,
			justify="center",
			padx=18,
			pady=18,
		)
		label.pack(expand=True, fill="both")
		sub = tk.Label(
			frame,
			text="Contacting Riot services...",
			font=("Segoe UI", 9),
			bg="#151618",
			fg="#B0B6BD",
			pady=4,
		)
		sub.pack()

		def _poll():
			if self._stop_event.is_set():
				try:
					root.destroy()
				except Exception:
					pass
				return
			root.after(200, _poll)

		root.after(200, _poll)
		try:
			root.mainloop()
		except Exception:
			pass

	def stop(self) -> None:
		self._stop_event.set()
		if self._thread:
			self._thread.join(timeout=1.0)
			self._thread = None


class SingleInstanceGuard:
	"""Prevent multiple concurrent client instances."""

	def __init__(self, name: str):
		self.name = name
		self._handle = None
		self._lock_path: Path | None = None
		self._lock_fd: int | None = None

	def acquire(self) -> bool:
		if os.name == "nt":
			try:
				import ctypes

				kernel32 = ctypes.windll.kernel32
				mutex = kernel32.CreateMutexW(None, False, self.name)
				if not mutex:
					return True
				if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
					kernel32.CloseHandle(mutex)
					return False
				self._handle = mutex
				return True
			except Exception:
				pass

		lock_dir = Path(gettempdir())
		lock_dir.mkdir(parents=True, exist_ok=True)
		self._lock_path = lock_dir / f"{self.name}.lock"
		try:
			fd = os.open(str(self._lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
			self._lock_fd = fd
			os.write(fd, str(os.getpid()).encode("utf-8"))
			return True
		except FileExistsError:
			return False
		except Exception:
			return True

	def release(self) -> None:
		if self._handle:
			try:
				import ctypes

				kernel32 = ctypes.windll.kernel32
				kernel32.ReleaseMutex(self._handle)
				kernel32.CloseHandle(self._handle)
			except Exception:
				pass
			self._handle = None

		if self._lock_fd is not None:
			try:
				os.close(self._lock_fd)
			except Exception:
				pass
			self._lock_fd = None
			if self._lock_path and self._lock_path.exists():
				with suppress(Exception):
					self._lock_path.unlink()

image_cache = {}


def load_image(url, size=None):
	"""Load and optionally resize an image from a URL using caching."""
	if url in image_cache:
		img = image_cache[url]
	else:
		try:
			img = Image.open(get(url, stream=True).raw)
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
		indicator: HeadlessLoadingIndicator | None = None
		if globals().get("args") is not None and getattr(args, "no_console", False):
			indicator = HeadlessLoadingIndicator("Loading Valorant Store...")
			indicator.start()

		login_status = await log_in()
		if not login_status:
			console.print("Please make sure Riot Client is open!")
			return
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
			bundle_items: dict[str, list[BundleItem]] = {}
			bundle_duration = None  # Default value if no bundles are found
			featured_bundle = store_data.get('FeaturedBundle', {})

			if 'Bundles' in featured_bundle:
				for bundle in featured_bundle['Bundles']:
					bundle_uuid = bundle.get('DataAssetID', '')
					bundles_uuid.append(bundle_uuid)

					bundle_items[bundle_uuid] = []

					# Calculate the total discounted price from all items in the bundle
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
						item_cost = int(
							itemOffer["Offer"]["Cost"].get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", 0)
						)
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
						# If Flex
						elif item_type_uuid == "03a572de-4234-31ed-d344-ababa488f981":
							item_data = api_request("GET",
							                        f"https://valorant-api.com/v1/flex/{item_uuid}").json()
						else:
							item_data = {"data": {"displayName": "null",
							                      "displayIcon": "https://img.icons8.com/liquid-glass/48/no-image.png"}}
						if item_data.get("status", 404) == 200 and item_data.get("data"):
							item_name: str = item_data["data"].get("displayName", "Unknown")
							item_icon: str = item_data["data"].get("displayIcon",
							                                       "https://img.icons8.com/liquid-glass/48/no-image.png")
						else:
							item_name = "Unknown"
							item_icon = ""

						skin_rarity: tuple[str, str, str] | None = None
						if is_skin and item_data.get("status", 404) == 200:
							for data in all_skins_data:
								if data.get("displayName", "").lower() == item_name.lower():
									tier_uuid = data.get("contentTierUuid", "")
									if tier_uuid:
										tier_response = api_request("GET",
										                            f"https://valorant-api.com/v1/contenttiers/{tier_uuid}")
										tier_data = tier_response.json().get("data", {})
										skin_rarity = (
											tier_data.get("devName", "") or "Skin",
											tier_data.get("highlightColor", "") or "",
											tier_data.get("displayIcon", "") or "",
										)
										break

						bundle_items[bundle_uuid].append(
							BundleItem(
								name=item_name,
								icon_url=item_icon,
								cost=item_cost,
								rarity=skin_rarity,
								item_type=ITEM_TYPE_LABELS.get(item_type_uuid, "Item"),
							)
						)

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
			if indicator:
				indicator.stop()
				indicator = None
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
		finally:
			if indicator:
				indicator.stop()

	async def display_gui(
			self,
			vp, vp_icon, rp, rp_icon, kc, kc_icon,
			current_bundles, bundles_images, bundle_prices, bundle_duration, bundle_items,
			skin_names, skin_images, skin_videos, skin_prices, skin_duration, skin_rarity,
			nm_offers, nm_prices, nm_images, nm_duration
	):
		# PySide6-based shop UI (no Tkinter)
		from PySide6.QtCore import Qt, QTimer, QSize, QUrl
		from PySide6.QtGui import QPixmap, QImage, QIcon, QDesktopServices, QCursor
		from PySide6.QtWidgets import (
			QApplication,
			QMainWindow,
			QWidget,
			QScrollArea,
			QVBoxLayout,
			QHBoxLayout,
			QLabel,
			QPushButton,
			QFrame,
			QGridLayout,
			QSizePolicy,
			QSystemTrayIcon,
			QMenu,
			QLineEdit,
			QComboBox,
			QToolTip,
		)

		# Theme palette
		DARK_BG = "#151618"
		LIGHT_BG = "#F6F7FB"
		DARK_SURFACE = "#1E2023"
		LIGHT_SURFACE = "#FFFFFF"
		DARK_CARD = "#212327"
		LIGHT_CARD = "#FFFFFF"
		ACCENT = "#FF4654"
		FG_DARK = "#0F1113"
		FG_LIGHT = "#FFFFFF"

		def fmt_num(n) -> str:
			try:
				return f"{int(n):,}"
			except Exception:
				return str(n)

		def format_duration(seconds: int) -> str:
			d = seconds // (24 * 3600)
			seconds %= (24 * 3600)
			h = seconds // 3600
			seconds %= 3600
			m = seconds // 60
			s = seconds % 60
			return f"{d}d {h}h {m}m {s}s"

		pixmap_cache: dict[str, QPixmap] = {}

		def _normalize_hex(color: str, fallback: str | None = None) -> str:
			if not fallback:
				fallback = ACCENT
			val = (color or "").strip().lstrip("#")
			if len(val) < 6:
				return fallback
			val = val[:6]
			return f"#{val}"

		def _darken_hex(color: str, factor: float = 0.6) -> str:
			val = _normalize_hex(color)
			try:
				r = int(val[1:3], 16)
				g = int(val[3:5], 16)
				b = int(val[5:7], 16)
			except ValueError:
				return _normalize_hex(ACCENT)
			r = max(0, min(255, int(r * factor)))
			g = max(0, min(255, int(g * factor)))
			b = max(0, min(255, int(b * factor)))
			return f"#{r:02x}{g:02x}{b:02x}"

		def _format_timer_value(seconds: int) -> str:
			return "Expired" if seconds <= 0 else format_duration(int(seconds))

		def get_pixmap(url: str, w: int | None = None, h: int | None = None) -> QPixmap | None:
			if not url:
				return None
			key = f"{url}|{w}x{h}"
			if key in pixmap_cache:
				return pixmap_cache[key]
			try:
				r = get(url, timeout=10)
				r.raise_for_status()
				img = QImage.fromData(r.content)
				if img.isNull():
					return None
				pm = QPixmap.fromImage(img)
				if w or h:
					tw = w or pm.width()
					th = h or pm.height()
					pm = pm.scaled(QSize(tw, th), Qt.KeepAspectRatio,
					               Qt.SmoothTransformation)
				pixmap_cache[key] = pm
				return pm
			except Exception as e:
				console.print(f"Pixmap load error: {e}")
				return None

		class CardsGrid(QWidget):
			def __init__(self, min_w: int, max_cols: int):
				super().__init__()
				self.min_w = min_w
				self.max_cols = max_cols
				self.cards: list[QFrame] = []
				self.grid = QGridLayout(self)
				self.grid.setContentsMargins(0, 0, 0, 0)
				self.grid.setHorizontalSpacing(12)
				self.grid.setVerticalSpacing(12)

			def add_card(self, c: QFrame):
				self.cards.append(c)
				self.grid.addWidget(c)

			def relayout(self):
				while self.grid.count():
					item = self.grid.takeAt(0)
					if item and item.widget():
						self.grid.removeItem(item)
				w = max(self.width(), 1)
				cols = max(1, min(self.max_cols, w // (self.min_w + 20)))
				visible_cards = [c for c in self.cards if c.isVisible()]
				for i, c in enumerate(visible_cards):
					r = i // cols
					col = i % cols
					self.grid.addWidget(c, r, col)

			def resizeEvent(self, e):  # noqa: N802
				super().resizeEvent(e)
				self.relayout()

		class BundleDetailsPanel(QFrame):
			def __init__(self):
				super().__init__()
				self.setObjectName("bundleDetails")
				self.setVisible(False)
				self.current_bundle: str | None = None
				self.items: list[BundleItem] = []

				layout = QVBoxLayout(self)
				layout.setContentsMargins(20, 16, 20, 16)
				layout.setSpacing(10)

				header = QHBoxLayout()
				header.setContentsMargins(0, 0, 0, 0)
				header.setSpacing(8)
				self.title_lbl = QLabel("Bundle details")
				self.title_lbl.setObjectName("detailTitle")
				self.price_lbl = QLabel("")
				self.price_lbl.setObjectName("detailPrice")
				close_btn = QPushButton("Close")
				close_btn.setObjectName("detailClose")
				close_btn.clicked.connect(self.hide_panel)
				header.addWidget(self.title_lbl, 1)
				header.addWidget(self.price_lbl, 0, Qt.AlignRight)
				header.addWidget(close_btn, 0, Qt.AlignRight)
				layout.addLayout(header)

				self.message_lbl = QLabel("Select a bundle to view its contents.")
				self.message_lbl.setObjectName("subtle")
				layout.addWidget(self.message_lbl)

				self.scroll = QScrollArea()
				self.scroll.setWidgetResizable(True)
				self.scroll.setFrameShape(QFrame.NoFrame)
				layout.addWidget(self.scroll)

				self.content = QWidget()
				self.list_layout = QVBoxLayout(self.content)
				self.list_layout.setContentsMargins(0, 0, 0, 0)
				self.list_layout.setSpacing(8)
				self.scroll.setWidget(self.content)

			def hide_panel(self):
				self.setVisible(False)
				self.current_bundle = None

			def _clear_items(self):
				while self.list_layout.count():
					item = self.list_layout.takeAt(0)
					widget = item.widget()
					if widget is not None:
						widget.deleteLater()

			def show_bundle(self, bundle_name: str, base_price: int, discount_price: int, items: Sequence[BundleItem]):
				self.current_bundle = bundle_name
				self.title_lbl.setText(bundle_name)
				if base_price and discount_price and base_price > discount_price:
					self.price_lbl.setText(f"{fmt_num(discount_price)} VP (was {fmt_num(base_price)} VP)")
				elif discount_price:
					self.price_lbl.setText(f"{fmt_num(discount_price)} VP")
				elif base_price:
					self.price_lbl.setText(f"{fmt_num(base_price)} VP")
				else:
					self.price_lbl.setText("Price unavailable")

				self._clear_items()
				if not items:
					self.message_lbl.setText("No bundle contents are available.")
					self.message_lbl.show()
				else:
					self.message_lbl.hide()
					for entry in items:
						row = QFrame()
						row.setObjectName("detailRow")
						row_layout = QHBoxLayout(row)
						row_layout.setContentsMargins(14, 10, 14, 10)
						row_layout.setSpacing(14)

						icon = QLabel()
						icon.setFixedSize(120, 80)
						icon.setAlignment(Qt.AlignCenter)
						icon.setObjectName("detailIcon")
						pix = get_pixmap(entry.icon_url, 220, 120) if entry.icon_url else None
						if pix:
							scaled = pix.scaled(
								QSize(120, 80), Qt.KeepAspectRatio, Qt.SmoothTransformation
							)
							icon.setPixmap(scaled)
						row_layout.addWidget(icon, 0)

						info = QVBoxLayout()
						info.setContentsMargins(0, 0, 0, 0)
						info.setSpacing(4)
						name_lbl = QLabel(entry.name or "Unknown item")
						name_lbl.setObjectName("detailTitle")
						info.addWidget(name_lbl)

						meta_bits = [entry.item_type]
						meta_lbl = QLabel(" - ".join(bit for bit in meta_bits if bit))
						meta_lbl.setObjectName("detailMeta")
						info.addWidget(meta_lbl)

						price_lbl = QLabel(f"{fmt_num(entry.cost)} VP")
						price_lbl.setObjectName("detailMeta")
						info.addWidget(price_lbl)

						if entry.rarity and entry.rarity[0] not in {"", "N/A"}:
							rarity_lbl = QLabel(entry.rarity[0])
							rarity_lbl.setObjectName("detailRarity")
							info.addWidget(rarity_lbl)

						row_layout.addLayout(info, 1)
						self.list_layout.addWidget(row)

				self.setVisible(True)

		class ShopWindow(QMainWindow):
			def __init__(self):
				super().__init__()
				self.setWindowTitle("Zoro Shop")
				self.setWindowIcon(QIcon("assets/Zoro.ico"))
				self.resize(1200, 800)
				self.dark = True
				self.refresh_requested = False
				self.allow_close = False
				self.tray = None

				# Central scroll area
				central = QWidget()
				central_v = QVBoxLayout(central)
				central_v.setContentsMargins(0, 0, 0, 0)
				central_v.setSpacing(0)
				self.setCentralWidget(central)
				self.bundle_items = bundle_items

				# App bar
				appbar = QFrame()
				appbar.setObjectName("appbar")
				appbar_l = QHBoxLayout(appbar)
				appbar_l.setContentsMargins(16, 12, 16, 12)
				appbar_l.setSpacing(10)

				left = QWidget()
				left_l = QVBoxLayout(left)
				left_l.setContentsMargins(0, 0, 0, 0)
				left_l.setSpacing(2)
				title = QLabel("Zoro Shop")
				title.setObjectName("title")
				subtitle = QLabel(
					"Featured bundles, daily offers, and Night Market"
				)
				subtitle.setObjectName("subtitle")
				left_l.addWidget(title)
				left_l.addWidget(subtitle)
				appbar_l.addWidget(left, 1)

				# Wallet chips
				wallet = QWidget()
				wallet_l = QHBoxLayout(wallet)
				wallet_l.setContentsMargins(0, 0, 0, 0)
				wallet_l.setSpacing(8)

				def chip(icon_url: str, amt: int, tip: str) -> QFrame:
					ch = QFrame()
					ch.setObjectName("chip")
					ch_l = QHBoxLayout(ch)
					ch_l.setContentsMargins(10, 6, 10, 6)
					ch_l.setSpacing(6)
					pm = get_pixmap(icon_url, 18, 18)
					icon = QLabel()
					if pm:
						icon.setPixmap(pm)
					txt = QLabel(fmt_num(amt))
					ch_l.addWidget(icon)
					ch_l.addWidget(txt)
					ch.setToolTip(f"{tip}: {fmt_num(amt)}")
					return ch

				wallet_l.addWidget(chip(vp_icon, vp, "Valorant Points"))
				wallet_l.addWidget(chip(rp_icon, rp, "Radianite Points"))
				wallet_l.addWidget(chip(kc_icon, kc, "Kingdom Credits"))

				# Controls
				copy_btn = QPushButton("Copy summary")
				refresh_btn = QPushButton("Refresh")
				controls = QWidget()
				controls_l = QHBoxLayout(controls)
				controls_l.setContentsMargins(0, 0, 0, 0)
				controls_l.setSpacing(8)
				controls_l.addWidget(copy_btn)
				controls_l.addWidget(refresh_btn)

				def on_refresh():
					self.refresh_requested = True
					self.close()

				def build_summary_text() -> str:
					stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
					lines = [
						f"Zoro Valorant Shop - {stamp}",
						f"Wallet: {fmt_num(vp)} VP | {fmt_num(rp)} RP | {fmt_num(kc)} KC",
					]
					if current_bundles:
						lines.append("Featured Bundles:")
						for i, (name_uuid, _img) in enumerate(zip(current_bundles, bundles_images)):
							name, _ = name_uuid
							base, disc = bundle_prices[i] if i < len(bundle_prices) else (0, 0)
							if base and disc and base > disc:
								pct = int(round((base - disc) / float(base) * 100))
								lines.append(f" - {name}: {fmt_num(disc)} VP (-{pct}% from {fmt_num(base)} VP)")
							elif disc:
								lines.append(f" - {name}: {fmt_num(disc)} VP")
							elif base:
								lines.append(f" - {name}: {fmt_num(base)} VP")
					if skin_names:
						lines.append("Daily Offers:")
						for i, name in enumerate(skin_names):
							price = skin_prices[i] if i < len(skin_prices) else 0
							lines.append(f" - {name}: {fmt_num(price)} VP")
					if nm_offers:
						lines.append("Night Market:")
						for i, name in enumerate(nm_offers):
							base, disc = nm_prices[i] if i < len(nm_prices) else (0, 0)
							if base and disc and base > disc:
								pct = int(round((base - disc) / float(base) * 100))
								lines.append(f" - {name}: {fmt_num(disc)} VP (-{pct}% from {fmt_num(base)} VP)")
							elif disc:
								lines.append(f" - {name}: {fmt_num(disc)} VP")
							elif base:
								lines.append(f" - {name}: {fmt_num(base)} VP")
					return "\n".join(lines)

				def copy_summary():
					summary = build_summary_text()
					QApplication.clipboard().setText(summary)
					QToolTip.showText(QCursor.pos(), "Shop summary copied!")

				copy_btn.clicked.connect(copy_summary)
				refresh_btn.clicked.connect(on_refresh)
				appbar_l.addWidget(wallet, 0, Qt.AlignRight)
				appbar_l.addWidget(controls, 0, Qt.AlignRight)
				central_v.addWidget(appbar)

				self.dynamic_timers: list[dict[str, Any]] = []

				# Quick stats row
				stats = QFrame()
				stats.setObjectName("stats")
				stats_l = QHBoxLayout(stats)
				stats_l.setContentsMargins(20, 12, 20, 12)
				stats_l.setSpacing(12)

				def stat_card(title: str, value: str, detail: str) -> tuple[QFrame, QLabel, QLabel]:
					card = QFrame()
					card.setObjectName("statCard")
					lay = QVBoxLayout(card)
					lay.setContentsMargins(14, 10, 14, 10)
					lay.setSpacing(2)
					title_lbl = QLabel(title.upper())
					title_lbl.setObjectName("statTitle")
					value_lbl = QLabel(value)
					value_lbl.setObjectName("statValue")
					detail_lbl = QLabel(detail)
					detail_lbl.setObjectName("statLabel")
					lay.addWidget(title_lbl)
					lay.addWidget(value_lbl)
					lay.addWidget(detail_lbl)
					return card, value_lbl, detail_lbl

				def register_timer(label: QLabel, duration: int | None, formatter: Callable[[int], str]):
					if duration is None:
						return
					try:
						remaining = max(0, int(duration))
					except Exception:
						return
					self.dynamic_timers.append(
						{"label": label, "remaining": remaining, "formatter": formatter}
					)

				def _duration_text(value: int | None) -> str:
					return format_duration(int(value)) if value else "Unknown"

				daily_value = _duration_text(skin_duration or bundle_duration or 0)
				daily_detail = f"{len(skin_names)} daily skins"
				daily_card, daily_value_lbl, _daily_detail_lbl = stat_card("Daily reset", daily_value, daily_detail)
				stats_l.addWidget(daily_card)
				register_timer(daily_value_lbl, skin_duration or bundle_duration, _format_timer_value)

				bundle_count = len(current_bundles)
				bundle_value = f"{bundle_count} active"
				if bundle_count:
					bundle_detail = f"Rotation in {_duration_text(bundle_duration)}"
				else:
					bundle_detail = "No featured bundles"
				bundle_card, _bundle_value_lbl, bundle_detail_lbl = stat_card("Bundles", bundle_value, bundle_detail)
				stats_l.addWidget(bundle_card)
				if bundle_count:
					register_timer(
						bundle_detail_lbl,
						bundle_duration,
						lambda secs: "Rotation in " + (_format_timer_value(secs) if secs > 0 else "ended"),
					)

				best_nm_pct = None
				best_nm_idx = None
				for idx, (base, disc) in enumerate(nm_prices):
					if base and disc and base > disc:
						pct = int(round((base - disc) / float(base) * 100))
						if best_nm_pct is None or pct > best_nm_pct:
							best_nm_pct = pct
							best_nm_idx = idx
				if best_nm_idx is not None and best_nm_pct is not None:
					nm_value = f"-{best_nm_pct}%"
					nm_detail = nm_offers[best_nm_idx]
					if nm_duration:
						nm_detail += f" - {_duration_text(nm_duration)} left"
				elif nm_offers:
					nm_value = "Open"
					nm_detail = f"{len(nm_offers)} offers live"
				else:
					nm_value = "Closed"
					nm_detail = "Night Market inactive"
				nm_card, _nm_value_lbl, nm_detail_lbl = stat_card("Night Market", nm_value, nm_detail)
				stats_l.addWidget(nm_card)
				if best_nm_idx is not None and nm_duration:
					register_timer(
						nm_detail_lbl,
						nm_duration,
						lambda secs, prefix=nm_offers[best_nm_idx]: (
							f"{prefix} - {_format_timer_value(secs)} left" if secs > 0 else f"{prefix} - expired"
						),
					)
				stats_l.addStretch(1)
				central_v.addWidget(stats)

				# Scroll area content
				scroll = QScrollArea()
				scroll.setWidgetResizable(True)
				viewport = QWidget()
				vbox = QVBoxLayout(viewport)
				vbox.setContentsMargins(20, 12, 20, 12)
				vbox.setSpacing(16)
				scroll.setWidget(viewport)
				central_v.addWidget(scroll, 1)

				self.details_panel = BundleDetailsPanel()
				self.details_panel.hide_panel()
				central_v.addWidget(self.details_panel)

				# Section helper
				self.section_timers: list[tuple[QLabel, int]] = []

				def add_section(title_text: str, subtitle_text: str | None,
				                duration: int | None,
				                min_w: int, max_cols: int,
				                trailing_widget: QWidget | None = None) -> tuple[CardsGrid, QLabel | None]:
					header = QWidget()
					h = QHBoxLayout(header)
					h.setContentsMargins(0, 0, 0, 0)
					h.setSpacing(8)
					t = QLabel(title_text)
					t.setObjectName("section")
					h.addWidget(t)
					if subtitle_text:
						sub = QLabel(subtitle_text)
						sub.setObjectName("subtle")
						h.addWidget(sub)
					h.addStretch(1)
					timer_lbl = None
					if duration is not None:
						timer_lbl = QLabel(
							f"Expires in: {format_duration(duration)}"
						)
						timer_lbl.setObjectName("timer")
						h.addWidget(timer_lbl)
						self.section_timers.append((timer_lbl, int(duration)))
					if trailing_widget is not None:
						h.addWidget(trailing_widget)
					vbox.addWidget(header)
					grid = CardsGrid(min_w=min_w, max_cols=max_cols)
					vbox.addWidget(grid)
					return grid, timer_lbl

				# Card factory
				def make_card(width: int) -> QFrame:
					c = QFrame()
					c.setObjectName("card")
					c.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
					lay = QVBoxLayout(c)
					lay.setContentsMargins(12, 12, 12, 12)
					lay.setSpacing(6)
					return c

				def create_art_label(img_url: str, target_w: int, target_h: int, object_name: str) -> QLabel:
					label = QLabel()
					label.setObjectName(object_name)
					label.setAlignment(Qt.AlignCenter)
					label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
					label.setFixedHeight(target_h)
					if target_w:
						label.setMinimumWidth(min(target_w, 120))
					pm = get_pixmap(img_url, target_w, target_h)
					if pm:
						label.setProperty("empty", False)
						label.setPixmap(
							pm.scaled(target_w, target_h, Qt.KeepAspectRatio, Qt.SmoothTransformation)
						)
					else:
						label.setText("Preview unavailable")
						label.setProperty("empty", True)
					return label

				def build_rarity_badge(
						rarity_info: tuple[str, str, str] | None,
				) -> tuple[QFrame | None, str]:
					if not rarity_info:
						return None, ""
					r_name, r_hex, r_icon = rarity_info
					name = (r_name or "").strip()
					if not name:
						return None, ""
					badge = QFrame()
					badge.setObjectName("rarityBadge")
					badge.setFixedHeight(26)
					bg_color = _darken_hex(r_hex or ACCENT, 0.7)
					badge.setStyleSheet(f"background-color: {bg_color}; border-radius: 13px;")
					badge_l = QHBoxLayout(badge)
					badge_l.setContentsMargins(10, 0, 10, 0)
					badge_l.setSpacing(6)
					if r_icon:
						icon_pm = get_pixmap(r_icon, 16, 16)
						if icon_pm:
							icon_lbl = QLabel()
							icon_lbl.setObjectName("rarityIcon")
							icon_lbl.setPixmap(icon_pm)
							icon_lbl.setFixedSize(16, 16)
							icon_lbl.setAlignment(Qt.AlignCenter)
							badge_l.addWidget(icon_lbl)
					text_lbl = QLabel(name)
					text_lbl.setObjectName("rarityText")
					badge_l.addWidget(text_lbl)
					return badge, name.lower()

				# Bundles
				if current_bundles:
					g_b, _tb = add_section(
						"Featured Bundles", "Limited time offers",
						bundle_duration or 0, 440, 3
					)
					for i, (name_uuid, img_url) in enumerate(
							zip(current_bundles, bundles_images)):
						name, b_uuid = name_uuid
						base, disc = (
							bundle_prices[i] if i < len(bundle_prices) else (0, 0)
						)
						card = make_card(440)
						img = create_art_label(img_url, 420, 220, "bundleArt")
						card.layout().addWidget(img)
						title_lbl = QLabel(name)
						title_lbl.setObjectName("itemtitle")
						card.layout().addWidget(title_lbl)
						row = QWidget()
						row_l = QHBoxLayout(row)
						row_l.setContentsMargins(0, 0, 0, 0)
						row_l.setSpacing(6)
						base_lbl = QLabel(f"{fmt_num(base)} VP")
						base_lbl.setObjectName("strike")
						disc_lbl = QLabel(f"{fmt_num(disc)} VP")
						row_l.addWidget(base_lbl)
						row_l.addWidget(disc_lbl)
						if base and disc and base > disc:
							pct = int(round((base - disc) / float(base) * 100))
							pct_lbl = QLabel(f"-{pct}%")
							pct_lbl.setObjectName("pct")
							row_l.addWidget(pct_lbl)
						row_l.addStretch(1)
						card.layout().addWidget(row)
						card.setToolTip(f"{name}\nClick for contents")

						def _click(_e=None, bid=b_uuid, nm=name, b_price=base, d_price=disc):
							self.show_bundle_details(bid, nm, b_price, d_price)

						card.mouseReleaseEvent = _click  # type: ignore
						g_b.add_card(card)

				# Daily offers
				if skin_names:
					filter_bar = QWidget()
					filter_layout = QHBoxLayout(filter_bar)
					filter_layout.setContentsMargins(0, 0, 0, 0)
					filter_layout.setSpacing(6)
					rarity_combo = QComboBox()
					rarity_combo.setObjectName("rarityFilter")
					rarity_combo.addItem("All rarities", None)
					unique_rarities = sorted(
						{(r[0] or "").strip() for r in skin_rarity if r and (r[0] or "").strip()}
					)
					for rarity_name in unique_rarities:
						rarity_combo.addItem(rarity_name, rarity_name.lower())
					search_box = QLineEdit()
					search_box.setObjectName("search")
					search_box.setPlaceholderText("Search skins or weapons...")
					search_box.setClearButtonEnabled(True)
					search_box.setMinimumWidth(200)
					filter_layout.addWidget(rarity_combo)
					filter_layout.addWidget(search_box)
					g_s, _ts = add_section(
						"Daily Offers", None, skin_duration or 0, 260, 5, trailing_widget=filter_bar
					)
					daily_cards_meta: list[tuple[QFrame, str, str]] = []
					for i, (name, img_url) in enumerate(zip(skin_names, skin_images)):
						price = skin_prices[i] if i < len(skin_prices) else 0
						rarity = skin_rarity[i] if i < len(skin_rarity) else None
						video_url = skin_videos[i] if i < len(skin_videos) else ""
						card = make_card(260)
						rarity_display = (rarity[0] or "").strip() if rarity else ""
						badge, rarity_filter = build_rarity_badge(rarity)
						if badge:
							card.layout().addWidget(badge, 0)
						img = create_art_label(img_url, 260, 140, "itemArt")
						card.layout().addWidget(img)
						title_lbl = QLabel(name)
						title_lbl.setObjectName("itemtitle")
						price_lbl = QLabel(f"{fmt_num(price)} VP")
						price_lbl.setObjectName("priceLabel")
						card.layout().addWidget(title_lbl)
						card.layout().addWidget(price_lbl)
						if video_url and video_url.startswith(("http://", "https://")):
							preview_btn = QPushButton("Preview")
							preview_btn.setObjectName("ghost")
							preview_btn.clicked.connect(
								lambda _checked=False, link=video_url: QDesktopServices.openUrl(QUrl(link))
							)
							card.layout().addWidget(preview_btn)
						card.setToolTip(f"{name}\nPrice: {fmt_num(price)} VP")
						meta_text = f"{name} {rarity_display}".strip().lower()
						daily_cards_meta.append((card, meta_text, rarity_filter))
						g_s.add_card(card)

					def apply_daily_filters(_=None):
						text = search_box.text().strip().lower()
						selected_rarity = rarity_combo.currentData()
						for widget, meta_text, rarity_value in daily_cards_meta:
							match_text = not text or text in meta_text
							match_rarity = not selected_rarity or rarity_value == selected_rarity
							widget.setVisible(match_text and match_rarity)
						g_s.relayout()

					search_box.textChanged.connect(apply_daily_filters)
					rarity_combo.currentIndexChanged.connect(apply_daily_filters)
					apply_daily_filters()

				# Night Market
				if nm_offers:
					g_nm, _tn = add_section(
						"Night Market", "Discounted offers",
						nm_duration or 0, 340, 4
					)
					for i, name in enumerate(nm_offers):
						img_url = nm_images[i] if i < len(nm_images) else ""
						base, disc = (
							nm_prices[i] if i < len(nm_prices) else (0, 0)
						)
						card = make_card(340)
						img = create_art_label(img_url, 320, 160, "nightArt")
						card.layout().addWidget(img)
						title_lbl = QLabel(name)
						title_lbl.setObjectName("itemtitle")
						row = QWidget()
						row_l = QHBoxLayout(row)
						row_l.setContentsMargins(0, 0, 0, 0)
						row_l.setSpacing(6)
						base_lbl = QLabel(f"{fmt_num(base)} VP")
						base_lbl.setObjectName("strike")
						disc_lbl = QLabel(f"{fmt_num(disc)} VP")
						row_l.addWidget(base_lbl)
						row_l.addWidget(disc_lbl)
						if base and disc and base > disc:
							pct = int(round((base - disc) / float(base) * 100))
							pct_lbl = QLabel(f"-{pct}%")
							pct_lbl.setObjectName("pct")
							row_l.addWidget(pct_lbl)
						row_l.addStretch(1)
						card.layout().addWidget(title_lbl)
						card.layout().addWidget(row)
						card.setToolTip(
							f"{name}\nWas {fmt_num(base)} VP -> Now {fmt_num(disc)} VP"
						)
						g_nm.add_card(card)
				else:
					note = QLabel("Night Market is currently not available.")
					note.setObjectName("subtle")
					vbox.addWidget(note)

				# Footer
				stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				foot = QFrame()
				foot.setObjectName("footer")
				fl = QHBoxLayout(foot)
				fl.setContentsMargins(12, 6, 12, 6)
				fl.addStretch(1)
				fl.addWidget(QLabel(f"Last updated: {stamp}"))
				central_v.addWidget(foot)

				# Style application
				def apply_theme():
					bg = DARK_BG
					surf = DARK_SURFACE
					card_bg = DARK_CARD
					border = "#2C2F36"
					hover = "#2A2D33"
					chip = DARK_CARD
					fg = FG_LIGHT
					sub = "#B0B6BD"
					pct = ACCENT
					ss = f"""
					QMainWindow {{ background-color: {bg}; color: {fg}; }}
					QScrollArea {{ background-color: {bg}; border: none; }}
					QFrame#appbar {{ background-color: {surf}; }}
					QFrame#footer {{ background-color: {surf}; }}
					QLabel#title {{ font: 700 20px 'Segoe UI'; color: {fg}; }}
					QLabel#subtitle {{ color: {sub}; font: 10px 'Segoe UI'; }}
					QLabel#section {{ font: 700 16px 'Segoe UI'; color: {fg}; }}
					QLabel#subtle {{ color: {sub}; font: 10px 'Segoe UI'; }}
					QLabel#timer {{ color: {sub}; font: italic 10px 'Segoe UI'; }}
					QFrame#chip {{ background-color: {chip}; border-radius: 10px; }}
					QFrame#card {{
						background-color: {card_bg};
						border: 1px solid {border};
						border-radius: 12px;
					}}
					QFrame#card:hover {{ background-color: {hover}; }}
					QFrame#bundleDetails {{
						background-color: {surf};
						border-top: 1px solid {border};
					}}
					QFrame#detailRow {{
						background-color: {card_bg};
						border: 1px solid {border};
						border-radius: 10px;
					}}
					QLabel#detailTitle {{ font: 600 13px 'Segoe UI'; color: {fg}; }}
					QLabel#detailPrice {{ font: 600 12px 'Segoe UI'; color: {fg}; }}
					QLabel#detailMeta {{ color: {sub}; font: 11px 'Segoe UI'; }}
					QLabel#detailRarity {{ color: {pct}; font: 11px 'Segoe UI'; font-weight: 600; }}
					QLabel#strike {{ color: #E06B74; }}
					QLabel#pct    {{ color: {pct}; font-weight: 700; }}
					QLabel#itemtitle {{ font: 600 12px 'Segoe UI'; }}
					QFrame#stats {{ background-color: {surf}; border-bottom: 1px solid {border}; }}
					QFrame#statCard {{
						background-color: {card_bg};
						border: 1px solid {border};
						border-radius: 12px;
					}}
					QLabel#statTitle {{ color: {sub}; font: 600 10px 'Segoe UI'; letter-spacing: 0.08em; }}
					QLabel#statValue {{ color: {fg}; font: 700 20px 'Segoe UI'; }}
					QLabel#statLabel {{ color: {sub}; font: 11px 'Segoe UI'; }}
					QFrame#rarityBadge {{
						border-radius: 13px;
						min-height: 26px;
					}}
					QLabel#rarityText {{
						color: {FG_LIGHT};
						font: 600 11px 'Segoe UI';
					}}
					QLabel#priceLabel {{
						color: {fg};
						font: 600 13px 'Segoe UI';
					}}
					QLabel#itemArt, QLabel#bundleArt, QLabel#nightArt {{
						background-color: {surf};
						border-radius: 12px;
						padding: 6px;
					}}
					QLabel#itemArt[empty="true"],
					QLabel#bundleArt[empty="true"],
					QLabel#nightArt[empty="true"] {{
						color: {sub};
						font: italic 11px 'Segoe UI';
					}}
					QLineEdit#search {{
						background-color: {card_bg};
						border: 1px solid {border};
						border-radius: 8px;
						padding: 4px 8px;
						color: {fg};
						min-width: 200px;
					}}
					QComboBox#rarityFilter {{
						background-color: {card_bg};
						border: 1px solid {border};
						border-radius: 8px;
						padding: 2px 8px;
						color: {fg};
						min-width: 140px;
					}}
					QPushButton#ghost {{
						border: 1px solid {border};
						border-radius: 8px;
						background: transparent;
						color: {fg};
						padding: 4px 10px;
					}}
					QPushButton#ghost:hover {{
						border-color: {pct};
						color: {pct};
					}}
					QPushButton {{ padding: 6px 12px; }}
					"""
					self.setStyleSheet(ss)

				apply_theme()

				# Timers
				self.timer = QTimer(self)
				self.timer.setInterval(1000)
				self.timer.setTimerType(Qt.PreciseTimer)

				def tick():
					new_list: list[tuple[QLabel, int]] = []
					for lbl, remaining in self.section_timers:
						if remaining > 0:
							remaining -= 1
							lbl.setText(
								f"Expires in: {format_duration(int(remaining))}"
							)
						else:
							lbl.setText("Expired")
						new_list.append((lbl, remaining))
					self.section_timers = new_list
					for entry in self.dynamic_timers:
						lbl = entry.get("label")
						if lbl is None:
							continue
						remaining = entry.get("remaining", 0)
						if remaining > 0:
							remaining -= 1
						try:
							lbl.setText(entry["formatter"](max(remaining, 0)))
						except Exception:
							pass
						entry["remaining"] = remaining

				tick()
				self.timer.timeout.connect(tick)
				self.timer.start()

			def show_bundle_details(self, bundle_id: str, bundle_name: str, base_price: int, discount_price: int):
				if getattr(self, "details_panel", None) is None:
					return
				items = self.bundle_items.get(bundle_id) or []
				self.details_panel.show_bundle(bundle_name, base_price, discount_price, items)

			def closeEvent(self, event):  # noqa: N802
				# In no-console mode, minimize to system tray instead of exiting
				if getattr(self, "allow_close", False):
					return super().closeEvent(event)
				try:
					if self.tray is not None and isinstance(self.tray, QSystemTrayIcon):
						event.ignore()
						self.hide()
						try:
							self.tray.showMessage(
								"Zoro",
								"Running in system tray. Right-click to restore or exit.",
								QSystemTrayIcon.Information,
								3000,
							)
						except Exception:
							pass
						return
				except Exception:
					pass
				return super().closeEvent(event)

		app = QApplication.instance() or QApplication(sys.argv)
		win = ShopWindow()
		# System tray (for no-console or general convenience)
		if args.no_console or getattr(args, "_store_from_config", False):
			try:
				icon = QIcon("assets/Zoro.ico") if QIcon("assets/Zoro.ico").isNull() is False else QIcon()
				tray = QSystemTrayIcon(icon, win)
				menu = QMenu()
				act_show = menu.addAction("Show Shop")
				act_show.triggered.connect(lambda: (win.showNormal(), win.raise_(), win.activateWindow()))
				menu.addSeparator()
				act_show_console = menu.addAction("Show Console")
				act_show_console.triggered.connect(lambda: show_console())
				act_hide_console = menu.addAction("Hide Console")
				act_hide_console.triggered.connect(lambda: hide_console())
				menu.addSeparator()
				act_exit = menu.addAction("Exit")

				def _do_exit():
					win.allow_close = True
					app.quit()
					sys.exit()

				act_exit.triggered.connect(_do_exit)
				tray.setContextMenu(menu)
				tray.setToolTip("Zoro")
				tray.show()
				win.tray = tray

				def _on_tray_activated(reason):
					if reason == QSystemTrayIcon.Trigger:
						if win.isVisible():
							win.hide()
						else:
							win.showNormal()
							win.raise_()
							win.activateWindow()

				tray.activated.connect(_on_tray_activated)
			except Exception:
				pass

		win.show()
		app.exec()
		if win.refresh_requested:
			await self.run()


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
				"adr": 0.10,
				"multikill": 0.15,
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


def _coerce_stat_number(value: Any) -> float | None:
	"""Attempt to convert a stat value into a float."""
	if isinstance(value, (int, float)):
		return float(value)
	if isinstance(value, str):
		normalized = value.strip()
		if not normalized:
			return None
		if normalized.endswith("%"):
			normalized = normalized[:-1]
		try:
			return float(normalized)
		except ValueError:
			return None
	return None


def _format_stat_placeholder(value: Any) -> str:
	"""Return a safe fallback string for stats that cannot be colored."""
	if isinstance(value, str):
		normalized = value.strip()
		return normalized if normalized else "--"
	return "--"


def _colorize_stat_value(
		value: Any,
		*,
		good_threshold: float,
		decimals: int,
		suffix: str = "",
		min_valid: float | None = None,
) -> str:
	"""Format a numeric stat with red/green coloring based on the threshold."""
	numeric_value = _coerce_stat_number(value)
	if numeric_value is None:
		return _format_stat_placeholder(value)
	if min_valid is not None and numeric_value < min_valid:
		return _format_stat_placeholder("--")

	if decimals <= 0:
		display_value = str(int(round(numeric_value)))
	else:
		display_value = str(round(numeric_value, decimals))

	display_value = f"{display_value}{suffix}"
	color = "green" if numeric_value >= good_threshold else "red"
	return f"[{color}]{display_value}[/{color}]"


def colorize_kd_stat(value: Any) -> str:
	return _colorize_stat_value(value, good_threshold=0.90, decimals=2, min_valid=0.0)


def colorize_headshot_stat(value: Any) -> str:
	return _colorize_stat_value(value, good_threshold=20.0, decimals=0, suffix="%", min_valid=0.0)


def colorize_score_stat(value: Any) -> str:
	return _colorize_stat_value(value, good_threshold=50.0, decimals=0, min_valid=0.0)


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

	def save(self, parser: configparser.ConfigParser) -> None:
		"""Persist the provided configparser to disk using managed comments."""
		self._write_with_comments(parser)


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

	def normalize_default_menu_action(value: str) -> str:
		normalized = value.strip().lower()
		if normalized in VALID_MENU_ACTIONS:
			return normalized
		raise ConfigValidationError(
			"Value must be one of: manual, shop, loader."
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
					default=True,
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
				ConfigOption(
					key="default_menu_action",
					default="manual",
					description=(
						"Select what happens after login when you are idle.",
						"manual = always ask, shop = open the store viewer, loader = jump into the in-game loader.",
						"Default = manual.",
					),
					normalizer=normalize_default_menu_action,
				),
				ConfigOption(
					key="setup_completed",
					default=False,
					value_type="bool",
					description=(
						"Tracks whether the interactive setup wizard has been accepted.",
						"Automatically updated by the application.",
					),
				),
			),
		),
	)

	return ConfigManager(path, sections)


def refresh_runtime_preferences(config_main: configparser.SectionProxy) -> bool:
	"""Synchronize runtime globals from the configuration."""
	global DEFAULT_MENU_ACTION, SETUP_COMPLETED, DEBUG, STORE_ONLY_MODE
	default_action = config_main.get("default_menu_action", "manual").strip().lower()
	if default_action not in VALID_MENU_ACTIONS:
		default_action = "manual"
		config_main["default_menu_action"] = default_action
	DEFAULT_MENU_ACTION = default_action
	SETUP_COMPLETED = config_main.get("setup_completed", "false").strip().lower() == "true"
	debug_enabled = config_main.get("enable_debug_logging", "false").strip().lower() == "true"
	STORE_ONLY_MODE = config_main.get("start_in_store_mode", "false").strip().lower() == "true"
	if not CLI_DEBUG_OVERRIDE:
		DEBUG = debug_enabled
	return debug_enabled


def _apply_store_mode_override() -> None:
	"""Force store-only CLI behaviour when configured to auto-launch the shop."""
	if "args" not in globals():
		return
	try:
		current = getattr(args, "store", False)
		if STORE_ONLY_MODE:
			setattr(args, "store", True)
			setattr(args, "_store_from_config", True)
		else:
			setattr(args, "store", current)
			if hasattr(args, "_store_from_config"):
				delattr(args, "_store_from_config")
	except Exception:
		pass


def _print_setup_step(
		step_number: int, total_steps: int, title: str, description: Sequence[str] | str
) -> None:
	"""Render a consistent Rich panel for each setup step."""
	body = description if isinstance(description, str) else "\n".join(description)
	console.print(
		Panel.fit(
			body,
			title=f"Step {step_number}/{total_steps} | {title}",
			border_style="cyan",
		)
	)


def run_setup_wizard(
		config_manager: ConfigManager,
		config_parser: configparser.ConfigParser,
		*,
		game_modes: Mapping[str, str],
) -> None:
	"""Guide the user through the interactive setup workflow."""
	if not sys.stdin or not sys.stdin.isatty():
		raise RuntimeError("Interactive setup requires a terminal session.")
	clear_console()
	console.rule("[bold cyan]Initial Setup[/bold cyan]")
	disclaimer_text = "\n".join(f"- {line}" for line in DISCLAIMER_LINES)
	console.print(
		Panel(
			disclaimer_text,
			title="Disclaimer",
			border_style="red",
			subtitle="Read carefully before continuing",
		)
	)
	console.print(
		Panel.fit(
			"This wizard configures core behaviour and stores your preferences in config.ini.",
			border_style="blue",
			title="What to Expect",
		)
	)

	if not _prompt_bool("Do you understand and accept this disclaimer?", default=False):
		raise RuntimeError("Setup aborted because the disclaimer was not accepted.")

	config_main = config_parser["Main"]

	console.rule("[bold cyan]Preferences[/bold cyan]")
	console.print(
		"[bright_white]Answer the prompts below. Press enter to keep the suggested value in brackets.[/bright_white]"
	)
	total_steps = 7
	step_counter = 1

	def _bool_label(value: bool) -> str:
		return "Enabled" if value else "Disabled"

	current_match_count = int(config_main.get("amount_of_matches_for_player_stats", "10"))
	_print_setup_step(
		step_counter,
		total_steps,
		"Player statistics window",
		[
			f"Current: {current_match_count} matches",
			"Increasing this smooths stats but reacts slower to changes.",
		],
	)
	match_count = _prompt_int(
		"How many matches should be aggregated for player statistics?",
		default=current_match_count,
		minimum=1,
		maximum=20,
	)
	step_counter += 1

	current_mode_setting = config_main.get("stats_used_game_mode", "ALL").strip()
	default_mode_key = current_mode_setting.lower()
	if current_mode_setting.upper() in {"ALL", "SAME"}:
		default_mode_key = current_mode_setting.lower()
	mode_choices = {"all": "All queues", "same": "Matchmaking queue"}
	for code, label in sorted(game_modes.items()):
		mode_choices[code] = label
	mode_display = mode_choices.get(default_mode_key, current_mode_setting.upper())
	_print_setup_step(
		step_counter,
		total_steps,
		"Queue focus for statistics",
		[
			f"Current: {mode_display}",
			"Choose ALL for every match or SAME to follow the active queue.",
		],
	)
	selected_mode = _prompt_choice(
		"Which queue should player statistics use?",
		mode_choices,
		default_mode_key,
	)
	if selected_mode == "all":
		config_main["stats_used_game_mode"] = "ALL"
	elif selected_mode == "same":
		config_main["stats_used_game_mode"] = "SAME"
	else:
		config_main["stats_used_game_mode"] = selected_mode
	step_counter += 1

	use_rpc_default = config_main.get("use_discord_rich_presence", "false").strip().lower() == "true"
	_print_setup_step(
		step_counter,
		total_steps,
		"Discord Rich Presence",
		[
			f"Current: {_bool_label(use_rpc_default)}",
			"Publish your Valorant Zoro activity to your Discord profile.",
		],
	)
	use_rpc = _prompt_bool("Enable Discord Rich Presence?", default=use_rpc_default)
	step_counter += 1

	advanced_default = config_main.get("advanced_missing_agents", "false").strip().lower() == "true"
	_print_setup_step(
		step_counter,
		total_steps,
		"Advanced missing agent detection",
		[
			f"Current: {_bool_label(advanced_default)}",
			"Beta feature that highlights agents missing in pregame.",
		],
	)
	advanced_agents = _prompt_bool(
		"Enable advanced missing agent detection (beta)?",
		default=advanced_default,
	)
	step_counter += 1

	debug_default = config_main.get("enable_debug_logging", "false").strip().lower() == "true"
	_print_setup_step(
		step_counter,
		total_steps,
		"Verbose debug logging",
		[
			f"Current: {_bool_label(debug_default)}",
			"Helpful when troubleshooting API calls or support investigations.",
		],
	)
	debug_logging = _prompt_bool("Enable verbose debug logging?", default=debug_default)
	step_counter += 1

	menu_choices = {
		"manual": "Choose every time",
		"shop": "Launch Valorant Store viewer",
		"loader": "Start the in-game loader",
	}
	default_menu = config_main.get("default_menu_action", "manual").strip().lower()
	if default_menu not in menu_choices:
		default_menu = "manual"
	_print_setup_step(
		step_counter,
		total_steps,
		"Idle action after login",
		[
			f"Current: {menu_choices[default_menu]}",
			"Pick what the client should do when you reach the main menu.",
		],
	)
	selected_menu_action = _prompt_choice(
		"What should happen after login when idle?",
		menu_choices,
		default_menu,
	)
	step_counter += 1

	config_main["amount_of_matches_for_player_stats"] = str(match_count)
	config_main["advanced_missing_agents"] = "true" if advanced_agents else "false"
	config_main["use_discord_rich_presence"] = "true" if use_rpc else "false"
	config_main["enable_debug_logging"] = "true" if debug_logging else "false"
	config_main["default_menu_action"] = selected_menu_action
	config_main["setup_completed"] = "true"

	config_manager.save(config_parser)
	refresh_runtime_preferences(config_main)
	_apply_store_mode_override()

	mode_summary_label = mode_choices.get(selected_mode, selected_mode.upper())
	summary_table = Table(
		title="Saved Preferences",
		box=box.SIMPLE_HEAD,
		show_header=True,
		header_style="bold",
	)
	summary_table.add_column("Setting", style="cyan", no_wrap=True)
	summary_table.add_column("Value", style="bright_white")
	summary_table.add_row("Player stats matches", str(match_count))
	summary_table.add_row("Stats queue", mode_summary_label)
	summary_table.add_row("Discord Rich Presence", _bool_label(use_rpc))
	summary_table.add_row("Advanced missing agents", _bool_label(advanced_agents))
	summary_table.add_row("Debug logging", _bool_label(debug_logging))
	summary_table.add_row("Idle action", menu_choices[selected_menu_action])

	console.print(summary_table)
	console.print(
		Panel(
			"Setup complete! Review the summary above. Re-run this wizard anytime with the --setup flag or from the main menu.",
			style="bold green",
		)
	)


CONFIG_MANAGER: Optional[ConfigManager] = None
CONFIG: Optional[configparser.ConfigParser] = None


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


@lru_cache(maxsize=999)
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
	"Omen": "Both",
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
	session = Session()
	retry = Retry(
		total=2,  # Total number of retries
		read=3,  # Number of retries on read errors
		connect=2,  # Number of retries on connection errors
		backoff_factor=1,  # Backoff factor to apply between attempts
		status_forcelist=[500, 502, 503, 504]  # Retry on these status codes
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


def _build_match_history_query(gamemode: str | None) -> tuple[str, str]:
	"""
	Compute the match-history query suffix and human-readable queue filter label.
	"""
	stats_used_game_mode = config_main.get("stats_used_game_mode", "ALL").lower()
	search = ""
	if stats_used_game_mode != "all":
		if stats_used_game_mode == "same" and gamemode is not None:
			search = f"&queue={gamemode}"
		elif stats_used_game_mode != "same":
			search = f"&queue={stats_used_game_mode}"

	queue_filter = search.split("=")[-1] if search else "all"
	return search, queue_filter


def get_all_agents_list() -> tuple[list[dict[str, str]], dict[str, str]] | None:
	all_agents = []
	r = api_request("GET", "https://valorant-api.com/v1/agents?isPlayableCharacter=true")
	if r.status_code == 200:
		# Format again...
		for agent in r.json()["data"]:
			data = {"name": agent.get("displayName"), "uuid": agent.get("uuid"),
			        "baseContent": agent.get("isBaseContent")}
			all_agents.append(data)
		agents_by_uuid = {agent["uuid"]: agent["name"] for agent in all_agents}
		return all_agents, agents_by_uuid
	else:
		print(r.status_code)
	return None


def get_owned_agents() -> list[dict[str, str]] | list:
	r = api_request("GET",
	                f"https://pd.na.a.pvp.net/store/v1/entitlements/{val_uuid}/01bb38e1-da47-4e6a-9b3d-945fe4655707",
	                headers=internal_api_headers)
	if r.status_code == 200:
		all_owned_agents = []
		all_agents, all_agents_by_uuid = get_all_agents_list()
		# Format request
		for owned_agent in r.json()["Entitlements"]:
			agent_id = owned_agent["ItemID"]
			if all_agents_by_uuid.get(agent_id, None) is not None:
				all_owned_agents.append({"name": str(all_agents_by_uuid.get(agent_id)), "uuid": str(agent_id)})
		# Add all free agents
		missing_agents = []
		for agents in all_agents:
			if agents["baseContent"]:
				missing_agents.append({"name": agents["name"], "uuid": agents["uuid"]})
		all_owned_agents.extend(missing_agents)
		return all_owned_agents
	return []


def select_agent(agent_uuid: str) -> bool:
	try:
		if get_user_current_state(val_uuid) == 3:
			r = api_request("GET", f"https://glz-na-1.na.a.pvp.net/pregame/v1/players/{val_uuid}",
			                headers=internal_api_headers)
			if r.status_code == 200:
				match_id = r.json()["MatchID"]
				return_code = api_request("POST",
				                          f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{match_id}/select/{agent_uuid}",
				                          headers=internal_api_headers)
				if return_code.status_code == 200:
					return True
				else:
					logger.warning(f"Error selecting agent", context={"match_id": match_id, "agent_uuid": agent_uuid,
					                                                  "return_data": return_code.json()})
			else:
				logger.info("Error with select_agent, called without being in pregame",
				            context={"return_data": r.json()})
		else:
			logger.info("Error with select_agent, called without state being in pregame")
		return False
	except Exception as e:
		logger.error("Error with select_agent", exc_info=e)
		return False


def get_player_data_from_uuid(user_id: str, cache: dict | None, platform: str = "PC", gamemode: str = None):
	global PLAYER_STATS_CACHE, PLAYER_STATS_PARTY_CACHE, PLAYER_STATS_CACHE_EXPIRY

	user_id = str(user_id)
	if cache is None:
		cache = PLAYER_STATS_CACHE.copy()

	def _store_cache(
			stats_entry: PlayerStatsTuple,
			parties: dict[str, list[str]],
			ttl: float = PLAYER_STATS_CACHE_TTL,
			metadata: Optional[Mapping[str, Any]] = None,
	):
		cache[user_id] = stats_entry
		PLAYER_STATS_CACHE[user_id] = stats_entry
		PLAYER_STATS_PARTY_CACHE[user_id] = parties
		PLAYER_STATS_CACHE_EXPIRY[user_id] = time.time() + ttl
		context = {
			"player_id": user_id,
			"party_groups": len(parties),
			"ttl_seconds": ttl,
		}
		if metadata:
			context.update(metadata)
		log_debug_event("player_stats_cache_update", "Stored player stats snapshot", **context)
		return parties, cache

	current_time = time.time()
	cached_entry = cache.get(user_id)
	if cached_entry is not None:
		expiry_at = PLAYER_STATS_CACHE_EXPIRY.get(user_id)
		if expiry_at is None or expiry_at > current_time:
			ttl_remaining = None if expiry_at is None else round(expiry_at - current_time, 1)
			log_debug_event(
				"player_stats_cache_hit",
				"Serving cached player stats",
				player_id=user_id,
				ttl_remaining=ttl_remaining,
			)
			return PLAYER_STATS_PARTY_CACHE.get(user_id, {}), cache
		log_debug_event(
			"player_stats_cache_expired",
			"Cached player stats expired; refreshing",
			player_id=user_id,
			expired_by=round(current_time - expiry_at, 1) if expiry_at else None,
		)
	else:
		log_debug_event("player_stats_cache_miss", "Player stats missing from cache", player_id=user_id)

	kills = 0
	deaths = 0
	wins: list[str] = []
	partyIDs: dict[str, list[str]] = {}
	headshot: list[int] = []
	search = ""

	try:
		search, queue_filter = _build_match_history_query(gamemode)

		headers = internal_api_headers if platform == "PC" else internal_api_headers_console
		url = f"https://pd.na.a.pvp.net/match-history/v1/history/{user_id}?endIndex={int(config_main.get('amount_of_matches_for_player_stats', '10'))}{search}"

		log_debug_event(
			"player_stats_fetch_start",
			"Fetching recent match history for player stats",
			player_id=user_id,
			platform=platform,
			queue_filter=queue_filter,
		)

		response = api_request("GET", url, headers=headers)
		history = response.json().get("History", [])

		if not history:
			return _store_cache(
				(-1, ['No Matches'], -1, -1),
				{},
				metadata={"reason": "no_match_history", "queue_filter": queue_filter},
			)

		save_match_data = None
		match_scores: list[float] = []
		for history_entry in history:
			# time.sleep(3)
			match_id = history_entry["MatchID"]
			match_data = get_match_details(match_id, platform)

			if match_data is None:
				continue  # Skip if match data couldn't be retrieved

			player_data = match_data.get("players", [])
			performance = ValorantPerformanceScorer()
			for match in player_data:
				if str(match["subject"]) == user_id:
					party_id = match["partyId"]

					if save_match_data is None:
						if party_id not in partyIDs:
							partyIDs[party_id] = [match["subject"]]
						elif match["subject"] not in partyIDs[party_id]:
							partyIDs[party_id].append(match["subject"])
						save_match_data = player_data

					team = match["teamId"]
					game_team_id = match_data["teams"][0]["teamId"]
					won = match_data["teams"][0]["won"] if game_team_id == team else match_data["teams"][1]["won"]
					wins.append("[green]W[/green]" if won else "[red]L[/red]")
					kills += match["stats"]["kills"]
					deaths += match["stats"]["deaths"]

					performance.prepare(match_data)
					score = performance.score_player(user_id)[0]
					match_scores.append(score)

			headshot_data = get_headshot_percent(match_data)
			user_headshot = headshot_data.get(user_id)
			if user_headshot is not None:
				headshot.append(round(user_headshot))

		avg_score = sum(match_scores) / len(match_scores) if match_scores else 0
		avg_headshot = sum(headshot) / len(headshot) if headshot else 0

		kd_ratio = calculate_kd(kills, deaths)
		try:
			stats_entry: PlayerStatsTuple = (kd_ratio, wins, round(avg_headshot), avg_score)
			return _store_cache(
				stats_entry,
				partyIDs,
				metadata={
					"matches_considered": len(history),
					"headshot_samples": len(headshot),
					"queue_filter": queue_filter,
				},
			)
		except ReferenceError:
			logger.log(2, "get_player_data_from_uuid ReferenceError on avg_headshot | avg_score")
			stats_entry = (kd_ratio, wins, 0, avg_score)
			return _store_cache(stats_entry, partyIDs, metadata={"fallback": "avg_headshot"})

	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
		return _store_cache(
			(-1, ['Error'], -1, -1),
			{},
			ttl=min(PLAYER_STATS_CACHE_TTL, 60),
			metadata={"reason": "exception", "player_id": user_id},
		)


def _resolve_queue_name(queue_id: str | None) -> str:
	if not queue_id:
		return "Unknown"
	queue_key = str(queue_id).lower()
	if queue_key == "null":
		return "Unknown"
	return GAME_MODES.get(queue_key, str(queue_id).capitalize())


def _coerce_datetime_from_millis(epoch_ms: Any) -> datetime | None:
	try:
		return datetime.fromtimestamp(int(epoch_ms) / 1000)
	except (TypeError, ValueError, OSError):
		return None


def _relative_time_label(event_at: datetime | None) -> str:
	if event_at is None:
		return "--"
	diff = datetime.now() - event_at
	if diff < timedelta(minutes=1):
		return "just now"
	if diff < timedelta(hours=1):
		minutes = int(diff.total_seconds() // 60)
		return f"{minutes}m ago"
	if diff < timedelta(days=1):
		hours = int(diff.total_seconds() // 3600)
		return f"{hours}h ago"
	days = diff.days
	return f"{days}d ago"


def _determine_match_result(teams: Sequence[Mapping[str, Any]], player_team: str | None) -> tuple[str, int, int]:
	result = "Unknown"
	team_rounds = 0
	opp_rounds = 0

	for team in teams:
		rounds = int(team.get("roundsWon", 0))
		if player_team and team.get("teamId") == player_team:
			team_rounds = rounds
			if team.get("won") is True:
				result = "Win"
			elif team.get("won") is False:
				result = "Loss"
		else:
			opp_rounds = rounds

	if result == "Unknown" and team_rounds == opp_rounds and team_rounds > 0:
		result = "Draw"
	return result, team_rounds, opp_rounds


def _build_zoro_entry_from_match(player_id: str, match_data: dict[str, Any], match_id: str) -> ZoroScoreEntry | None:
	player_entry = next((p for p in match_data.get("players", []) if str(p.get("subject")) == player_id), None)
	if player_entry is None:
		return None

	scorer = ValorantPerformanceScorer()
	scorer.prepare(match_data)
	score, breakdown = scorer.score_player(player_id, explain=True)

	stats = player_entry.get("stats", {})
	kills = int(stats.get("kills", 0))
	deaths = int(stats.get("deaths", 0))
	kd_ratio = calculate_kd(kills, deaths)

	map_name = get_mapdata_from_id(match_data.get("matchInfo", {}).get("mapId", "")) or "Unknown"
	queue_name = _resolve_queue_name(match_data.get("matchInfo", {}).get("queueID"))
	agent_name = get_agent_data_from_id(player_entry.get("characterId", "")) or "Unknown"

	teams = match_data.get("teams", [])
	result, team_rounds, opp_rounds = _determine_match_result(teams, player_entry.get("teamId"))
	rounds_played = match_data.get("matchInfo", {}).get("roundCount")
	if rounds_played is None and teams:
		rounds_played = sum(int(team.get("roundsWon", 0)) for team in teams)
	if rounds_played is None:
		rounds_played = 0

	headshot_percent = get_headshot_percent(match_data).get(player_id)

	started_at = _coerce_datetime_from_millis(match_data.get("matchInfo", {}).get("gameStartMillis"))

	return ZoroScoreEntry(
		match_id=str(match_id),
		started_at=started_at,
		map_name=map_name,
		queue_name=queue_name,
		agent_name=agent_name,
		result=result,
		team_rounds=team_rounds,
		opponent_rounds=opp_rounds,
		rounds_played=int(rounds_played),
		kills=kills,
		deaths=deaths,
		kd_ratio=kd_ratio,
		headshot_percent=headshot_percent,
		score=round(score, 2),
		breakdown=breakdown or {},
	)


def build_zoro_score_entries(
		player_id: str,
		*,
		platform: str = "PC",
		match_limit: int | None = None,
		gamemode: str | None = None,
) -> list[ZoroScoreEntry]:
	if match_limit is None:
		try:
			match_limit = int(config_main.get("scorecard_match_limit", "5"))
		except (TypeError, ValueError):
			match_limit = 5

	match_limit = max(1, min(match_limit, 10))
	query_suffix, queue_filter = _build_match_history_query(gamemode)
	headers = internal_api_headers if platform.upper() == "PC" else internal_api_headers_console
	url = f"https://pd.na.a.pvp.net/match-history/v1/history/{player_id}?endIndex={match_limit}{query_suffix}"

	log_debug_event(
		"zoro_scorecard_fetch_begin",
		"Fetching Zoro scorecard entries",
		player_id=player_id,
		limit=match_limit,
		queue_filter=queue_filter,
		platform=platform,
	)

	response = api_request("GET", url, headers=headers)
	if response.status_code != 200:
		logger.log(2, f"Failed to fetch scorecard history for {player_id}: {response.status_code}")
		return []

	history = response.json().get("History", [])
	entries: list[ZoroScoreEntry] = []
	for history_entry in history[:match_limit]:
		match_id = history_entry.get("MatchID")
		if not match_id:
			continue
		match_data = get_match_details(match_id, platform)
		if not match_data:
			continue
		entry = _build_zoro_entry_from_match(str(player_id), match_data, match_id)
		if entry:
			entries.append(entry)

	log_debug_event(
		"zoro_scorecard_fetch_complete",
		"Fetched scorecard entries",
		player_id=player_id,
		entry_count=len(entries),
	)
	return entries


def _summarize_component_details(component: Mapping[str, Any]) -> str:
	parts: list[str] = []
	for key, value in component.items():
		if key in {"score", "weight"}:
			continue
		if isinstance(value, float):
			parts.append(f"{key}={round(value, 2)}")
		else:
			parts.append(f"{key}={value}")
	return ", ".join(parts) if parts else "--"


def _render_breakdown_panel(entry: ZoroScoreEntry, index: int) -> Panel:
	breakdown = entry.breakdown or {}
	components = breakdown.get("components", {})

	component_table = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
	component_table.add_column("Component", style="magenta")
	component_table.add_column("Score", style="green")
	component_table.add_column("Weight", style="cyan")
	component_table.add_column("Details", style="white")

	if components:
		for name, data in components.items():
			weight_value = data.get("weight", 0)
			try:
				weight_text = str(round(float(weight_value), 2))
			except (TypeError, ValueError):
				weight_text = "--"
			component_table.add_row(
				name.title(),
				str(data.get("score", "--")),
				weight_text,
				_summarize_component_details(data),
			)
	else:
		component_table.add_row("--", "--", "--", "No breakdown data.")

	meta_line = Text(
		f"Base {breakdown.get('base_score', '--')}  •  Penalty {breakdown.get('penalty', '--')}",
		style="dim",
	)

	return Panel(
		Group(meta_line, component_table),
		title=f"Match {index} breakdown — {entry.map_name}",
		border_style="grey50",
	)


def render_zoro_scorecard(
		player_label: str,
		entries: Sequence[ZoroScoreEntry],
		*,
		show_breakdown: bool = False,
) -> Panel:
	title = f"{player_label} — Zoro scorecard"
	if not entries:
		return Panel(
			"[dim]No recent matches available for this player.[/dim]",
			title=title,
			border_style="magenta",
		)

	table = Table(
		show_header=True,
		header_style="bold magenta",
		title=None,
		expand=True,
	)
	table.add_column("#", justify="center", style="dim", width=3)
	table.add_column("When", justify="center")
	table.add_column("Result", justify="center")
	table.add_column("Score", justify="center")
	table.add_column("Agent", justify="center")
	table.add_column("K/D", justify="center")
	table.add_column("HS%", justify="center")
	table.add_column("Map / Queue", justify="left")

	for idx, entry in enumerate(entries, start=1):
		if entry.result == "Win":
			result_color = "green"
		elif entry.result == "Loss":
			result_color = "red"
		else:
			result_color = "yellow"
		result_text = f"[{result_color}]{entry.result} {entry.team_rounds}-{entry.opponent_rounds}[/{result_color}]"
		score_text = colorize_score_stat(entry.score)
		kd_text = colorize_kd_stat(entry.kd_ratio)
		if entry.headshot_percent is None:
			hs_text = "--"
		else:
			hs_text = colorize_headshot_stat(entry.headshot_percent)
		when_text = "--" if entry.started_at is None else f"{entry.started_at.strftime('%b %d %H:%M')} ({_relative_time_label(entry.started_at)})"
		map_text = f"{entry.map_name} ({entry.queue_name})"

		table.add_row(
			str(idx),
			when_text,
			result_text,
			score_text,
			entry.agent_name,
			kd_text,
			hs_text,
			map_text,
		)

	body: Sequence[Any]
	if show_breakdown:
		breakdown_panels = [_render_breakdown_panel(entry, idx) for idx, entry in enumerate(entries, start=1)]
		body = (table, *breakdown_panels)
	else:
		body = (table,)

	return Panel(
		Group(*body),
		title=title,
		border_style="magenta",
		padding=(0, 1),
	)


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
			"Radiant": "\033[38;5;220mR\033[38;5;229ma\033[38;5;231md\033[38;5;229mi\033[38;5;220ma\033[38;5;221mn\033[38;5;229mt"
			# Gold-to-white gradient to mimic the in-game badge
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

		# Handle "Radiant" with a multicolor effect
		if "Radiant" in rank_cap:
			return "[#f2c94c]R[/][#ffe39c]a[/][#fff8df]d[/][#ffe39c]i[/][#f2c94c]a[/][#edb949]n[/][#fff2c2]t[/]"

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
				5: Replay
				6: Unknown State
		"""
	disable_warnings()  # noqa
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
					# console.print(f"State: {0}")
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
					else:
						return -1
				elif state == "PREGAME":
					return 3
				elif state == "INGAME":
					return 4
				elif state == "REPLAY":
					return 5
				else:  # Unknown State
					return 6
	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
	if DEBUG:
		console.print(f"State of {puuid}: {-1}")
	return -1


def get_current_game_score(puuid: str) -> tuple[int, int]:
	disable_warnings()  # noqa
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
	log_debug_event("match_report_poll_begin", "Waiting for post-game data", match_id=match_id)
	poll_attempts = 0
	# Poll every 2.5 seconds until match data is available.
	while True:
		response = api_request("GET", f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}",
		                       headers=internal_api_headers)
		poll_attempts += 1
		if response.status_code == 200:
			match_data = response.json()
			break
		await asyncio.sleep(2.5)

	player_ids = [player.get("subject") for player in match_data.get("players", [])]
	invalidate_player_stats_cache(player_ids, reason=f"match_completed:{match_id}")
	log_info_event(
		"match_report_ready",
		"Post-game data ready",
		match_id=match_id,
		polls=poll_attempts,
		player_count=len(player_ids),
	)

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


async def run_in_game(cache: dict | None = None, partys: dict | None = None):
	if cache is None:
		cache = PLAYER_STATS_CACHE

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
	last_reported_state = None

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
			party_size=[party_size, 5],
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
			current_state = match_data.get("State")
			if current_state != last_reported_state:
				log_debug_event(
					"ingame_state_transition",
					"Detected in-game state change",
					match_id=match_id,
					state=current_state,
				)
				last_reported_state = current_state
			mode_name = "null"
			gamemode_name = "null"
			if match_data["State"] not in ("CLOSED", "POST_GAME"):
				map_id = match_data["MapID"]
				try:
					gamemode_name = str(match_data["MatchmakingData"]["QueueID"]).capitalize()
					mode_name = GAME_MODES.get(gamemode_name.lower(), gamemode_name)
				except TypeError:
					gamemode_name = match_data["ProvisioningFlow"]
					if gamemode_name == "ShootingRange":
						mode_name = "Shooting Range"
					elif gamemode_name == "ReplayNewPlayerExperience":
						mode_name = "Tutorial"
					elif gamemode_name == "CustomGame":
						mode_name = "Custom Game"
				map_name = get_mapdata_from_id(map_id)
				if map_name is None or map_name == "":
					map_name = "The Range"

				if config_main.get("use_discord_rich_presence", "").lower() == "true":
					RPC.update(
						state=f"In-Game",
						details=f"{map_name} | {mode_name.capitalize()} | {host_player_agent.capitalize() if host_player_agent is not None else ''}",
						large_image="valorant",
						large_text="Valorant Zoro",
						party_size=[party_size, 5],
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

				if not got_players:
					log_debug_event(
						"ingame_roster_initialized",
						"Hydrated live match roster",
						match_id=match_id,
						player_count=len(match_data["Players"]),
					)

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
					return colorize_kd_stat(value)

				def format_hs_value(value: Any) -> str:
					return colorize_headshot_stat(value)

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

				# ---------- Centered, table-less renderer ----------
				def _measure(markup: str) -> int:
					try:
						return console.measure(Text.from_markup(markup)).maximum
					except Exception:
						# Fallback to plain length if markup parsing fails
						return len(markup)

				def _level_markup(level_value: str, color: str) -> str:
					lv = level_value
					if lv in ("", "-", "--", "None"):
						lv = "--"
					return f"[{color}]LVL {lv}[/{color}]"

				def _agent_markup(agent_value: str) -> str:
					if agent_value in ("-", "--", "Unknown"):
						return agent_value
					return f"[italic]{agent_value}[/]"

				def _compute_widths(all_rows: list[dict[str, str]], color: str) -> dict[str, int]:
					widths = {k: 0 for k in ("party", "level", "rank", "player", "agent", "kd", "hs", "recent")}
					for row in all_rows:
						level_m = _level_markup(row["level"], color)
						values = {
							"party": row["party"],
							"level": level_m,
							"rank": get_rank_color(row["rank"], True),
							"player": row["player"],
							"agent": _agent_markup(row["agent"]),
							"kd": row["kd"],
							"hs": row["hs"],
							"recent": row["recent"],
						}
						for key, val in values.items():
							widths[key] = max(widths[key], _measure(val))
					return widths

				def _pad(markup: str, width: int) -> str:
					w = _measure(markup)
					pad = max(0, width - w)
					return markup + (" " * pad)

				def build_team_panel(rows: list[dict[str, str]], *, header_color: str, widths: dict[str, int],
				                     title: str, border_style: str) -> Panel:
					lines: list[str] = []
					for row in rows:
						level_m = _level_markup(row["level"], header_color)
						rank_m = get_rank_color(row["rank"], True)
						agent_m = _agent_markup(row["agent"])
						parts = [
							_pad(row["party"], widths["party"]),
							_pad(level_m, widths["level"]),
							_pad(rank_m, widths["rank"]),
							_pad(row["player"], widths["player"]),
							_pad(agent_m, widths["agent"]),
							_pad(row["kd"], widths["kd"]),
							_pad(row["hs"], widths["hs"]),
							_pad(row["recent"], widths["recent"]),
						]
						lines.append("  ".join(parts))
					block = Text.from_markup("\n".join(lines)) if lines else Text("")
					return Panel(Align.center(block), title=title, border_style=border_style, padding=(0, 1))

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

				# Shared widths across both sides for perfect lining
				all_rows = own_team_rows + opponent_rows
				# Compute widths using blue as the level color (only affects LVL styling width)
				widths = _compute_widths(all_rows, "blue")
				own_team_panel = build_team_panel(
					own_team_rows,
					header_color="blue",
					widths=widths,
					title=own_team_title,
					border_style="blue",
				)
				opponent_panel = build_team_panel(
					opponent_rows,
					header_color="red",
					widths=widths,
					title=opponent_title,
					border_style="red",
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
						log_info_event(
							"match_report_dispatch",
							"Dispatching post-game report task",
							match_id=match_id,
						)
						asyncio.create_task(match_report(match_id))
						match_report_dispatched = True
					exit_after_render = True
					exit_sleep = 1
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
					console.print(Align.center(Text.from_markup(render_header)))
					console.print(Columns([own_team_panel, opponent_panel], expand=True, equal=True))
					for line in scoreboard_lines:
						console.print(line)

				got_players = True

			else:
				if not match_report_dispatched:
					log_info_event(
						"match_report_dispatch",
						"Dispatching post-game report task",
						match_id=match_id,
					)
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
		canonical_party_id = str(party_id)
		incoming_members = [str(player) for player in new_players]
		if party_id in partys:
			# Add new players to the existing party, ensuring no duplicates
			existing_members = set(partys[party_id])
			partys[party_id].extend(incoming_members)
			partys[party_id] = list(dict.fromkeys(partys[party_id]))  # Preserve order while removing duplicates
			added_members = set(partys[party_id]) - existing_members
			if added_members:
				log_debug_event(
					"party_roster_extended",
					"Extended cached party roster",
					party_id=canonical_party_id,
					added=len(added_members),
					total=len(partys[party_id]),
				)
		else:
			# Create a new party with the new players
			partys[party_id] = incoming_members
			log_debug_event(
				"party_roster_created",
				"Cached new party roster",
				party_id=canonical_party_id,
				member_count=len(incoming_members),
			)
	return partys


def invalidate_player_stats_cache(player_ids: Iterable[str], *, reason: str | None = None) -> None:
	"""
	Ensure party/player stat snapshots are recomputed the next time they are requested.
	"""
	unique_ids = {str(pid) for pid in player_ids if pid}
	if not unique_ids:
		return

	removed = 0
	for player_id in unique_ids:
		if PLAYER_STATS_CACHE.pop(player_id, None) is not None:
			removed += 1
		PLAYER_STATS_PARTY_CACHE.pop(player_id, None)
		PLAYER_STATS_CACHE_EXPIRY.pop(player_id, None)

	context = {
		"candidates": len(unique_ids),
		"purged_entries": removed,
		"reason": reason or "unspecified",
	}
	if len(unique_ids) <= 5:
		context["players"] = list(unique_ids)
	log_debug_event("player_stats_cache_invalidated", "Invalidated cached player data", **context)


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

	cache = PLAYER_STATS_CACHE
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
			party_size=[party_size, 5],
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
				map_name = "null"
				mode_name = "null"

				map_id = match_data["MapID"]
				try:
					gamemode_name = match_data["ProvisioningFlow"]
					if gamemode_name == "ShootingRange":
						mode_name = "Shooting Range"
					elif gamemode_name == "ReplayNewPlayerExperience":
						mode_name = "Tutorial"
					elif gamemode_name == "CustomGame":
						mode_name = "Custom Game"
				except KeyError:
					mode_name = str(match_data["QueueID"]).capitalize()

				if mode_name.lower() in GAME_MODES.keys():
					mode_name = GAME_MODES[mode_name.lower()]

				map_name = get_mapdata_from_id(map_id)
				if map_name is None or map_name == "":
					map_name = "The Range"
				if config_main.get("use_discord_rich_presence", "").lower() == "true":
					RPC.update(
						state="In Agent Select",
						details=f"{map_name} | {mode_name.capitalize()}",
						start=int(time.time()),
						party_size=[party_size, 5],
					)

				got_map_and_gamemode = True

			buffer.write(f"[bright_white]{'=' * 30}[/bright_white]\n")
			buffer.write(f"[green]Map: {map_name}[/green]\n")
			buffer.write(f"[cyan]Game Mode: {str(mode_name).capitalize()}[/cyan]\n")
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
								details=f"{map_name} | {mode_name.capitalize()} | ({'H' if state.lower() == 'selected' else 'L'}) {agent_name.capitalize()}",
								party_size=[party_size, 5],
							)
				except Exception:
					agent_name = "None"

				if not got_rank:
					if "console" in mode_name.lower():
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
				kd_display = colorize_kd_stat(kd)
				headshot_display = colorize_headshot_stat(avg)
				score_display = colorize_score_stat(score)
				buffer.write(f"  Player KD: {kd_display} | Headshot: {headshot_display} | Score: {score_display}\n")
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
		except KeyError as e:
			logger.warning("Pregame KeyError",
			               context={"error": "".join(traceback.format_exception(type(e), e, e.__traceback__))})
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


def _parse_scorecard_command(command_text: str) -> tuple[list[str], bool, int | None]:
	tokens = command_text.split()
	if not tokens:
		return ["self"], False, None

	selectors: list[str] = []
	show_breakdown = False
	match_limit: int | None = None
	idx = 1  # Skip the command keyword
	while idx < len(tokens):
		token = tokens[idx]
		if token in {"-d", "--detail", "--details"}:
			show_breakdown = True
		elif token.startswith("--limit="):
			value = token.split("=", 1)[1]
			try:
				match_limit = int(value)
			except ValueError:
				pass
		elif token in {"-l", "--limit"}:
			idx += 1
			if idx < len(tokens):
				value = tokens[idx]
				try:
					match_limit = int(value)
				except ValueError:
					pass
		else:
			selectors.append(token)
		idx += 1

	if not selectors:
		selectors = ["self"]
	return selectors, show_breakdown, match_limit


async def _build_scorecard_roster(party_id: str | None) -> list[dict[str, Any]]:
	roster: list[dict[str, Any]] = []
	party_data: dict[str, Any] | None = None
	if party_id:
		try:
			party_data = await fetch_party_data(party_id)
		except Exception as exc:
			logger.log(2, f"Failed to fetch party data for scorecard: {exc}")

	if party_data:
		for member in party_data.get("Members", []):
			player_id = str(member.get("Subject"))
			if not player_id:
				continue
			player_name, _ = get_userdata_from_id(player_id, val_uuid)
			platform_type = str(member.get("PlatformInfo", {}).get("platformType", "PC")).upper()
			platform = "PC" if platform_type == "PC" else "CONSOLE"
			roster.append({
				"id": player_id,
				"label": player_name,
				"platform": platform,
				"is_self": player_id == str(val_uuid),
			})

	if not roster:
		player_name, _ = get_userdata_from_id(str(val_uuid), val_uuid)
		roster.append({
			"id": str(val_uuid),
			"label": player_name,
			"platform": "PC",
			"is_self": True,
		})
	return roster


def _resolve_scorecard_targets(selectors: Sequence[str], roster: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
	normalized = [sel.strip() for sel in selectors if sel.strip()]
	if not normalized:
		normalized = ["self"]

	if any(sel in {"all", "party"} for sel in normalized):
		return list(roster)

	resolved: list[dict[str, Any]] = []
	seen: set[str] = set()

	def _add(member: dict[str, Any]) -> None:
		player_id = member.get("id")
		if player_id and player_id not in seen:
			seen.add(player_id)
			resolved.append(member)

	for selector in normalized:
		if selector in {"self", "me"}:
			for member in roster:
				if member.get("is_self"):
					_add(member)
			continue

		if selector.isdigit():
			index = int(selector) - 1
			if 0 <= index < len(roster):
				_add(roster[index])
			continue

		for member in roster:
			label = member.get("label", "").lower()
			if selector in label:
				_add(member)

	if not resolved:
		for member in roster:
			if member.get("is_self"):
				_add(member)
				break
	return resolved


async def handle_scorecard_command(user_input: str, party_id: str | None) -> None:
	selectors, show_breakdown, match_limit = _parse_scorecard_command(user_input)
	roster = await _build_scorecard_roster(party_id)
	targets = _resolve_scorecard_targets(selectors, roster)

	if not targets:
		console.print("[red]No players available for scorecards.[/red]")
		return

	log_debug_event(
		"zoro_scorecard_command",
		"Rendering Zoro scorecards",
		target_count=len(targets),
		show_breakdown=show_breakdown,
		match_limit=match_limit,
	)

	console.print("[cyan]Fetching Zoro scorecards...[/cyan]")

	for target in targets:
		try:
			entries = await asyncio.to_thread(
				build_zoro_score_entries,
				target["id"],
				platform=target.get("platform", "PC"),
				match_limit=match_limit,
			)
		except Exception as exc:
			logger.log(2, f"Failed to build scorecard for {target.get('id')}: {exc}")
			entries = []
		console.print(
			render_zoro_scorecard(target.get("label", "Unknown Player"), entries, show_breakdown=show_breakdown))


async def listen_for_input(party_id: str = None):
	# FIXME | Fix the party_id can be None
	is_ready = True  # Start with the default ready state
	console.print("Enter a command: ")

	while True:
		try:
			user_input = await asyncio.to_thread(input, "> ")  # Non-blocking input
			user_input: str = user_input.strip().lower()

			if not user_input:
				continue

			command_root = user_input.split()[0]
			if command_root in SCORECARD_COMMANDS:
				await handle_scorecard_command(user_input, party_id)
				continue

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
				await with_spinner("Loading Store...", ValorantShop.run())
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
			elif user_input.lower() in ["random", "rand", "rando", "randomize", "pick", "agent"]:
				print("Randomizing agents...")
				all_owned_agents = get_owned_agents()
				random_agent = random.choice(all_owned_agents)
				# TODO | Check if taken
				if select_agent(random_agent['uuid']):
					console.print(f"Selected random agent: {random_agent['name']}")
				else:
					console.print(
						f"[light_gray]Issue with auto select[/light_gray]\nRandom agent: {random_agent['name']}")
			elif user_input.lower() in ["help", "h", "?"]:
				table = Table(show_header=False, box=None, show_lines=True, row_styles=["red", "dim"])
				table.add_row("r", "Toggle Ready State", end_section=True)
				table.add_row("clear/cls", "Clear Console", end_section=True)
				table.add_row("party", "Show Party Details", end_section=True)
				table.add_row(
					"score [player|all] [--limit N] [--detail]",
					"Show recent Zoro scores (supports names, indexes, or 'all').",
					end_section=True,
				)
				table.add_row("store", "Open Valorant Store Interface", end_section=True)
				table.add_row("quit/leave", "Quit Current Game", end_section=True)
				table.add_row("friends/f", "Show Friend States", end_section=True)
				table.add_row("random/rand/agent", "Randomize Agent", end_section=True)
				table.add_row("help/h/?", "Show This Help Message", end_section=True)
				console.print(table, style="cyan")
			if DEBUG:
				if user_input.lower()[0] == "-":
					exec(user_input[1:])  # TODO | Make a bit safer

		except asyncio.CancelledError:
			break
		except Exception as e:
			console.print(f"Error in input listener: {e}")
			break


async def get_friend_states() -> list[str]:
	disable_warnings()  # noqa
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
					5: Replay
					6: Unknown State
					"""
					if state == 0:
						continue
					state_str = "In Menu" if state == 1 else "Queueing" if state == 2 else "Pre-game" if state == 3 else "In-game" if state == 4 else "Replay" if state == 5 else "Unknown State" if state == 6 else "Unknown"
					full_str = f"{user['game_name']}#{user['game_tag']}: {state_str}"
					friend_list.append(full_str)
	except Exception:
		console.print("Please make sure Riot Client is open!")
		return []

	return friend_list


async def get_party(got_rank: dict = None):
	"""Fetch and display party details in Valorant."""
	global input_task, party_size
	buffer = StringIO()
	last_rendered_content = ""
	input_task = None  # Task for input handling
	got_rank = got_rank or {}
	prefetch_tasks: dict[str, asyncio.Task] = {}

	logger.log(3, "Loading Party... ")

	if config_main.get("use_discord_rich_presence", "").lower() == "true":
		RPC.update(
			state="In Menu",
			details="Valorant Match Tracker",
			large_image="valorant",
			large_text="Valorant Zoro",
			party_size=[party_size, 5],
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
					party_size=[party_size, 5],
					start=int(time.time()),
				)

		try:
			buffer.truncate(0)
			buffer.seek(0)

			# Build the dynamic party section (centered, no tables)
			party_id = await fetch_party_id()

			if party_id:
				party_data = await fetch_party_data(party_id)
				party_size = len(party_data["Members"])
				for player_id, task in list(prefetch_tasks.items()):
					if not task.done():
						continue

					await prefetch_tasks.pop(player_id, None)
					try:
						task.result()
					except asyncio.CancelledError:
						continue
					except Exception as exc:
						logger.log(2, f"Prefetch stats task failed for {player_id}: {exc}")

				if input_task is None or input_task.done():
					input_task = asyncio.create_task(listen_for_input(party_id))

				# Helpers for measurement and rendering
				def _measure(markup: str) -> int:
					try:
						return console.measure(Text.from_markup(markup)).maximum
					except Exception:
						return len(markup)

				def _rank_markup(rank: str) -> str:
					return get_rank_color(rank, True)

				def _level_markup(level_value: str) -> str:
					lv = level_value
					if lv in ("", "-", "--", "None"):
						lv = "--"
					return f"[cyan]LVL {lv}[/cyan]"

				def _score_markup(player_id: str) -> str:
					stats = PLAYER_STATS_CACHE.get(player_id)
					if stats is None:
						if player_id in prefetch_tasks:
							return "[yellow]Loading[/yellow]"
						return "[dim]--[/dim]"
					score_value = stats[3]
					score_markup = colorize_score_stat(score_value)
					if score_markup.strip().lower() == "loading":
						return "[yellow]Loading[/yellow]"
					if score_markup == "--":
						return "[dim]--[/dim]"
					return score_markup

				def _schedule_prefetch(member: dict[str, Any]) -> None:
					player_id = str(member.get("Subject", ""))
					if not player_id:
						return

					expiry_at = PLAYER_STATS_CACHE_EXPIRY.get(player_id, 0)
					if player_id in PLAYER_STATS_CACHE and expiry_at > time.time():
						return

					task = prefetch_tasks.get(player_id)
					if task and not task.done():
						return

					platform_info = member.get("PlatformInfo", {})
					platform_type = str(platform_info.get("platformType", "PC")).upper()
					platform = "PC" if platform_type == "PC" else "CONSOLE"

					async def _prefetch_async() -> None:
						def _prefetch_sync() -> None:
							try:
								with request_semaphore:
									get_player_data_from_uuid(player_id, PLAYER_STATS_CACHE, platform)
							except Exception as exc:
								logger.log(2, f"Failed to prefetch stats for {player_id}: {exc}")

						try:
							await asyncio.to_thread(_prefetch_sync)
						finally:
							prefetch_tasks.pop(player_id, None)  # noqa

					prefetch_tasks[player_id] = asyncio.create_task(_prefetch_async())

				# Collect rows (badges, level, rank, score, name)
				rows: list[dict[str, str]] = []
				for member in party_data.get("Members", []):
					member_id = str(member["Subject"])
					_schedule_prefetch(member)
					player_name, is_user = get_userdata_from_id(member_id, val_uuid)
					if member_id in ROLE_PUUID_LIST:
						role: list[str] | None = ROLE_PUUID_LIST.get(member_id, None)
						if role is not None:
							player_name += f" {str(b64decode(role[0].encode()).decode())}"
					is_leader = member.get("IsOwner", False)
					player_lvl = str(member["PlayerIdentity"].get("AccountLevel", "-1"))

					badges: list[str] = []
					if is_leader:
						badges.append("[red]LEADER[/red]")
					if is_user:
						badges.append(SELF_BADGE_RICH)

					if member_id not in got_rank:
						player_rank_str = _rank_markup(get_rank_from_uuid(member_id))
						got_rank[member_id] = player_rank_str
					else:
						player_rank_str = got_rank[member_id]

					score_markup = _score_markup(member_id)

					rows.append({
						"badges": " ".join(badges),
						"level": _level_markup(player_lvl),
						"rank": player_rank_str,
						"score": score_markup,
						"name": player_name,
					})

				# Compute widths across rows
				widths = {k: 0 for k in ("badges", "level", "rank", "score", "name")}
				for r in rows:
					for key in widths:
						widths[key] = max(widths[key], _measure(r[key]))

				# Ensure minimal badge width using the header name
				widths["badges"] = max(widths["badges"], _measure("[dim]BADGES[/dim]"))
				widths["score"] = max(widths["score"], _measure("[dim]SCORE[/dim]"))

				# Render header and block lines
				line_parts: list[str] = []
				head_parts = [
					"[dim]BADGES[/dim]",
					"[dim]LVL[/dim]",
					"[dim]RANK[/dim]",
					"[dim]SCORE[/dim]",
					"[dim]PLAYER[/dim]",
				]

				# Helper to pad a cell by markup width
				def _pad_cell(markup: str, width: int) -> str:
					return markup + (" " * max(0, width - _measure(markup)))

				# Build a centered header line with a subtle divider
				gap = "  "
				head_line = gap.join([
					_pad_cell(head_parts[0], widths["badges"]),
					_pad_cell(head_parts[1], widths["level"]),
					_pad_cell(head_parts[2], widths["rank"]),
					_pad_cell(head_parts[3], widths["score"]),
					_pad_cell(head_parts[4], widths["name"]),
				])
				total_width = len(head_line)
				divider = f"[dim]{'\u2500' * total_width}[/dim]"
				line_parts.append(head_line)
				line_parts.append(divider)

				for r in rows:
					pad_badges = _pad_cell(r["badges"], widths["badges"]) if r["badges"] else (" " * widths["badges"])
					pad_level = _pad_cell(r["level"], widths["level"])
					pad_rank = _pad_cell(r["rank"], widths["rank"])
					pad_score = _pad_cell(r["score"], widths["score"])
					pad_name = _pad_cell(r["name"], widths["name"])
					line_parts.append(gap.join([pad_badges, pad_level, pad_rank, pad_score, pad_name]).rstrip())

				# Header line for mode/queue
				game_mode = str(party_data.get("MatchmakingData", {}).get("QueueID", "Unknown")).lower()
				game_mode = GAME_MODES.get(game_mode.lower(), str(game_mode))
				head = f"[green]Mode:[/green] {game_mode}"
				block_text = Text.from_markup("\n".join(line_parts)) if line_parts else Text(
					"[dim]No party members[/dim]", justify="center")
				party_panel = Panel(
					Align.center(block_text),
					title="Party",
					border_style="cyan",
					padding=(0, 1),
				)

				# For content-change detection, keep a plain string signature
				party_section = f"{head}\n" + "\n".join(line_parts)

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
					console.print(Text.from_markup(head))
					console.print(Columns([party_panel], expand=True, equal=True))
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
		if member["Subject"] in ROLE_PUUID_LIST:
			role: list[str] | None = ROLE_PUUID_LIST.get(member["Subject"], None)
			if role is not None:
				player_name += f" {str(b64decode(role[0].encode()).decode())}"
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
	input_task = None
	if send_message:
		console.print("\n\nChecking if player is in match")

	state_manager = OFFLINE_STATE_MANAGER if OFFLINE_MODE else None
	if state_manager is not None:
		state_manager.grant_replay()

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
					if input_task is None:
						input_task = asyncio.create_task(listen_for_input())
					await run_pregame(data)
					if state_manager is not None:
						state_manager.exhaust()
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
				if state_manager is not None:
					state_manager.exhaust()
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


def _resolve_menu_action(user_input: str) -> str | None:
	"""Normalize raw user input from the main menu into an action keyword."""
	normalized = user_input.strip().lower()
	if not normalized:
		return None
	if normalized in {"1", "shop", "store"}:
		return "shop"
	if normalized in {"2", "loader", "load", "ingame", "in-game"}:
		return "loader"
	if normalized in {"settings", "setup", "config", "preferences"}:
		return "settings"
	if normalized in {"exit", "quit", "close", "leave", "e", "q", "c", "l"}:
		_print_exit_message()
		sys.exit(0)
	return None


def _prompt_menu_action(default_action: str) -> str | None:
	"""Prompt the user for a menu choice, respecting a configured default."""
	if (not sys.stdin or not sys.stdin.isatty()) and not DEBUG:
		logger.info("No interactive stdin available; using default menu action or Shop")
		if default_action in {"shop", "loader"}:
			return default_action
		return "shop"

	if default_action == "manual":
		console.print(
			"\n(1) Valorant Shop, (2) In-Game Loader\nType 'settings' to adjust preferences."
		)
		return _resolve_menu_action(input("> ").strip())

	pretty_default = "Valorant Shop" if default_action == "shop" else "In-Game Loader"
	console.print(
		f"\nDefault action: {pretty_default}. Press Enter to continue, "
		"type 'menu' to choose manually, or 'settings' to open configuration."
	)
	choice = input("> ").strip().lower()
	if not choice:
		return default_action
	if choice in {"menu", "m", "manual"}:
		console.print(
			"\n(1) Valorant Shop, (2) In-Game Loader\nType 'settings' to adjust preferences."
		)
		choice = input("> ").strip()
	return _resolve_menu_action(choice)


async def _run_manual_loader_sequence() -> None:
	"""Launch the in-game loader until the session requests an exit."""
	while True:
		logged_in = await log_in()
		if logged_in:
			await check_if_user_in_pregame()
			logger.debug("Calling get_party from manual launch flow")
			if await get_party() == -1:
				break
		else:
			await asyncio.sleep(2.5)
			console.clear()


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
	console.print(f"\n[bold green]You have been logged in! Welcome, {name}[/bold green]")


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
		loop = asyncio.get_running_loop()
		if ASYNC_EXCEPTION_HANDLER is not None:
			loop.set_exception_handler(ASYNC_EXCEPTION_HANDLER)
			logger.debug(
				"Attached asyncio exception handler to running loop",
				context={"loop_id": id(loop)},
			)
	except RuntimeError:
		logger.warning(
			"Failed to obtain running asyncio loop during main startup",
			context={"thread": threading.current_thread().name},
		)

	try:
		logger.info("Attempting Riot login via UI flow.")
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
		logger.info(
			"Login succeeded",
			context={"version": VERSION, "player": f"{name}#{tag}"},
		)

		ValorantShop = ValorantShopChecker()
		Notification = NotificationManager()

		if args.store:
			shop = ValorantShopChecker()
			clear_console()
			if getattr(args, "_store_from_config", False):
				console.print("[bold cyan]Launching Valorant Shop (configured auto-start).[/bold cyan]")
				hide_console()
			console.print(f"[bold red]STORE ONLY MODE...[/bold red]\nUse system tray to exit.")
			await with_spinner("Loading Store...", shop.run())

		state: Optional[int] = None

		clear_console()

		while True:
			try:
				await display_logged_in_status(name)

				# Kill input thread
				if input_task is not None:
					input_task.cancel()

				# Fetch and display friend states dynamically
				friend_states = await get_friend_states()
				await display_friend_states(friend_states)

				state = get_user_current_state(val_uuid)
				if state not in (3, 4):
					action = _prompt_menu_action(DEFAULT_MENU_ACTION)
					if action == "shop":
						await with_spinner("Loading Store...", ValorantShop.run())
					elif action == "loader":
						await _run_manual_loader_sequence()
					elif action == "settings":
						if CONFIG_MANAGER is None or CONFIG is None:
							console.print(
								Panel("Configuration manager unavailable. Restart the client to re-run setup.",
								      style="bold red")
							)
						else:
							try:
								run_setup_wizard(CONFIG_MANAGER, CONFIG, game_modes=GAME_MODES)
								config_main = CONFIG["Main"]
								refresh_runtime_preferences(config_main)
								_apply_store_mode_override()
								logger.info(
									"Interactive setup wizard re-run from menu",
									context={"default_menu_action": DEFAULT_MENU_ACTION},
								)
							except RuntimeError as exc:
								console.print(Panel(str(exc), style="bold red"))
						await asyncio.sleep(1.0)
					elif action == "close":
						_print_exit_message()
						return False
					else:
						console.print("[bold red]Invalid input. Please try again.[/bold red]")
						await asyncio.sleep(1.5)
				else:
					while True:
						logged_in = await log_in()
						if logged_in:
							await check_if_user_in_pregame()
							logger.debug("Calling get_party from automated main loop")
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
				logger.error(
					"Unhandled error inside interactive main loop",
					context={"state": state},
					exc_info=e,
				)
				console.print(f"[bold red]An Error Has Happened![/bold red]\n")
				console.print_exception()
				await asyncio.sleep(2)
	else:
		logger.warning("Login attempt unsuccessful; main loop will retry.")
		console.print("[bold red]Failed to log in. Retrying in 5 seconds...[/bold red]")
	await asyncio.sleep(5)
	return True


import platform

# --- Console window helpers (Windows only) ---
_CONSOLE_HWND = None


def _get_console_hwnd():
	"""Return the Windows console HWND or None on non-Windows."""
	global _CONSOLE_HWND
	try:
		if platform.system() != "Windows":
			return None
		import ctypes  # local import to avoid issues on non-Windows
		user32 = ctypes.WinDLL('user32')
		_CONSOLE_HWND = user32.GetForegroundWindow()
		return _CONSOLE_HWND
	except Exception:
		return None


def hide_console():
	"""Hide the console window (no-op on non-Windows)."""
	try:
		if platform.system() != "Windows":
			return
		import ctypes
		user32 = ctypes.WinDLL('user32')
		if _CONSOLE_HWND:
			user32.ShowWindow(_CONSOLE_HWND, 0)
		else:
			hwnd = _get_console_hwnd()
			if hwnd:
				user32.ShowWindow(hwnd, 0)
		user32.SetForegroundWindow(_CONSOLE_HWND)
	except Exception:
		pass


def show_console():
	"""Show and focus the console window (no-op on non-Windows)."""
	try:
		if platform.system() != "Windows":
			return
		import ctypes
		user32 = ctypes.WinDLL('user32')
		if _CONSOLE_HWND:
			user32.ShowWindow(_CONSOLE_HWND, 5)
		else:
			hwnd = _get_console_hwnd()
			if hwnd:
				user32.ShowWindow(hwnd, 5)
		user32.SetForegroundWindow(_CONSOLE_HWND)

	except Exception:
		pass


if __name__ == "__main__":
	parser = argparse.ArgumentParser(add_help=True)
	parser.add_argument("--debug", action="store_true", help="Enable debug mode")
	parser.add_argument("--no-rpc", action="store_true", help="Disable Discord Rich Presence")
	parser.add_argument("--version", action="store_true", help="Show version and exit")
	parser.add_argument("--offline", action="store_true", help="Run without Riot client using offline fixtures")
	parser.add_argument("--offline-state",
	                    choices=["menus", "party", "pregame", "ingame", "postgame"],
	                    default="menus",
	                    help="Offline scenario to simulate (requires --offline)")
	parser.add_argument("--setup",
	                    action="store_true",
	                    help="Open the interactive setup wizard before starting the client")
	parser.add_argument("--no-console",
	                    action="store_true",
	                    help="Hide console window")
	parser.add_argument("--store",
	                    action="store_true",
	                    help="Launch directly into the Valorant store interface")
	args = parser.parse_args()

	instance_guard = SingleInstanceGuard("ValorantZoroClient")
	if not instance_guard.acquire():
		console.print(Panel("Another Zoro session is already running.", style="bold red"))
		time.sleep(2.5)
		sys.exit(1)
	atexit.register(instance_guard.release)

	# Set console title
	console.set_window_title(f"Zoro {VERSION}")

	if args.version:
		console.print(f"Zoro Version: {VERSION}")
		sys.exit(0)

	if args.no_console:
		# Hide the actual console window; can be restored from the system tray
		hide_console()

	CLI_DEBUG_OVERRIDE = args.debug
	setup_invoked = False
	offline_mode_enabled = False
	offline_mode_exception: Optional[Exception] = None

	# Activate offline mode early so later calls (including config and API fetches) can be stubbed
	if args.offline:
		try:
			from devtools.offline.integration import activate_offline_mode

			activate_offline_mode(globals(), scenario=args.offline_state)
			DEBUG = True  # extra logging helpful in offline
			args.no_rpc = True
			offline_mode_enabled = True
		except Exception as e:
			offline_mode_exception = e
			console.print(Panel(f"Failed to enable offline mode: {e}", style="bold red"))

	config_manager = build_main_config_manager(CONFIG_FILE, GAME_MODES)
	config_result = config_manager.load()
	config = config_result.config
	config_main = config["Main"]
	CONFIG_MANAGER = config_manager
	CONFIG = config

	debug_from_config = refresh_runtime_preferences(config_main)
	_apply_store_mode_override()
	if CLI_DEBUG_OVERRIDE:
		DEBUG = True

	if args.setup or not SETUP_COMPLETED:
		try:
			clear_console()
			run_setup_wizard(config_manager, config, game_modes=GAME_MODES)
			setup_invoked = True
		except RuntimeError as exc:
			console.print(Panel(str(exc), style="bold red"))
			sys.exit(1)
		debug_from_config = refresh_runtime_preferences(config_main)
		_apply_store_mode_override()
		if CLI_DEBUG_OVERRIDE:
			DEBUG = True

	# Preserve existing flags behavior
	if args.no_rpc:
		config_main["use_discord_rich_presence"] = "false"

	ADVANCED_MISSING_AGENTS: bool = config_main.get("advanced_missing_agents", "false").strip().lower() == "true"

	# Common initialization before launching UI/CLI
	clear_console()
	colorama.init(autoreset=True)
	logger = Logger("Zoro", "logs/Zoro", ".log")
	logger.load_public_key(pub_key)
	install_global_exception_handlers(logger)

	if setup_invoked:
		logger.info(
			"Interactive setup wizard completed",
			context={"default_menu_action": DEFAULT_MENU_ACTION, "debug_logging": DEBUG},
		)

	logger.debug(
		"Runtime arguments resolved",
		context={
			"debug_flag": args.debug,
			"config_debug_flag": debug_from_config,
			"no_rpc_flag": args.no_rpc,
			"offline": args.offline,
			"offline_state": args.offline_state,
			"default_menu_action": DEFAULT_MENU_ACTION,
		},
	)

	if DEBUG:
		logger.debug("Debug mode enabled", context={"source": "cli_or_config"})

	if offline_mode_enabled:
		logger.info("Offline mode enabled", context={"scenario": args.offline_state})
	elif offline_mode_exception is not None:
		logger.error(
			"Offline mode activation failed",
			context={"scenario": args.offline_state},
			exc_info=offline_mode_exception,
		)

	if config_result.created:
		console.print(Panel(f"Created default configuration at '{CONFIG_FILE}'.", style="bold green"))
		logger.info("Created default configuration file", context={"path": CONFIG_FILE})

	if config_result.issues:
		logger.warning(
			"Configuration issues detected and adjusted",
			context={"issue_count": len(config_result.issues)},
		)
		console.rule("[bold yellow]Configuration Adjustments[/bold yellow]")
		for issue in config_result.issues:
			key_path = f"{issue.section}.{issue.key}" if issue.key != "*" else issue.section
			console.print(f"[yellow]{key_path}[/yellow]: {issue.message}")
			logger.debug(
				"Configuration setting adjusted",
				context={
					"section": issue.section,
					"key": issue.key,
					"message": issue.message,
					"reverted_to": issue.reverted_to,
				},
			)
			if issue.reverted_to is not None:
				console.print(f"  Using value: {issue.reverted_to}")
		console.print(Panel("Update the config file to apply your preferred values.", style="bold yellow"))
		if sys.stdin and sys.stdin.isatty():
			input("Press enter to continue...")
	elif DEBUG:
		console.print(Panel("Configuration loaded successfully.", style="bold green"))
		logger.debug("Configuration loaded successfully without adjustments.")
		time.sleep(1)

	# Get user roles by PUUID
	ROLE_PUUID_LIST: dict = api_request("GET", f"{b64decode(ROLE_URL.encode()).decode()}").json()

	RPC = None
	if not args.no_rpc & bool(config_main.get("use_discord_rich_presence", "true").lower() == "true"):
		try:
			nest_asyncio.apply()
			RPC = Presence(CLIENT_ID)
			RPC.connection_timeout = 10
			RPC.connect()
		except Exception as e:
			logger.log(2, f"Error initializing Discord RPC: {e}")
			RPC = None
			# Make sure RPC is not used.
			config_main["use_discord_rich_presence"] = "false"
			args.no_rpc = True

	while True:
		try:
			should_continue = asyncio.run(main())
		except KeyboardInterrupt:
			_print_exit_message()
			break
		if not should_continue:
			break
