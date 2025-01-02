VERSION = "v2.1.5"

import asyncio
import threading
import time
import os
import configparser
import traceback
import sys
import aiohttp
import colorama
import requests
import ssl

from json import dump, loads
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
from pathlib import Path
from tkinter import Tk, ttk, Canvas, Frame, Scrollbar
from tkinter import Label as tkLabel
from PIL import Image, ImageTk
from datetime import datetime, timedelta

val_token = ""
val_access_token = ""
val_entitlements_token = ""
val_uuid = ""
region = ""

internal_api_headers = {}
internal_api_headers_console = {}

password = ""
port = ""

input_task = None

CONFIG_FILE = "config.ini"
if not os.path.exists("config.ini"):
	raw_config_data = (f'[Main]\n'
	                   f'; Amount of matches to look at before using that data for player stats\n'
	                   f'; Wins / Loss | KD, HS%, ETC\n'
	                   f'; Default = 10\n'
	                   f'\n'
	                   f'amount_of_matches_for_player_stats = 10\n'
	                   f'; What game mode should these stats be taken from\n'
	                   f'; "ALL", "SAME", Specific -> "competitive", "unrated"\n'
	                   f'; Default = "ALL"\n'
	                   f'stats_used_game_mode = ALL')
	with open(CONFIG_FILE, "w") as file:
		file.write(raw_config_data)

config = configparser.ConfigParser()
parentdir = os.path.dirname(__file__)

config.read("/".join([parentdir, CONFIG_FILE]))
config_main = config["Main"]

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path("./assets")

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
██╗   ██╗ █████╗ ██╗      ██████╗ ██████╗  █████╗ ███╗   ██╗████████╗    ██╗      ██████╗  █████╗ ██████╗ ███████╗██████╗ 
██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝    ██║     ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
██║   ██║███████║██║     ██║   ██║██████╔╝███████║██╔██╗ ██║   ██║       ██║     ██║   ██║███████║██║  ██║█████╗  ██████╔╝
╚██╗ ██╔╝██╔══██║██║     ██║   ██║██╔══██╗██╔══██║██║╚██╗██║   ██║       ██║     ██║   ██║██╔══██║██║  ██║██╔══╝  ██╔══██╗
 ╚████╔╝ ██║  ██║███████╗╚██████╔╝██║  ██║██║  ██║██║ ╚████║   ██║       ███████╗╚██████╔╝██║  ██║██████╔╝███████╗██║  ██║
  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ 
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
		c = WMI()
		self.hwid = c.Win32_ComputerSystemProduct()[0].UUID, c.Win32_BaseBoard()[0].SerialNumber

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
		ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1  # deprecated since 3.10
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

	# get lockfile password
	file_path = os.getenv("localappdata")
	with open(f"{file_path}\\Riot Games\\Riot Client\\Config\\lockfile", "r") as f:
		lockfile_data = f.read()
	# Base 64 encode the password
	password = b64encode(f"riot:{str(lockfile_data.split(':')[3])}".encode("ASCII")).decode()
	# Get the port the WS is running on
	port = str(lockfile_data.split(":")[2])
	if password is not None:
		# Make secure connection with the WS
		conn = aiohttp.TCPConnector(ssl=create_riot_auth_ssl_ctx())
		async with aiohttp.ClientSession(
				connector=conn, raise_for_status=True
		) as session:
			# Get user login tokens
			try:
				async with session.get(
						f"https://127.0.0.1:{port}/entitlements/v1/token",
						headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, ssl=False
				) as r:
					return_data = await r.json()
			except aiohttp.client.ClientResponseError:
				print("Please make sure Riot Client is open!")
				return None
		return return_data["accessToken"], return_data["token"], return_data["subject"]
	else:
		raise Exception("Riot Client Login Password Not Found!")


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

	with requests.get("https://valorant-api.com/v1/version") as r:
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


async def val_shop_checker():
	print("Loading Shop...")
	await log_in()
	try:
		get_headers()

		# Fetch player store data
		response = requests.post(f"https://pd.na.a.pvp.net/store/v3/storefront/{val_uuid}",
		                         headers=internal_api_headers, json={})
		data = response.json()

		with open(f"{DATA_PATH}/data.json", "w") as file:
			dump(data, file, indent=4)

		GetPoints = requests.get(f"https://pd.na.a.pvp.net/store/v1/wallet/{val_uuid}", headers=internal_api_headers)
		GetPoints_data = GetPoints.json()

		vp = GetPoints_data["Balances"]["85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741"]
		rp = GetPoints_data["Balances"]["e59aa87c-4cbf-517a-5983-6e81511be9b7"]

		# Bundles handling
		bundles_uuid = []
		bundle_prices = []
		featured_bundles = data.get('FeaturedBundle', {})
		# time = convert_time(featured_bundles.get('BundleRemainingDurationInSeconds', 0))

		if 'Bundles' in featured_bundles:
			bundles = featured_bundles['Bundles']
			for element in bundles:
				bundle_uuid = element.get('DataAssetID', '')
				bundles_uuid.append(bundle_uuid)
				all_prices = [item.get('DiscountedPrice', 0) for item in element.get('Items', [])]
				bundle_prices.append(sum(all_prices))

		# Skins handling
		all_skin_uuids = []
		singleweapons_prices = []
		daily_shop = data.get("SkinsPanelLayout", {}).get("SingleItemStoreOffers", [])

		for item in daily_shop:
			all_skin_uuids.append(str(item.get("OfferID", '')))
			singleweapons_prices.append(str(item.get("Cost", {}).get("85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741", 0)))

		skin_names, skin_images, skin_videos = [], [], []
		for item in all_skin_uuids:
			skin_data = requests.get(f'https://valorant-api.com/v1/weapons/skinlevels/{item}').json()
			skin_names.append(skin_data.get('data', {}).get('displayName', 'Unknown'))
			skin_images.append(skin_data.get('data', {}).get('displayIcon', ''))
			skin_videos.append(skin_data.get('data', {}).get('streamedVideo', ''))

		# Bundles
		bundles_images, current_bundles = [], []
		for bundle in bundles_uuid:
			bundle_data = requests.get(f'https://valorant-api.com/v1/bundles/{bundle}').json()
			current_bundles.append(bundle_data.get('data', {}).get('displayName', 'Unknown'))
			bundles_images.append(bundle_data.get('data', {}).get('displayIcon', ''))

		# Night Market data
		nm_price = []
		nm_offers = []
		nm_images = []
		nm_skins_id = []
		try:
			for i in data['BonusStore']['BonusStoreOffers']:
				[nm_price.append(k) for k in i['DiscountCosts'].values()]  # night market prices
			for i in data['BonusStore']['BonusStoreOffers']:
				[nm_skins_id.append(k['ItemID']) for k in i['Offer']['Rewards']]  # night market offers
		except KeyError:
			for i in range(6):
				nm_skins_id.append('NONE')
			for i in range(6):
				nm_price.append('NONE')

		for nmskinid in nm_skins_id:
			with requests.get(f'https://valorant-api.com/v1/weapons/skinlevels/{nmskinid}') as r:
				nmdata = r.json()
			nm_offers.append(nmdata['data']['displayName'])  # names of daily items
			nm_images.append(nmdata['data']['displayIcon'])  # images of daily items

		main_gui(vp, rp, current_bundles, bundles_images, bundle_prices, skin_names, skin_images, singleweapons_prices, nm_offers, nm_price, nm_images)

	except Exception as e:
		traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.log(1, traceback_str)
		print(f"Error: {e}")


def main_gui(vp, rp, current_bundles, bundles_images, bundle_prices, skin_names, skin_images, singleweapons_prices, nm_offers, nm_price, nm_images):
	print("Loaded Shop\nDisplaying!")
	root = Tk()
	root.title("Valorant Shop Checker")
	root.configure(bg="#121212")  # Improved dark background

	# Styling with ttk themes
	style = ttk.Style()
	style.configure("TFrame", background="#121212")
	style.configure("TLabelframe", background="#121212", foreground="white", borderwidth=0)
	style.configure("TLabel", background="#121212", foreground="white", font=("Helvetica", 12, "bold"))

	# Title Section
	title = tkLabel(root, text="Valorant Shop Checker", font=("Helvetica", 24, "bold"), fg="white", bg="#121212")
	title.pack(pady=10)

	# Points Section
	points_frame = ttk.Frame(root)
	points_frame.pack(pady=5)

	vp_label = ttk.Label(points_frame, text=f"Valorant Points (VP): {vp}", font=("Helvetica", 14), style="TLabel")
	vp_label.grid(row=0, column=0, padx=20)

	rp_label = ttk.Label(points_frame, text=f"Radianite Points (RP): {rp}", font=("Helvetica", 14), style="TLabel")
	rp_label.grid(row=0, column=1, padx=20)

	# Main Scrollable Canvas
	main_canvas = Canvas(root, bg="#121212", highlightthickness=0)
	main_canvas.pack(fill="both", expand=True, pady=10, padx=10)

	scrollbar = Scrollbar(root, orient="vertical", command=main_canvas.yview)
	scrollbar.pack(side="right", fill="y")
	main_canvas.configure(yscrollcommand=scrollbar.set)

	content_frame = Frame(main_canvas, bg="#121212")
	main_canvas.create_window((0, 0), window=content_frame, anchor="nw")

	def on_frame_configure(event):
		main_canvas.configure(scrollregion=main_canvas.bbox("all"))

	content_frame.bind("<Configure>", on_frame_configure)

	# Helper function to resize images while keeping the aspect ratio
	def resize_image(image, max_width, max_height):
		original_width, original_height = image.size
		ratio = min(max_width / original_width, max_height / original_height)
		new_size = (int(original_width * ratio), int(original_height * ratio))
		return image.resize(new_size, Image.Resampling.LANCZOS)

	# Bundles Section as banners
	bundles_frame = ttk.LabelFrame(content_frame, text="Bundles", style="TLabelframe")
	bundles_frame.pack(fill="x", pady=10, padx=20)

	if current_bundles:
		for i, bundle in enumerate(current_bundles):
			bundle_frame = Frame(bundles_frame, bg="#2a2a2a", highlightbackground="#ffffff", highlightthickness=2)
			bundle_frame.pack(side="top", fill="x", padx=10, pady=10)

			bundle_image = Image.open(requests.get(bundles_images[i], stream=True).raw)
			bundle_image = resize_image(bundle_image, 400, 150)  # Make the bundle image larger
			img = ImageTk.PhotoImage(bundle_image)

			img_label = tkLabel(bundle_frame, image=img, bg="#2a2a2a", bd=0, highlightthickness=0)
			img_label.image = img
			img_label.pack(pady=(10, 5))

			bundle_label = tkLabel(
				bundle_frame,
				text=bundle,
				font=("Helvetica", 16, "bold"),
				fg="white",
				bg="#2a2a2a",
				justify="center",
			)
			bundle_label.pack()

			price_label = tkLabel(
				bundle_frame,
				text=f"Price: {bundle_prices[i]} VP",
				font=("Helvetica", 14, "bold"),
				fg="white",
				bg="#2a2a2a",
			)
			price_label.pack(pady=5)

	# Daily Skins Section
	skins_frame = ttk.LabelFrame(content_frame, text="Daily Skins", style="TLabelframe")
	skins_frame.pack(fill="x", pady=10, padx=20)

	for i, skin in enumerate(skin_names):
		skin_frame = Frame(skins_frame, bg="#2a2a2a", highlightbackground="#ffffff", highlightthickness=2)
		skin_frame.pack(side="left", padx=10, pady=10)

		skin_image = Image.open(requests.get(skin_images[i], stream=True).raw)
		skin_image = resize_image(skin_image, 200, 200)
		img = ImageTk.PhotoImage(skin_image)

		img_label = tkLabel(skin_frame, image=img, bg="#2a2a2a", bd=0, highlightthickness=0)
		img_label.image = img
		img_label.pack(pady=(10, 5))

		skin_label = tkLabel(
			skin_frame,
			text=skin,
			font=("Helvetica", 12, "bold"),
			fg="white",
			bg="#2a2a2a",
			justify="center",
		)
		skin_label.pack()

		price_label = tkLabel(
			skin_frame,
			text=f"Price: {singleweapons_prices[i]} VP",
			font=("Helvetica", 10, "bold"),
			fg="white",
			bg="#2a2a2a",
		)
		price_label.pack(pady=5)

	# Night Market Section
	night_market_frame = ttk.LabelFrame(content_frame, text="Night Market", style="TLabelframe")
	night_market_frame.pack(fill="x", pady=10, padx=20)

	if nm_offers:
		for i, offer in enumerate(nm_offers):
			nm_frame = Frame(night_market_frame, bg="#2a2a2a", highlightbackground="#ffffff", highlightthickness=2)
			nm_frame.pack(side="left", padx=10, pady=10)

			nm_image = Image.open(requests.get(nm_images[i], stream=True).raw)
			nm_image = resize_image(nm_image, 200, 200)
			img = ImageTk.PhotoImage(nm_image)

			img_label = tkLabel(nm_frame, image=img, bg="#2a2a2a", bd=0, highlightthickness=0)
			img_label.image = img
			img_label.pack(pady=(10, 5))

			offer_label = tkLabel(
				nm_frame,
				text=offer,
				font=("Helvetica", 12, "bold"),
				fg="white",
				bg="#2a2a2a",
				justify="center",
			)
			offer_label.pack()

			price_label = tkLabel(
				nm_frame,
				text=f"Price: {nm_price[i]} VP",
				font=("Helvetica", 10, "bold"),
				fg="white",
				bg="#2a2a2a",
			)
			price_label.pack(pady=5)

	root.update_idletasks()
	root.geometry(f"{round(root.winfo_width() * 3.15)}x{round(root.winfo_height() * 2.25)}")
	root.mainloop()


def calculate_kd(kills, deaths):
	if deaths == 0:
		return kills  # Stop div of zero
	return round(kills / deaths, 2)


def get_userdata_from_id(user_id: str, host_player_uuid: str | None = None) -> tuple[str, bool]:
	with requests.put(f"https://pd.na.a.pvp.net/name-service/v2/players",
	                  headers=internal_api_headers, json=[user_id]) as req:
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

	return host_player, False


def get_agent_data_from_id(agent_id: str) -> str:
	with requests.get(f"https://valorant-api.com/v1/agents/{agent_id}") as val_api:
		agent_name = val_api.json()["data"]["displayName"]
	return agent_name


def get_mapdata_from_id(map_id: str) -> str:
	with requests.get(f"https://valorant-api.com/v1/maps") as val_api:
		maps = val_api.json()["data"]
	for map_data in maps:
		if map_data["mapUrl"] == map_id:
			return map_data['displayName']


def update_damage_stats(damage_dict, main_player, damage_info):
	if main_player not in damage_dict:
		damage_dict[main_player] = {"legshots": 0, "bodyshots": 0, "headshots": 0}

	damage_dict[main_player]["legshots"] += damage_info["legshots"]
	damage_dict[main_player]["bodyshots"] += damage_info["bodyshots"]
	damage_dict[main_player]["headshots"] += damage_info["headshots"]

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


def generate_match_report(match_stats: dict, host_player_uuid: str, only_host_player: bool = False):
	all_players = match_stats['players']
	report = []
	damage_stats = {}

	for player in all_players:
		user_name = get_userdata_from_id(player['subject'])[0]
		agent_name = get_agent_data_from_id(player['characterId'])
		stats = player['stats']

		if player['subject'] == host_player_uuid:
			report.append(f"Player: (You) {user_name} ({agent_name})")
			report.append(f"  Score: {stats['score']}")
			kd = calculate_kd(stats["kills"], stats["deaths"])
			report.append(f"  KD:    {kd}")
			report.append(f"  Kills: {stats['kills']}")
			report.append(f"  Deaths: {stats['deaths']}")
			report.append(f"  Assists: {stats['assists']}")

			# Round by Round
			for round_stats in match_stats["roundResults"]:
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

			# Calculate and display damage statistics for the host player
			host_damage_stats = damage_stats.get(host_player_uuid, {"legshots": 0, "bodyshots": 0, "headshots": 0})
			total_shots = host_damage_stats["legshots"] + host_damage_stats["bodyshots"] + host_damage_stats["headshots"]
			if total_shots > 0:
				headshot_percentage = (host_damage_stats["headshots"] / total_shots) * 100
			else:
				headshot_percentage = 0
			try:
				report.append(f"  Ability Casts: Grenades: {stats['abilityCasts']['grenadeCasts']}, Ability1: {stats['abilityCasts']['ability1Casts']}, Ability2: {stats['abilityCasts']['ability2Casts']}, Ultimates: {stats['abilityCasts']['ultimateCasts']}")
				for rd in player['roundDamage']:
					user = get_userdata_from_id(str(rd['receiver']))[0]
					report.append(f"  Round {rd['round']} - Damage to {user}: {rd['damage']}")
			except:
				report.append("Failed to get!")

			# Append host player specific damage stats
			report.append(f"  Total Shots: {total_shots}")
			report.append(f"  Leg Shots: {host_damage_stats['legshots']}")
			report.append(f"  Body Shots: {host_damage_stats['bodyshots']}")
			report.append(f"  Head Shots: {host_damage_stats['headshots']}")
			report.append(f"  Headshot Percentage: {headshot_percentage:.2f}%")
		else:
			if not only_host_player:
				report.append(f"Player: {user_name} ({agent_name})")
				report.append(f"  Score: {stats['score']}")
				kd = calculate_kd(stats["kills"], stats["deaths"])
				report.append(f"  KD:    {kd}")
				report.append(f"  Kills: {stats['kills']}")
				report.append(f"  Deaths: {stats['deaths']}")
				report.append(f"  Assists: {stats['assists']}")

	return report


def get_rank_from_uuid(user_id: str, platform: str = "PC"):
	if platform == "PC":
		with requests.get(f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=competitive",
		                  headers=internal_api_headers) as r:
			try:
				rank_tier = r.json()["Matches"][0]["TierAfterUpdate"]
			except:
				return "Unranked"
	elif platform == "CONSOLE":
		with requests.get(f"https://pd.na.a.pvp.net/mmr/v1/players/{user_id}/competitiveupdates?queue=console_competitive",
		                  headers=internal_api_headers_console) as r:
			try:
				rank_tier = r.json()["Matches"][0]["TierAfterUpdate"]
			except:
				# If no comp match are played by the user
				return "Unranked"

	with open(f"{DATA_PATH}/comp_data.json", "a") as file:
		dump(r.json(), file, indent=4)
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
	print(rank)
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
			if stats_used_game_mode == "same":
				if gamemode is not None:
					search = f"&queue={gamemode}"
			else:
				search = f"&queue={stats_used_game_mode}"

		if platform == "PC":
			url = f"https://pd.na.a.pvp.net/match-history/v1/history/{user_id}?endIndex={int(config_main.get('amount_of_matches_for_player_stats', '10'))}{search}"
			headers = internal_api_headers
		else:
			url = f"https://pd.na.a.pvp.net/match-history/v1/history/{user_id}?endIndex={int(config_main.get('amount_of_matches_for_player_stats', '10'))}{search}"
			headers = internal_api_headers_console

		response = requests.get(url, headers=headers)
		if response.status_code == 429:
			print("Rate Limited!")
			raise Exception("Rate Limited")
		history = response.json().get("History", [])
		time.sleep(2.5)  # Delay to prevent rate limiting

		save_match_data = None
		for i in history:
			match_id = i["MatchID"]
			match_url = f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}"
			match_response = requests.get(match_url, headers=headers)

			match_data = match_response.json()
			player_data = match_data.get("players", [])

			for match in player_data:
				if str(match["subject"]) == str(user_id):
					partyId = match["partyId"]

					if save_match_data is None:
						# Add player to their party, avoiding duplicates
						if partyId not in partyIDs:
							partyIDs[partyId] = [match["subject"]]
						else:
							if match["subject"] not in partyIDs[partyId]:
								partyIDs[partyId].append(match["subject"])
						save_match_data = player_data

					# Collect kill/death and win data
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
		print(f"Error: {e}")
		cache[user_id] = (-1, ['Error'], -1)
		return {}, cache


def get_members_of_party_from_uuid(player_id: str):
	player_list = []
	with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(player_id)}", headers=internal_api_headers) as r:
		try:
			if r.status_code == 400:
				is_console = str(r.json()["errorCode"]) == "PLAYER_PLATFORM_TYPE_MISMATCH"
				if is_console:
					with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(player_id)}", headers=internal_api_headers_console) as r2:
						party_id = r2.json()['CurrentPartyID']

			else:
				party_id = r.json()['CurrentPartyID']

		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			print("Error Logged!")

	if party_id is not None:
		with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}", headers=internal_api_headers) as r:
			party_data = r.json()
		for member in party_data["Members"]:
			player_name = get_userdata_from_id(str(member["Subject"]))[0]
			player_list.append(player_name)
	else:
		player_list.clear()
		player_list.append("Player is not in a party. Player could be offline.")
	return player_list, party_id


def get_rank_color(rank: str):
	"""Return colored text for a rank, with Radiant being multicolored."""

	# Define color codes
	RANK_COLORS = {
		"Iron": "\033[90m",  # Gray
		"Bronze": "\033[38;5;130m",  # Orange/Brown
		"Silver": "\033[37m",  # Light Gray/White
		"Gold": "\033[33m",  # Yellow
		"Plat": "\033[36m",  # Cyan
		"Diamond": "\033[35m",  # Magenta
		"Ascendant": "\033[38;5;82m",  # Bright Green
		"Immortal": "\033[31m",  # Red
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


def get_user_current_state(puuid: str) -> int:
	"""
	:return: int: 1 = In Menus, 2 = In Menus Queueing, 3 = Pregame, 4 = In-Game, 5 = Other State, -1 = Error
	"""
	requests.packages.urllib3.disable_warnings()  # noqa
	try:

		with requests.get(f"https://127.0.0.1:{port}/chat/v4/presences",
		                  headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, verify=False) as r:
			data = r.json()

		all_user_data = data["presences"]
		for user in all_user_data:
			if user["puuid"] == puuid:
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
	try:

		with requests.get(f"https://127.0.0.1:{port}/chat/v4/presences",
		                  headers={"authorization": f"Basic {password}", "accept": "*/*", "Host": f"127.0.0.1:{port}"}, verify=False) as r:
			data = r.json()

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


async def run_in_game(cache: dict = None, partys: dict = None):
	if cache is None:
		cache = {}

	buffer = StringIO()
	last_rendered_content = ""

	print("Loading...")

	# Fetch match ID
	while True:
		try:
			with requests.get(f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}", headers=internal_api_headers) as r:
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
		party_data, cache = get_playerdata_from_uuid(player_id, cache, platform)
		partys = add_parties(partys, party_data)
		return None

	while True:
		buffer.truncate(0)
		buffer.seek(0)
		try:
			with requests.get(f"https://glz-na-1.na.a.pvp.net/core-game/v1/matches/{match_id}",
			                  headers=internal_api_headers) as r:
				if r.status_code == 400:
					await log_in()
				match_data = r.json()

				if r.status_code != 404 or match_data["State"] != "CLOSED":
					map_id = match_data["MapID"]
					try:
						gamemode_name = match_data["MatchmakingData"]["QueueID"]
					except TypeError:
						gamemode_name = match_data["ProvisioningFlow"]
					map_name = get_mapdata_from_id(map_id)

					buffer.write(Fore.GREEN + f"Map: {map_name}\n" + Style.RESET_ALL)
					buffer.write(Fore.CYAN + f"Game mode: {str(gamemode_name).capitalize()}\n\n" + Style.RESET_ALL)

					if not got_players:
						threads = []
						for player in match_data["Players"]:
							player_id = player["PlayerIdentity"]["Subject"]
							team_id = player["TeamID"]
							player_lvl = player["PlayerIdentity"]["AccountLevel"]
							agent_name = get_agent_data_from_id(player['CharacterID'])

							host_player = get_userdata_from_id(player_id, val_uuid)[0]
							player_name_cache.append(host_player)

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

					count = 0
					party_exists = []
					party_number = 1
					for player in match_data["Players"]:
						player_id = player["PlayerIdentity"]["Subject"]
						player_data[str(player_name_cache[count])] = cache.get(str(player_id), ("Loading", "Loading", "Loading"))
						count += 1

					# Ensure the rank color is applied correctly

					buffer.write(Fore.BLUE + "Team Blue:\n" + Style.RESET_ALL)
					for user_name, data in team_blue_player_list.items():
						party_symbol = ""
						for party_id, members in partys.items():
							if len(members) > 1:
								if str(data[3]) in members:
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
						buffer.write(Fore.BLUE + f"{party_symbol}{color_text(f'[LVL {data[1]}]', Fore.BLUE)} {get_rank_color(data[2])} {user_name} ({data[0]})\n" + Style.RESET_ALL)
						kd, wins, hs = player_data.get(user_name, ("Loading", "Loading", "Loading"))
						buffer.write(Fore.MAGENTA + f"Player KD: {kd} | Headshot: {hs}%\nPast Matches: {''.join(wins)}\n\n" + Style.RESET_ALL)

					buffer.write(Fore.RED + "VS\n\nTeam Red:\n" + Style.RESET_ALL)
					for user_name, data in team_red_player_list.items():
						party_symbol = ""
						for party_id, members in partys.items():
							if len(members) > 1:
								if str(data[3]) in members:
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
						buffer.write(Fore.RED + f"{party_symbol}{color_text(f'[LVL {data[1]}]', Fore.RED)} {get_rank_color(data[2])} {user_name} ({data[0]})\n" + Style.RESET_ALL)
						kd, wins, hs = player_data.get(user_name, ("Loading", "Loading", "Loading"))
						buffer.write(Fore.MAGENTA + f"Player KD: {kd} | Headshot: {hs}%\nPast Matches: {''.join(wins)}\n\n" + Style.RESET_ALL)

					score = get_current_game_score(val_uuid)
					buffer.write(f"{score[0]} | {score[1]}\n")

					got_players = True

					try:
						with requests.get(f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}",
						                  headers=internal_api_headers) as re_match_stats:
							match_stats = re_match_stats.json()

						total_rounds = match_stats["teams"][0]["roundsPlayed"]
						team_1_rounds = match_stats["teams"][0]["roundsWon"]
						team_2_rounds = match_stats["teams"][1]["roundsWon"]

						buffer.write(Fore.YELLOW + f"Total Rounds: {total_rounds}\n" + Style.RESET_ALL)
						buffer.write(Fore.YELLOW + f"Score: {team_1_rounds}  |  {team_2_rounds}\n" + Style.RESET_ALL)
						if len(threads) > 0:
							for thread in threads:
								if thread.is_alive():
									print("Thread is alive!")
						await asyncio.sleep(3)
						return

					except:
						pass

					# Render buffer content if it has changed
					current_rendered_content = buffer.getvalue()
					if current_rendered_content != last_rendered_content:
						clear_console()
						print(current_rendered_content)
						last_rendered_content = current_rendered_content

					time.sleep(5)

				else:
					# TODO | Will fix later
					"""
					clear_console()
					print("Match Ended!")
					print("Loading Match Report (BETA)")
					report = generate_match_report(match_stats, val_uuid, False)
					for line in report:
						print(line)
					input("\nPress any key to continue")
					"""
					return None
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
		party_data, cache = get_playerdata_from_uuid(player_id, cache, platform)
		partys = add_parties(partys, party_data)
		return None

	while True:
		buffer.truncate(0)
		buffer.seek(0)
		try:
			with requests.get(f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{data['MatchID']}",
			                  headers=internal_api_headers) as r:
				match_data = r.json()
				with open(f"{DATA_PATH}/pre_match_data.json", "w") as f:
					dump(match_data, f, indent=4)

			if not got_map_and_gamemode:
				map_name = get_mapdata_from_id(match_data["MapID"])
				gamemode_name = match_data["QueueID"]
				got_map_and_gamemode = True

			# Ensure color resets after each section
			buffer.write(color_text(f"Map: {map_name}\n", Fore.GREEN))
			buffer.write(color_text(f"Game mode: {str(gamemode_name).capitalize()}\n\n", Fore.CYAN))

			our_team_colour = match_data["AllyTeam"]["TeamID"]

			party_number = 1
			party_exists = []

			for ally_player in match_data["AllyTeam"]["Players"]:
				user_name, is_user = get_userdata_from_id(ally_player["PlayerIdentity"]["Subject"], val_uuid)
				player_level = ally_player["PlayerIdentity"]["AccountLevel"]

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

				if state == "":
					buffer.write(f"{party_symbol}{color_text(f'[LVL {player_level}]', Fore.YELLOW)} {get_rank_color(rank)} {user_name}: {agent_name} (Picking)\n")
				elif state == "selected":
					buffer.write(f"{party_symbol}{color_text(f'[LVL {player_level}]', Fore.BLUE)} {get_rank_color(rank)} {user_name}: {agent_name} (Hovering)\n")
				else:
					buffer.write(f"{party_symbol}{color_text(f'[LVL {player_level}]', Fore.GREEN)} {get_rank_color(rank)} {user_name}: {agent_name} (Locked)\n")

				kd, wins, avg = cache.get(str(ally_player["PlayerIdentity"]["Subject"]), ("Loading", "Loading", "Loading"))
				buffer.write(color_text(f"Player KD: {kd} | Headshot: {avg}%\nPast Matches: {''.join(wins)}\n\n", Fore.MAGENTA))

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
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)
			print("Error Logged!")

	await run_in_game(cache, partys)
	return


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
		response = requests.post(url, json=data, headers=headers)
		if response.status_code == 200:
			print(f"Ready state set to: {is_ready}")
			return True
		else:
			print(f"Failed to toggle ready state: {response.status_code} - {response.text}")
			return False
	except Exception as e:
		print(f"Error while toggling ready state: {e}")
		return False


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
				await get_party()
		except Exception as e:
			print(f"Error in input listener: {e}")
			break


async def get_party(got_rank: dict = None):
	global input_task
	buffer = StringIO()
	last_rendered_content = ""
	input_task = None  # Task for input handling
	if got_rank is None:
		got_rank = {}
	while True:
		await check_if_user_in_pregame()
		try:
			buffer.truncate(0)
			buffer.seek(0)

			message_list = [color_text("----- Party -----\n", Fore.CYAN)]
			with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}", headers=internal_api_headers) as r:
				if r.status_code == 400:
					is_console = str(r.json()["errorCode"]) == "PLAYER_PLATFORM_TYPE_MISMATCH"
					if is_console:
						with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}", headers=internal_api_headers_console) as r2:
							party_id = r2.json()['CurrentPartyID']
					else:
						buffer.write(color_text("Error fetching party details.\n", Fore.RED))
						party_id = r.json()['CurrentPartyID']
				elif r.status_code == 404:
					party_id = None
				else:
					party_id = r.json()['CurrentPartyID']

			if party_id is not None:
				if input_task is None or input_task.done():
					input_task = asyncio.create_task(listen_for_input(party_id))

				with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}", headers=internal_api_headers) as r:
					party_data = r.json()

				is_queueing = party_data["State"]
				if is_queueing == "MATCHMAKING":
					message_list.append(color_text("Queueing!\n", Fore.YELLOW))
					last_rendered_content = ""
					cancel = True
					await check_if_user_in_pregame()

				# is_console = str(party_data["Members"][0]["PlatformType"]).lower() == "console"
				game_mode = str(party_data["MatchmakingData"]["QueueID"]).capitalize()
				message_list.append(color_text(f"Mode: {game_mode}\n\n", Fore.GREEN))

				for member in party_data["Members"]:
					player_name, is_user = get_userdata_from_id(str(member["Subject"]), val_uuid)
					is_leader = bool(member.get("IsOwner", False))
					player_lvl = str(member["PlayerIdentity"]["AccountLevel"])

					color = Fore.YELLOW if is_user else (Fore.LIGHTRED_EX if is_leader else Fore.WHITE)
					leader_text = "[Leader] " if is_leader else ""
					if member["Subject"] not in got_rank:
						print("Not Cached")
						player_rank_str = get_rank_color(get_rank_from_uuid(str(member['Subject'])))
						got_rank[str(member["Subject"])] = player_rank_str
					else:
						player_rank_str = got_rank[str(member["Subject"])]
					message_list.append(color_text(f"{leader_text}[LVL {player_lvl}] {player_name} {player_rank_str}\n", color))

				current_rendered_content = ''.join(message_list)

				if current_rendered_content != last_rendered_content:
					buffer.write(current_rendered_content)
					last_rendered_content = current_rendered_content
					clear_console()
					print_buffered(buffer)

				await asyncio.sleep(0.25)
				"""
				if cancel:
					last_rendered_content = ""
					await check_if_user_in_pregame()
					break
				"""
			else:
				new_message = color_text("Valorant is not running for that user!\n", Fore.RED)
				if new_message != last_rendered_content:
					buffer.write(new_message)
					last_rendered_content = new_message
					print_buffered(buffer)
				await asyncio.sleep(3.5)
		except KeyboardInterrupt:
			sys.exit(1)
		except Exception as e:
			logged_in = await log_in()
			if not logged_in:
				return
			print("Error Logged!")
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, traceback_str)


async def check_if_user_in_pregame(send_message: bool = False):
	if send_message:
		print("\n\nChecking if player is in match")

	# Try pregame
	with requests.get(f"https://glz-na-1.na.a.pvp.net/pregame/v1/players/{val_uuid}",
	                  headers=internal_api_headers) as r:
		data = r.json()
	try:
		if data["errorCode"] == "RESOURCE_NOT_FOUND":
			pass
	except KeyError:
		if data["MatchID"]:
			clear_console()
			await run_pregame(data)

	# Try playing in-game
	with requests.get(f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}",
	                  headers=internal_api_headers) as r:
		try:
			return_code = r.status_code
			if return_code == 200:
				clear_console()
				await run_in_game()
			elif return_code == 400:
				await log_in()
			else:
				pass
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(1, f"Error: {traceback_str}")

	return


def get_userdata_from_token() -> tuple[str, str]:
	with requests.get("https://auth.riotgames.com/userinfo", headers={"Authorization": f"Bearer {val_access_token}"}) as r:
		try:
			account_name = r.json()["acct"]["game_name"]
			account_tag = r.json()["acct"]["tag_line"]
			return account_name, account_tag
		except Exception as e:
			traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
			logger.log(3, f"Failed to get account name/tag: {traceback_str}")
			return "None", "None"


def main_display():
	print("\n" + Fore.LIGHTCYAN_EX + BANNER + Style.RESET_ALL)

	print(Fore.BLUE + "============\n|  Welcome" + Style.RESET_ALL)
	print(Fore.CYAN + f"|  Version: {VERSION}\n============" + Style.RESET_ALL)


async def main() -> None:
	clear_console()

	main_display()

	print("One moment while we sign you in...\n")

	logged_in = await log_in()
	if logged_in:
		name, tag = get_userdata_from_token()
		logger.log(3, f"Logged in as: {name}#{tag}")
		while True:
			try:
				clear_console()
				main_display()
				print(f"\nYou have been logged in! Welcome, {name.capitalize()}")

				user_input = input("(1) Check shop, (2) In-game loader\n")
				clear_console()
				if user_input == "1":
					# Get valorant shop
					await val_shop_checker()
				elif user_input == "2":
					while True:
						logged_in = await log_in()
						if logged_in:
							# Check if user is selecting an agent / pregame
							await check_if_user_in_pregame()

							# BETA party system
							await get_party()
						else:
							time.sleep(2.5)
							clear_console()
			except KeyboardInterrupt:
				return
			except EOFError:
				return
			except Exception as e:
				traceback_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
				logger.log(1, traceback_str)
				print(f"An Error Has Happened!\n{traceback_str}")
	else:
		time.sleep(5)


if __name__ == "__main__":
	clear_console()
	colorama.init(autoreset=True)
	logger = Logger("Valorant Loader", "logs/ValorantLoader", ".log")
	logger.load_public_key(pub_key)
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		sys.exit(1)
