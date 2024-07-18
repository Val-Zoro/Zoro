import asyncio
import threading
import time
import os
import configparser
import colorama

import aioconsole
import json
import urllib.request
import argparse
import requests

from requests import session as sesh, get
from ssl import PROTOCOL_TLSv1_2
from auth import RiotAuth, RiotAuthError
from urllib3 import PoolManager
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry  # noqa
from pathlib import Path
from tkinter import Tk, Canvas, Entry, Label, Button, PhotoImage
from PIL import ImageTk, Image
from io import BytesIO
from datetime import date
from rich.table import Table, box
from rich.console import Console

val_token = ""
val_access_token = ""
val_user_id = ""
val_entitlements_token = ""
val_uuid = ""
region = ""

internal_api_headers = {}
internal_api_headers_console = {}

cache = {}
our_team_colour = ""

config = configparser.ConfigParser()
parentdir = os.path.dirname(__file__)
config.read("/".join([parentdir, "config.ini"]))

parser = argparse.ArgumentParser()
parser.add_argument("-g", "--gui", help="Display or not the GUI window")
args = vars(parser.parse_args())

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path("./assets")

auth = RiotAuth()


def url_image(link, size, skinname):
	longs = ['vandal', 'phantom', 'operator', 'shorty', 'frenzy', 'sheriff', 'ghost', 'stinger', 'spectre', 'bucky', 'judge', 'bulldog', 'marshall', 'ares', 'odin', 'guardian']
	theweapon = (skinname.split(" ")[-1:][0]).lower()
	checklong = theweapon in longs
	if checklong:  # weapons
		pixels_x, pixels_y = 150, 45
	else:
		if size == 'big':  # bundle
			pixels_x, pixels_y = 547, 237
		else:  # melees
			pixels_x, pixels_y = 100, 45
	with urllib.request.urlopen(link) as u:
		raw_data = u.read()
	image = Image.open(BytesIO(raw_data)).resize((pixels_x, pixels_y))
	return ImageTk.PhotoImage(image)


def relative_to_assets(path: str) -> Path:
	return ASSETS_PATH / Path(path)


class TLSAdapter(HTTPAdapter):
	def init_poolmanager(self, connections, maxsize, block=False):
		self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, ssl_version=PROTOCOL_TLSv1_2)


def convert_time(sec):
	days = sec // (24 * 3600)
	sec %= (24 * 3600)
	hours = sec // 3600
	sec %= 3600
	minutes = sec // 60
	sec %= 60
	return "%d:%02d:%02d:%02d" % (days, hours, minutes, sec)


def price_retriver(skinUuid, offers_data):
	for row in offers_data["Offers"]:
		if row["OfferID"] == skinUuid:
			for cost in row["Cost"]:
				return row["Cost"][cost]


def MainGui(vp: int = 0, rp: int = 0):
	window = Tk()
	window.geometry("779x417")
	window.configure(bg="#081527")
	window.title('Valorant Store Watcher')

	dailyshop = json.load(open("/".join([parentdir, 'dailyshop.json'])))
	bundle_name = dailyshop['Bundle']['bundle_name']
	bundle_image = dailyshop['Bundle']['bundle_image']
	bundle_price = dailyshop['Bundle']['bundle_price']
	skin1_image = dailyshop['Skins']['skin1']['skin1_image']
	skin1_name = dailyshop['Skins']['skin1']['skin1_name']
	skin1_price = dailyshop['Skins']['skin1']['skin1_price']
	skin2_image = dailyshop['Skins']['skin2']['skin2_image']
	skin2_name = dailyshop['Skins']['skin2']['skin2_name']
	skin2_price = dailyshop['Skins']['skin2']['skin2_price']
	skin3_image = dailyshop['Skins']['skin3']['skin3_image']
	skin3_name = dailyshop['Skins']['skin3']['skin3_name']
	skin3_price = dailyshop['Skins']['skin3']['skin3_price']
	skin4_image = dailyshop['Skins']['skin4']['skin4_image']
	skin4_name = dailyshop['Skins']['skin4']['skin4_name']
	skin4_price = dailyshop['Skins']['skin4']['skin4_price']
	valorant_points_amount = vp
	radianite_points_amount = rp
	'''
	def NightMarketPage():
		offer1 = [dailyshop['NightMarket']['skin1']['name'], dailyshop['NightMarket']['skin1']['price'], dailyshop['NightMarket']['skin1']['icon']]
		offer2 = [dailyshop['NightMarket']['skin2']['name'], dailyshop['NightMarket']['skin2']['price']]
		offer3 = [dailyshop['NightMarket']['skin3']['name'], dailyshop['NightMarket']['skin3']['price']]
		offer4 = [dailyshop['NightMarket']['skin4']['name'], dailyshop['NightMarket']['skin4']['price']]
		offer5 = [dailyshop['NightMarket']['skin5']['name'], dailyshop['NightMarket']['skin5']['price']]
		offer6 = [dailyshop['NightMarket']['skin6']['name'], dailyshop['NightMarket']['skin6']['price']]
		nmwind = Tk()
		nmwind.geometry("779x417")
		nmwind.configure(bg="#081527")
		nmwind.title('Night Market')
		canvas = Canvas(
			nmwind,
			bg="#081527",
			height=417,
			width=779,
			bd=0,
			highlightthickness=0,
			relief="ridge"
		)
		canvas.create_text(
			250,
			10,
			anchor="nw",
			text="NIGHT.MARKET",
			fill="white",
			font=("Passion One Bold", 48 * -1)
		)
		canvas.create_text(
			320,
			60,
			anchor="nw",
			text=f"ends in TOT hours",
			fill="white",
			font=("Passion One Bold", 20 * -1)
		)
		canvas.place(x=0, y=0)
		if offer1[0] == 'NONE':
			canvas.create_text(
				120,
				200,
				anchor="nw",
				text="NIGHT MARKET NOT AVAILABLE",
				fill="#DC3D4B",
				font=("VALORANT", 32 * -1)
			)
		else:
			# page work in progess
			print(offer1[0], '|', offer1[1])
			print(offer2[0], '|', offer2[1])
			print(offer3[0], '|', offer3[1])
			print(offer4[0], '|', offer4[1])
			print(offer5[0], '|', offer5[1])
			print(offer6[0], '|', offer6[1])
		nmwind.resizable(False, False)
		nmwind.mainloop()
	'''
	canvas = Canvas(
		window,
		bg="#081527",
		height=417,
		width=779,
		bd=0,
		highlightthickness=0,
		relief="ridge"
	)

	canvas.place(x=0, y=0)

	canvas.create_text(
		22.0,
		280.0,
		anchor="nw",
		text="VALORANT",
		fill="#DC3D4B",
		font=("VALORANT", 64 * -1)
	)

	canvas.create_text(
		197.0,
		342.0,
		anchor="nw",
		text="SHOP",
		fill="#DC3D4B",
		font=("VALORANT", 64 * -1)
	)

	'''
	button_1 = Button(
		image=image_image_0,
		borderwidth=0,
		highlightthickness=0,
		command=lambda: NightMarketPage(),
		relief="flat"
	)
	button_1.place(
		x=155.0,
		y=362.0,
	)
	'''

	image_image_1 = url_image(bundle_image, 'big', bundle_name)
	canvas.create_image(
		295.0,
		146.0,
		image=image_image_1
	)

	image_image_2 = PhotoImage(
		file=relative_to_assets("valopoints.png"))
	canvas.create_image(
		610.0,
		180.0,
		image=image_image_2
	)

	canvas.create_text(
		628.0,
		175.0,
		anchor="nw",
		text=skin2_price,
		fill="#FFFFFF",
		font=("VALORANT", 13 * -1)
	)

	image_image_3 = PhotoImage(
		file=relative_to_assets("valopoints.png"))
	canvas.create_image(
		610.0,
		300.0,
		image=image_image_3
	)

	canvas.create_text(
		628.0,
		295.0,
		anchor="nw",
		text=skin3_price,
		fill="#FFFFFF",
		font=("VALORANT", 13 * -1)
	)

	canvas.create_text(
		601.0,
		375.0,
		anchor="nw",
		text=skin3_name,
		fill="#FFFFFF",
		font=("VALORANT", 12 * -1)
	)

	canvas.create_text(
		417.0,
		375.0,
		anchor="nw",
		text=skin4_name,
		fill="#FFFFFF",
		font=("VALORANT", 12 * -1)
	)

	image_image_4 = url_image(skin1_image, 'melee', skin1_name)
	canvas.create_image(
		663.0,
		73.0,
		image=image_image_4
	)

	image_image_5 = PhotoImage(file=relative_to_assets("valopoints.png"))
	canvas.create_image(
		610.0,
		50.0,
		image=image_image_5
	)

	canvas.create_text(
		628.0,
		45.0,
		anchor="nw",
		text=skin1_price,
		fill="#FFFFFF",
		font=("VALORANT", 13 * -1)
	)

	canvas.create_text(
		681.0,
		11.0,
		anchor="nw",
		text=date.today().strftime("%d/%m/%Y"),
		fill="#FFFFFF",
		font=("VALORANT", 12 * -1)
	)

	image_image_6 = PhotoImage(
		file=relative_to_assets("valopoints.png"))
	canvas.create_image(
		64.0,
		366.0,
		image=image_image_6
	)

	image_image_7 = PhotoImage(
		file=relative_to_assets("valopoints.png"))
	canvas.create_image(
		535.0,
		244.0,
		image=image_image_7
	)

	image_image_8 = PhotoImage(
		file=relative_to_assets("radianite.png"))
	canvas.create_image(
		64.0,
		391.0,
		image=image_image_8
	)

	canvas.create_text(
		82.0,
		361.0,
		anchor="nw",
		text=valorant_points_amount,
		fill="#FFFFFF",
		font=("VALORANT", 13 * -1)
	)

	image_image_9 = PhotoImage(
		file=relative_to_assets("valopoints.png"))
	canvas.create_image(
		419.0,
		300.0,
		image=image_image_9
	)

	canvas.create_text(
		437.0,
		295.0,
		anchor="nw",
		text=skin4_price,
		fill="#FFFFFF",
		font=("VALORANT", 13 * -1)
	)

	canvas.create_text(
		486.0,
		237.0,
		anchor="nw",
		text=bundle_price,
		fill="#FFFFFF",
		font=("VALORANT", 15 * -1)
	)

	canvas.create_text(
		82.0,
		386.0,
		anchor="nw",
		text=radianite_points_amount,
		fill="#FFFFFF",
		font=("VALORANT", 13 * -1)
	)

	canvas.create_text(
		40.0,
		229.0,
		anchor="nw",
		text=bundle_name,
		fill="#FFFFFF",
		font=("VALORANT", 24 * -1)
	)

	canvas.create_text(
		601.0,
		103.0,
		anchor="nw",
		text=skin1_name,
		fill="#FFFFFF",
		font=("VALORANT", 12 * -1)
	)

	canvas.create_text(
		601.0,
		236.0,
		anchor="nw",
		text=skin2_name,
		fill="#FFFFFF",
		font=("VALORANT", 12 * -1)
	)

	image_image_10 = url_image(skin2_image, '', skin2_name)
	canvas.create_image(
		668.0,
		209.0,
		image=image_image_10
	)

	image_image_11 = url_image(skin3_image, '', skin3_name)
	canvas.create_image(
		670.9556884765625,
		341.7883071899414,
		image=image_image_11
	)

	image_image_12 = url_image(skin4_image, '', skin4_name)
	canvas.create_image(
		476.0,
		341.0,
		image=image_image_12
	)

	window.resizable(False, False)
	window.mainloop()

	with open("/".join([parentdir, 'dailyshop.json']), 'r+') as jsf:
		jsf.truncate(0)


async def log_in() -> bool:
	global region, val_token, val_access_token, val_user_id, val_entitlements_token, val_uuid
	acc = config['LOGIN']
	username = acc['riot_username']
	password = acc['password']
	region = acc['region']

	if username == "xxx" or password == "xxx" or region == "xxx":
		print(colorama.Fore.LIGHTRED_EX + f'INFO: Enter your login details in the file named "config.ini"' + colorama.Style.RESET_ALL)
		return False
	if region.lower() not in ["na", "latam", "br", "eu", "ap", "kr"]:
		print(colorama.Fore.LIGHTRED_EX + f'INFO: Region is not Valid in the file named "config.ini"\n   Valid regions are "na", "latam", "br", "eu", "ap", "kr"\n' + colorama.Style.RESET_ALL)

	CREDS = username, password
	multifactor_status = await auth.authorize(*CREDS)
	if multifactor_status:
		print(colorama.Fore.LIGHTRED_EX + "WARNING: This account requires multi-factor authentication. Because of anti bot login, the 2FA code WILL NOT be sent to your email.\nYou will require to log in on a separate device via 'https://authenticate.riotgames.com'. Once you have the code, enter it below" + colorama.Style.RESET_ALL)
	while multifactor_status is True:
		# Fetching the code must be asynchronous or blocking
		code = await aioconsole.ainput("Input 2fa code: ")
		try:
			await auth.authorize_mfa(code)
			break
		except RiotAuthError:
			print("Invalid 2fa code, please try again")
	val_token = auth.token_type
	val_access_token = auth.access_token
	val_user_id = auth.user_id
	val_entitlements_token = auth.entitlements_token
	val_uuid = auth.user_id

	'''
		with open("creds.json", "w") as f:
			json.dump({'val_token': val_token, 'val_access_token': val_access_token, 'val_uuid': val_uuid, 'val_entitlements_token': val_entitlements_token}, f, indent=4)
	'''

	return True


def get_headers():
	global internal_api_headers, internal_api_headers_console

	with requests.get("https://valorant-api.com/v1/version") as r:
		client_version = r.json()["data"]["riotClientVersion"]

	headers_pc = {
		"X-Riot-Entitlements-JWT": f"{val_entitlements_token}",
		"Authorization": f"Bearer {val_access_token}",
		"X-Riot-ClientPlatform": "ewogICAgInBsYXRmb3JtVHlwZSI6ICJQQyIsCiAgICAicGxhdGZvcm1PUyI6ICJXaW5kb3dzIiwKICAgICJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwKICAgICJwbGF0Zm9ybUNoaXBzZXQiOiAiVW5rbm93biIKfQ==",
		"X-Riot-ClientVersion": client_version
	}
	headers_console = {
		"X-Riot-Entitlements-JWT": f"{val_entitlements_token}",
		"Authorization": f"Bearer {val_access_token}",
		"X-Riot-ClientPlatform": "ewogICAgInBsYXRmb3JtVHlwZSI6ICJwbGF5c3RhdGlvbiIsCiAgICAicGxhdGZvcm1PUyI6ICJQUzUiLAogICAgInBsYXRmb3JtT1NWZXJzaW9uIjogIiIsCiAgICAicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iLAogICAgInBsYXRmb3JtRGV2aWNlIjogIiIKfQ==",
		"X-Riot-ClientVersion": client_version
	}

	internal_api_headers = headers_pc.copy()
	internal_api_headers_console = headers_console.copy()


# VALORANT STORE WATCHER
def val_shop_checker():
	# Get skins

	client_version: str = requests.get("https://valorant-api.com/v1/version").json()["data"]["riotClientBuild"]
	RiotAuth.RIOT_CLIENT_USER_AGENT = f"RiotClient/{client_version} %s (Windows;10;;Professional, x64)"

	headers = {
		'User-Agent': f"RiotClient/{client_version} %s (Windows;10;;Professional, x64)",
		'Authorization': f'Bearer {val_access_token}',
	}

	get_headers()

	session = sesh()
	session.headers = headers
	session.mount('https://', TLSAdapter())

	with requests.get(f"https://pd.na.a.pvp.net/store/v2/storefront/{val_user_id}",
	                  headers=internal_api_headers) as r:
		data = r.json()
	weapon_fetch = get(f'https://valorant-api.com/v1/weapons/skinlevels')
	weapon_fetch = weapon_fetch.json()
	of_data = get(f"https://pd.{region}.a.pvp.net/store/v1/offers/", headers=internal_api_headers)
	offers_data = of_data.json()
	# with open('offersdata.json', 'a') as f: f.write(json.dumps(offers_data, indent = 4))
	GetPoints = get(f"https://pd.na.a.pvp.net/store/v1/wallet/{val_uuid}", headers=internal_api_headers)

	vp = GetPoints.json()["Balances"]["85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741"]
	rp = GetPoints.json()["Balances"]["e59aa87c-4cbf-517a-5983-6e81511be9b7"]

	# bundles
	bundles_uuid = []  # list of current bundles
	bundle_prices = []
	feautured_bundles = data['FeaturedBundle']
	time = convert_time(feautured_bundles['BundleRemainingDurationInSeconds'])
	if len(feautured_bundles['Bundles']) > 1:
		bundles = [feautured_bundles['Bundles'][0], feautured_bundles['Bundles'][1]]
		for element in bundles:
			bundle_uuid = element['DataAssetID']
			bundles_uuid.append(bundle_uuid)
			n = 0
			all_prices = []
			for i in range(len(element['Items'])):
				bundle_item_price = element['Items'][n]['DiscountedPrice']
				all_prices.append(bundle_item_price)
				n = n + 1
			bundle_prices.append(sum(all_prices))  # price of the bundles
	else:
		bundles = [feautured_bundles['Bundle']]
		for element in bundles:
			bundle_uuid = element['DataAssetID']
			bundles_uuid.append(bundle_uuid)
			n = 0
			all_prices = []
			for i in range(len(element['Items'])):
				bundle_item_price = element['Items'][n]['DiscountedPrice']
				all_prices.append(bundle_item_price)
				n = n + 1
			bundle_prices.append(sum(all_prices))  # price of the single bundle

	# todo night market fix
	nm_price = []
	nm_offers = []
	nm_images = []
	nm_skins_id = []
	use_nm = True
	'''
	try:
		for i in data['BonusStore']['BonusStoreOffers']:
			[nm_price.append(k) for k in i['DiscountCosts'].values()]  # night market prices
		for i in data['BonusStore']['BonusStoreOffers']:
			[nm_skins_id.append(k['ItemID']) for k in i['Offer']['Rewards']]  # night market offers
	except KeyError:
		use_nm = False
		for i in range(6):
			nm_skins_id.append('NONE')
		for i in range(6):
			nm_price.append('NONE')

	for nmskinid in nm_skins_id:
		with requests.get(f'https://valorant-api.com/v1/weapons/skinlevels/{nmskinid}') as r:
			nmdata = r.json()
		nm_offers.append(nmdata['data']['displayName'])  # names of daily items
		nm_images.append(nmdata['data']['displayIcon'])  # images of daily items
	'''

	# daily shop
	singleweapons_prices = []
	daily_shop = data['SkinsPanelLayout']
	daily_items = daily_shop['SingleItemOffers']  # list of daily items
	for skin in daily_items:
		for row in weapon_fetch["data"]:
			if skin == row["uuid"]:
				skin_price = price_retriver(skin, offers_data)
				singleweapons_prices.append(skin_price)  # prices of daily items

	skin_names = []
	skin_images = []
	skin_videos = []
	for item in daily_items:
		with session.get(f'https://valorant-api.com/v1/weapons/skinlevels/{item}', headers=headers) as r:
			data = r.json()
		skin_names.append(data['data']['displayName'])  # names of daily items
		skin_images.append(data['data']['displayIcon'])  # images of daily items
		skin_videos.append(data['data']['streamedVideo'])  # videos of daily items

	bundles_images = []
	current_bundles = []
	for bundle in bundles_uuid:
		with session.get(f'https://valorant-api.com/v1/bundles/{bundle}', headers=headers) as r:
			data = r.json()
		current_bundles.append(data['data']['displayName'])  # current bundle
		bundles_images.append(data['data']['displayIcon'])  # bundle image

	# Display
	if not args['gui']:
		console = Console()
		table_one = Table(box=box.HORIZONTALS, show_header=True, header_style='bold #2070b2')
		table_one.add_column('Skin', justify='left')
		table_one.add_column('Price', justify='center')
		table_one.add_column('Visual', justify='center')
		n = 0
		for i in range(4):
			table_one.add_row(skin_names[n], str(singleweapons_prices[n]), skin_images[n])
			n = n + 1

		table_two = Table(box=box.HORIZONTALS, show_header=True, header_style='bold #2070b2')
		table_two.add_column('Bundle', justify='left')
		table_two.add_column('Price', justify='center')
		table_two.add_column('Time Left', justify='center')
		n = 0
		for i in range(len(current_bundles)):
			table_two.add_row(current_bundles[n], str(bundle_prices[n]), str(time))
			n += 1
		for i in range(4 - len(current_bundles)):
			table_two.add_row()

		table_three = Table(box=box.HORIZONTALS, show_header=True, header_style='bold #2070b2')
		table_three.add_column('Offers', justify='left')
		table_three.add_column('Price', justify='center')
		table_three.add_column('Visual', justify='center')
		n = 0
		for i in range(6):
			# table_three.add_row(nm_offers[n], str(nm_price[n]), nm_images[n])
			n = n + 1

		night_market_table = Table(box=box.HEAVY_EDGE, title='[bold]NIGHT MARKET[/bold]', show_header=True, header_style='bold #2070b2')
		night_market_table.add_row(table_three)

		table = Table(box=box.HEAVY_EDGE, show_header=True, title=f" ╔══ [bold]{get_userdata_from_id(val_uuid).capitalize()}'S DAILY STORE[/bold]\n ╠════ Valorant Points: [#2070b2]{vp} VP [/#2070b2] \n ╚══════ Radianite Points: [#2070b2] {rp} R [/#2070b2]")
		table.add_column('DAILY ITEMS', justify='center')
		table.add_column('BUNDLES', justify='center')
		table.add_row(table_one, table_two)
		console.print(table)
	# console.print(night_market_table)
	else:
		def write_json(new_data, filename="/".join([parentdir, 'dailyshop.json'])):
			with open(filename, 'r+') as file:
				file.seek(0)
				json.dump(new_data, file, indent=4)

		shop = {
			"Bundle": {
				"bundle_name": current_bundles[0],
				"bundle_image": bundles_images[0],
				"bundle_price": str(bundle_prices[0])
			},
			"Skins": {
				"skin1": {
					"skin1_name": skin_names[0],
					"skin1_image": skin_images[0],
					"skin1_price": singleweapons_prices[0],
					"skin1_video": skin_videos[0],
				},
				"skin2": {
					"skin2_name": skin_names[1],
					"skin2_image": skin_images[1],
					"skin2_price": singleweapons_prices[1],
					"skin2_video": skin_videos[1],
				},
				"skin3": {
					"skin3_name": skin_names[2],
					"skin3_image": skin_images[2],
					"skin3_price": singleweapons_prices[2],
					"skin3_video": skin_videos[2],
				},
				"skin4": {
					"skin4_name": skin_names[3],
					"skin4_image": skin_images[3],
					"skin4_price": singleweapons_prices[3],
					"skin4_video": skin_videos[3],
				}
			}
		}

		write_json(shop)
		MainGui(vp, rp)


def calculate_kd(kills, deaths):
	if deaths == 0:
		return kills  # Stop div of zero
	return round(kills / deaths, 2)


def get_userdata_from_id(user_id: str, host_player_uuid: str | None = None) -> str:
	with requests.put(f"https://pd.na.a.pvp.net/name-service/v2/players",
	                  headers=internal_api_headers, json=[user_id]) as req:
		user_info = req.json()[0]
		user_name = f"{user_info['GameName']}#{user_info['TagLine']}"
		if host_player_uuid is not None:
			if user_id == host_player_uuid:
				host_player = f"(You) {user_name}"
			else:
				host_player = user_name
		else:
			host_player = user_name

	return host_player


def get_agentdata_from_id(agent_id: str) -> str:
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


def generate_match_report(match_stats: dict, host_player_uuid: str, only_host_player: bool = False):
	all_players = match_stats['players']
	report = []
	damage_stats = {}

	for player in all_players:
		user_name = get_userdata_from_id(player['subject'])
		agent_name = get_agentdata_from_id(player['characterId'])
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
					user = get_userdata_from_id(str(rd['receiver']))
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

	with open("comp_data.json", "a") as f:
		json.dump(r.json(), f, indent=4)
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


def get_playerdata_from_uuid(user_id: str, platform: str = "PC"):
	kills = 0
	deaths = 0
	wins = []
	session = create_session()

	try:
		if platform == "PC":
			url = f"https://pd.na.a.pvp.net/match-history/v1/history/{user_id}"
			headers = internal_api_headers
		else:
			url = f"https://pd.na.a.pvp.net/match-history/v1/history/{user_id}"
			headers = internal_api_headers_console

		response = session.get(url, headers=headers)
		response.raise_for_status()  # Raise an exception for HTTP errors

		history = response.json().get("History", [])
		time.sleep(5)  # Delay to prevent rate limiting
		for i in history:
			match_id = i["MatchID"]
			match_url = f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}"
			match_response = session.get(match_url, headers=headers)
			match_response.raise_for_status()

			match_data = match_response.json()
			player_data = match_data.get("players", [])

			for match in player_data:
				if str(match["subject"]) == str(user_id):
					team = match["teamId"]
					# Get win or loss
					game_team_id = match_data["teams"][0]["teamId"]
					if str(game_team_id).lower() == str(team).lower():
						won = match_data["teams"][0]["won"]
					else:
						won = match_data["teams"][1]["won"]

					if won:
						wins.append("True")
					else:
						wins.append("False")
					kills += match["stats"]["kills"]
					deaths += match["stats"]["deaths"]

		kd_ratio = calculate_kd(kills, deaths)
		cache[user_id] = (kd_ratio, wins)
	except Exception as e:
		print(f"Error: {e}")
		cache[user_id] = (0, ['Error'])


def get_members_of_party_from_uuid(player_id: str):
	player_list = []
	print(f"Called: {player_id}")
	with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(player_id)}", headers=internal_api_headers) as r:
		try:
			if r.status_code == 400:
				is_console = str(r.json()["errorCode"]) == "PLAYER_PLATFORM_TYPE_MISMATCH"
				if is_console:
					with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(player_id)}", headers=internal_api_headers_console) as r2:
						party_id = r2.json()['CurrentPartyID']
						print("this: ", r2.json())
						input()

			else:
				print("this:", r.json())
				party_id = r.json()['CurrentPartyID']
				input()

		except Exception as e:
			raise e
			party_id = None

	if party_id is not None:
		print(party_id)
		with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}", headers=internal_api_headers) as r:
			party_data = r.json()
			print(party_data)
		for member in party_data["Members"]:
			player_name = get_userdata_from_id(str(member["Subject"]))
			player_list.append(player_name)
	else:
		player_list.clear()
		player_list.append("Player is not in a party. Player could be offline.")
	print(player_list)
	return player_list, party_id


def run_in_game(cache=None, our_team_colour: str = None):
	if cache is None:
		cache = {}
	os.system("cls")
	print("Loading...")
	while True:
		try:
			with requests.get(f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}", headers=internal_api_headers) as r:
				match_id = r.json()["MatchID"]
				break
		except:
			pass
	got_players = False
	freeze_prints = False
	message_list = []
	player_data = {}
	player_name_cache = []
	team_blue_player_list = {}
	team_red_player_list = {}

	def fetch_player_data(player_id, platform):
		get_playerdata_from_uuid(player_id, platform)

	while True:
		with requests.get(f"https://glz-na-1.na.a.pvp.net/core-game/v1/matches/{match_id}",
		                  headers=internal_api_headers) as r:
			match_data = r.json()
			try:
				match_data["State"]
			except Exception as e:
				print(f"Error: {e}")
			with open("match_data.json", "w") as f:
				json.dump(match_data, f, indent=4)

		if r.status_code != 404:
			if match_data["State"] != "CLOSED":
				# Get map ID
				map_id = match_data["MapID"]
				gamemode_name = match_data["MatchmakingData"]["QueueID"]
				# Map id to Map Name
				map_name = get_mapdata_from_id(map_id)
				if not freeze_prints:
					os.system("cls")
					print(f"Map: {map_name}")
					print(f"Game mode: {str(gamemode_name).capitalize()}")
				if not got_players:
					threads = []
					for player in match_data["Players"]:
						player_id = player["PlayerIdentity"]["Subject"]
						team_id = player["TeamID"]
						player_lvl = player["PlayerIdentity"]["AccountLevel"]

						agent_name = get_agentdata_from_id(player['CharacterID'])

						host_player = get_userdata_from_id(player_id, val_uuid)
						player_name_cache.append(host_player)

						if "console" in gamemode_name:
							rank = get_rank_from_uuid(str(player_id), "CONSOLE")
							if our_team_colour is not None:
								if str(our_team_colour) != str(team_id):
									thread = threading.Thread(target=fetch_player_data, args=(player_id, "CONSOLE"))
									threads.append(thread)
									thread.start()
							else:
								thread = threading.Thread(target=fetch_player_data, args=(player_id, "CONSOLE"))
								threads.append(thread)
								thread.start()
						else:
							rank = get_rank_from_uuid(str(player_id))
							if our_team_colour is not None:
								if str(our_team_colour) != str(team_id):
									thread = threading.Thread(target=fetch_player_data, args=(player_id, "PC"))
									threads.append(thread)
									thread.start()
							else:
								thread = threading.Thread(target=fetch_player_data, args=(player_id, "PC"))
								threads.append(thread)
								thread.start()

						if team_id.lower() == "blue":
							team_blue_player_list[host_player] = (agent_name, player_lvl, rank)
						elif team_id.lower() == "red":
							team_red_player_list[host_player] = (agent_name, player_lvl, rank)
						player_data[host_player] = cache.get(str(player_id), ("Loading", "Loading"))
				count = 0
				for player in match_data["Players"]:
					player_id = player["PlayerIdentity"]["Subject"]
					player_data[str(player_name_cache[count])] = cache.get(str(player_id), ("Loading", "Loading"))
					count += 1
				if not freeze_prints:
					message_list.append("Team Blue:")
					for user_name, data in team_blue_player_list.items():
						message_list.append(f"[LVL {data[1]}] [Rank {data[2]}] {user_name} ({data[0]})")
						try:
							kd, wins = player_data[str(user_name)]
						except:
							kd = "Loading"
							wins = "Loading"
						message_list.append(f"Player KD: {kd} | Past Matches: {wins}\n")

					message_list.append("\nVS\n\nTeam Red:")
					for user_name, data in team_red_player_list.items():
						message_list.append(f"[LVL {data[1]}] [Rank {data[2]}] {user_name}  ({data[0]})")
						kd, wins = player_data[str(user_name)]
						message_list.append(f"Player KD: {kd} | Past Matches: {wins}\n")
				got_players = True

				for i in message_list:
					print(i)
				message_list.clear()
				# Try and Get match stats
				try:
					with requests.get(f"https://pd.na.a.pvp.net/match-details/v1/matches/{match_id}",
					                  headers=internal_api_headers) as re_match_stats:
						match_stats = re_match_stats.json()
						with open("match_stats.json", "w") as f:
							json.dump(match_stats, f, indent=4)
					total_rounds = match_stats["teams"][0]["roundsPlayed"]
					team_1_rounds = match_stats["teams"][0]["roundsWon"]
					team_2_rounds = match_stats["teams"][1]["roundsWon"]
					os.system("cls")
					for i in message_list:
						print(i)
					print(f"Total Rounds: {total_rounds}")
					print(f"Score: {team_1_rounds}  |  {team_2_rounds}")
				except:
					pass
				time.sleep(5)
			else:
				os.system("cls")
				print("Match Ended!")
				print("Loading Match Report (BETA)")
				report = generate_match_report(match_stats, val_uuid, False)
				for i in report:
					print(i)
				input("\nPress any key to continue")
				break
		else:
			os.system("cls")
			print("Match Ended!")
			print("Loading Match Report (BETA)")
			report = generate_match_report(match_stats, val_uuid, False)
			for i in report:
				print(i)
			input("\nPress any key to continue")
			break


def run_pregame(data: dict):
	global cache, our_team_colour
	print("Match FOUND! Getting match details")
	got_rank = False
	got_map_and_gamemode = False
	player_data = {}
	threads = []
	rank_list = {}

	def fetch_player_data(player_id, platform):
		get_playerdata_from_uuid(player_id, platform)

	while True:
		os.system('cls')
		try:
			with requests.get(f"https://glz-na-1.na.a.pvp.net/pregame/v1/matches/{data['MatchID']}",
			                  headers=internal_api_headers) as r:
				match_data = r.json()
				with open("pre_match_data.json", "w") as f:
					json.dump(match_data, f, indent=4)

			if not got_map_and_gamemode:
				map_name = get_mapdata_from_id(match_data["MapID"])
				gamemode_name = match_data["QueueID"]
				got_map_and_gamemode = True
			print(f"Map: {map_name}")
			print(f"Game mode: {str(gamemode_name).capitalize()}\n")
			our_team_colour = match_data["AllyTeam"]["TeamID"]

			for ally_player in match_data["AllyTeam"]["Players"]:
				user_name = get_userdata_from_id(ally_player["PlayerIdentity"]["Subject"], val_uuid)
				player_level = ally_player["PlayerIdentity"]["AccountLevel"]
				# party_members, party_id = get_members_of_party_from_uuid(str(ally_player["PlayerIdentity"]["Subject"]))
				'''
				if party_id:
					if party_id not in party_tracker:
						party_tracker[party_id] = party_number
						party_number += 1
					party_num = party_tracker[party_id]
				else:
					party_num = None
				'''
				party_num = False
				try:
					agent_name = get_agentdata_from_id(ally_player["CharacterID"])
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
				if ally_player["CharacterSelectionState"] == "":
					rank = rank_list.get(str(user_name), "Failed")
					if party_num:
						print(f"({party_num}) [LVL {player_level}] [Rank {rank}] {user_name}: {agent_name} (Picking)")
					else:
						print(f"([LVL {player_level}] [Rank {rank}] {user_name}: {agent_name} (Picking)")
				elif ally_player["CharacterSelectionState"] == "selected":
					rank = rank_list.get(str(user_name), "Failed")
					if party_num:
						print(f"({party_num}) [LVL {player_level}] [Rank {rank}] {user_name}: {agent_name} (Hovering)")
					else:
						print(f"[LVL {player_level}] [Rank {rank}] {user_name}: {agent_name} (Hovering)")
				else:
					rank = rank_list.get(str(user_name), "Failed")
					if party_num:
						print(f"({party_num}) [LVL {player_level}] [Rank {rank}] {user_name}: {agent_name} (Locked)")
					else:
						print(f"[LVL {player_level}] [Rank {rank}] {user_name}: {agent_name} (Locked)")

				kd, wins = cache.get(str(ally_player["PlayerIdentity"]["Subject"]), ("Loading", "Loading"))
				print(f"Player KD: {kd} | Past Matches: {wins}\n")

			got_rank = True
			print(f"Enemy team: {match_data['EnemyTeamLockCount']}/5 LOCKED")
			if match_data["PhaseTimeRemainingNS"] == 0:
				print("In Loading Phase")
				break
			time.sleep(2)

		except Exception as e:
			raise e

	run_in_game(cache, our_team_colour)


def get_party():
	cancel = False
	os.system("cls")
	party_id = None
	while True:
		check_if_user_in_pregame()
		message_list = ["-----Party-----\n"]
		with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}", headers=internal_api_headers) as r:
			try:
				if r.status_code == 400:
					is_console = str(r.json()["errorCode"]) == "PLAYER_PLATFORM_TYPE_MISMATCH"
					if is_console:
						with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/players/{str(val_uuid)}", headers=internal_api_headers_console) as r2:
							party_id = r2.json()['CurrentPartyID']
					else:
						print(r.json())
						party_id = r.json()['CurrentPartyID']
				else:
					party_id = r.json()['CurrentPartyID']
			except Exception as e:
				raise e

		if party_id is not None:
			with requests.get(f"https://glz-na-1.na.a.pvp.net/parties/v1/parties/{party_id}", headers=internal_api_headers) as r:
				party_data = r.json()
			is_queueing = party_data["State"]
			if is_queueing == "MATCHMAKING":
				print("Queueing!")
				check_if_user_in_pregame()
				cancel = True
			is_console: bool = str(party_data["Members"][0]["PlatformType"]).lower() == "console"
			game_mode: str = str(party_data["MatchmakingData"]["QueueID"]).capitalize()
			message_list.append(f"Mode: {game_mode}\n\n")
			for member in party_data["Members"]:
				player_name = get_userdata_from_id(str(member["Subject"]), val_uuid)
				is_leader: bool = bool(member["IsOwner"])
				player_lvl: str = str(member["PlayerIdentity"]["AccountLevel"])
				if is_leader:
					message_list.append(f"[Leader] [LVL {player_lvl}] {player_name}\n")
				else:
					message_list.append(f"[{player_lvl}] {player_name}\n")
			os.system("cls")
			for i in message_list:
				print(i)
			time.sleep(0.5)
			if cancel:
				check_if_user_in_pregame()
				break
		else:
			print("Valorant is not running for that user!")
			time.sleep(3.5)
			os.system("cls")


def check_if_user_in_pregame(send_message: bool = False):
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
			os.system("cls")
			run_pregame(data)

	# Try playing in-game
	with requests.get(f"https://glz-na-1.na.a.pvp.net/core-game/v1/players/{val_uuid}",
	                  headers=internal_api_headers) as r:
		data = r.json()
	try:
		if data["errorCode"] == "RESOURCE_NOT_FOUND":
			pass
	except KeyError:
		if data["MatchID"]:
			os.system("cls")
			run_in_game()


def get_userdata_from_token() -> tuple[str, str]:
	with requests.get("https://auth.riotgames.com/userinfo", headers={"Authorization": f"Bearer {val_access_token}"}) as r:
		try:
			account_name = r.json()["acct"]["game_name"]
			account_tag = r.json()["acct"]["tag_line"]
			return account_name, account_tag
		except Exception as e:
			return "None", "None"


async def main():
	os.system("cls")
	print(colorama.Fore.BLUE + "Welcome" + colorama.Style.RESET_ALL)
	print("One moment while we sign you in...\n")
	logged_in = await log_in()
	if logged_in:
		name, tag = get_userdata_from_token()
		get_headers()
		print(f"\nYou have been logged in! Welcome, {name.capitalize()}")

		user_input = input("(1) Check shop, (2) In-game loader\n")
		if user_input == "1":
			# Get valorant shop
			val_shop_checker()
		elif user_input == "2":
			while True:
				# Check if user is selecting an agent / pregame
				check_if_user_in_pregame(False)

				# BETA party system
				get_party()


if __name__ == "__main__":

	asyncio.run(main())
