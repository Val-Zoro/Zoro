import base64
import os
import platform
from datetime import datetime, timedelta

import wmi
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

LEVELS = {1: "Error", 2: "Warning", 3: "Info", 4: "Debug"}
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
LOG_TIME_INTERVAL = timedelta(days=1)  # 1 day

VERSION = "v1.5.2"


# Load the public key
def load_public_key():
	try:
		with open("public_key.pem", "r") as file:
			return RSA.import_key(file.read())
	except FileNotFoundError:
		pub_key = ("-----BEGIN PUBLIC KEY-----\n"
		           "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqIKYJWIl6Wif397yi3P+\n"
		           "YnVZ9ExhGvuUpECU+BhpnJkP1pHJldurnKfpIdGhsiTblzlFvMS5y3wdKNmtpIW7\n"
		           "8KVC8bL7FwLShmMBQNkEL4GvZfgGHYbAlJOXOiWuqDk/CS28ccZyEzAkxT4WY4H2\n"
		           "BWVVBPax72ksJL2oMOxYJVZg2w3P3LbWNfcrgAC1/HPVzmuYka0IDo9TevbCwccC\n"
		           "yNS3GlJ6g4E7yp8RIsFyEoq7DueHuK+zkvgpmb5eLRg8Ssq9t6bCcnx6Sl2hb4n/\n"
		           "5OmRNvohCFM3WpP1vAdNxrsQT8uSuExbH4g7uDT/l5+ZdpxytzEzGdvPezmPiXhL\n"
		           "5QIDAQAB\n"
		           "-----END PUBLIC KEY-----")
		return RSA.import_key(pub_key)


KEY = load_public_key()


def get_sys_hwid():
	c = wmi.WMI()
	return c.Win32_ComputerSystemProduct()[0].UUID, c.Win32_BaseBoard()[0].SerialNumber


def encrypt_message(message: str, public_key) -> str:
	cipher_rsa = PKCS1_OAEP.new(public_key)

	aes_key = get_random_bytes(16)

	cipher_aes = AES.new(aes_key, AES.MODE_CBC)

	encrypted_message = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))

	encrypted_aes_key = cipher_rsa.encrypt(aes_key)

	encrypted_message = base64.b64encode(encrypted_aes_key + cipher_aes.iv + encrypted_message).decode('utf-8')

	return encrypted_message


def timestamp():
	return datetime.now()


def format_message(level: int, message: str) -> str:
	level_name = LEVELS.get(level, "Unknown")
	timestamp_str = timestamp().strftime("%Y-%m-%d %H:%M:%S")
	return f"{timestamp_str} - {level_name}: {message}"


def get_log_filename(base_name: str) -> str:
	now = timestamp()
	return f"{base_name}_{now.strftime('%Y-%m-%d')}.log"


def is_file_large(file_name: str) -> bool:
	return os.path.exists(file_name) and os.path.getsize(file_name) >= MAX_FILE_SIZE


def log_file_header(app_name, app_version):
	return (f"\n"
	        f"============================================================\n"
	        f"Application Name:    {app_name}\n"
	        f"Version:             {app_version}\n"
	        f"Log File Created:    {timestamp()}\n"
	        f"Log Levels:          [DEBUG | INFO | WARNING | ERROR]\n"
	        f"------------------------------------------------------------\n"
	        f"Hostname:            [Null]\n"
	        f"Operating System:    [{platform.system()}, {platform.version()}]\n"
	        f"HWID:                {get_sys_hwid()}\n"
	        f"------------------------------------------------------------\n"
	        f"Log Format:          [Timestamp] [Log Level] [Message]\n\n"
	        f"============================================================\n\n"
	        f"Log Start:\n")


def log(file_base_name: str, level: int, message: str) -> int:
	if level not in LEVELS:
		return -1  # Invalid level

	current_time = timestamp()
	log_filename = get_log_filename(file_base_name)

	if "/" in log_filename:
		file_path = log_filename.split("/")[0]
		if not os.path.exists(file_path):
			os.mkdir(file_path)

	# Check if the file needs to be rotated
	if is_file_large(log_filename) or (os.path.exists(log_filename) and (current_time - datetime.fromtimestamp(os.path.getmtime(log_filename))) > LOG_TIME_INTERVAL):
		log_filename = get_log_filename(file_base_name)  # Ensure new file name is generated

	try:
		if os.path.exists(log_filename):
			with open(log_filename, "a") as f:
				f.write(encrypt_message(format_message(level, message), KEY) + "\n")
		else:
			with open(log_filename, "w") as f:
				f.write(encrypt_message(log_file_header(file_base_name, VERSION), KEY) + "\n")
				f.write(encrypt_message(format_message(level, message), KEY) + "\n")

	except IOError as e:
		print(f"Error writing to log file: {e}")
		return -2  # File I/O error

	return 1  # Success
