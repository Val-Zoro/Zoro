# Logger.py

import os

from base64 import b64encode
from datetime import timedelta, datetime
from platform import system, version

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from colorama import Fore, Style


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
		self.hwid = "null"

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
			log_filename = self._get_log_filename()  # Ensure a new file name is generated

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

		print(self._format_message(level, message))

		return 1  # Success