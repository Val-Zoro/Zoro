import Riot
import Logger

KEY = ("-----BEGIN PUBLIC KEY-----\n"
       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqIKYJWIl6Wif397yi3P+\n"
       "YnVZ9ExhGvuUpECU+BhpnJkP1pHJldurnKfpIdGhsiTblzlFvMS5y3wdKNmtpIW7\n"
       "8KVC8bL7FwLShmMBQNkEL4GvZfgGHYbAlJOXOiWuqDk/CS28ccZyEzAkxT4WY4H2\n"
       "BWVVBPax72ksJL2oMOxYJVZg2w3P3LbWNfcrgAC1/HPVzmuYka0IDo9TevbCwccC\n"
       "yNS3GlJ6g4E7yp8RIsFyEoq7DueHuK+zkvgpmb5eLRg8Ssq9t6bCcnx6Sl2hb4n/\n"
       "5OmRNvohCFM3WpP1vAdNxrsQT8uSuExbH4g7uDT/l5+ZdpxytzEzGdvPezmPiXhL\n"
       "5QIDAQAB\n"
       "-----END PUBLIC KEY-----")

# Log in
logger = Logger.Logger("Zoro", "logs/Zoro", ".log")
logger.load_public_key(key=KEY)

riot_auth = Riot.Auth(logger)
if riot_auth.log_in():
	# Shop
	riot_shop = Riot.Shop(riot_auth, logger)
	print(riot_shop.get_daily_shop())
	print(riot_shop.get_currency())
else:
	print("Login Failed")