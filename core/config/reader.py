import configparser
import os

DEFAULT_CONFIG_PATH = "/etc/thea/thea.conf"

def load_config(config_path=DEFAULT_CONFIG_PATH):
	config = configparser.ConfigParser()
	if not os.path.exists(config_path):
		raise FileNotFoundError(f"Fichier de configuration introuvable : {config_path}")
	config.read(config_path)
	return config