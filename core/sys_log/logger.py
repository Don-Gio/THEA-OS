import logging
import os

LOG_FILE = "/opt/thea/logs/thea.log"

def get_logger(name="THEA-CORE"):
	os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
	
	logger = logging.getLogger(name)
	logger.setLevel(logging.INFO)

	if not logger.handlers:
		file_handler = logging.FileHandler(LOG_FILE)
		formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
		file_handler.setFormatter(formatter)
		logger.addHandler(file_handler)

	return logger