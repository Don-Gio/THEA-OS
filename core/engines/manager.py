import os

ENGINES_DIR = "/opt/thea/engines"

def list_engines():
	if not os.path.exists(ENGINES_DIR):
		return []
	engines = []
	for item in os.listdir(ENGINES_DIR):
		item_path = os.path.join(ENGINES_DIR, item)
		if os.path.isdir(item_path) and not item.startswith('.'):
			engines.append(item)
	return sorted(engines)