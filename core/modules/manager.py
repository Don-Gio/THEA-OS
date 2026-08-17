import os

MODULES_DIR = "/opt/thea/modules"

def list_modules():
	if not os.path.exists(MODULES_DIR):
		return[]
	modules = []
	for item in os.listdir(MODULES_DIR):
		item_path = os.path.join(MODULES_DIR, item)
		if os.path.isdir(item_path) and not item.startswith('.'):
			modules.append(item)
	return sorted(modules)