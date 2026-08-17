import platform
import subprocess

def get_system_info():
	info = {
		"kernel": platform.release(),
		"arch": platform.machine(),
		"hypervisor": "Unknown"
	}
	try:
		res = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True)
		if res.returncode == 0:
			virt = res.stdout.strip()
			info["hypervisor"] = "Hyper-V" if virt.lower() == "microsoft" else virt.capitalize()
	except Exception:
		pass
	return info