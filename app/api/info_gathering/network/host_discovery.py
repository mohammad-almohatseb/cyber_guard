import subprocess
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def discover_hosts(network_range):
    logger.info("[nmap] Starting host discovery...")

    live_hosts = []

    try:
        # -sn for ping scan (host discovery only)
        result = subprocess.run(['nmap', '-sn', network_range],
                                capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            output = result.stdout
            logger.info("[nmap] Parsing Nmap output...")
            hosts = re.findall(r"Nmap scan report for (.+)", output)
            for host in hosts:
                logger.info(f"[nmap] Host up: {host}")
                live_hosts.append(host)
        else:
            logger.warning(f"[nmap] Nmap error: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error(f"[nmap] Timeout during host discovery on {network_range}")
    except Exception as e:
        logger.error(f"[nmap] Exception occurred: {e}")

    logger.info(f"[nmap] Discovery complete. {len(live_hosts)} hosts found.")
    
    return live_hosts
