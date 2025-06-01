import asyncio
import logging
import re
import subprocess
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def discover_hosts(network_range: str) -> list[dict]:
    logger.info("[nmap] Starting host discovery...")

    live_hosts = []

    try:
        result = subprocess.run(['nmap', '-sn', network_range],
                                capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            output = result.stdout
            logger.info("[nmap] Parsing Nmap output...")
            hosts = re.findall(r"Nmap scan report for (.+)", output)
            for host in hosts:
                logger.info(f"[nmap] Host up: {host}")
                live_hosts.append({'host': host})
        else:
            logger.warning(f"[nmap] Nmap error: {result.stderr}")
            return [{'error': result.stderr.strip()}]
    except subprocess.TimeoutExpired:
        logger.error(f"[nmap] Timeout during host discovery on {network_range}")
        return [{'error': 'Timeout'}]
    except Exception as e:
        logger.error(f"[nmap] Exception occurred: {e}")
        return [{'error': str(e)}]

    logger.info(f"[nmap] Discovery complete. {len(live_hosts)} hosts found.")
    return live_hosts


async def check_hosts(hosts: list[dict]) -> list[dict]:
    logger.info("Starting HTTP check on discovered hosts...")
    alive_hosts = []

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = []
        mapping = []

        for entry in hosts:
            host = entry.get("host")
            if host:
                mapping.append((host, "http"))
                tasks.append(client.get(f"http://{host}", timeout=5))
                mapping.append((host, "https"))
                tasks.append(client.get(f"https://{host}", timeout=5))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for i, response in enumerate(responses):
            host, protocol = mapping[i]

            if isinstance(response, httpx.Response) and response.status_code < 500:
                logger.info(f"[httpx] {protocol.upper()} alive: {host} [{response.status_code}]")
                alive_hosts.append({
                    "host": host,
                    "protocol": protocol,
                    "status": response.status_code,
                    "url": f"{protocol}://{host}"
                })
            elif isinstance(response, Exception):
                logger.debug(f"[httpx] Error probing {protocol}://{host}: {response}")

    logger.info(f"HTTP check complete. {len(alive_hosts)} hosts confirmed alive.")
    return alive_hosts
