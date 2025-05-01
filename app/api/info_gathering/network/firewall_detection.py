import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def check_firewall(host):
    logger.info(f"[nmap] Checking firewall status on host: {host}")
    firewall_detected = False

    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-p', '1-1000', '--open', '--unprivileged', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            logger.error(f"[nmap] Timeout during firewall detection on {host}")
            process.kill()
            return f"{host}: False"

        if process.returncode == 0:
            output = stdout.decode()
            if "filtered" in output:
                firewall_detected = True
                logger.info(f"[nmap] Firewall detected on {host}")
            else:
                logger.info(f"[nmap] No firewall detected on {host}")
        else:
            logger.warning(f"[nmap] Nmap error during firewall scan on {host}: {stderr.decode().strip()}")
    except Exception as e:
        logger.error(f"[nmap] Exception occurred while checking firewall on {host}: {e}")
    
    return f"{host}: {firewall_detected}"

async def scan_hosts(host_list):
    tasks = [check_firewall(host) for host in host_list]
    return await asyncio.gather(*tasks)

