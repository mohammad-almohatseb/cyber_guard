import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def check_firewall(host: str) -> list[dict]:
    logger.info(f"[Firewall Check] Checking firewall status on host: {host}")
    firewall_detected = False

    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-Pn', '-p', '1-1000', '--open', '--unprivileged', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            logger.error(f"[Firewall Check] Timeout during firewall detection on {host}")
            process.kill()
            return [{
                'host': host,
                'firewall_detected': None,
                'error': 'Timeout',
                
            }]

        output = stdout.decode()
        error_msg = stderr.decode().strip()

        if process.returncode == 0:
            # Enhanced detection logic
            suspicious_keywords = [
                "filtered",
                "0 open ports",
                "All 1000 scanned ports",
                "host seems down",
                "no response"
            ]
            if any(keyword in output for keyword in suspicious_keywords):
                firewall_detected = True
                logger.info(f"[Firewall Check] Firewall detected on {host}")
            else:
                logger.info(f"[Firewall Check] No firewall detected on {host}")
        else:
            logger.warning(f"[Firewall Check] Nmap error on {host}: {error_msg}")
            return [{
                'host': host,
                'firewall_detected': None,
                'error': error_msg,
                
            }]

    except Exception as e:
        logger.error(f"[Firewall Check] Exception occurred on {host}: {e}")
        return [{
            'host': host,
            'firewall_detected': None,
            'error': str(e),
           
        }]

    return [{
        'host': host,
        'firewall_detected': firewall_detected,
        'error': None,
        
    }]


async def enumerate_firewalls(hosts: list[str]) -> list[dict]:
    tasks = [check_firewall(host) for host in hosts]
    results = await asyncio.gather(*tasks)

    # Flatten list of lists
    flat_results = [item for sublist in results for item in sublist]

    for res in flat_results:
        if res["firewall_detected"] is True:
            logger.info(f" Host: {res['host']} has a firewall.")
        elif res["firewall_detected"] is False:
            logger.info(f" Host: {res['host']} does not have a firewall.")
        else:
            logger.warning(f" Host: {res['host']} could not be checked due to error: {res['error']}")

    return flat_results
