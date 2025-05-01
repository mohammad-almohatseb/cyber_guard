import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def detect_services(host, port_range="1-1000"):
    logger.info(f"[nmap] Detecting services on host: {host}")

    services = []

    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-p', port_range, '-sV', '--open', '--unprivileged', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            logger.error(f"[nmap] Timeout during service detection on {host}")
            process.kill()
            return (host, [])

        if process.returncode == 0:
            output = stdout.decode()
            for line in output.splitlines():
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    port = parts[0]        # e.g., 22/tcp
                    service = ' '.join(parts[2:])  # e.g., ssh OpenSSH 7.4
                    services.append(f"{port}: {service}")
            logger.info(f"[nmap] Services detected on {host}: {services}")
        else:
            logger.warning(f"[nmap] Error during service detection on {host}: {stderr.decode().strip()}")

    except Exception as e:
        logger.error(f"[nmap] Exception during service detection on {host}: {e}")

    return (host, services)


async def scan_hosts(host_list, port_range="1-1000"):
    tasks = [detect_services(host, port_range) for host in host_list]
    return await asyncio.gather(*tasks)

