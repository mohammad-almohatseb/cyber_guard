import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def scan_ports(host, port_range="1-1000"):
    logger.info(f"[nmap] Scanning ports on host: {host}")

    open_ports = []

    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-p', port_range, '--open', '--unprivileged', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            logger.error(f"[nmap] Timeout during port scan on {host}")
            process.kill()
            return (host, [])

        if process.returncode == 0:
            output = stdout.decode()
            for line in output.splitlines():
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    port_info = parts[0]  # e.g., "80/tcp"
                    open_ports.append(port_info)

            logger.info(f"[nmap] Open ports on {host}: {open_ports}")
        else:
            logger.warning(f"[nmap] Error during port scan on {host}: {stderr.decode().strip()}")

    except Exception as e:
        logger.error(f"[nmap] Exception during port scan on {host}: {e}")

    return (host, open_ports)


async def scan_hosts(host_list, port_range="1-1000"):
    tasks = [scan_ports(host, port_range) for host in host_list]
    return await asyncio.gather(*tasks)


