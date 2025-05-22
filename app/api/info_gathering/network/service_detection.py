import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def detect_services(host, port_range="1-1000") -> list:
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
            return [{"host": host, "services": ["Timeout"]}]

        if process.returncode == 0:
            output = stdout.decode()
            for line in output.splitlines():
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    port = parts[0]
                    service = ' '.join(parts[2:])
                    services.append(f"{port}: {service}")
            logger.info(f"[nmap] Services detected on {host}: {services}")
        else:
            error_msg = stderr.decode().strip()
            logger.warning(f"[nmap] Error during service detection on {host}: {error_msg}")
            return [{"host": host, "services": [f"Error: {error_msg}"]}]

    except Exception as e:
        logger.error(f"[nmap] Exception during service detection on {host}: {e}")
        return [{"host": host, "services": [f"Exception: {e}"]}]

    return {"host": host, "services": services}
