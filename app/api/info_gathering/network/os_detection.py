import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def scan_os(host):
    logger.info(f"[nmap] Detecting OS on host: {host}")
    os_info = ""

    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-O', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        except asyncio.TimeoutError:
            logger.error(f"[nmap] Timeout during OS detection on {host}")
            process.kill()
            return {
                "host": host,
                "os_info": "Timeout"
            }

        if process.returncode == 0:
            output = stdout.decode()
            for line in output.splitlines():
                if "OS details" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        os_info = parts[1].strip()
                    else:
                        logger.warning(f"[nmap] Unexpected OS details format for {host}: {line}")
            if os_info:
                logger.info(f"[nmap] Detected OS on {host}: {os_info}")
            else:
                logger.info(f"[nmap] OS detection failed for {host}")
        else:
            error_message = stderr.decode().strip()
            logger.warning(f"[nmap] Error during OS detection on {host}: {error_message}")
            if "os detection failed" in error_message.lower():
                logger.warning(f"[nmap] OS detection failure details for {host}: {error_message}")

    except Exception as e:
        logger.error(f"[nmap] Exception during OS detection on {host}: {e}")

    return {
        "host": host,
        "os_info": os_info if os_info else "Unknown"
    }


