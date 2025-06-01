import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def scan_open_services(ip: str, port_range="1-1000"):
    logger.info(f"[scan_open_services] Starting Nmap scan for: {ip}")

    try:
        process = await asyncio.create_subprocess_exec(
            "nmap", "-p", port_range, "-sV", "-T4", "--open", "--unprivileged", "-Pn", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)

        output = stdout.decode()
        services = []

        for line in output.splitlines():
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    port = parts[0]
                    service = " ".join(parts[2:])
                    services.append({"port": port, "service": service})

        if not services:
            logger.info(f"[scan_open_services] No open services found for {ip}")
        else:
            logger.info(f"[scan_open_services] Open services for {ip}: {services}")

        return {"host": ip, "services": services}

    except asyncio.TimeoutError:
        logger.error(f"[scan_open_services] Nmap scan timed out for {ip}")
        return {"host": ip, "services": ["Timeout"]}

    except Exception as e:
        logger.error(f"[scan_open_services] Unexpected error for {ip}: {e}")
        return {"host": ip, "services": [f"Exception: {e}"]}

