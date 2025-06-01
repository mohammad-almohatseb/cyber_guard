import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_open_ports(domain: str):
    logger.info(f"[open_ports] Starting Nmap scan for: {domain}")

    try:
        process = await asyncio.create_subprocess_exec(
            "nmap", "-p1-1000", "-T4", "--open", "-Pn", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

        output = stdout.decode()
        open_ports = []

        for line in output.splitlines():
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    port = parts[0]
                    service = " ".join(parts[2:])
                    open_ports.append({"domain":domain, "port": port, "service": service })

        if not open_ports:
            logger.info(f"[open_ports] No open ports found for {domain}")
        else:
            logger.info(f"[open_ports] Open ports for {domain}: {open_ports}")

        return open_ports

    except asyncio.TimeoutError:
        logger.error(f"[open_ports] Nmap scan timed out for {domain}")
        return []

    except Exception as e:
        logger.error(f"[open_ports] Unexpected error for {domain}: {e}")
        return []
