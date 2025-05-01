import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_open_ports(domain: str):
    """Scans open ports using Nmap and stores the results in a list."""
    try:
        logger.info(f"[open_ports] Starting Nmap scan for: {domain}")

        result = subprocess.run(
            ["nmap", "-p-", "--open", "-T4", "-Pn", domain],
            capture_output=True,
            text=True,
            timeout=120
        )

        output = result.stdout
        open_ports = []

        for line in output.splitlines():
            if "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    service = parts[2]
                    open_ports.append({"port": port, "service": service})

        if not open_ports:
            logger.info(f"[open_ports] No open ports found for {domain}")
        else:
            logger.info(f"[open_ports] Open ports for {domain}: {open_ports}")

        return open_ports

    except subprocess.TimeoutExpired:
        logger.error(f"[open_ports] Nmap scan timed out for {domain}")
        return []  # Return empty list instead of dict

    except Exception as e:
        logger.error(f"[open_ports] Unexpected error for {domain}: {e}")
        return []  # Return empty list instead of dict