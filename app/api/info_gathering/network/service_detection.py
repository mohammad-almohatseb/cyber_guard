import asyncio, logging, re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- helpers -----------------------------------------------------------
IP_REGEX = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

def sanitize_target(raw: str) -> str:
    """Extract the bare IP or hostname (strip parentheses, spaces)."""
    ip_match = IP_REGEX.search(raw)
    return ip_match.group(0) if ip_match else raw.split()[0]

def dedup_ports(port_range: str) -> str:
    ports = set(p.strip() for p in port_range.split(',') if p.strip())
    return ','.join(sorted(ports, key=lambda x: (x.count('-'), x)))

# --- main --------------------------------------------------------------
async def scan_open_services(raw_target: str,
                             port_range: str = "1-1000,5900,5432,8180,5432",
                             timeout: int = 300) -> dict:
    target = sanitize_target(raw_target)
    ports = dedup_ports(port_range)

    cmd = ["nmap", "-p", ports, "-sV", "-T4", "--open", "-Pn", target]
    logger.info("[scan_open_services] command: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)

    except asyncio.TimeoutError:
        logger.error("[scan_open_services] timed out (%ds) for %s", timeout, target)
        return {"host": target, "services": ["Timeout"]}

    # dump stderr so you can see resolution errors or warnings
    if stderr:
        logger.warning("[nmap stderr] %s", stderr.decode().strip())

    services = []
    for line in stdout.decode().splitlines():
        if "/tcp" in line or "/udp" in line:
            cols = line.split()
            if len(cols) >= 3 and cols[1] == "open":
                services.append({"port": cols[0], "service": " ".join(cols[2:])})

    logger.info("[scan_open_services] %d services found on %s", len(services), target)
    return {"host": target, "services": services or ["None"]}
