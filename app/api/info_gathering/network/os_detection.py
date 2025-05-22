import asyncio
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_version_range(start_version, end_version):
    """Generate a list of versions between start_version and end_version."""
    start_parts = [int(part) for part in start_version.split('.')]
    end_parts = [int(part) for part in end_version.split('.')]

    versions = []
    while start_parts <= end_parts:
        version = '.'.join(map(str, start_parts))
        versions.append(version)
        start_parts[1] += 1
        if start_parts[1] > 9:
            start_parts[0] += 1
            start_parts[1] = 0
    return versions

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
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            logger.error(f"[nmap] Timeout during OS detection on {host}")
            process.kill()
            return [{
                "host": host,
                "os_info": "Timeout",
                "urls": []
            }]

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

    # Build URLs based on version ranges
    urls = []
    if os_info:
        os_info_cleaned = re.sub(r'[^0-9,.\-]', '', os_info)
        version_ranges = os_info_cleaned.split(",")
        for version_range in version_ranges:
            version_range = version_range.strip()
            if '-' in version_range:
                start_version, end_version = version_range.split("-")
                start_version = start_version.strip()
                end_version = end_version.strip()

                versions = generate_version_range(start_version, end_version)
                for version in versions:
                    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Linux+{version.replace(' ', '+')}"
                    urls.append(url)
            else:
                version = version_range.strip()
                if version:
                    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Linux+{version.replace(' ', '+')}"
                    urls.append(url)

    result = {
        "host": host,
        "os_info": os_info if os_info else "Unknown",
        "urls": urls
    }

    return result  
