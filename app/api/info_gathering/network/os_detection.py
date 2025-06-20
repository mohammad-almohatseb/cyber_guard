import asyncio
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def scan_os(host):
    logger.info(f"[nmap] Detecting OS on host: {host}")
    os_info = ""

    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-O', '-Pn', '--osscan-guess', '-sV', host,
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

        output = stdout.decode()
        error_message = stderr.decode().strip()

        if process.returncode == 0:
            # Look for the line with OS guesses
            for line in output.splitlines():
                if "OS guesses" in line or "Detected OS" in line or "Aggressive OS guesses" in line:
                    # Example line:
                    # "OS guesses: Crestron XPanel control system (90%), Oracle VM Server 3.4.2 (Linux 4.1) (88%), ..."
                    # Extract first guess before the first comma
                    guesses_part = line.split(":", 1)[1].strip()
                    # Split by comma to get individual guesses
                    guesses = guesses_part.split(",")
                    if guesses:
                        # Clean up the first guess string
                        top_guess = guesses[0].strip()
                        # Optionally, remove confidence percent (parentheses) if you want just name
                        os_info = re.sub(r"\s*\(\d+%\)", "", top_guess)
                        break
                elif "OS details" in line or "Running:" in line or "Service Info" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        os_info = parts[1].strip()
                        break
                elif "Ubuntu" in line:
                    os_info = "Ubuntu (from service detection)"
                    break

            if not os_info:
                if "No exact OS matches" in output:
                    os_info = "No exact match - try adjusting flags or ensure full probe access"
                    logger.warning(f"[nmap] OS not detected exactly on {host}")
                else:
                    logger.info(f"[nmap] OS detection failed for {host}")
                    logger.debug(f"[nmap] Full Nmap output:\n{output}")
            else:
                logger.info(f"[nmap] Detected OS on {host}: {os_info}")

        else:
            logger.warning(f"[nmap] Error during OS detection on {host}: {error_message}")
            if "os detection failed" in error_message.lower():
                logger.warning(f"[nmap] OS detection failure details for {host}: {error_message}")

    except Exception as e:
        logger.error(f"[nmap] Exception during OS detection on {host}: {e}")

    return {
        "host": host,
        "os_info": os_info if os_info else "Unknown"
    }

# Example usage
if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) != 2:
            print("Usage: python3 scan_os.py <target_ip>")
            return
        host = sys.argv[1]
        result = await scan_os(host)
        print(result)

    asyncio.run(main())
