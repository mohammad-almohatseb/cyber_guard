import subprocess
import asyncio
from utils import get_domain_from_url
from app.api.requests.request_flow import target_url

# Extract domain
domain = get_domain_from_url(target_url)
print(f"Extracted domain: {domain}")

# Async function to scan open ports
async def scan_open_ports(url: str):
    try:
        domain = get_domain_from_url(url)

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

        return {
            "service": "open_ports",
            "target": domain,
            "results": open_ports
        }

    except ValueError as e:
        return {"error": str(e)}
    except subprocess.CalledProcessError:
        return {"error": "Nmap scan failed"}
    except subprocess.TimeoutExpired:
        return {"error": "Nmap scan timed out"}
    except Exception as e:
        return {"error": str(e)}

# Main execution
if __name__ == "__main__":
    parsed_domain = get_domain_from_url(target_url)
    result = asyncio.run(scan_open_ports(parsed_domain))

    print("Open ports found:", result.get("results", []))
    print("Total number of open ports:", len(result.get("results", [])))
