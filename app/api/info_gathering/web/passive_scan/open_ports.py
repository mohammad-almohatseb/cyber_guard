import subprocess
import asyncio
from utils import get_domain_from_url
from app.api.requests.request_flow import target_url
from models.information import InfoGatheringModel, OpenPort

domain = get_domain_from_url(target_url)
print(f"Extracted domain: {domain}")

async def scan_open_ports(url: str):
    """Scans open ports using Nmap and stores the results in the database."""
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
                    open_ports.append(OpenPort(port=port, service=service))

        if not open_ports:
            return {"message": "No open ports found"}

        # Store results in MongoDB
        await store_open_ports(domain, open_ports)

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

async def store_open_ports(target_domain, open_ports):
    """Stores the open ports data in the InfoGatheringModel collection."""
    info_gathering = await InfoGatheringModel.find_one({"target": target_domain})

    if not info_gathering:
        info_gathering = InfoGatheringModel(
            target=target_domain,
            target_type="network",  # Adjust for correct categorization
        )

    # Store open ports in the database
    info_gathering.open_ports = open_ports
    await info_gathering.save()
    print(f"Open ports stored in database for domain: {target_domain}")

# Example usage
if __name__ == "__main__":
    asyncio.run(scan_open_ports(domain))
