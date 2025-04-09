import subprocess

async def scan_open_ports(domain: str):
    """Scans open ports using Nmap and stores the results in a list."""
    try:
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
            print("No open ports found")
        else:
            print(f"Open ports for domain {domain}: {open_ports}")

        return open_ports

    except ValueError as e:
        return {"error": str(e)}
    except subprocess.CalledProcessError:
        return {"error": "Nmap scan failed"}
    except subprocess.TimeoutExpired:
        return {"error": "Nmap scan timed out"}
    except Exception as e:
        return {"error": str(e)}
