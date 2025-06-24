import subprocess
import json
import re

def search_exploit(service_name):
    try:
        result = subprocess.run(
            ['searchsploit', '--json', '--disable-colour', service_name],
            capture_output=True, text=True, check=True, timeout=10
        )
        data = json.loads(result.stdout)

        exploits = data.get("RESULTS_EXPLOIT", [])
        if not exploits:
            return []

        exploit_list = []
        for exploit in exploits:
            title = exploit.get("Title", "N/A")
            path = exploit.get("Path", "N/A")
            exploit_list.append({"title": title, "path": path})

        return exploit_list

    except Exception as e:
        print(f"[!] Error during search_exploit: {e}")
        return []

def extract_info_from_content(content, title):
    # Known exploit title to CVE mapping
    KNOWN_CVE_MAPPINGS = {
        "vsftpd 2.3.4 - Backdoor Command Execution": "CVE-2011-2523",
        "vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)": "CVE-2011-2523",
        "Apache Struts 2.3.1 - Remote Code Execution": "CVE-2017-5638",
        "ProFTPd 1.3.5 - Mod_Copy Command Execution": "CVE-2015-3306",
        # Add more mappings as needed
    }

    # 1. Try to extract CVE ID from content
    cve_match = re.search(r'CVE-\d{4}-\d+', content)
    cve = cve_match.group(0) if cve_match else KNOWN_CVE_MAPPINGS.get(title, "N/A")

    # 2. Extract description
    description = "N/A"
    
    # Try Metasploit-style description
    meta_desc = re.search(r"'Description'\s*=>\s*%q\{(.*?)\}", content, re.DOTALL)
    if meta_desc:
        description = meta_desc.group(1).strip()
    else:
        # Fallback: try comment block
        lines = content.splitlines()
        comment_lines = [line.strip('# ').strip() for line in lines if line.strip().startswith('#')]
        for line in comment_lines:
            if "description" in line.lower():
                description = line
                break
        if description == "N/A" and comment_lines:
            description = comment_lines[0]

    return cve, description

def parse_exploits(service_name, exploit_list):
    parsed_results = []

    for exploit in exploit_list:
        title = exploit["title"]
        path = exploit["path"]

        print(f"[~] Reading exploit file: {path}")
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            cve, description = extract_info_from_content(content, title)

            parsed_results.append({
                "service": service_name,
                "cve": cve,
                "description": description
            })

        except Exception as e:
            print(f"[!] Failed to process {path}: {e}")
            parsed_results.append({
                "service": service_name,
                "cve": "N/A",
                "description": f"[!] Error reading file: {e}"
            })

    return parsed_results

if __name__ == "__main__":
    service_name = "Apache Tomcat"
    exploits = search_exploit(service_name)
    results = parse_exploits(service_name, exploits)

    for r in results:
        print("\n[+] Service:", r["service"])
        print("    CVE:", r["cve"])
        print("    Description:", r["description"])
        print("-" * 60)
