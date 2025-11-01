import xml.etree.ElementTree as ET
import json
from typing import Dict, List, Any

# --- Simulasi Output Nmap XML ---
NMAP_XML_OUTPUT = """
<nmaprun scanner="nmap">
<host starttime="1678886400">
<address addr="192.168.1.100" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port>
<port protocol="tcp" portid="3306"><state state="filtered" reason="no-response"/></port>
</ports>
</host>
</nmaprun>
"""

# --- Fungsi Parsing dan Integrasi ---

def parse_nmap_xml(xml_data: str) -> List[Dict]:
    """
    Mengurai output XML Nmap untuk mendapatkan status port yang akurat.
    """
    print("[1] Mengurai Nmap XML output...")
    root = ET.fromstring(xml_data)
    scan_results = []

    for host in root.findall('host'):
        ip = host.find('address').get('addr')
        ports_data = []

        for port in host.findall('./ports/port'):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            state = port.find('state').get('state')
            
            ports_data.append({
                "port": int(port_id),
                "protocol": protocol,
                "status": state,
            })
            
        scan_results.append({
            "ip": ip,
            "ports_data": ports_data
        })
        
    return scan_results

def integrate_nmap_data(nmap_results: List[Dict], current_state: Dict) -> Dict:
    """
    Mengintegrasikan hasil Nmap yang akurat ke dalam state scanner yang ada.
    """
    print("[2] Mengintegrasikan hasil Nmap ke dalam State Scanner...")
    
    # Memperbarui data port di state (misalnya, untuk host 192.168.1.100)
    for host_data in nmap_results:
        ip = host_data['ip']
        
        if ip not in current_state['hosts']:
             current_state['hosts'][ip] = {"ports": []}
        
        # Ganti data port lama dengan data Nmap yang lebih andal
        current_state['hosts'][ip]['ports'] = host_data['ports_data']

        print(f"    [SUCCESS] Port {ip} diperbarui dengan {len(host_data['ports_data'])} entri dari Nmap.")

    return current_state

# --- Main Logic ---

def main():
    print(f"\n--- 22. EKOSISTEM DAN OPEN SOURCE CONTRIBUTION ---")
    
    # Simulasi Current State Scanner (dari Tahap 1-21)
    current_scanner_state = {
        "metadata": {"version": "2.0-Alpha"},
        "hosts": {
            "192.168.1.100": {"ports": [{"port": 80, "status": "UNKNOWN"}, {"port": 3306, "status": "OPEN"}]}, # Status UNKNOWN/OPEN ini mungkin kurang akurat
        }
    }

    # 1. Parsing Output Nmap
    nmap_parsed_data = parse_nmap_xml(NMAP_XML_OUTPUT)
    
    # 2. Integrasi Data
    updated_state = integrate_nmap_data(nmap_parsed_data, current_scanner_state)
    
    print("\n--- RINGKASAN INTEGRASI ---")
    print(json.dumps(updated_state['hosts']['192.168.1.100']['ports'], indent=2))

if __name__ == "__main__":
    main()