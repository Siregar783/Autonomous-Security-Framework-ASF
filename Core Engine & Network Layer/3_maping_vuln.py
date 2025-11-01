import asyncio
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# --- Konfigurasi ---
TIMEOUT = 3.0
MAX_WORKERS = 20
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# --- Database Simulasi CVE (Common Vulnerabilities and Exposures) ---
# Scanner expert membandingkan versi yang ditemukan dengan database ini.
SIMULATED_CVE_DB = {
    "Apache/2.4.41": {"id": "CVE-2019-0211", "severity": "HIGH", "desc": "Local privilege escalation."},
    "Nginx/1.18.0": {"id": "CVE-2020-20984", "severity": "MEDIUM", "desc": "Memory buffer overflow."}
}

# --- Fungsi Requests (Sinkron - Blocking I/O) ---

def http_vulnerability_check_sync(ip: str, port: int) -> Dict:
    """
    Melakukan Banner Grabbing dan mengecek kerentanan Server Header Disclosure.
    Fungsi ini SINKRON dan akan dijalankan di thread.
    """
    url = f"http://{ip}:{port}"
    vulnerability_report = {
        "ip": ip,
        "port": port,
        "url": url,
        "banner": "N/A",
        "cve_match": None,
        "disclosure_active": False
    }

    try:
        # 1. SERVICE BANNER GRABBING (Mendapatkan header)
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        
        # Mengambil header 'Server'
        server_banner = response.headers.get('Server', 'Not Disclosed')
        vulnerability_report['banner'] = server_banner

        # 2. VERIFIKASI KERENTANAN HEADER DISCLOSURE
        if server_banner != 'Not Disclosed':
            vulnerability_report['disclosure_active'] = True
            
            # 3. MAPPING KERENTANAN (Simulasi CVE)
            for known_banner, cve_data in SIMULATED_CVE_DB.items():
                if known_banner in server_banner:
                    vulnerability_report['cve_match'] = cve_data
                    break
        
    except requests.exceptions.RequestException:
        vulnerability_report['banner'] = "Connection Failed or Timed Out"
        
    return vulnerability_report

# --- Fungsi Asinkron (Orkestrasi) ---

async def run_verification_task(ip: str, port: int) -> Dict:
    """
    Menjalankan pengecekan kerentanan HTTP secara asinkron.
    """
    loop = asyncio.get_running_loop()
    
    # Menjalankan fungsi Requests (sinkron) di thread pool
    result = await loop.run_in_executor(
        executor, 
        http_vulnerability_check_sync, 
        ip, 
        port
    )
    return result

async def main_verification_engine(open_ports: List[Dict]):
    """
    Fungsi utama untuk menjalankan Verification Engine.
    """
    print(f"\n--- 3. VERIFICATION ENGINE (Requests + Asyncio) ---")
    
    # Filter hanya port yang mungkin menjalankan layanan HTTP
    http_targets = [
        p for p in open_ports 
        if p.get('service') in ['HTTP/Web', 'HTTPS/Web']
    ]
    
    if not http_targets:
        print("[INFO] Tidak ada target HTTP/HTTPS untuk diverifikasi.")
        executor.shutdown(wait=False)
        return []

    print(f"[INFO] Memverifikasi {len(http_targets)} target HTTP/HTTPS...")
    
    verification_tasks = [
        run_verification_task(target['ip'], target['port']) 
        for target in http_targets
    ]
            
    results = await asyncio.gather(*verification_tasks)
    executor.shutdown(wait=False)
    
    return results

# --- Simulasi Integrasi dari Step 2 ---

async def main():
    # Simulasi hasil 'open_ports_results' dari Tahap 2
    simulated_open_ports = [
        {"ip": "192.168.1.1", "port": 80, "service": "HTTP/Web"},
        {"ip": "192.168.1.1", "port": 443, "service": "HTTPS/Web"},
        {"ip": "192.168.1.100", "port": 8080, "service": "HTTP/Web"}, # Misal ini server Apache rentan
        {"ip": "192.168.1.5", "port": 80, "service": "HTTP/Web"}, # Misal ini server Nginx rentan
        {"ip": "10.0.0.1", "port": 22, "service": "SSH"}, # SSH tidak dicek di sini, dilewati
    ]
    
    print(f"--- SIMULASI INPUT DARI STEP 2: {len(simulated_open_ports)} PORT TERBUKA DENGAN LAYANAN ---")

    # Override banner untuk simulasi CVE match
    def get_simulated_banner(ip):
        if ip == "192.168.1.100": return "Apache/2.4.41"
        if ip == "192.168.1.5": return "Nginx/1.18.0"
        return "Microsoft-IIS/10.0" # Banner lain

    # Override fungsi Requests untuk simulasi banner
    original_get = requests.get
    def mock_get(*args, **kwargs):
        class MockResponse:
            status_code = 200
            headers = {'Server': get_simulated_banner(ipaddress.urlparse(args[0]).hostname)}
            content = b"<html>Body</html>"
            def raise_for_status(self): pass
        return MockResponse()

    # Menerapkan mock hanya untuk demonstrasi di sini
    requests.get = mock_get 
    
    verification_results = await main_verification_engine(simulated_open_ports)
    
    # Kembalikan fungsi requests asli (penting jika kode ini dijalankan di lingkungan yang lebih besar)
    requests.get = original_get

    print("\n--- RINGKASAN VERIFIKASI KERENTANAN (Header Disclosure) ---")
    for result in verification_results:
        print(f"\n[TARGET] {result['ip']}:{result['port']} ({result['url']})")
        print(f"  - Banner Ditemukan: {result['banner']}")
        print(f"  - Disclosure AKTIF: {'✅ YA' if result['disclosure_active'] else '❌ TIDAK'}")
        
        if result['cve_match']:
            cve = result['cve_match']
            print(f"  - 🔥 CVE MATCH! ID: {cve['id']}, Severity: {cve['severity']}, Deskripsi: {cve['desc']}")
        else:
            print("  - 🟢 CVE Match: Tidak ada CVE spesifik yang ditemukan untuk versi ini (mungkin aman atau membutuhkan analisis manual).")
    
    print("---------------------------------------------------------------")


if __name__ == "__main__":
    asyncio.run(main())