import asyncio
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
# import ipaddress Dihapus, karena sebenarnya yang dipakai adalah urllib.parse,
# tapi karena hanya digunakan di fungsi mock, kita ganti yang lebih tepat

# Mengganti import ipaddress dengan urllib.parse
from urllib.parse import urlparse

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
        # Tambahkan verifikasi HTTPS pada port umum 443
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{ip}:{port}"
        # Tambahkan verifikasi SSL (verify=False) jika tujuannya port 443, 
        # namun untuk scanning umum lebih aman menggunakan verify=True atau menangani exception.
        # Untuk simulasi sederhana, biarkan requests.get yang akan menangani
        # koneksi HTTP/HTTPS, kita fokus di logicnya.

        # Mengupdate URL di report (penting jika ada redirect atau modifikasi protokol)
        vulnerability_report['url'] = url 
        
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False) 
        
        # Mengambil header 'Server'
        server_banner = response.headers.get('Server', 'Not Disclosed')
        vulnerability_report['banner'] = server_banner

        # 2. VERIFIKASI KERENTANAN HEADER DISCLOSURE
        if server_banner != 'Not Disclosed':
            vulnerability_report['disclosure_active'] = True
            
            # 3. MAPPING KERENTANAN (Simulasi CVE)
            for known_banner, cve_data in SIMULATED_CVE_DB.items():
                # Memastikan pencocokan substring 'Apache/2.4.41' dalam 'Apache/2.4.41 (Ubuntu)'
                if known_banner in server_banner: 
                    vulnerability_report['cve_match'] = cve_data
                    break
        
    # Tambahkan penanganan untuk kesalahan sertifikat SSL (hanya relevan jika verify=True)
    except requests.exceptions.SSLError:
        vulnerability_report['banner'] = "SSL Error or Misconfiguration"
    except requests.exceptions.RequestException as e:
        # Menangkap semua kesalahan requests lainnya (Timeout, Connection Refused, dll.)
        vulnerability_report['banner'] = f"Connection Failed or Timed Out ({type(e).__name__})"
        
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
    
    # Filter hanya port yang mungkin menjalankan layanan HTTP/HTTPS
    http_targets = [
        p for p in open_ports 
        if p.get('service') in ['HTTP/Web', 'HTTPS/Web']
    ]
    
    if not http_targets:
        print("[INFO] Tidak ada target HTTP/HTTPS untuk diverifikasi.")
        # Executor hanya di-shutdown di akhir main() untuk memastikan semua task selesai
        return []

    print(f"[INFO] Memverifikasi {len(http_targets)} target HTTP/HTTPS...")
    
    verification_tasks = [
        run_verification_task(target['ip'], target['port']) 
        for target in http_targets
    ]
            
    results = await asyncio.gather(*verification_tasks)
    
    # Jangan lakukan shutdown di sini, biarkan fungsi main yang menanganinya
    # executor.shutdown(wait=False)
    
    return results

# --- Simulasi Integrasi dari Step 2 ---

async def main():
    # Simulasi hasil 'open_ports_results' dari Tahap 2
    simulated_open_ports = [
        {"ip": "192.168.1.1", "port": 80, "service": "HTTP/Web"},
        {"ip": "192.168.1.1", "port": 443, "service": "HTTPS/Web"}, # Menambahkan HTTPS
        {"ip": "192.168.1.100", "port": 8080, "service": "HTTP/Web"}, # Misal ini server Apache rentan
        {"ip": "192.168.1.5", "port": 80, "service": "HTTP/Web"}, # Misal ini server Nginx rentan
        {"ip": "10.0.0.1", "port": 22, "service": "SSH"}, # SSH tidak dicek di sini, dilewati
    ]
    
    print(f"--- SIMULASI INPUT DARI STEP 2: {len(simulated_open_ports)} PORT TERBUKA DENGAN LAYANAN ---")

    # Override banner untuk simulasi CVE match
    def get_simulated_banner(ip):
        if ip == "192.168.1.100": return "Apache/2.4.41 (Ubuntu)" # Contoh banner lebih lengkap
        if ip == "192.168.1.5": return "Nginx/1.18.0"
        return "Microsoft-IIS/10.0" # Banner lain

    # Override fungsi Requests untuk simulasi banner
    original_get = requests.get
    def mock_get(*args, **kwargs):
        class MockResponse:
            status_code = 200
            # Menggunakan urlparse untuk mendapatkan hostname dari URL
            hostname = urlparse(args[0]).hostname 
            headers = {'Server': get_simulated_banner(hostname)}
            content = b"<html>Body</html>"
            def raise_for_status(self): pass
        return MockResponse()

    # Menerapkan mock hanya untuk demonstrasi di sini
    requests.get = mock_get 
    
    verification_results = await main_verification_engine(simulated_open_ports)
    
    # Kembalikan fungsi requests asli (penting jika kode ini dijalankan di lingkungan yang lebih besar)
    requests.get = original_get
    
    # Tambahkan shutdown executor setelah semua task selesai
    executor.shutdown(wait=True) 

    print("\n--- RINGKASAN VERIFIKASI KERENTANAN (Header Disclosure) ---")
    for result in verification_results:
        print(f"\n[TARGET] {result['ip']}:{result['port']} ({result['url']})")
        print(f"  - **Banner Ditemukan**: {result['banner']}")
        print(f"  - **Disclosure AKTIF**: {'✅ YA' if result['disclosure_active'] else '❌ TIDAK'}")
        
        if result['cve_match']:
            cve = result['cve_match']
            print(f"  - 🔥 **CVE MATCH!** ID: {cve['id']}, Severity: {cve['severity']}, Deskripsi: {cve['desc']}")
        else:
            print("  - 🟢 CVE Match: Tidak ada CVE spesifik yang ditemukan untuk versi ini (mungkin aman atau membutuhkan analisis manual).")
    
    print("---------------------------------------------------------------")


if __name__ == "__main__":
    # Penting: Error 'Module 'ipaddress' has no attribute 'urlparse'' telah diperbaiki
    # dengan mengganti 'ipaddress' menjadi 'urllib.parse' di awal kode dan di fungsi 'mock_get'.
    # Selain itu, penambahan 'verify=False' pada requests.get di http_vulnerability_check_sync
    # memungkinkan pengujian koneksi ke 443 (HTTPS) meskipun ini bukan praktik terbaik
    # di lingkungan produksi nyata.
    asyncio.run(main())