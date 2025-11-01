import asyncio
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# --- Konfigurasi ---
TIMEOUT = 5.0
MAX_WORKERS = 20
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# --- Payload Tingkat Lanjut untuk Fuzzing ---
FUZZING_PAYLOADS = {
    # Payload untuk Verifikasi Reflected XSS (Mencari tag di respons)
    "XSS_TEST": "<xss-test-payload>", 
    
    # Payload untuk Verifikasi SQLi (Mencari error database di respons)
    "SQLI_TEST": "' OR 1=1 -- "
}

SQL_ERROR_PATTERNS = [
    "You have an error in your SQL syntax",
    "mysql_fetch_array()",
    "ODBC",
    "ORA-01722"
]

# --- Fungsi Fuzzing (Sinkron - Blocking I/O) ---

def perform_fuzzing_sync(target_url: str, payload_type: str, payload: str) -> Dict:
    """
    Menyuntikkan payload ke URL dan menganalisis respons untuk verifikasi.
    """
    parsed_url = urllib.parse.urlparse(target_url)
    
    # Hanya lakukan fuzzing jika ada parameter query yang dapat dimanipulasi
    if not parsed_url.query:
        return {"url": target_url, "type": payload_type, "status": "SKIPPED", "message": "No query parameters found."}

    # Asumsi: Kita menyuntikkan payload ke parameter pertama
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    # Mendapatkan nama parameter pertama
    first_param_name = next(iter(query_params)) 
    
    # Membuat URL baru dengan payload yang disuntikkan
    injected_params = query_params.copy()
    injected_params[first_param_name] = [payload] # Suntikkan payload ke parameter pertama
    
    injected_url = parsed_url._replace(query=urllib.parse.urlencode(injected_params, doseq=True)).geturl()
    
    report = {
        "url": injected_url, 
        "type": payload_type, 
        "status": "NOT VULNERABLE", 
        "vulnerability_proof": "N/A"
    }

    try:
        response = requests.get(injected_url, timeout=TIMEOUT)
        content = response.text
        
        # --- VERIFIKASI XSS (Reflected Payload) ---
        if payload_type == "XSS_TEST":
            # Mencari payload yang 'terpantul' di badan respons
            if payload in content:
                report['status'] = "VULNERABLE (XSS Reflected)"
                report['vulnerability_proof'] = f"Payload '{payload}' ditemukan dalam respons HTML."
        
        # --- VERIFIKASI SQLi (Database Error) ---
        elif payload_type == "SQLI_TEST":
            for error in SQL_ERROR_PATTERNS:
                if error.lower() in content.lower():
                    report['status'] = "VULNERABLE (SQLi Error-Based)"
                    report['vulnerability_proof'] = f"Pola error SQL '{error}' ditemukan dalam respons."
                    break
        
    except requests.exceptions.RequestException:
        report['status'] = "NETWORK ERROR"
        
    return report

# --- Fungsi Asinkron (Orkestrasi) ---

async def run_fuzzing_task(target_url: str, payload_type: str, payload: str) -> Dict:
    """Menjalankan fuzzing secara asinkron."""
    loop = asyncio.get_running_loop()
    
    result = await loop.run_in_executor(
        executor, 
        perform_fuzzing_sync, 
        target_url, 
        payload_type, 
        payload
    )
    return result

async def main_fuzzing_engine(targets_with_params: List[str]):
    """
    Fungsi utama untuk menjalankan Fuzzing Engine secara konkuren.
    """
    print(f"\n--- 5. FUZZING AND PAYLOAD INJECTION ---")
    
    fuzzing_tasks = []
    
    # Membuat task untuk setiap target dan setiap jenis payload
    for url in targets_with_params:
        for payload_type, payload in FUZZING_PAYLOADS.items():
            fuzzing_tasks.append(run_fuzzing_task(url, payload_type, payload))
            
    print(f"[INFO] Total {len(fuzzing_tasks)} fuzzing tasks dibuat.")
    
    results = await asyncio.gather(*fuzzing_tasks)
    executor.shutdown(wait=False)
    
    return [r for r in results if r['status'].startswith("VULNERABLE")] # Hanya kembalikan kerentanan


# --- Simulasi Integrasi dari Step 3 (URL yang memiliki parameter) ---

async def main():
    # Simulasi URL target yang memiliki parameter query
    simulated_fuzz_targets = [
        "http://target-a.com/search?q=test",  # Akan rentan terhadap XSS (Simulasi)
        "http://target-b.com/profile?id=123", # Akan rentan terhadap SQLi (Simulasi)
        "http://target-c.com/static"          # Tidak ada parameter, akan dilewati
    ]
    
    # --- MOCKING: Memaksa hasil rentan untuk demonstrasi ---
    original_get = requests.get
    def mock_fuzz_get(url, **kwargs):
        class MockResponse:
            status_code = 200
            text = "Normal content"
        
        # Simulate XSS Reflected vulnerability
        if "target-a.com" in url and FUZZING_PAYLOADS['XSS_TEST'] in url:
            MockResponse.text = f"Search results for: {FUZZING_PAYLOADS['XSS_TEST']}" # Payload terpantul
        
        # Simulate SQLi Error
        elif "target-b.com" in url and FUZZING_PAYLOADS['SQLI_TEST'] in url:
            MockResponse.text = "Error: You have an error in your SQL syntax" # Error database terpantul

        return MockResponse()

    requests.get = mock_fuzz_get 
    # --- END MOCKING ---

    vulnerabilities = await main_fuzzing_engine(simulated_fuzz_targets)
    
    requests.get = original_get # Kembalikan fungsi asli

    print("\n--- RINGKASAN KERENTANAN INJECTION TERVERIFIKASI ---")
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"\n[🚨 DITEMUKAN] {vuln['status']}")
            print(f"  - URL Rentan: {vuln['url']}")
            print(f"  - Tipe Payload: {vuln['type']}")
            print(f"  - Bukti (PoC): {vuln['vulnerability_proof']}")
    else:
        print("[🟢 SECURE] Tidak ada kerentanan XSS atau SQLi yang terverifikasi dalam pengujian fuzzing ini.")
        
    executor.shutdown(wait=False)
    print("----------------------------------------------------------")

if __name__ == "__main__":
    asyncio.run(main())