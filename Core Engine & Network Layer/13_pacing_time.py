import asyncio
import httpx
import random
import time
from typing import List, Dict

# --- Konfigurasi Stealth dan Evasion ---
# Membatasi 5 request yang berjalan secara konkuren pada satu waktu (Pacing)
CONCURRENT_REQUESTS_LIMIT = 5 
# Batasan jumlah request per detik (misalnya, maksimal 2 request/detik per IP)
REQUEST_RATE_LIMIT = 0.5 

# Rotasi User-Agents populer (untuk menghindari deteksi bot)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

# Semaphore untuk membatasi konkurensi (Pacing)
semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS_LIMIT)

# --- Fungsi HTTP Asinkron dengan Stealth ---

async def check_web_service_stealth_async(ip: str, port: int, client: httpx.AsyncClient) -> Dict:
    """
    Melakukan permintaan HTTP GET dengan teknik Evasion.
    """
    url = f"http://{ip}:{port}"
    result = {"ip": ip, "port": port, "status": "Error", "stealth_info": "N/A"}
    
    # 1. Implementasi Pacing dan Delay
    async with semaphore:
        # Delay acak untuk menghindari pola waktu yang mudah dideteksi oleh IDS
        delay = random.uniform(REQUEST_RATE_LIMIT, REQUEST_RATE_LIMIT * 2) 
        await asyncio.sleep(delay)

        try:
            # 2. Implementasi Evasion (Rotasi Header)
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                # Tambahkan header yang ambigu untuk evasion
                "Accept-Language": "en-US,en;q=0.9", 
                "Connection": "keep-alive"
            }
            
            response = await client.get(url, timeout=5, headers=headers)
            
            result['status'] = f"Status: {response.status_code}"
            result['stealth_info'] = f"Success with UA: {headers['User-Agent'][:30]}..."
            
        except httpx.ConnectError:
            result['status'] = "Connection Refused/Failed"
        except httpx.HTTPStatusError as e:
            # Seringkali WAF mengembalikan 403 atau 406 saat mendeteksi payload/header mencurigakan
            result['status'] = f"HTTP Error: {e.response.status_code} (WAF/IDS Triggered?)"
        except httpx.TimeoutException:
            result['status'] = "Timeout"
            
    return result

async def main_stealth_engine(target_hosts: List[Dict]):
    """
    Mengorkestrasi scan yang menggunakan teknik evasion.
    """
    print(f"\n--- 13. PENGURANGAN JEJAK DAN EVASION (STEALTH) ---")
    
    # Batas koneksi Concurrent diatur lebih tinggi dari Semaphore agar Semaphore yang mengontrol
    limits = httpx.Limits(max_connections=50) 
    
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        
        tasks = [
            check_web_service_stealth_async(host['ip'], host['port'], client) 
            for host in target_hosts
        ]
        
        print(f"[INFO] Menjalankan {len(tasks)} scan dengan Pacing (Max {CONCURRENT_REQUESTS_LIMIT} reqs/concurrent)...")
        results = await asyncio.gather(*tasks)
        return results

# --- Simulasi Target ---
async def main():
    # Simulasi daftar target (hanya 10 untuk demonstrasi efek delay)
    target_list = [{"ip": f"10.10.10.{i+1}", "port": 80} for i in range(10)]
    
    start_time = time.time()
    stealth_results = await main_stealth_engine(target_list)
    end_time = time.time()
    
    print(f"\n[FINAL METRIC] Selesai memindai {len(stealth_results)} target dalam {end_time - start_time:.2f} detik.")
    print(f"  (Catatan: Waktu lebih lama karena Pacing diterapkan untuk Stealth).")
    
    print("\n--- SAMPEL OUTPUT (Dengan Bukti Evasion) ---")
    for result in stealth_results:
        print(f"  [HOST] {result['ip']} | Status: {result['status']:<40} | Evasion: {result['stealth_info']}")

if __name__ == "__main__":
    asyncio.run(main())