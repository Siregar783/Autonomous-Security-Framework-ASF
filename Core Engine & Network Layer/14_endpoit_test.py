import asyncio
import httpx
from typing import Dict, List

# --- Konfigurasi ---
TARGET_BASE_URL = "http://target-app.com"
LOGIN_ENDPOINT = f"{TARGET_BASE_URL}/login"
PROTECTED_ENDPOINT = f"{TARGET_BASE_URL}/profile/123" # Endpoint yang memerlukan login

LOGIN_CREDENTIALS = {
    "username": "scanner_user",
    "password": "secure_password123"
}

# Payload yang diuji di Protected Endpoint (Simulasi IDOR)
IDOR_TEST_URL = f"{TARGET_BASE_URL}/profile/999" # Mencoba mengakses profil pengguna 999

# --- Fungsi Manajemen Sesi dan Pengujian ---

async def perform_stateful_scan(client: httpx.AsyncClient) -> List[Dict]:
    """
    Melakukan proses login, verifikasi sesi, dan pengujian terautentikasi.
    """
    reports = []
    
    # 1. LOGIN DAN EKSTRAKSI SESI
    print(f"[1] Mencoba Login ke: {LOGIN_ENDPOINT}...")
    try:
        # httpx.AsyncClient secara otomatis mengelola cookies yang diterima
        login_response = await client.post(LOGIN_ENDPOINT, data=LOGIN_CREDENTIALS, timeout=5)
        
        if login_response.status_code == 200 and 'session' in login_response.cookies:
            session_cookie = client.cookies.get('session')
            reports.append({"stage": "Login", "status": "SUCCESS", "info": f"Sesi Diterima: {session_cookie[:20]}..."})
        else:
            reports.append({"stage": "Login", "status": "FAILURE", "info": f"Login Gagal. Status: {login_response.status_code}"})
            return reports
            
    except httpx.RequestError as e:
        reports.append({"stage": "Login", "status": "FAILURE", "info": f"Network Error: {type(e).__name__}"})
        return reports

    # 2. VERIFIKASI AKSES KE PROTECTED ENDPOINT
    print(f"[2] Memverifikasi akses ke: {PROTECTED_ENDPOINT} (sebagai pengguna 123)...")
    profile_response = await client.get(PROTECTED_ENDPOINT, timeout=5)
    
    if profile_response.status_code == 200:
        reports.append({"stage": "Access Control", "status": "SUCCESS", "info": "Akses ke halaman terautentikasi berhasil."})
    else:
        reports.append({"stage": "Access Control", "status": "FAILURE", "info": f"Gagal mengakses. Status: {profile_response.status_code}"})
        return reports

    # 3. PENGUJIAN KERENTANAN STATEFUL (Simulasi IDOR)
    print(f"[3] Menguji IDOR: Mencoba mengakses profil yang TIDAK diizinkan ({IDOR_TEST_URL})...")
    idor_response = await client.get(IDOR_TEST_URL, timeout=5)

    if idor_response.status_code == 200 and "profile pengguna 999" in idor_response.text.lower():
        reports.append({
            "stage": "IDOR Test", 
            "status": "VULNERABLE (IDOR)", 
            "info": f"Akses ke ID {IDOR_TEST_URL} berhasil. Pengguna lain dapat melihat data."
        })
    elif idor_response.status_code == 403 or "akses ditolak" in idor_response.text.lower():
        reports.append({"stage": "IDOR Test", "status": "SECURE", "info": "Akses Ditolak (Status 403/Forbidden). IDOR Mitigated."})
    else:
        reports.append({"stage": "IDOR Test", "status": "UNCERTAIN", "info": f"Status: {idor_response.status_code}. Perlu analisis manual."})
        
    return reports

async def main():
    print(f"\n--- 14. PENGUJIAN STATEFUL (Manajemen Sesi) ---")
    
    # Menggunakan httpx.AsyncClient tanpa batas koneksi untuk operasi ini
    async with httpx.AsyncClient(follow_redirects=True) as client:
        results = await perform_stateful_scan(client)
    
    print("\n--- RINGKASAN PENGUJIAN STATEFUL ---")
    for r in results:
        print(f"[{r['status']:<10}] {r['stage']}: {r['info']}")

if __name__ == "__main__":
    # Mocking respons untuk simulasi login berhasil dan kerentanan IDOR
    import unittest.mock
    
    original_post = httpx.AsyncClient.post
    original_get = httpx.AsyncClient.get

    async def mock_post(*args, **kwargs):
        class MockResponse:
            status_code = 200
            cookies = httpx.Cookies()
            cookies['session'] = 'a_very_secret_session_token'
            
        # Untuk simulasi: login selalu berhasil
        return MockResponse()

    async def mock_get(*args, **kwargs):
        url = args[1]
        
        class MockResponse:
            status_code = 200
            text = "Data profile pengguna 123"
            
        if "profile/999" in url:
            # Simulasi Kerentanan IDOR: Mengembalikan 200 dan data
            MockResponse.status_code = 200
            MockResponse.text = "Data profile pengguna 999" 
        elif "profile/123" in url:
            # Simulasi akses profile sendiri
            MockResponse.status_code = 200
            
        return MockResponse()

    # Terapkan Mocking
    with unittest.mock.patch('httpx.AsyncClient.post', side_effect=mock_post):
        with unittest.mock.patch('httpx.AsyncClient.get', side_effect=mock_get):
            asyncio.run(main())