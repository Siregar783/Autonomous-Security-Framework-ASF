import asyncio
import httpx
from typing import Dict, List
import unittest.mock

# --- Konfigurasi Scanner ---
# Ganti dengan URL target yang sebenarnya
TARGET_BASE_URL = "http://target-app.com" 
LOGIN_ENDPOINT = f"{TARGET_BASE_URL}/login"
PROTECTED_ENDPOINT = f"{TARGET_BASE_URL}/profile/123" # Endpoint yang memerlukan login (Self-Access)
IDOR_TEST_URL = f"{TARGET_BASE_URL}/profile/999" # Endpoint yang diuji (Accessing other user's profile)

LOGIN_CREDENTIALS = {
    "username": "scanner_user",
    "password": "secure_password123"
}

# --- Fungsi Manajemen Sesi dan Pengujian ---

async def perform_stateful_scan(client: httpx.AsyncClient) -> List[Dict]:
    """
    Melakukan proses login, verifikasi sesi, dan pengujian terautentikasi (simulasi IDOR).
    """
    reports = []
    
    print(f"[1] Mencoba Login ke: {LOGIN_ENDPOINT}...")
    try:
        # 1. LOGIN DAN EKSTRAKSI SESI
        # httpx.AsyncClient secara otomatis mengelola cookies yang diterima
        login_response = await client.post(LOGIN_ENDPOINT, data=LOGIN_CREDENTIALS, timeout=5)
        
        # Cek status dan pastikan cookie sesi tersimpan di client
        session_cookie_value = client.cookies.get('session')
        
        if login_response.status_code == 200 and session_cookie_value:
            reports.append({
                "stage": "Login", 
                "status": "SUCCESS", 
                "info": f"Sesi Diterima. Cookie: {session_cookie_value[:20]}..."
            })
        else:
            reports.append({
                "stage": "Login", 
                "status": "FAILURE", 
                "info": f"Login Gagal. Status: {login_response.status_code}. Respons: {login_response.text[:50]}..."
            })
            return reports
            
    except httpx.RequestError as e:
        reports.append({"stage": "Login", "status": "NETWORK_FAIL", "info": f"Network Error: {type(e).__name__} - {e}"})
        return reports

    # 2. VERIFIKASI AKSES KE PROTECTED ENDPOINT (Self-Access Test)
    print(f"[2] Memverifikasi akses ke: {PROTECTED_ENDPOINT} (sebagai pengguna 123)...")
    profile_response = await client.get(PROTECTED_ENDPOINT, timeout=5)
    
    if profile_response.status_code == 200:
        reports.append({"stage": "Access Control (Self)", "status": "SUCCESS", "info": "Akses ke halaman terautentikasi (milik sendiri) berhasil."})
    else:
        reports.append({"stage": "Access Control (Self)", "status": "FAILURE", "info": f"Gagal mengakses. Status: {profile_response.status_code}. Sesi mungkin tidak valid."})
        # Jika gagal di sini, pengujian IDOR tidak perlu dilanjutkan
        return reports

    # 3. PENGUJIAN KERENTANAN STATEFUL (Simulasi IDOR - Other User Access)
    print(f"[3] Menguji IDOR: Mencoba mengakses profil yang TIDAK diizinkan ({IDOR_TEST_URL})...")
    idor_response = await client.get(IDOR_TEST_URL, timeout=5)

    # Kondisi 1: VULNERABLE (Berhasil mengakses data pengguna lain)
    if idor_response.status_code == 200 and "profile pengguna 999" in idor_response.text.lower():
        reports.append({
            "stage": "IDOR Test", 
            "status": "VULNERABLE (IDOR)", 
            "info": f"Akses ke ID {IDOR_TEST_URL} berhasil (Status 200). Pengguna lain dapat melihat data."
        })
    
    # Kondisi 2: SECURE (Explicit denial)
    elif idor_response.status_code in [401, 403]:
        reports.append({"stage": "IDOR Test", "status": "SECURE", "info": f"Akses Ditolak (Status {idor_response.status_code}). IDOR Mitigated."})
    
    # Kondisi 3: UNCERTAIN (Respons selain 200, 401, 403. Mungkin 404, 302, atau respons error generik)
    else:
        reports.append({"stage": "IDOR Test", "status": "UNCERTAIN", "info": f"Status: {idor_response.status_code}. Perlu analisis manual (bukan 200, 401, atau 403)."})
            
    return reports

async def main():
    print(f"\n--- 14. PENGUJIAN STATEFUL (Manajemen Sesi dan IDOR) ---")
    
    # Menggunakan httpx.AsyncClient untuk manajemen sesi otomatis
    async with httpx.AsyncClient(follow_redirects=True) as client:
        results = await perform_stateful_scan(client)
    
    print("\n--- RINGKASAN PENGUJIAN STATEFUL ---")
    for r in results:
        # Menghilangkan padding, menggunakan format yang lebih bersih
        status_color = "✅" if "SUCCESS" in r['status'] or "SECURE" in r['status'] else "🔥" if "VULNERABLE" in r['status'] else "❌"
        print(f"{status_color} [{r['status']:<18}] {r['stage']:<20}: {r['info']}")

# --- Implementasi Mocking untuk Simulasi (Jangan gunakan pada target nyata!) ---
if __name__ == "__main__":
    
    # --- Mock Responses ---
    class MockLoginResponse:
        """Simulasi respons sukses login."""
        status_code = 200
        # Di sini, kita menambahkan cookie ke AsyncClient secara manual, 
        # karena MockResponse tidak dapat secara otomatis memodifikasi client.cookies.
        cookies = httpx.Cookies({'session': 'a_very_secret_session_token_12345'})
        text = "Login Berhasil"
        
    class MockProfileResponse:
        """Simulasi respons akses profil."""
        def __init__(self, url):
            self.status_code = 200
            if "profile/999" in url:
                # Simulasi Kerentanan IDOR: Mengembalikan 200 dan data pengguna 999
                self.text = "<html><h1>Data profile pengguna 999</h1></html>" 
            elif "profile/123" in url:
                # Simulasi akses profile sendiri
                self.text = "<html><h1>Data profile pengguna 123</h1></html>"
            elif "login" in url:
                # Jika mock_get dipanggil untuk login (seharusnya tidak), gunakan respons login
                self.status_code = 200
                self.text = "Login Page"
        
    # --- Mock Callbacks ---
    async def mock_post(*args, **kwargs):
        """Mock POST untuk endpoint /login."""
        # Secara manual tambahkan cookie ke client yang sedang diuji (args[0])
        client = args[0]
        client.cookies.update(MockLoginResponse.cookies)
        return MockLoginResponse()

    async def mock_get(*args, **kwargs):
        """Mock GET untuk endpoint /profile/123 dan /profile/999."""
        url = args[1]
        return MockProfileResponse(url)

    # Terapkan Mocking
    with unittest.mock.patch('httpx.AsyncClient.post', side_effect=mock_post, autospec=True) as post_mock:
        with unittest.mock.patch('httpx.AsyncClient.get', side_effect=mock_get, autospec=True) as get_mock:
            asyncio.run(main())

    print("\n[INFO] Simulasi Selesai (Menggunakan Mocking)")
