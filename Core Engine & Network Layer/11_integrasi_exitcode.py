import sys
import json
import time
from typing import List, Dict

# --- Konfigurasi Keluar (Exit Codes) ---
CRITICAL_THRESHOLD_SCORE = 9.0
EXIT_CODE_VULNERABILITY_FOUND = 101
EXIT_CODE_SUCCESS = 0

# --- Fungsi Klasifikasi Risiko CVSS (Disintegrasi dari Tahap 8) ---
def get_cvss_score(risk: str) -> float:
    """Mengembalikan skor CVSS simulasi berdasarkan tingkat risiko."""
    if risk == "CRITICAL": return 9.8
    if risk == "HIGH": return 8.5
    return 0.0

# --- Fungsi Main Integrasi CI/CD ---

def main_ci_cd_integration(report_data: List[Dict]):
    """
    Menganalisis laporan dan menentukan Exit Code untuk pipa CI/CD.
    """
    critical_findings_count = 0
    
    print("\n--- 11. AUTOMASI DAN INTEGRASI CI/CD ---")
    
    # 1. Analisis Kritis
    for finding in report_data:
        score = get_cvss_score(finding['risk'])
        if score >= CRITICAL_THRESHOLD_SCORE:
            print(f"[🚨 CRITICAL FINDING] {finding['vulnerability']} pada {finding['ip']} (CVSS: {score})")
            critical_findings_count += 1
            
    # 2. Penentuan Exit Code
    if critical_findings_count > 0:
        print(f"\n[❌ BUILD FAILED] {critical_findings_count} kerentanan Kritis terdeteksi.")
        print("MENCEGAH deployment ke production.")
        # Mengembalikan exit code untuk menghentikan proses CI/CD
        sys.exit(EXIT_CODE_VULNERABILITY_FOUND) 
    else:
        print("\n[🟢 BUILD SUCCESS] Tidak ada kerentanan Kritis terdeteksi. Deployment diizinkan.")
        sys.exit(EXIT_CODE_SUCCESS)

# --- Simulasi Main Execution ---
if __name__ == "__main__":
    
    # Simulasi Laporan Terdapat Temuan Kritis (Simulasi FAILED BUILD)
    simulated_report_failed = [
        {"ip": "192.168.1.100", "risk": "CRITICAL", "vulnerability": "RCE via Apache Exploit", "remediation": "Upgrade Apache."},
        {"ip": "192.168.1.5", "risk": "HIGH", "vulnerability": "SQL Injection", "remediation": "Input Sanitization."},
        {"ip": "192.168.1.1", "risk": "LOW", "vulnerability": "Header Disclosure", "remediation": "Hide Server Header."},
    ]
    
    # Simulasi Laporan Bersih (Simulasi SUCCESS BUILD)
    simulated_report_success = [
        {"ip": "192.168.1.5", "risk": "HIGH", "vulnerability": "SQL Injection", "remediation": "Input Sanitization."}, # High < Critical Threshold
        {"ip": "192.168.1.1", "risk": "LOW", "vulnerability": "Header Disclosure", "remediation": "Hide Server Header."},
    ]

    # CATATAN: Karena sys.exit akan menghentikan interpreter, kita hanya bisa menjalankan satu skenario.
    # Kita akan menjalankan skenario FAILED BUILD.
    
    print(f"[{time.strftime('%H:%M:%S')}] Menjalankan Simulasi Integrasi dengan Temuan Kritis...")
    
    try:
        main_ci_cd_integration(simulated_report_failed)
    except SystemExit as e:
        print(f"[{time.strftime('%H:%M:%S')}] Proses dihentikan dengan Exit Code: {e.code}")
    
    # Jika Anda ingin menjalankan skenario sukses:
    # try: main_ci_cd_integration(simulated_report_success)
    # except SystemExit as e: print(f"Proses dihentikan dengan Exit Code: {e.code}")