import time
from typing import List, Dict

# --- Fungsi Klasifikasi Risiko ---

def classify_risk(cve_match: Dict, disclosure_active: bool) -> str:
    """
    Mengklasifikasikan risiko berdasarkan CVE match dan keberadaan header disclosure.
    """
    if cve_match and cve_match.get('severity') == 'HIGH':
        return "CRITICAL"
    elif cve_match and cve_match.get('severity') == 'MEDIUM':
        return "HIGH"
    elif disclosure_active:
        # Header disclosure tanpa CVE spesifik tetap dianggap risiko Low/Informational
        return "LOW"
    return "INFORMATIONAL"

# --- Fungsi Pembuatan Laporan ---

def generate_final_report(verification_results: List[Dict]):
    """
    Mengambil hasil verifikasi dan menghasilkan laporan yang terstruktur.
    """
    report_data = []
    
    for result in verification_results:
        risk_level = classify_risk(result.get('cve_match'), result['disclosure_active'])
        
        # 1. Menentukan Bukti (Proof of Concept - PoC)
        # Dalam kasus Header Disclosure, PoC adalah tampilan header itu sendiri.
        proof = f"Respon HTTP menunjukkan header Server: {result['banner']}"
        
        # 2. Menentukan Rekomendasi (Mitigasi)
        if result.get('cve_match'):
            # Jika ada CVE match, rekomendasi spesifik adalah upgrade
            remediation = f"Segera upgrade software {result['banner']} ke versi yang telah menambal {result['cve_match']['id']}."
        else:
            # Jika hanya disclosure, rekomendasinya adalah hardening
            remediation = "Sembunyikan atau palsukan (obfuscate) header 'Server' di konfigurasi web server (e.g., set ServerTokens Prod di Apache)."
            
        report_data.append({
            "ip": result['ip'],
            "port": result['port'],
            "url": result['url'],
            "risk": risk_level,
            "vulnerability": "Server Header Disclosure (Pengungkapan Informasi Versi)",
            "details": f"Server mengumumkan versi softwarenya ({result['banner']}), memfasilitasi penyerang.",
            "proof_of_concept": proof,
            "remediation": remediation
        })

    # 3. Struktur Laporan Akhir
    print("\n========================================================")
    print("         LAPORAN ANALISIS KERENTANAN - FINAL            ")
    print(f"       Tanggal: {time.strftime('%Y-%m-%d %H:%M:%S')}         ")
    print("========================================================")
    
    # Kelompokkan berdasarkan Tingkat Risiko untuk prioritas
    risk_groups = {"CRITICAL": [], "HIGH": [], "LOW": [], "INFORMATIONAL": []}
    for item in report_data:
        risk_groups[item['risk']].append(item)
        
    for risk, items in risk_groups.items():
        if items:
            print(f"\n### {risk} ({len(items)} DITEMUKAN) ###")
            for i, item in enumerate(items):
                print(f"\n--- KERENTANAN #{i+1} ---")
                print(f"Target: {item['ip']}:{item['port']} ({item['url']})")
                print(f"VULN: {item['vulnerability']}")
                print(f"Risiko: {item['risk']}")
                print(f"Detail: {item['details']}")
                print(f"Bukti (PoC): {item['proof_of_concept']}")
                print(f"REMEDIATION: {item['remediation']}")
                
    print("\n========================================================")
    print("                LAPORAN SELESAI                         ")
    print("========================================================")


# --- Simulasi Input dari Step 3 ---

def main():
    # Simulasi hasil 'verification_results' dari Tahap 3
    # Catatan: Kita tidak perlu menjalankan I/O lagi
    simulated_verification_results = [
        # Hasil 1: CRITICAL/HIGH Risk karena CVE Match (Apache)
        {"ip": "192.168.1.100", "port": 8080, "url": "http://192.168.1.100:8080", "banner": "Apache/2.4.41", "disclosure_active": True, 
         "cve_match": {"id": "CVE-2019-0211", "severity": "HIGH", "desc": "Local privilege escalation."}},
         
        # Hasil 2: HIGH/MEDIUM Risk karena CVE Match (Nginx)
        {"ip": "192.168.1.5", "port": 80, "url": "http://192.168.1.5:80", "banner": "Nginx/1.18.0", "disclosure_active": True,
         "cve_match": {"id": "CVE-2020-20984", "severity": "MEDIUM", "desc": "Memory buffer overflow."}},
         
        # Hasil 3: LOW Risk karena Disclosure (tanpa CVE spesifik)
        {"ip": "192.168.1.1", "port": 80, "url": "http://192.168.1.1:80", "banner": "Microsoft-IIS/10.0", "disclosure_active": True,
         "cve_match": None},
         
        # Hasil 4: LOW Risk karena Disclosure (tanpa CVE spesifik)
        {"ip": "192.168.1.1", "port": 443, "url": "http://192.168.1.1:443", "banner": "Microsoft-IIS/10.0", "disclosure_active": True,
         "cve_match": None},
    ]

    generate_final_report(simulated_verification_results)

if __name__ == "__main__":
    main()