import json
from typing import List, Dict

# --- Simulasi Data Laporan dari Tahap 7 ---
REPORT_FILE = "vulnerability_report.json"

def calculate_cvss_score(vulnerability_data: Dict) -> float:
    """
    Simulasi fungsi untuk menghitung skor CVSS (real-world sangat kompleks).
    Skor didasarkan pada tingkat risiko yang sudah diklasifikasikan.
    """
    risk = vulnerability_data['risk']
    if risk == "CRITICAL":
        return 9.8  # Contoh skor CVSS Kritis
    elif risk == "HIGH":
        return 8.5
    elif risk == "LOW":
        return 3.5
    return 0.0

def generate_executive_summary(report_data: List[Dict]):
    """
    Membuat ringkasan non-teknis untuk manajemen dan menghitung statistik.
    """
    total_findings = len(report_data)
    
    # Menghitung statistik
    stats = {}
    for item in report_data:
        risk = item['risk']
        stats[risk] = stats.get(risk, 0) + 1
        
    # Menemukan temuan paling kritis
    most_critical = next((item for item in report_data if item['risk'] == 'CRITICAL'), None)

    print("\n========================================================")
    print("         PRESENTASI TEMUAN - RINGKASAN EKSEKUTIF        ")
    print("========================================================")
    print(f"Total Kerentanan Terverifikasi: {total_findings}")
    print(f"Kerentanan Kritis/Tinggi: {stats.get('CRITICAL', 0) + stats.get('HIGH', 0)}")
    print(f"Kerentanan Rendah/Informasional: {stats.get('LOW', 0)}")
    
    if most_critical:
        cvss = calculate_cvss_score(most_critical)
        print(f"\n# TEMUAN KUNCI DAN PRIORITAS TERTINGGI #")
        print(f"Isu: {most_critical['vulnerability']}")
        print(f"Target: {most_critical['ip']} (Skor CVSS: {cvss})")
        print(f"Dampak: Kerentanan ini memungkinkan kendali penuh atas server (RCE).")
        print(f"Tindakan Cepat: Segera terapkan {most_critical['remediation']}")
    
    print("\n--- RINGKASAN STATISTIK ---")
    for risk, count in stats.items():
        print(f"  {risk:<10}: {count} Temuan")
        
    print("\n(Dokumentasi teknis lengkap ada di bagian lampiran)")
    print("========================================================")

# --- Main Logic ---
def main():
    try:
        with open(REPORT_FILE, 'r') as f:
            full_report = json.load(f)
            report_findings = full_report['findings']
            
            # Menghasilkan Ringkasan Eksekutif
            generate_executive_summary(report_findings)
            
    except FileNotFoundError:
        print(f"[ERROR] File laporan {REPORT_FILE} tidak ditemukan. Pastikan Tahap 7 sudah dijalankan.")
    except Exception as e:
        print(f"[ERROR] Gagal memproses laporan: {e}")

if __name__ == "__main__":
    main()