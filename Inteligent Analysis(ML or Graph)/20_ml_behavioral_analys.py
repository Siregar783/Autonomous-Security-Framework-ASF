import numpy as np
from sklearn.cluster import KMeans
from typing import List, Dict
import random

# --- Konfigurasi ML ---
# Jumlah cluster yang diinginkan
N_CLUSTERS = 3 

# --- Simulasi Data Input dari Tahap Sebelumnya (Features) ---
# Fitur: [Panjang_Respons, Waktu_Respons_Avg, Jumlah_Param_Input, Kerentanan_Skor]
def generate_simulated_data(n_samples=20):
    data = []
    # Cluster 1: Endpoint Statis (Pendek, Cepat, Sedikit Input)
    for i in range(1, 10):
        data.append({"url": f"/static/{i}", "features": [random.randint(500, 1000), random.uniform(0.1, 0.2), 1, 0]})
    # Cluster 2: Endpoint Dinamis (Sedang, Sedang, Banyak Input)
    for i in range(10, 18):
        data.append({"url": f"/api/{i}", "features": [random.randint(2000, 4000), random.uniform(0.3, 0.5), 5, 1]})
    # Outlier (Endpoint Curiouse)
    # 1. Endpoint Sangat Panjang (Large Report)
    data.append({"url": "/admin/full_report", "features": [20000, 0.5, 2, 3]}) # Outlier 1
    # 2. Endpoint Sangat Lambat dan Rentan (Misalnya, RCE)
    data.append({"url": "/auth/critical_action", "features": [500, 4.0, 3, 9.8]}) # Outlier 2

    # Acak data agar tidak berurutan
    random.shuffle(data)
    return data

# --- Fungsi ML Clustering ---

def run_kmeans_analysis(raw_data: List[Dict]) -> List[Dict]:
    """
    Melakukan K-Means Clustering untuk mengidentifikasi Outlier/Anomali.
    """
    
    # Ekstraksi Fitur dan Metadata
    X = np.array([d['features'] for d in raw_data])
    
    # Normalisasi (sangat penting untuk ML) - Menggunakan Min-Max Scaler sederhana
    X_normalized = X / X.max(axis=0) 
    
    # 1. Jalankan K-Means
    kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=42, n_init=10)
    kmeans.fit(X_normalized)
    
    # 2. Hitung Jarak dari Pusat Cluster (Centroid) untuk Deteksi Outlier
    distances = kmeans.transform(X_normalized)
    # Jarak ke cluster terdekat
    min_distances = distances[np.arange(len(distances)), kmeans.labels_] 
    
    # Tentukan ambang batas outlier (misalnya, 1.5x deviasi standar dari jarak rata-rata)
    distance_threshold = np.mean(min_distances) + 1.5 * np.std(min_distances)
    
    # 3. Klasifikasi Hasil
    analyzed_results = []
    for i, data_point in enumerate(raw_data):
        data_point['cluster'] = int(kmeans.labels_[i])
        data_point['distance_to_center'] = float(min_distances[i])
        data_point['is_outlier'] = min_distances[i] > distance_threshold
        analyzed_results.append(data_point)
        
    return analyzed_results, distance_threshold


# --- Main Logic ---

def main():
    print(f"\n--- 20. INTEGRASI MACHINE LEARNING (Analisis Behavioral) ---")
    
    raw_data = generate_simulated_data()
    analyzed_results, threshold = run_kmeans_analysis(raw_data)
    
    outliers = [r for r in analyzed_results if r['is_outlier']]
    
    print(f"[INFO] Total Endpoint dianalisis: {len(raw_data)}")
    print(f"[INFO] Ambang Batas Outlier (Jarak): {threshold:.4f}")
    
    print("\n--- RINGKASAN DETEKSI OUTLIER ---")
    if outliers:
        print(f"[🚨 DITEMUKAN] {len(outliers)} Endpoint Anomali (Outlier) terdeteksi.")
        print("\nURL | Cluster | Jarak | Fitur (L.Resp, T.Resp, N.Param, Score)")
        print("-------------------------------------------------------------------")
        for o in outliers:
            features_str = f"({o['features'][0]}, {o['features'][1]:.1f}s, {o['features'][2]}, {o['features'][3]:.1f})"
            print(f"{o['url']:<20} | {o['cluster']:<7} | {o['distance_to_center']:.4f} | {features_str}")
            
    else:
        print("[🟢 BERSIH] Tidak ada Outlier Behavioral yang signifikan terdeteksi.")

    # (Laporan selanjutnya akan merekomendasikan pemeriksaan manual pada Outlier ini)

if __name__ == "__main__":
    main()