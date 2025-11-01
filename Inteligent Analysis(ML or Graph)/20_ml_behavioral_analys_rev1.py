import numpy as np
from sklearn.cluster import KMeans
from typing import List, Dict, Tuple
import random

# --- Konfigurasi ML ---
# Jumlah cluster yang diinginkan
N_CLUSTERS = 3 
# Nama fitur untuk memudahkan interpretasi
FEATURE_NAMES = ["Panjang_Respons", "Waktu_Respons_Avg", "Jumlah_Param_Input", "Kerentanan_Skor"]

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
    # Cluster 3: Endpoint Admin/Akses Khusus (Panjang, Sedang, Sedikit Input)
    for i in range(18, 26):
        data.append({"url": f"/data/user_profile/{i}", "features": [random.randint(1500, 2500), random.uniform(0.2, 0.4), 2, 2]})

    # Outlier (Endpoint Curiouse)
    # 1. Endpoint Sangat Panjang (Large Report) - Jauh dari Panjang Respons Rata-rata
    data.append({"url": "/admin/full_report", "features": [20000, 0.5, 2, 3]}) 
    # 2. Endpoint Sangat Lambat dan Rentan (Misalnya, RCE) - Jauh dari Waktu Respons & Kerentanan Rata-rata
    data.append({"url": "/auth/critical_action", "features": [500, 4.0, 3, 9.8]}) 

    # Acak data agar tidak berurutan
    random.shuffle(data)
    return data

# --- Fungsi ML Clustering ---

def run_kmeans_analysis(raw_data: List[Dict]) -> Tuple[List[Dict], float, np.ndarray, np.ndarray]:
    """
    Melakukan K-Means Clustering untuk mengidentifikasi Outlier/Anomali.
    Mengembalikan hasil analisis, ambang batas outlier, pusat cluster (normalized), dan nilai max fitur.
    """
    
    # Ekstraksi Fitur dan Metadata
    X = np.array([d['features'] for d in raw_data])
    
    # Normalisasi (Min-Max Scaler sederhana: X / X_max)
    # Simpan nilai maksimum untuk mengembalikan Centroid ke skala asli (De-Normalisasi)
    X_max = X.max(axis=0) 
    # Hindari pembagian dengan nol
    X_normalized = np.divide(X, X_max, out=np.zeros_like(X), where=X_max!=0)
    
    # 1. Jalankan K-Means
    kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=42, n_init=10)
    kmeans.fit(X_normalized)
    
    # 2. Hitung Jarak dari Pusat Cluster (Centroid) untuk Deteksi Outlier
    distances = kmeans.transform(X_normalized)
    # Jarak ke cluster terdekat
    min_distances = distances[np.arange(len(distances)), kmeans.labels_] 
    
    # Tentukan ambang batas outlier (menggunakan formula standar: Rata-rata + 1.5 * Deviasi Standar)
    mean_distance = np.mean(min_distances)
    std_distance = np.std(min_distances)
    distance_threshold = mean_distance + 1.5 * std_distance
    
    # 3. Klasifikasi Hasil
    analyzed_results = []
    for i, data_point in enumerate(raw_data):
        data_point['cluster'] = int(kmeans.labels_[i])
        data_point['distance_to_center'] = float(min_distances[i])
        data_point['is_outlier'] = min_distances[i] > distance_threshold
        analyzed_results.append(data_point)
        
    return analyzed_results, distance_threshold, kmeans.cluster_centers_, X_max


# --- Main Logic ---

def main():
    print(f"\n--- 20. INTEGRASI MACHINE LEARNING (Analisis Behavioral) ---")
    print(f"Menggunakan K-Means Clustering dengan N_CLUSTERS = {N_CLUSTERS}")
    
    raw_data = generate_simulated_data()
    # Menerima Centroid yang dinormalisasi dan nilai max fitur untuk de-normalisasi
    analyzed_results, threshold, normalized_centroids, X_max = run_kmeans_analysis(raw_data)
    
    # De-Normalisasi Centroid untuk ditampilkan dalam skala asli
    original_centroids = normalized_centroids * X_max
    
    outliers = [r for r in analyzed_results if r['is_outlier']]
    
    print(f"[INFO] Total Endpoint dianalisis: {len(raw_data)}")
    print(f"[INFO] Ambang Batas Outlier (Jarak Euclidean): {threshold:.4f}")
    
    
    print("\n--- PUSAT CLUSTER TERBENTUK (Nilai Rata-rata Fitur) ---")
    header = "Cluster | " + " | ".join(f"{name:<18}" for name in FEATURE_NAMES)
    print(header)
    print("-" * len(header))

    for i, center in enumerate(original_centroids):
        # Format angka agar mudah dibaca
        center_str = f"{center[0]:<18.2f} | {center[1]:<18.2f} | {center[2]:<18.2f} | {center[3]:<18.2f}"
        print(f"   {i}    | {center_str}")


    print("\n--- RINGKASAN DETEKSI OUTLIER (Titik Data Jauh dari Pusat) ---")
    if outliers:
        print(f"[🚨 DITEMUKAN] {len(outliers)} Endpoint Anomali (Outlier) terdeteksi.")
        print("\nURL | Cluster | Jarak (Harus < Ambang Batas) | Fitur (L.Resp, T.Resp, N.Param, Score)")
        print("-----------------------------------------------------------------------------------------")
        for o in outliers:
            # Format fitur untuk tampilan yang ringkas
            features_str = f"({o['features'][0]}, {o['features'][1]:.1f}s, {o['features'][2]}, {o['features'][3]:.1f})"
            print(f"{o['url']:<25} | {o['cluster']:<7} | {o['distance_to_center']:.4f} | {features_str}")
            
    else:
        print("[🟢 BERSIH] Tidak ada Outlier Behavioral yang signifikan terdeteksi.")

    print("\n[REKOMENDASI] Endpoint yang terdeteksi sebagai Anomali perlu ditinjau secara manual karena memiliki profil fitur yang sangat berbeda dari kelompok normal.")


if __name__ == "__main__":
    main()
