import json
from typing import Dict, List, Any

# --- Simulasi Struktur Graph Database ---

GRAPH_DATABASE = {
    "NODES": {
        "A1": {"type": "Host", "name": "Web Server 1 (192.168.1.100)", "risk_level": "Medium"},
        "A2": {"type": "URL", "name": "/api/v1/search", "risk_level": "High"},
        "A3": {"type": "Database", "name": "DB-Production", "risk_level": "Critical"},
        "V1": {"type": "Vulnerability", "name": "Stored XSS (A2)", "severity": 8.5},
        "V2": {"type": "Vulnerability", "name": "Admin Panel RCE", "severity": 9.8},
        "V3": {"type": "Credentials", "name": "User Session", "info": "Didapat dari V1"},
    },
    "EDGES": [
        # Hubungan Fisik/Akses
        {"source": "A1", "target": "A2", "relationship": "HOSTS_ENDPOINT"},
        {"source": "A1", "target": "A3", "relationship": "CAN_ACCESS_DB"},
        
        # Hubungan Kerentanan
        {"source": "A2", "target": "V1", "relationship": "IS_VULNERABLE_TO"},
        {"source": "A1", "target": "V2", "relationship": "IS_VULNERABLE_TO"},
        
        # Jalur Serangan (Prediktif)
        {"source": "V1", "target": "V3", "relationship": "CAN_LEAD_TO", "impact": "Session Hijack"}, # XSS -> Session
        {"source": "V3", "target": "A1", "relationship": "AUTHENTICATES_AS", "impact": "Admin Access"}, # Session -> Host A1
        {"source": "A1", "target": "V3", "relationship": "HAS_CREDENTIALS"},
    ]
}

# --- Fungsi Prediktif: Mencari Jalur Serangan Multi-Langkah ---

def find_attack_paths(start_node_id: str, end_node_id: str, graph: Dict[str, Any], path: List[str] = None):
    """
    Algoritma dasar pencarian jalur (DFS/BFS) pada graph untuk menemukan rantai serangan.
    """
    if path is None:
        path = []
    path = path + [start_node_id]

    # 1. Kasus Berhenti (Goal Reached)
    if start_node_id == end_node_id:
        return [path]
    
    # Node tidak ditemukan
    if start_node_id not in graph['NODES']:
        return []

    paths = []
    
    # 2. Iterasi Melalui Edges (Hubungan)
    for edge in graph['EDGES']:
        if edge['source'] == start_node_id:
            next_node_id = edge['target']
            
            # Mencegah loop tak terbatas
            if next_node_id not in path:
                # Rekursif mencari jalur dari node berikutnya
                new_paths = find_attack_paths(next_node_id, end_node_id, graph, path)
                for new_path in new_paths:
                    paths.append(new_path)
    
    return paths

# --- Main Logic ---

def main():
    print(f"\n--- 21. PREDICTIVE SECURITY DENGAN GRAPH DATABASE ---")

    # Pertanyaan Prediktif: "Bisakah XSS (V1) mengarah pada Kompromi Database (A3)?"
    START_VULNERABILITY = "V1" # Stored XSS
    END_ASSET = "A3" # Database Production
    
    # 1. Jalankan Analisis Jalur Serangan
    attack_paths = find_attack_paths(START_VULNERABILITY, END_ASSET, GRAPH_DATABASE)
    
    print("\n--- ANALISIS JALUR SERANGAN PREDIKTIF ---")
    
    if not attack_paths:
        print(f"[🟢 AMAN] Tidak ada jalur serangan langsung yang ditemukan dari {START_VULNERABILITY} ke {END_ASSET}.")
        return

    print(f"[🚨 JALUR DITEMUKAN] {len(attack_paths)} rantai serangan teridentifikasi.")
    
    # 2. Interpretasi Hasil
    for idx, path in enumerate(attack_paths):
        path_description = []
        total_risk = 0
        
        # Konversi ID Jalur menjadi Nama Entitas
        for i in range(len(path)):
            node_id = path[i]
            node = GRAPH_DATABASE['NODES'].get(node_id, {"name": f"Unknown Node ({node_id})", "severity": 0})
            path_description.append(node['name'])
            total_risk += node.get('severity', 0) 
            
            # Tambahkan hubungan (Edge)
            if i < len(path) - 1:
                next_node_id = path[i+1]
                edge_info = next((e for e in GRAPH_DATABASE['EDGES'] if e['source'] == node_id and e['target'] == next_node_id), None)
                if edge_info:
                     path_description.append(f" --({edge_info['relationship']} -> Impact: {edge_info.get('impact', 'N/A')})--> ")
        
        print(f"\n[Rantai {idx+1} (RISK SCORE: {total_risk:.1f})]:")
        print("".join(path_description))

if __name__ == "__main__":
    main()