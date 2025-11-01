# WARNING: This script requires root/sudo privileges to run Scapy's raw sockets.

import asyncio
import ipaddress
import os
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# Library yang dibutuhkan untuk low-level scanning
from scapy.all import IP, TCP, sr1, conf

# --- Konfigurasi dan Executor ---
TARGET_PORTS = [22, 23, 80, 443, 8080] # Port umum untuk dicoba
TIMEOUT = 1.0 # Timeout rendah untuk scanning cepat
MAX_THREADS = 40

# Inisialisasi ThreadPoolExecutor untuk menjalankan Scapy secara non-blocking
executor = ThreadPoolExecutor(max_workers=MAX_THREADS) 

# --- Fungsi Scapy (Sinkron - Blocking I/O) ---

def tcp_syn_scan_sync(target_ip: str, port: int) -> str:
    """
    Melakukan TCP SYN scan (half-open) pada satu target dan port.
    Fungsi ini SINKRON dan dijalankan di thread terpisah.
    """
    try:
        # Konfigurasi Scapy: Non-verbose
        conf.verb = 0 
        
        # 1. Buat paket IP dan TCP SYN
        # dst_port=port, flags="S" (SYN flag)
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=port, flags="S") 
        
        packet = ip_layer / tcp_layer
        
        # 2. Kirim paket dan tunggu 1 respons (sr1)
        response = sr1(packet, timeout=TIMEOUT)

        # 3. Analisis Respons
        if response and response.haslayer(TCP):
            # Cek TCP flag: "SA" (SYN-ACK) berarti port terbuka
            if response.getlayer(TCP).flags == 0x12: # 0x12 adalah SYN-ACK
                # Kirim RST untuk menutup koneksi (clean up)
                sr1(IP(dst=target_ip)/TCP(dport=response.sport, flags="R"), timeout=0.1)
                return "OPEN"
            
            # Cek TCP flag: "RA" (RST-ACK) berarti port tertutup
            elif response.getlayer(TCP).flags == 0x14: # 0x14 adalah RST-ACK
                return "CLOSED"
        
        # Jika tidak ada respons atau ICMP error (seperti host down)
        return "FILTERED/NO_RESPONSE"

    except Exception:
        return "ERROR"

# --- Fungsi Asinkron (Orkestrasi) ---

async def run_scan_task(target_ip: str, port: int) -> Dict:
    """
    Mengorkestrasi scan sinkron dalam event loop asyncio.
    """
    loop = asyncio.get_running_loop()
    
    # Menjalankan tcp_syn_scan_sync di thread pool
    status = await loop.run_in_executor(
        executor, 
        tcp_syn_scan_sync, 
        target_ip, 
        port
    )
    
    # Simulasi Service Enumeration (Berdasarkan Port Umum)
    service = "Unknown"
    if status == "OPEN":
        if port == 80 or port == 8080:
            service = "HTTP/Web"
        elif port == 443:
            service = "HTTPS/Web"
        elif port == 22:
            service = "SSH"
        elif port == 23:
            service = "Telnet"

    return {
        "ip": target_ip, 
        "port": port, 
        "status": status, 
        "service": service if status == "OPEN" else None
    }

# --- Fungsi Utama ---

async def main_active_scanning(target_ips: List[str]):
    """
    Fungsi utama untuk menjalankan port scanning secara konkuren.
    """
    if not target_ips:
        print("[INFO] Tidak ada target IP untuk dipindai.")
        return []

    print(f"\n--- 2. ACTIVE SCANNING (Scapy + Asyncio) ---")
    print(f"[INFO] Memindai {len(target_ips) * len(TARGET_PORTS)} kombinasi IP:Port...")
    
    scan_tasks = []
    # Membuat list of tasks (Port Scanning untuk setiap IP dan Port)
    for ip in target_ips:
        for port in TARGET_PORTS:
            scan_tasks.append(run_scan_task(ip, port))
            
    # Menjalankan semua task secara konkuren
    results = await asyncio.gather(*scan_tasks)
    
    # Mematikan executor
    executor.shutdown(wait=False)
    
    return [res for res in results if res['status'] == 'OPEN'] # Hanya kembalikan yang OPEN


# --- Simulasi Integrasi dari Step 1 ---

async def main():
    # Simulasi hasil parsing dari Step 1
    # Kita hanya mengambil IP yang valid dan di LAN (untuk mempermudah Scapy)
    
    # Gantilah dengan IP yang Anda tahu aktif di jaringan Anda untuk hasil terbaik
    simulated_target_ips = ["192.168.1.1", "192.168.1.100", "8.8.8.8"] 
    
    print(f"--- SIMULASI INPUT DARI STEP 1: {len(simulated_target_ips)} TARGET IP ---")

    open_ports_results = await main_active_scanning(simulated_target_ips)
    
    print("\n--- RINGKASAN HOST AKTIF DENGAN PORT TERBUKA ---")
    if open_ports_results:
        for result in open_ports_results:
            print(f"[✅ OPEN] IP: {result['ip']}, Port: {result['port']} -> Layanan Teridentifikasi: {result['service']}")
    else:
        print("[!] Tidak ada port terbuka yang ditemukan pada target.")
    
    print("-------------------------------------------------")


if __name__ == "__main__":
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("!!! GAGAL: Skrip harus dijalankan dengan hak superuser (sudo/root) untuk Scapy !!!")
    else:
        asyncio.run(main())