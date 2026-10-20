# -*- coding: utf-8 -*-
"""
REAL-TIME IDS (K=2 UYUMLU)
"""
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from collections import deque
import os
import time

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    print("❌ Scapy bulunamadı. Lütfen yükleyin: pip install scapy")
    SCAPY_AVAILABLE = False

print("=" * 70)
print("🚀 REAL-TIME IDS BAŞLATILIYOR...")
print("=" * 70)

# 1. Modeli Yükle
if not os.path.exists("anomaly_detector_kmeans_k2.pkl"):
    print("❌ Model dosyası yok! Önce egitim.py'yi çalıştırın.")
    exit()

with open("anomaly_detector_kmeans_k2.pkl", "rb") as f:
    model = pickle.load(f)

kmeans = model["kmeans"]
scaler = model["scaler"]
pca = model["pca"]
label_encoders = model["label_encoders"]
thresholds = model["thresholds_per_cluster"]
centers = model["cluster_centers"]
FEATURES = model["minimal_features"]

print("✔ Model Yüklendi.")

# 2. Trafik Hafızası (Sliding Window - 2 Saniye)
traffic_window = deque()
WINDOW_SEC = 2.0

def map_service(port):
    mapping = {80:"http", 443:"http", 21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"domain"}
    return mapping.get(int(port), "other") if str(port).isdigit() else "other"

def safe_encode(col, val):
    le = label_encoders[col]
    return le.transform([val])[0] if val in le.classes_ else le.transform([le.classes_[0]])[0]

def extract_features(pkt):
    if not IP in pkt: return None
    
    # Temel Paket Bilgileri
    src, dst = pkt[IP].src, pkt[IP].dst
    proto = "tcp" if pkt[IP].proto == 6 else "udp" if pkt[IP].proto == 17 else "icmp"
    byte_len = len(pkt[IP])
    
    sport, dport = 0, 0
    flag, srv = "SF", "other"
    serror, logged_in = 0, 0
    
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        srv = map_service(dport)
        f = pkt[TCP].flags
        # SYN=2, ACK=16. Sadece SYN varsa (ACK yoksa) S0 (Bağlantı isteği)
        if (f & 0x02) and not (f & 0x10): 
            flag = "S0"; serror = 1
        # PSH=8. Veri taşıyorsa logged_in varsayılabilir
        if (f & 0x08): logged_in = 1
            
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        srv = map_service(dport)

    # İstatistik Hesapla (Window)
    now = time.time()
    traffic_window.append((now, src, dst, srv, sport, serror))
    
    # Süresi dolanları sil
    while traffic_window and (now - traffic_window[0][0] > WINDOW_SEC):
        traffic_window.popleft()
        
    # Sayaçlar
    count = 0 # Hedef IP aynı
    srv_count = 0 # Hedef IP + Port aynı
    serror_count = 0 
    same_src_port = 0
    diff_srv_set = set()
    
    for t, s, d, sv, sp, err in traffic_window:
        if d == dst: # Aynı hedef
            count += 1
            if sv == srv: srv_count += 1
            if err: serror_count += 1
            if sp == sport: same_src_port += 1
        if s == src: # Aynı kaynak (farklı servislere gidiyor mu?)
            diff_srv_set.add(sv)
            
    # Oranlar (0'a bölünmeyi engelle)
    serror_rate = serror_count / count if count else 0
    same_srv_rate = srv_count / count if count else 0
    diff_srv_rate = len(diff_srv_set) / count if count else 0
    dst_host_same_src_port_rate = same_src_port / count if count else 0
    
    # DataFrame Oluştur
    data = {
        'protocol_type': proto, 'service': srv, 'flag': flag,
        'src_bytes': byte_len, 'dst_bytes': 0, 'duration': 0, 'logged_in': logged_in,
        'count': count, 'srv_count': srv_count,
        'serror_rate': serror_rate, 'same_srv_rate': same_srv_rate, 'diff_srv_rate': diff_srv_rate,
        'dst_host_count': count, 'dst_host_srv_count': srv_count,
        'dst_host_same_srv_rate': same_srv_rate, 'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
        'dst_host_serror_rate': serror_rate
    }
    
    df = pd.DataFrame([data])[FEATURES] # Sıralama garantisi
    
    # Log Transform
    for c in ['src_bytes', 'dst_bytes', 'duration', 'count', 'srv_count', 'dst_host_count', 'dst_host_srv_count']:
        df[c] = np.log1p(df[c])
        
    # Encode
    for c in ['protocol_type', 'service', 'flag']:
        df[c] = df[c].apply(lambda x: safe_encode(c, x))
        
    return df

def ids_process(pkt):
    try:
        df = extract_features(pkt)
        if df is None: return

        # Tahmin
        scaled = scaler.transform(df.values)
        pca_out = pca.transform(scaled)
        
        dists = np.linalg.norm(centers - pca_out[0], axis=1)
        nearest = np.argmin(dists)
        dist = dists[nearest]
        thr = thresholds[nearest]
        
        if dist > thr:
            print(f"\033[91m🚨 SALDIRI ALGILANDI! [{pkt[IP].src} -> {pkt[IP].dst}] (Dist:{dist:.2f} > Thr:{thr:.2f})\033[0m")
        else:
            print(f"\033[92m✔ NORMAL TRAFİK\033[0m [{pkt[IP].src} -> {pkt[IP].dst}]")
            
    except Exception as e:
        pass

if __name__ == "__main__":
    if SCAPY_AVAILABLE:
        print("📡 Ağ dinleniyor...")
        sniff(prn=ids_process, store=False)