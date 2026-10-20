# -*- coding: utf-8 -*-

import os
import numpy as np
import pandas as pd
import pickle

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

os.environ["LOKY_MAX_CPU_COUNT"] = "8"

# =========================
# AYARLAR
# =========================
K_CLUSTERS = 2             # İsteğin üzerine k=2
THRESHOLD_PERCENTILE = 95  # %98'den %93'e çektik (Saldırıları yakalamak için sıkılaştırma)
PCA_VARIANCE = 0.99        # Veri kaybını en aza indirmek için artırdık

# =========================
# GÜÇLÜ FEATURE SET (Saldırı İmbaları)
# =========================
MINIMAL_FEATURES = [
    'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'duration', 'logged_in',
    'count', 'srv_count', 'serror_rate', 'same_srv_rate', 'diff_srv_rate',
    'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_serror_rate'
]

print("=" * 70)
print(f"🎯 KMEANS k={K_CLUSTERS} | Threshold=%{THRESHOLD_PERCENTILE} | OPTİMİZE MODEL")
print("=" * 70)

# =========================
# 1. VERİ YÜKLEME
# =========================
cols = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'class','difficulty_level'
]

if not os.path.exists("KDDTrain+.txt"):
    print("❌ HATA: KDDTrain+.txt dosyası yok!")
    exit()

df = pd.read_csv("KDDTrain+.txt", header=None)
df.columns = cols

if os.path.exists("KDDTest+.txt"):
    df_test = pd.read_csv("KDDTest+.txt", header=None)
    df_test.columns = cols
else:
    df_test = pd.DataFrame(columns=cols)

print(f"✅ Veri Yüklendi -> Train: {len(df):,}, Test: {len(df_test):,}")

# =========================
# 2. ÖN İŞLEME (LOG + ENCODING)
# =========================
# Sadece Normal veriyi al
df_normal = df[df['class'] == 'normal'].copy()

X_normal = df_normal[MINIMAL_FEATURES].copy()
X_all = df[MINIMAL_FEATURES].copy()
X_test = df_test[MINIMAL_FEATURES].copy() if len(df_test) > 0 else None

# Label Encoding
CAT_FEATURES = ['protocol_type', 'service', 'flag']
label_encoders = {}

for col in CAT_FEATURES:
    le = LabelEncoder()
    # Train ve Test'teki tüm değerleri birleştirip fit ediyoruz (Hata almamak için)
    all_vals = pd.concat([df[col], df_test[col]], axis=0).astype(str).unique()
    le.fit(all_vals)
    
    X_normal[col] = le.transform(X_normal[col].astype(str))
    X_all[col] = le.transform(X_all[col].astype(str))
    if X_test is not None:
        X_test[col] = le.transform(X_test[col].astype(str))
    label_encoders[col] = le

# Log Transform (Büyük sayıları küçültür)
def apply_log(df_in):
    temp = df_in.copy()
    log_cols = ['src_bytes', 'dst_bytes', 'duration', 'count', 'srv_count', 'dst_host_count', 'dst_host_srv_count']
    for c in log_cols:
        if c in temp.columns:
            temp[c] = np.log1p(temp[c])
    return temp

X_normal = apply_log(X_normal)
X_all = apply_log(X_all)
if X_test is not None: X_test = apply_log(X_test)

# Scaling
scaler = StandardScaler()
X_normal_scaled = scaler.fit_transform(X_normal.values)
X_all_scaled = scaler.transform(X_all.values)
if X_test is not None: X_test_scaled = scaler.transform(X_test.values)

# PCA
pca = PCA(n_components=PCA_VARIANCE, random_state=42)
X_normal_pca = pca.fit_transform(X_normal_scaled)
X_all_pca = pca.transform(X_all_scaled)
if X_test is not None: X_test_pca = pca.transform(X_test_scaled)

print(f"✔ PCA Bileşen Sayısı: {X_normal_pca.shape[1]}")

# =========================
# 3. MODEL EĞİTİMİ (k=2)
# =========================
kmeans = KMeans(n_clusters=K_CLUSTERS, random_state=42, n_init=10)
labels_normal = kmeans.fit_predict(X_normal_pca)
cluster_centers = kmeans.cluster_centers_

# Threshold Hesaplama
thresholds_per_cluster = {}
for c in range(K_CLUSTERS):
    mask = labels_normal == c
    if np.sum(mask) > 0:
        dists = np.linalg.norm(X_normal_pca[mask] - cluster_centers[c], axis=1)
        # %93'lük dilimi alıyoruz. Geri kalan %7 anomali sayılmaya aday.
        thresholds_per_cluster[c] = np.percentile(dists, THRESHOLD_PERCENTILE)
    else:
        thresholds_per_cluster[c] = 0

print(f"✔ Thresholdlar: {thresholds_per_cluster}")

# =========================
# 4. TESPİT VE PERFORMANS
# =========================
def predict_anomaly(X_pca):
    dists = np.linalg.norm(X_pca[:, np.newaxis] - cluster_centers, axis=2)
    nearest = np.argmin(dists, axis=1)
    min_dists = dists[np.arange(len(dists)), nearest]
    thrs = np.array([thresholds_per_cluster[c] for c in nearest])
    return min_dists > thrs

def print_scores(name, y_true, y_pred):
    tp = np.sum(y_pred & y_true)
    fp = np.sum(y_pred & ~y_true)
    tn = np.sum(~y_pred & ~y_true)
    fn = np.sum(~y_pred & y_true)
    
    acc = (tp + tn) / len(y_true)
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    rec = tp/(tp+fn) if (tp+fn)>0 else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    
    print(f"\n📊 {name} SONUÇLARI")
    print("-" * 30)
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"Detay    : TP={tp}, FP={fp}, TN={tn}, FN={fn}")

# Train Performansı
y_train_true = (df['class'] != 'normal').values
pred_train = predict_anomaly(X_all_pca)
print_scores("TRAIN", y_train_true, pred_train)

# Test Performansı
if X_test is not None:
    y_test_true = (df_test['class'] != 'normal').values
    pred_test = predict_anomaly(X_test_pca)
    print_scores("TEST", y_test_true, pred_test)

# =========================
# KAYDET
# =========================
model_data = {
    "kmeans": kmeans,
    "scaler": scaler,
    "pca": pca,
    "label_encoders": label_encoders,
    "thresholds_per_cluster": thresholds_per_cluster,
    "cluster_centers": cluster_centers,
    "minimal_features": MINIMAL_FEATURES
}

with open("anomaly_detector_kmeans_k2.pkl", "wb") as f:
    pickle.dump(model_data, f)
print("\n💾 Model Kaydedildi: anomaly_detector_kmeans_k2.pkl")