# 🛡️ IDS — Makine Öğrenmesi ile Ağ Trafiği Anomali Tespit Sistemi

Python ve makine öğrenmesi algoritmaları kullanılarak geliştirilmiş, ağ trafiğindeki anormal davranışları ve olası siber saldırıları tespit etmeyi amaçlayan deneysel bir **Intrusion Detection System (IDS)** projesidir.

## 🎯 Projenin Amacı

Bu projenin amacı, ağ trafiği verilerini analiz ederek normal trafik davranışından sapan bağlantıları tespit etmektir.

Sistem, NSL-KDD veri seti üzerinde eğitilen bir makine öğrenmesi modeli kullanmaktadır. PCA ile boyut indirgeme, K-Means ile kümeleme ve küme merkezlerine uzaklık üzerinden anomali tespiti gerçekleştirilmektedir.

Ayrıca Scapy kütüphanesi aracılığıyla canlı ağ paketlerini analiz etmeye yönelik bir uygulama geliştirilmiştir.

## 🛠️ Kullanılan Teknolojiler

| Teknoloji | Kullanım Amacı |
|---|---|
| Python | Yazılım geliştirme |
| Scikit-learn | K-Means, PCA ve StandardScaler |
| Pandas | Veri işleme ve analiz |
| NumPy | Sayısal işlemler |
| Scapy | Ağ paketlerini yakalama |
| NSL-KDD | Eğitim ve test veri seti |
| Pickle | Eğitilmiş modeli kaydetme ve yükleme |

## ⚙️ Sistem Nasıl Çalışır?

**1. Veri hazırlama:** NSL-KDD veri setindeki ağ bağlantı kayıtları okunur. Seçilen 18 özellik üzerinde veri ön işleme gerçekleştirilir.

**2. Boyut indirgeme:** PCA algoritması kullanılarak verinin boyutu azaltılır ve açıklanan varyansın %99'u korunmaya çalışılır.

**3. Model eğitimi:** K-Means algoritması, normal trafik kayıtlarını kullanarak iki küme oluşturur (`k=2`).

**4. Anomali tespiti:** Ağ bağlantılarının küme merkezlerine uzaklıkları hesaplanır. Belirlenen eşik değerinin üzerindeki kayıtlar anomali olarak işaretlenir.

**5. Canlı trafik analizi:** Scapy aracılığıyla yakalanan IP paketlerinden özellikler çıkarılır ve eğitilmiş modelle değerlendirilir.

## 📁 Proje Dosyaları

```text
IDS-Projesi/
├── egitim2.py
├── ids2.py
├── KDDTrain+.txt
├── KDDTest+.txt
└── README.md
```

| Dosya | Açıklama |
|---|---|
| `egitim2.py` | Model eğitimi ve performans değerlendirmesi |
| `ids2.py` | Canlı ağ paketlerinin analizi |
| `KDDTrain+.txt` | Eğitim veri seti |
| `KDDTest+.txt` | Test veri seti |

## 🚀 Kurulum ve Çalıştırma

### 1. Gerekli kütüphaneleri yükleyin

Python kurulumundan sonra terminalde:

```bash
pip install numpy pandas scikit-learn scapy
```

### 2. Modeli eğitin

```bash
python egitim2.py
```

Eğitim tamamlandığında aşağıdaki model dosyası oluşturulur:

```text
anomaly_detector_kmeans_k2.pkl
```

Bu dosya eğitilmiş K-Means modeli, PCA, ölçekleyici, kodlayıcılar ve anomali eşiklerini içerir.

### 3. IDS uygulamasını başlatın

```bash
python ids2.py
```

Uygulama ağ paketlerini izleyerek normal ve anormal trafik davranışlarını terminalde değerlendirmeyi amaçlar.

**Not:** Windows üzerinde canlı paket yakalama için Npcap kurulumu ve yönetici izinleri gerekebilir. Analiz yalnızca yetkili olunan ağlarda gerçekleştirilmelidir.

## 📊 Model Performansı

NSL-KDD veri setiyle gerçekleştirilen çevrimdışı değerlendirme sonuçları:

| Performans Metriği | Test Sonucu |
|---|---:|

| Precision | %85,92 |

**Eğitim veri sayısı:** 125.973

**Test veri sayısı:** 22.544

Model, test verisindeki 4.444 saldırı kaydını doğru tespit etmiş, 8.389 saldırı kaydını ise kaçırmıştır.

Bu sonuçlar sistemin henüz üretim ortamında güvenilir bir IDS olarak kullanılamayacağını göstermektedir.

## ⚠️ Projenin Sınırlamaları

- Canlı trafik analizinin gerçek ağ ortamındaki başarısı henüz doğrulanmamıştır.
- NSL-KDD bağlantı özellikleriyle canlı paketlerden çıkarılan özellikler tam olarak eşdeğer değildir.
- Modelin saldırı yakalama oranının artırılması gerekmektedir.
- Proje eğitim ve araştırma amaçlı geliştirilmiştir.

## 🔮 Gelecekteki Geliştirmeler

- Random Forest ve Isolation Forest gibi alternatif algoritmalarla karşılaştırma.
- Daha başarılı anomali tespit modellerinin geliştirilmesi.
- Gerçek zamanlı analiz sonuçları için web arayüzü.
- Saldırı kayıtlarının veritabanında saklanması.
- Gerçek ağ verileri üzerinde kontrollü performans testleri.

## 👨‍💻 Geliştiriciler

**Muhammet Ali Bayrak**

Yazılım Mühendisliği

[GitHub Profilim](https://github.com/MuhammetAliBayrak61)

## 📚 Veri Seti

Modelin eğitilmesi ve değerlendirilmesi için **NSL-KDD** veri seti kullanılmıştır. Bu veri seti, ağ saldırı tespit sistemleri üzerine yapılan akademik çalışmalarda kullanılan bir veri kaynağıdır.

---

**Proje Durumu:** Model eğitimi ve test işlemleri gerçekleştirilmiştir. Canlı trafik analizi deneysel aşamadadır.
