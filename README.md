# Otomatik Kod İnceleme ve Güvenlik Denetim Botu (PR Code Review Bot)

Bu proje, GitHub üzerinde bir Pull Request (PR) açıldığında veya yeni bir commit gönderildiğinde (synchronize) devreye girerek değişen kodları (`git diff`) otomatik olarak denetleyen bir **Kod İnceleme Botu** altyapısı içerir.

---

## 🚀 Temel Özellikler

1. **İkili Denetim Motoru (Hybrid Engine):**
   * **Statik Kural Motoru (Deterministic & Zero-Dependency):** Harici paket indirmeye ihtiyaç duymadan Python standart kütüphaneleriyle milisaniyeler içinde çalışır.
     * 🚨 **Açık Parola & Gizli Bilgiler:** Kod içine gömülü şifreler, API anahtarları, gizli token'lar.
     * 🚨 **SQL Injection (CWE-89):** Ham string birleştirme ile oluşturulan veritabanı sorguları.
     * 💥 **Çalışma Zamanı Çökme Riskleri (NullReference):** Null atanan değişkenlerin kontrolsüz çağrılması.
     * 🧹 **Temiz Kod & Anti-Pattern:** Üretim seviyesinde `Console.WriteLine` kullanımı, zayıf tip tanımları, asenkronluk eksiklikleri.
   * **Yapay Zeka Destekli Derin İnceleme (Google Gemini 2.5 Flash):** Eğer ortam değişkenlerinde `GEMINI_API_KEY` tanımlıysa, PR diff'ini analiz ederek kıdemli yazılım mimarı gözüyle detaylı mimari ve refactoring önerileri sunar.

2. **GitHub Entegrasyonu:**
   * **PR Yorumu (PR Comment):** İnceleme raporunu doğrudan Pull Request altına yorum olarak ekler. Yeni commit gelirse mevcut yorumu günceller (spam yapmaz).
   * **GitHub Step Summary:** GitHub Actions arayüzünde görsel özet kartı oluşturur.
   * **Kritik Hata Blokajı (`--fail-on-critical`):** Güvenlik açığı veya çökme riski varsa PR kontrolünü kırmızıya çekerek hatalı kodun `main` dalına merge edilmesini engeller.

---

## 📁 Proje Yapısı

```
.
├── .github/
│   └── workflows/
│       └── pr-review.yml          # GitHub Actions CI iş akışı
├── scripts/
│   ├── code_review.py             # Ana kod inceleme botu script'i
│   ├── test_code_review.py        # Bot için otomatik birim testler
│   └── requirements.txt           # Bağımlılık ve ortam açıklamaları
├── UserController.cs              # Örnek test sınıfı
└── README.md
```

---

## 🛠️ Yerel Ortamda Test Etme

Botu yerel makinenizde herhangi bir dal veya commit için çalıştırabilirsiniz:

```bash
# 1. 'main' dalı ile mevcut dal arasındaki farkı denetleme:
python3 scripts/code_review.py --base main --head HEAD

# 2. Kritik hatalar varsa komutun exit code 1 dönmesini sağlama (CI modu):
python3 scripts/code_review.py --base main --head HEAD --fail-on-critical

# 3. İnceleme raporunu bir dosyaya kaydetme:
python3 scripts/code_review.py --base main --head HEAD --output review-report.md

# 4. Otomatik birim testleri çalıştırma:
python3 -m unittest discover -s scripts
```

---

## 🔑 GitHub Yapılandırması (Repository Secrets)

GitHub Actions üzerinde botun tam kapasite çalışması için gereken adımlar:

1. **GitHub Token İzinleri:**
   * `pr-review.yml` dosyasında `pull-requests: write` ve `issues: write` izinleri tanımlanmıştır. Ek bir ayar yapmanıza gerek yoktur; GitHub Actions otomatik sağlar.
2. **(İsteğe Bağlı) Yapay Zeka Desteği:**
   * GitHub reponuzda **Settings -> Secrets and variables -> Actions** yolunu izleyin.
   * `GEMINI_API_KEY` adıyla yeni bir Repository Secret ekleyin.
   * Secret eklendiğinde bot otomatik olarak Gemini 2.5 Flash ile derin mimari analiz raporunu da PR'a ekleyecektir.
