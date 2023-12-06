# Deskripsi Proyek DDoS Detection

Proyek ini dibuat dengan menggunakan bahasa pemrograman Python dan bertujuan untuk menganalisis file log layanan web dari server Nginx, Apache, atau platform lainnya. Proyek ini memiliki fungsi utama yaitu mendeteksi serangan Distributed Denial of Service (DDoS) dengan menerapkan enam aturan pengecekan yang telah diimplementasikan dalam kode.

## Cara Kerja

1. **Baca Log Layanan Web:** Proyek ini dimulai dengan membaca file log layanan web yang dihasilkan oleh server yang bersangkutan.

2. **Pengecekan Enam Aturan:** Algoritma proyek menjalankan enam aturan yang telah ditentukan untuk mengidentifikasi pola-pola khusus dalam log yang dapat mengindikasikan adanya serangan DDoS.

3. **Aksi Firewall:** Jika proyek mendeteksi bahwa lalu lintas memenuhi kriteria serangan DDoS, langkah selanjutnya adalah memasukkan alamat IP penyerang ke dalam daftar firewall.

## Manfaat

- Proaktif Terhadap Serangan DDoS
- Analisis Log Otomatis
- Respons Cepat Melalui Integrasi dengan Firewall

## Tujuan

Melindungi server dan mengurangi dampak serangan DDoS terhadap ketersediaan layanan dengan mengidentifikasi dan memblokir alamat IP penyerang yang terdeteksi.

Proyek ini menyediakan solusi yang efektif dan otomatis untuk menghadapi serangan DDoS, menjadikannya pilihan yang kuat untuk meningkatkan keamanan server.
