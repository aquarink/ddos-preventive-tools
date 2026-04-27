# DDoS Preventive Tools

Tool open source berbasis Python untuk membaca access log Nginx/Apache, mendeteksi pola trafik yang mencurigakan, lalu menyiapkan aksi blokir IP lewat firewall.

Secara default tool berjalan dalam mode **dry-run**: IP yang terdeteksi hanya dicetak ke terminal. Blokir firewall baru dijalankan jika memakai opsi `--enforce`.

## Fitur

- Parsing access log format umum Nginx/Apache.
- Deteksi DDoS dan probing memakai beberapa rule berbasis window waktu.
- Cache negara IP memakai SQLite agar lookup eksternal tidak dilakukan berulang.
- Backend firewall: `firewalld`, `iptables`, `nft`, atau `print`.
- Bisa dijalankan manual, via cron, systemd timer, atau streaming dari `tail -F`.

## Arsitektur

Kode sudah dipecah menjadi beberapa modul agar mudah dirawat:

```text
ddos.py                     # entry point command lama
ddos_preventive/
  cli.py                    # argumen CLI dan flow utama
  detector.py               # rule deteksi DDoS/probing
  firewall.py               # backend firewalld/iptables/nft
  geoip.py                  # cache SQLite dan lookup ipinfo
  log_parser.py             # parser access log Nginx/Apache
  models.py                 # dataclass konfigurasi dan log entry
  stream.py                 # mode streaming dari stdin
```

## Rule Deteksi

Tool ini tidak lagi terbatas pada 6 rule awal. Rule yang tersedia sekarang:

1. **Large response body**: satu request mengirim byte terlalu besar.
2. **Uncommon HTTP method**: method di luar `GET,POST,HEAD,OPTIONS`.
3. **Unusual URL format**: path tidak diawali `/`, mengandung `*`, atau backslash.
4. **High request rate**: jumlah request dari satu IP melewati batas dalam window waktu.
5. **Same path requested too often**: satu IP memukul path yang sama terlalu sering.
6. **Too many suspicious response codes**: terlalu banyak status seperti `400,401,403,404,429,500,502,503`.
7. **Suspicious user-agent**: user-agent kosong atau umum dipakai scanner/tool otomatis.
8. **Sensitive path probing**: request ke path seperti `.env`, `wp-login.php`, `phpmyadmin`, `.git`, `backup`, dan sejenisnya.
9. **Long query string**: query string terlalu panjang.
10. **Too many unique URL paths**: satu IP mencoba banyak path berbeda dalam window waktu.
11. **Country allow-list**: opsional, hanya mengizinkan negara tertentu jika `--allowed-countries` diisi.

## Instalasi

Tidak ada dependency Python eksternal. Cukup gunakan Python 3 modern.

```bash
git clone https://github.com/aquarink/ddos-preventive-tools.git
cd ddos-preventive-tools
python3 -m py_compile ddos.py
```

## Cara Pakai

Dry-run dari folder log default `/var/log/nginx`:

```bash
python3 ddos.py
```

Dry-run dari file tertentu:

```bash
python3 ddos.py --log-file /var/log/nginx/example-access.log
```

Realtime ringan dari Nginx access log:

```bash
tail -F /var/log/nginx/access.log | python3 ddos.py --stdin
```

Realtime dan blokir sungguhan:

```bash
tail -F /var/log/nginx/access.log | sudo python3 ddos.py --stdin --enforce --firewall firewalld
```

Atur threshold:

```bash
python3 ddos.py \
  --log-file /var/log/nginx/example-access.log \
  --window-seconds 60 \
  --rate-limit 120 \
  --same-path-limit 60 \
  --error-limit 30
```

Blokir sungguhan memakai firewalld:

```bash
sudo python3 ddos.py --enforce --firewall firewalld
```

Blokir sungguhan memakai iptables:

```bash
sudo python3 ddos.py --enforce --firewall iptables
```

Blokir sungguhan memakai nftables:

```bash
sudo python3 ddos.py --enforce --firewall nft
```

## Country Allow-list

Rule negara bersifat opsional. Jika ingin hanya mengizinkan Indonesia dan Timor-Leste:

```bash
export IPINFO_TOKEN="token-ipinfo-anda"
python3 ddos.py --allowed-countries ID,TL
```

Token tidak disimpan di source code. Gunakan environment variable `IPINFO_TOKEN`.

Cache lookup disimpan di `ipinfo.db` secara default. Bisa diubah dengan:

```bash
python3 ddos.py --db-path /var/lib/ddos-preventive-tools/ipinfo.db
```

## Python atau Bash?

Python cukup untuk engine utama karena tool ini perlu parsing log, state window, cache SQLite, validasi IP, dan beberapa backend firewall. Bash tetap berguna sebagai wrapper deployment, misalnya untuk cron:

```bash
*/5 * * * * root /usr/bin/python3 /opt/ddos-preventive-tools/ddos.py --enforce --firewall firewalld >> /var/log/ddos-preventive-tools.log 2>&1
```

Sebaiknya jangan membuat versi Bash yang menduplikasi semua rule, karena logic deteksi akan lebih sulit dites dan mudah berbeda dari versi Python.

## Flow Realtime

Untuk proteksi HTTP layer 7, membaca access log Nginx masih masuk akal karena Nginx sudah menyediakan IP, method, path, status code, byte response, dan user-agent. Yang perlu dihindari adalah membaca ulang seluruh file log setiap kali program jalan.

Flow yang direkomendasikan:

1. Nginx menulis access log.
2. `tail -F` mengirim hanya baris log baru.
3. `ddos.py --stdin` membaca stream baris demi baris.
4. Detector menyimpan state request dalam window waktu.
5. Jika threshold terlampaui, firewall backend memblokir IP.

Untuk serangan layer 3/4 seperti SYN flood, UDP flood, atau bandwidth exhaustion, access log Nginx tidak cukup. Gunakan proteksi tambahan seperti firewall/kernel rate limit, CDN/WAF, atau proteksi dari provider jaringan.

## Catatan Keamanan

- Jalankan tanpa `--enforce` dulu untuk melihat IP dan alasan blokir.
- Naikkan atau turunkan threshold sesuai trafik normal server.
- Backend `nft` mengasumsikan table/chain `inet filter input` sudah ada.
- Tool ini membantu mitigasi sederhana di level host. Untuk serangan besar, tetap butuh proteksi tambahan seperti CDN, WAF, rate limit Nginx, atau proteksi dari provider jaringan.
