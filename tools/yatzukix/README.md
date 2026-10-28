# yatzukix tool's

Terminal guvenlik araci seti. Saf Python standart kutuphanesi: pip yok,
`cryptography` yok, derleme yok. Linux, Termux ve iSH uzerinde calisir.

```
                       __              __   _
     __  ______  ____  / /_  __  ______/ /__(_)  __
    / / / / __ \/ __ \/ __/ / / / / __  / __/ / |/_/
   / /_/ / /_/ / /_/ / /_  / /_/ / / /_/ / /_/ />  <
    \__, /\____/\____/\__/  \__,_/  \__,_/\__/_/_/|_|
   /____/          y a t z u k i x   t o o l ' s
```

## Kurulum

```sh
sh install.sh          # ortami algilar, Python kurar, modulleri dogrular, testleri calistirir
sh install.sh run      # kurulumdan sonra dogrudan baslatir
```

Elle calistirma:

```sh
python3 yatzukix.py            # interaktif menu
python3 yatzukix.py scan -h    # alt komut yardimi
python3 -m yatzukix            # modul olarak (dizin icinden)
```

Platform notlari:

| Platform | Python kurulumu | Not |
|---|---|---|
| Termux | `pkg install python` | Tam destek. Native ARM, tam eszamanlilik. |
| iSH (iOS) | `apk add python3` | Calisir. 32-bit emulasyon: yavas. `-w` otomatik 24'e sinirlanir. |
| Alpine | `apk add python3` | Tam destek. |
| Debian/Ubuntu | `apt install python3` | Tam destek. |
| macOS | `brew install python3` | Tam destek. |

`install.sh` POSIX `sh` ile yazildi: bash, dash ve BusyBox `ash` uzerinde
calisir. Bash gerekmez.

Gereksinim: Python 3.8+. Harici arac gerekmez; `nmap`, `hashcat`, `msfvenom`
varsa komut ureticileri onlara uygun satirlar basar, yoksa da calisir.

### iSH uzerinde calistirma

iSH, iOS'ta 32-bit x86 emulasyonu calistirir. Alpine tabanli, BusyBox `ash`
kullanir. Kurulum:

```sh
apk update
apk add python3

# kodu al ve calistir
cd ~/yatzukix
sh install.sh run
```

Beklenen cikti:

```
1/4  Ortam tespiti
  platform : ish
  kabuk    : POSIX sh / ash
  dizin    : /root/yatzukix
  not      : iSH 32-bit emulasyon, agir taramalarda -w dusur

2/4  Python kontrolu
[+] /usr/bin/python3 - Python 3.11.x
```

iSH gercekleri:

- **Hiz.** 32-bit emulasyon, native ARM'dan belirgin yavas. `default_workers()`
  iSH'te tavani 24'e indirir; 100 thread emulatoru bogar, tarama yavaslar.
  Elle `-w 200` versen bile 24'e kirpilir.
- **Arka plan.** iOS uygulamayi askiya alir. Uzun taramalarda iSH on planda
  kalmali. `discover 10.0.0.0/16` gibi isleri parcalara bol.
- **Root yok.** Raw socket yok, bu yuzden `net.py` SYN taramasi degil TCP
  connect taramasi kullanir. Bu iSH'te kisitlama degil, tasarim geregi.
- **Klavye.** Menu sayilari klavyeden girilir; `q` ile cikis.
- **Ag.** Yerel aga erisim icin VPN gerekebilir. Isletim sisteminin
  local network izni verildiginden emin ol.

Hizli test:

```sh
python3 yatzukix.py sysinfo
python3 yatzukix.py scan 192.168.1.1 -p 22,80,443 -t 2
```

## Moduller

| Komut | Ne yapar |
|---|---|
| `scan` | TCP connect port tarama, banner grab, servis tespiti, riskli port uyarisi |
| `discover` | CIDR/aralik genisletme ve TCP ping sweep |
| `webfp` | HTTP parmak izi, eksik guvenlik basliklari, CORS denetimi, CVE ipuclari |
| `webscan` | SQLi (error + time based), XSS, LFI, komut enjeksiyonu, open redirect probu |
| `dirs` | Dizin/dosya kesfi ve hassas dosya taramasi |
| `payload` | 20 reverse shell, listener komutlari, TTY yukseltme, msfvenom katalogu |
| `osint` | Kullanici adi taramasi, e-posta analizi, IOC ayiklama, metadata, strings |
| `hash` | Hash tanima, hashcat/john komut uretimi, sozluk saldirisi |
| `crypto` | Sifreleme/cozme, JWT zayifliklari, XOR brute-force, encoding |
| `wordlist` | Mutasyonlu kelime listesi uretimi |
| `dorks` | Google, GitHub ve Shodan sorgu setleri |
| `sysinfo` | Ortam, yetenek ve bagimlilik raporu |

## Ornekler

```bash
# Port tarama
python3 yatzukix.py scan 10.0.0.5 -p 22,80,443,8000-8100 -w 200

# Ag kesfi
python3 yatzukix.py discover 192.168.1.0/24

# Web parmak izi ve zafiyet probu
python3 yatzukix.py webfp https://example.com
python3 yatzukix.py webscan "https://example.com/item?id=1" --params id

# Dizin kesfi
python3 yatzukix.py dirs https://example.com --ext php,bak,sql,zip

# Payload uretimi
python3 yatzukix.py payload --lhost 10.10.14.7 --lport 4444 --encode base64

# OSINT
python3 yatzukix.py osint --username somehandle
python3 yatzukix.py osint --iocs "C2 45.77.12.9 CVE-2021-44228" --metadata sample.bin --strings 50

# Hash
python3 yatzukix.py hash --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
python3 yatzukix.py hash --text merhaba

# Kripto
python3 yatzukix.py crypto --encrypt secret.bin --password "parola"
python3 yatzukix.py crypto --jwt "$TOKEN"
python3 yatzukix.py crypto --password-gen 5
```

## Kripto notu

`crypto` modulu AES kullanmaz, cunku standart kutuphanede AES yok. Bunun yerine
gercek bir akis sifresi kurar: SHA-256 counter mode keystream + HMAC-SHA256
dogrulama + PBKDF2-HMAC-SHA256 anahtar turetimi. Yanlis parola veya degistirilmis
veri `ValueError` ile reddedilir. Kisisel dosyalar icin `age`, `gpg` veya
`cryptography` kutuphanesini tercih et; bu modul tasinabilirlik icin var.

## Testler

```bash
python3 -m unittest discover -s tests -t .
```

56 test, ag erisimi gerekmez. Kapsam: port ayristirma, hedef genisletme,
sifreleme round-trip ve kurcalama tespiti, hash dogrulugu, JWT forge/verify,
XOR kurtarma, payload formatlama, web yardimcilari, IOC ayiklama, metadata.

## Lisans ve kullanim

Sadece sahibi oldugun veya yazili izin aldigin sistemlerde kullan. Izinsiz
kullanim TCK 243-245 kapsaminda suctur. `webscan` ve `dirs` komutlari
calismadan once yetki onayi ister.
