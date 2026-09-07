# PRIMORDIUM — ÇÖZÜM (TAMAMLANDI)

## Şema özeti (kural → sayfa eşlemesi)
| Kural | Şema |
|---|---|
| 1 · "The mirror reverses" | **Page I = Atbash** (mod-26) |
| 2 · "One letter never speaks" | **F sessiz harf**: Page II'de F şifrelenmez (passthrough) ve **keystream'i durdurur** |
| 3 · "Primes are sacred, subtract one" | **Page III = asal akışı**: i. karakterin shift'i = (i. asal − 1) mod 26 |
| 4 · "The square is 3" | **Page III = 3-kolon kolon aktarımı** (75 satır × 3 kolon) — akıştan ÖNCE çözülür |

## Sayfa II'nin şifre sistemi
Vigenère, **anahtar = `CIRCUMFERENCE`** (13 harf — IC tepe noktası buydu), fakat:
- Çember = **25 harf** (F çıkarılmış): `A B C D E G H I J K L M N O P Q R S T U V W X Y Z`
- Shift değeri = anahtar harfin **normal 26-alfabe indeksi** (mod 25'e indirgenir)
  → C=2, I=8, R=17, C=2, U=20, M=12, **F=5**, E=4, R=17, E=4, N=13, C=2, E=4
- Şifre metninde `F` görürsen: düz metne `F` yaz, **anahtar bir sonraki harfe geçmez**
- Şifreleme: `C = circle(P + shift)`, çözme: `P = circle(C − shift)`

Page I'in bilmecesi kilit adını tam veriyor: *"Speak the name of the voice that sings
**along the rim**"* → bir çemberin kenarı boyunca uzanan şey = **CIRCUMFERENCE**.
Ve o kelimenin tam ortasındaki F, "hiç konuşmayan" harf: şifrelenmez, durdurur.

## Düz metinler

### PAGE I — THE MIRROR (Atbash)
> PRIMORDIUM THE BOOK OF THE CIRCLE. BELIEVE NOTHING YOU ARE TOLD UNTIL YOU HAVE TESTED
> IT YOURSELF. THE MIRROR REVERSES ALL THINGS. WHAT ENDS WHERE IT BEGINS IS A CIRCLE,
> AND THE CIRCLE HAS NO SIDES. SPEAK THE NAME OF THE VOICE THAT SINGS ALONG THE RIM,
> AND IT WILL UNLOCK THE SECOND DOOR.

### PAGE II — THE VOICE (CIRCUMFERENCE-Vigenère, 25-harf çemberi + F-durdurma)
> A STUDENT ASKED THE MASTER, "WHO AM I?" THE MASTER DREW A CIRCLE AND SAID, "YOU ARE
> THE ONE WHO READS THESE RUNES." THE STUDENT SAID, "I HEAR ONLY MY OWN THOUGHTS."
> THE MASTER REPLIED, "THEN YOU HAVE NOT LEARNED TO LISTEN. ONE LETTER NEVER SPEAKS,
> YET IT TEACHES EVERY RULE. THE PRIMES ARE SACRED, FOR THEY CANNOT BE DIVIDED.
> COUNT THEM AND SUBTRACT ONE TO OPEN THE FINAL DOOR."

(İki `F` de metinde serbest dolaşımda: "...SACRED **F**OR THEY..." ve "...THE **F**INAL DOOR" —
şifre metnindeki tek iki F bunlar, birebir örtüşüyor.)

### PAGE III — THE END (3-kolon kolon aktarımı + (asal−1) akışı)
> THE CIRCLE HAS NO END, YET IT ENDS WHERE IT BEGINS. SO TOO THE SELF HAS NO END UNTIL
> YOU CHOOSE TO END IT. BE LIKE THE PRIME: INDIVISIBLE AND TRUE. QUESTION ALL THINGS
> AND HOLD NONE. THE KEY WAS NEVER HIDDEN — IT WAS THE CIRCLE ITSELF, ALL ALONG.
> THE JOURNEY DOES NOT END. IT ONLY BEGINS ANEW. XX
(XX = 225 = 75×3 ızgarını dolduran dolgu)

## Kapılar
- **Door 1** — "sessiz harf"i söyle: **F** → "the voice will sing": F, sesin (CIRCUMFERENCE)
  içinden geçer. Ortaya çıkan: `dGhlLXZvaWNlLXNpbmdz` = **Base64** → "the-voice-sings".
- **Door 2** — "bölünemez, 2⁸+1" → **257** (Fermat asalı) → `7468652d656e642d626567696e73`
  = **Hexadecimal** → "the-end-begins".
- **Door 3** — "yedi kez kaydırılmış" → Caesar −7: `WYPTVYKPBT` → **PRIMORDIUM**.

## §7 teslim listesi
1. Page I/II/III düz metinleri ✅ (yukarıda)
2. Page II anahtarının adı: **CIRCUMFERENCE** ✅
3. Door kodlamaları: **Base64** ve **Hexadecimal (base16)** ✅
4. Final kelime: **PRIMORDIUM** ✅
5. Stego ifadesi: `clue.png` ve `tools/stego_extract.py` repoya hiç eklenmemiş
   (git geçmişi doğrulandı) — bu faz veri eksikliğinden yapılamaz.

## Çözüm sırasında yapılan iki hata (itiraf)
1. mod-25 "F hariç" denemelerinde **shift'i de 25-alfabe indeksinden aldım**
   (P25[key]); doğrusu shift = 26-alfabe indeksi, halka = 25-harf. Bu, kolon
   başına ±1'lık "tuhaf" sapmaların kaynağıydı (C=2→2, I=8→7 gibi).
2. "asal akışı"nı 26 asalı **döngüsel** denedim; Page III'teki **pozisyon bazlı
   dizi** (i. asal, ve −1'li hali) + 3-kolon kolon aktarımı kombinasyonunu
   ancak bilinen-düz-metin (Page II'nin ilk 22 harfi) anahtarı verdikten sonra
   tam kademeyle aradım. Frekans testi "düz" görünen Page II/III'ü doğru
   şekilde "monoalfabetik değil"diye elemişti ama "rastgele" teşhisi yanlıştı:
   polyalfabetik + transpozisyon tam da böyle düz bir frekans üretir.
