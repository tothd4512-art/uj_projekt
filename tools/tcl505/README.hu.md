# TCL 505 / T509K – diagnosztika, fájlmásoló és USB-figyelő 0.4.0

**Ez a csomag még nem bootloader-feloldó.** Egy saját telefonhoz készült,
windowsos állapotfelmérő eszköz, amely a feloldófejlesztés első lépéseként
összegyűjti a pontos firmware-azonosítókat és a bootloader lekérdezhető válaszait.
A 0.3.0 külön, opcionális ADB fájlmásolót is kap: célzott, olvasható rendszer-
konfigurációkat másol a gépedre, hogy feltölthesd őket elemzésre.
A 0.3.1 a fastboot gyártói `unlock_ability = ...` válaszát is felismeri; a
nem szabványos 0/1 értéket nyers bizonyítékként rögzíti, nem feloldási engedélyként.
A 0.4.0 új, **passzív Windows USB/PnP figyelőt** ad (`tcl505_usb_watch.py`):
kikapcsolt telefon + kézi gombkombinációk mellett azt figyeli, hogy megjelenik-e
MediaTek preloader/BROM USB eszköz, milyen VID/PID-vel és mennyi ideig.

Nem tartalmaz „univerzális unlock” gombot, más telefonról származó partíciót,
gyártói kulcsot vagy találgatásra épülő flashelést. A T509K működő feloldási
eljárása ezzel a változattal még nincs igazolva.

## Mit csinál és mit nem?

- Normál Androidban ADB-n keresztül meghatározott `getprop` értékeket olvas.
- A 0.3.0 változat a közösségi TCL token-jelzőket (`ro.boot.*token`) is
  lekérdezi. Váratlan, nem logikai érték esetén a nyers értéket a jelentésből
  és a parancsnaplóból is eltávolítja.
- A `ro.boot.tksn` mezőnek **csak a jelenlétét** rögzíti, az értékét nem.
  A `com.tcl.token` csomag jelenlétét pontos csomagnév-egyezéssel vizsgálja;
  az alkalmazást nem indítja el, az adatait nem olvassa, tokent nem igényel.
- Bootloader-fastbootban meghatározott `getvar` értékeket és a
  `flashing get_unlock_ability` **lekérdezést** futtatja. A gyártói
  `unlock_ability = ...` alias választ is rögzíti; a nem szabványos 0/1 érték
  nem minősül feloldási engedélynek.
- UTF-8 szöveges és JSON jelentést készít a `reports` mappában.
- Ismeri a hiányzó eszközt, az engedélyezetlen ADB-t, a több eszközt, a
  parancs-időtúllépést és a nem támogatott lekérdezéseket.
- A jelentésből eltávolítja az ADB/fastboot eszközazonosítókat és a szokásos
  IMEI/serial mezőket. Megosztás előtt ennek ellenére nézd át a fájlokat.
- Az állapotfelmérő (`tcl505_probe.py`) **nem** futtat `unlock`,
  `unlock_critical`, `lock`, `flash`, `erase`, `format`, `oem`, `reboot`, `push`
  vagy `pull` parancsot.
- A külön fájlmásoló (`tcl505_files.py`) csak rögzített engedélylistán szereplő,
  normál ADB shell felhasználó által olvasható rendszerfájlokat másol a gépedre.
  Nem kér rootot, nem olvas nyers partíciót, `/data` vagy `/sdcard` tartalmat.
- A passzív USB-figyelő (`tcl505_usb_watch.py`) csak Windows PnP eseményeket és
  eszköz-metaadatot (VID/PID, osztály, szolgáltatás) olvas. **Nem nyit meg
  eszközhandle-t, nem nyit COM portot, nem küld USB transzfert**, nem futtat
  ADB/fastboot/MTK parancsot, nem telepít drivert, nem indítja újra a telefont.
- **Nem** próbál BROM-exploitot, nem telepít drivert, nem tölt le programokat és
  nem küld adatot az internetre.
- Nem állítja, hogy az OEM-feloldás kapcsoló vagy egy `flash.locked=0` érték
  önmagában teljes TCL bootloader-feloldást bizonyít.

A `fastboot flashing get_unlock_ability` a parancscsoport neve ellenére
lekérdezés. A program nem hívja a csoport tényleges feloldóparancsát.

## Előkészítés

1. Csak a saját, normálisan hozzáfért telefonoddal használd.
2. Legyen Python 3.9 vagy újabb: <https://www.python.org/downloads/windows/>.
   Telepítéskor a `py` launcher hasznos; a csomag nem telepíti automatikusan.
3. Legyen hivatalos Android SDK Platform Tools:
   <https://developer.android.com/tools/releases/platform-tools>.
4. Csomagold ki ezt a csomagot egy írható mappába, például `C:\TCL505` alá.
5. A Platform Tools mappát teheted a program mellé `platform-tools` néven:

   ```text
   C:\TCL505\
     tcl505_probe.py
     tcl505_files.py
     tcl505_usb_watch.py
     TCL505-Diagnosztika.cmd
     TCL505-Fastboot.cmd
     TCL505-Fajlok.cmd
     TCL505-USBfigyelo.cmd
     README.hu.md
     platform-tools\
       adb.exe
       fastboot.exe
       ...
   ```

   Ha már PATH-on vannak, külön másolás nem szükséges. Más helyről is megadható:
   `--platform-tools "C:\utvonal\platform-tools"`.
   A passzív USB-figyelőhöz **nincs szükség** Platform Toolsra vagy ADB/fastboot
   driverekre; csak Windows 10/11 és Python 3.9+ kell hozzá.

## 1. futtatás: normál Android + ADB

1. Kapcsold be az USB-hibakeresést, csatlakoztasd a telefont, és engedélyezd a
   saját számítógép ADB-kulcsát a telefon megjelenő ablakában.
2. Indítsd a **`TCL505-Diagnosztika.cmd`** fájlt.
3. A program nem indítja újra a telefont. A végén megjeleníti a jelentések helyét.

Parancssorból ugyanez:

```powershell
py -3 .\tcl505_probe.py --platform-tools "C:\platform-tools"
```

## 2. futtatás: bootloader-fastboot, ha elérhető

Ezt csak akkor futtasd, ha a telefont **kézzel** a bootloader-fastboot módba
tudtad tenni. A program nem próbál különböző gombkombinációkat vagy exploitokat.

1. Indítsd a **`TCL505-Fastboot.cmd`** fájlt.
2. Ha a telefon kijelzőjén `fastbootd` szerepel, az userspace fastboot. A program
   ezt jelzi, ha az `is-userspace` változó olvasható; nem tekinti bootloader-fastbootnak.
3. Ha nincs felismerhető eszköz vagy üres a kijelző, állj meg ennél a lépésnél.
   A jelentés ettől még elkészülhet. Nem kell unlock parancsokat próbálgatni.

```powershell
py -3 .\tcl505_probe.py --mode fastboot --platform-tools "C:\platform-tools"
```

Több csatlakoztatott eszköz esetén a program nem választ automatikusan. Az
`adb devices -l`, illetve `fastboot devices` által mutatott azonosítóval választhatsz:

```powershell
py -3 .\tcl505_probe.py --serial "AZ_ESZKOZ_AZONOSITOJA"
```

Az azonosító nem kerül a jelentésbe. Időtúllépés esetén a helyi programfutás
véget ér; ez nem jelent igazolt telefon-oldali állapotváltozást.

## 3. futtatás: célzott fájlmásolás elemzéshez

Ez a lépés opcionális, de hasznos, ha a pontos firmware-hez tartozó rendszerfájlokat
is meg akarod mutatni. Normál Androidban, engedélyezett ADB mellett futtasd a
**`TCL505-Fajlok.cmd`** fájlt.

Parancssorból:

```powershell
py -3 .\tcl505_files.py --platform-tools "C:\platform-tools"
```

A program egy új `reports\tcl505-files-<azonosító>` mappát és egy azonos nevű
`.zip` fájlt készít. A ZIP feltölthető elemzésre. A `manifest.json` felsorolja,
mi másolódott, mi hiányzott, mi volt olvasási jogosultság nélkül, és mi nem került
a csomagba méret vagy tartalom miatt.

A másoló csak rögzített engedélylistán szereplő, normál ADB shell felhasználó által
olvasható szöveges rendszerfájlokat próbál másolni: `build.prop` változatokat,
`fstab` fájljelölteket és néhány `init`/token-related `.rc` fájlt. Nem másol APK-t,
nem olvas `/data` vagy `/sdcard` tartalmat, nem kér rootot, nem indít újra, nem ír
a telefonra, és nem olvas nyers partíciót. Ha egy fájl `denied` vagy `missing`,
azt a manifest rögzíti; nem próbálja megkerülni a jogosultságot.

Az ismert személyes/titkos mezőket (például serial, IMEI, Wi-Fi/MAC, tksn,
nem logikai tokenérték) a másolatban redakálja. Ez nem garancia minden egyedi
gyártói adatra; feltöltés előtt nézd át a ZIP-et.

Kézi ADB példa, ha csak egy fájlt szeretnél másolni:

```powershell
adb pull /system/build.prop system-build.prop
adb pull /vendor/build.prop vendor-build.prop
adb pull /vendor/etc/fstab.mt6765 fstab.mt6765
```

Ha `Permission denied` vagy `No such file` a válasz, ne használj `su`-t vagy
partíció-dumpolást; küldd vissza a hibát/manifestet, és célzottan döntünk a
következő fájlról. Mélyebb partícióképek (például `lk`, `preloader`, `vbmeta`,
`boot`, `oembin`) normál ADB-ből általában nem olvashatók; ezekhez külön,
ellenőrzött hozzáférési út kellene.

## 4. futtatás: passzív USB-mód figyelő (A opció)

Ez a lépés azt méri, hogy a **kikapcsolt** telefon kézi gombkombinációk hatására
mutat-e MediaTek preloader/BROM USB eszközt a Windowsnak, milyen VID/PID-vel és
mennyi ideig. A program **csak figyel**: nem nyit meg eszközt, nem küld semmilyen
USB/ADB/fastboot/MTK parancsot, nem telepít drivert, nem tölt be DA-t, nem futtat
exploitot, nem ír partíciót és nem indítja újra a telefont. A telefon módját
neked kell kézzel beállítanod; a program nem próbál gombkombinációkat.

### Előkészítés és futtatás

1. Csomagold ki a csomagot egy írható mappába (pl. `C:\TCL505`). Python 3.9+
   legyen telepítve. Platform Tools / MTK driver **nem kell**.
2. Indítsd a **`TCL505-USBfigyelo.cmd`** fájlt. Alapértelmezésben 120 másodpercig
   figyel. Hosszabb ablakhoz parancssorból:

   ```powershell
   py -3 .\tcl505_usb_watch.py --seconds 180
   ```

3. Amíg a program fut, **kézzel** kapcsold ki a telefont, majd próbáld a szokásos
   gombkombinációkat (például hangerő fel/le + tápellátás, vagy csak az egyik
   hangerőgomb nyomva tartása USB-bedugáskor). A pontos kombináció modellenként
   eltérő; a program nem találgatja és nem kényszeríti ki.
4. A program a végén `reports\tcl505-usb-<azonosító>` mappát és azonos nevű
   `.zip` fájlt készít. A ZIP feltölthető elemzésre.

### Mit rögzít?

- Windows PnP események: eszköz megjelenése (`enumerated`/`started`), eltűnése
  (`removed`), valamint rendszeres pillanatképek a jelenlévő USB eszközökről.
- USB azonosítók: `VID`, `PID`, opcionális `MI`, busz; ezekből származó
  **jelölt** osztályozás (MTK BROM / preloader / preloader-vagy-DA / TCL ADB).
- Láthatósági időtartam munkamenetenként, UTC és relatív időbélyeggel.
- Eszközleírás, osztály, szolgáltatás (driver) metaadat – redakció után.

Az eszköz instance-azonosítója/serialja **nem kerül a jelentésbe**; csak egy
futásonként sózott, rövid kivonat (`instance_key`) szerepel, hogy az események
összeköthetők legyenek anélkül, hogy a nyers azonosítót megosztanád.

### Mit jelent az eredmény?

- `mediatek_brom_candidate` (`0E8D:0003`), `mediatek_preloader_candidate`
  (`0E8D:2000/201D/20FF/3000/6000`), `mediatek_preloader_or_da_candidate`
  (`0E8D:2001`) vagy `tcl_adb_usb_candidate` (`1BBB:0C01`) **jelölt** esetén
  a napló megmutatja, mennyi ideig volt látható az adott USB mód.
- A VID/PID egyezés **nem bizonyít** BROM-exploitot, DA betöltést, SLA/DAA
  megkerülést vagy írható `seccfg` hozzáférést. Ez csak a USB-mód jelenlétének
  passzív bizonyítéka.
- Ha nem látszik jelölt, az **nem bizonyítja**, hogy nincs preloader ablak:
  a Windows PnP észlelésnek is van késleltetése, és egy nagyon rövid ablak
  kimaradhat. A negatív eredményt óvatosan kell értelmezni.
- A láthatósági idő Windows PnP idő, nem pontos preloader handshake idő.

A következő lépést (például MTKClient diagnosztika vagy fastboot feloldás) csak
a napló elemzése után, külön jóváhagyással szabad eldönteni. Ez a program nem
végez módosítást.

### Mért eredmény 2026-11-13 (valós Windows futás)

Két valós, 120 másodperces futás történt. Az első alatt a telefon végig ADB-s
Android módban volt (`1BBB:0C01`, `still_present_at_end`), ezért kikapcsolt
telefonról nem mond semmit. A második futás kezdetén a kábel le volt húzva
(tiszta baseline), és négy MediaTek ablak jelent meg:

| látható ablak (rel.) | VID:PID | osztály / szolgáltatás | hossz |
|---|---|---|---|
| 31.0 – 33.4 s | `0E8D:2000` | USBDevice / WinUSB (MT65xx Preloader) | 2.38 s |
| 57.6 – 58.9 s | `0E8D:20FF` | HIDClass / HidUsb | 1.24 s |
| 80.2 – 82.7 s | `0E8D:2000` | USBDevice / WinUSB (MT65xx Preloader) | 2.51 s |
| 107.0 – 110.8 s | `0E8D:20FF` | HIDClass / HidUsb | 3.80 s |
| 118.4 – 120.0 s | `0E8D:2000` | USBDevice / WinUSB (MT65xx Preloader) | 1.62 s |

`0E8D:0003` (BROM) egyszer sem jelent meg. A `0E8D:2000` tehát ezen a
telefonon kézzel elérhető, 2–3 másodperces preloader-ablakot ad; a `0E8D:20FF`
pedig HID-osztályú preloader-oldali mód, nem BROM. A napló nem tartalmazza,
melyik ablak melyik gombkombinációhoz tartozott, ezért a kombinációk hatása
még nem izolálható.

Javasolt címkézett újramérés: 180–300 másodperces futás, próbánként kb. 40
másodperces réssel, minden próba előtt teljes kikapcsolás (Power 10–15 s,
rezgésig) és kihúzott kábellel: (1) gomb nélkül csak bedugás, (2) Hangerő FEL
+ bedugás, (3) Hangerő LE + bedugás, (4) mindkét hangerőgomb + bedugás. A
T509K szervizkézikönyv szerint a Power + Hangerő FEL a recovery menüt hozza,
ezért az nem része ennek a sorrendnek, és a recovery `Wipe data/factory reset`
pontját nem szabad megerősíteni.

## Feltöltés elemzésre

A létrejött `tcl505-files-<azonosító>.zip` vagy `tcl505-usb-<azonosító>.zip`
fájlt feltöltheted:

- **Google Drive**: lehetőleg privát mappába. A Drive-csatlakozás aktív, így a
  saját Drive-odba feltöltött fájlt meg tudom keresni és olvasni; nem kell
  nyilvánossá tenni. Küldd el a fájl nevét vagy a Drive-linket.
- **GitHub**: nyilvános repó/release linkje is jó. Privát GitHub repóhoz nincs
  külön alkalmazáscsatlakozás ebben a beszélgetésben, ezért a Drive az egyszerűbb.

Ne tölts fel személyes adatot, fényképet, üzenetet, fiókadatot vagy teljes
`/data` mentést. A mostani csomag csak firmware-konfigurációkra való.

## Mit küldj vissza?

Először az **ADB-s szöveges jelentést**. Ha a fastboot is elérhető, mellékelhető a
másik szöveges jelentés is. A JSON ugyanazt géppel feldolgozható formában tartalmazza.
Ha lefuttattad a fájlmásolót, a **`tcl505-files-<azonosító>.zip`** is küldhető.
Ha lefuttattad a passzív USB-figyelőt, a **`tcl505-usb-<azonosító>.zip`**
tartalmazza a teljes eseménynaplót, a láthatósági időtartamokat és a manifestet.

Különösen ezek fontosak:

- `ro.build.fingerprint`
- `ro.build.version.incremental`
- `ro.build.display.id`
- `ro.build.version.security_patch`
- `ro.boot.flash.locked`
- `ro.boot.verifiedbootstate`
- fastboot: `unlocked`, `is-userspace`, `get_unlock_ability`
- a `ro.boot.*token` mezők állapota és a `TCL token nyomok` szakasz

Ezek közösségi nyomok, nem igazolt T509K feloldási jogosultságok. Egy `true`
érték nem helyettesíti a bootloader saját ellenőrzését; egy `false`, hiányzó
mező vagy hiányzó token alkalmazás pedig nem bizonyítja, hogy nincs authboot.

A korábban megadott `UP1A.231005.007` Android build-ID, nem a teljes TCL
firmware-változat. A 2026-11-12-i saját eszközjelentés TCL incremental azonosítója
`BLEL`, a biztonsági javítás mezője `2026-05-05`. A korábban említett `29/06/2026`
nem ez a biztonsági javítási dátum; a szerepe továbbra sem tisztázott.

## Hibajelentések

- `missing`: nincs érték. Nem azonos a `0`, `no` vagy `false` válasszal.
- `unsupported`: a bootloader nem ismeri a lekérdezést vagy változót (például
  `GetVar Variable Not found`). Nem bizonyít tiltást.
- `timeout`: a helyi időkorlát lejárt. Nem bizonyít hardveres hibát.
- `unauthorized`: az ADB-kulcs jóváhagyása hiányzik.
- `error` / `unavailable`: parancs- vagy programindítási hiba.
- `redacted`: a token-jelző váratlan, nem logikai értéket adott; a nyers érték
  szándékosan nem szerepel a jelentésben.

A sikeres programfutás csak sikeres jelentéskészítést jelent, **nem sikeres
bootloader-feloldást**.

## Fejlesztői ellenőrzés

A mellékelt tesztek telefon nélkül, szimulált ADB/fastboot válaszokkal és
szimulált Windows PnP backenddel futnak:

```powershell
py -3 -m unittest -v test_tcl505_probe.py test_tcl505_files.py test_tcl505_usb_watch.py
```

A 0.4.0 csomagból 94 offline teszt futott le Linux/Python 3.11 környezetben.
A 0.3.0 ADB diagnosztika és fájlmásoló 2026-11-12-én valós T509K-n, felhasználói
Windows/USB környezetben sikeres jelentést készített. Ugyanekkor valós
bootloader-fastboot lekérdezés is történt (`is-userspace=no`); a 0.3.1 a nyers
riportban megőrzött gyártói `unlock_ability = ...` választ is elemzi. A 0.4.0
USB-figyelő Windows PnP backendje 2026-11-13-án **valós Windows környezetben is
lefutott** (két 120 s-os mérés, `complete: true`, eldobott esemény nélkül), és
preloader szintű MediaTek ablakokat rögzített (`0E8D:2000`, `0E8D:20FF`); BROM
(`0E8D:0003`) nem jelent meg. MediaTek BROM/preloader **protokoll** kapcsolat
(handshake, DA betöltés) és módosító művelet nem lett tesztelve. A Windows
`.cmd` indítók célkörnyezete Windows 10/11.

## A következő fejlesztési lépés

A cél változatlan: bootloader-feloldás, majd root. A 0.4.0 az előtte álló
engedélyezési rétegek megkülönböztetését segíti, nem helyettesíti a feloldást.
A passzív USB-figyelő a MediaTek preloader/BROM ablak létének passzív bizonyítéka;
a fastboot és ADB ág ettől független, külön döntési pont marad.

1. A jelentésből meg kell állapítani a pontos firmware-t, a zároltságot,
   a fastboot tényleges elérhetőségét és a token-nyomokat.
2. Ha a valódi bootloader-fastboot `get_unlock_ability=1` választ ad, egy
   egyszeri, szabványos feloldási kísérlet szóba jöhet. Ez adatvesztéssel járhat,
   és TCL-nél nem garantált siker. Csak mentés, ellenőrzött helyreállítási út
   és külön jóváhagyás után szabad módosítani; ez a csomag nem teszi meg.
3. Nem szabványos érték (például `16777216` / `0x1000000`) esetén a válasz
   gyártói bizonyíték, nem automatikus engedély. Ilyenkor előbb a pontos
   firmware/bootloader/token-kezelés elemzése, mentés és helyreállítási út
   szükséges; egyszeri szabványos próba csak külön jóváhagyással mérlegelhető.
4. Ha az engedély `0`, a lekérdezés nem támogatott, vagy nincs használható
   fastboot, nem szabad unlock parancsokat találgatni. Ekkor a pontos firmware
   bootloader/token-kezelésének vizsgálata, illetve külön engedéllyel a
   MediaTek-hozzáférés diagnosztikája a következő lépés.
5. Egy nyilvános T509K szerviznapló `SBC SLA DAA` aktív jelzőket és
   `BROM disabled` üzenetet mutat. Ez **nem a te telefonod mérése**, és nem
   bizonyít bootloader-feloldást. Arra figyelmeztet, hogy a gombkombinációs
   BROM-exploitot nem szabad alapértelmezett, működő útnak tekinteni.

Az MTKClient puszta megléte nem igazolja egy adott TCL firmware sérülékenységét.
A MediaTek Secure Boot / SLA / DAA, a TCL fastboot/token-engedélyezés és az
Android Verified Boot külön rétegek; az egyik megkerülése nem igazolja a többiét.

Feloldott állapotban az AVB nem ugyanúgy kényszeríti a gyári aláírást, mint
zárolt állapotban. Ez nem jelenti azt, hogy bármely módosított kép automatikusan
elindul. Root előtt a pontos gyári `boot.img`/`init_boot.img` és AVB-konfiguráció
vizsgálata szükséges. TWRP nem előfeltétel. Ez a csomag nem végez rootolást.
