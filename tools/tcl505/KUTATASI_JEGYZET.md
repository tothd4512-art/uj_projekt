# TCL 505 / T509K – kutatási jegyzet

Rögzítés és frissítés dátuma: 2026-11-12. A felhasználó saját telefonjának
bootloader-feloldása, végső célja root. Windows; az OEM-feloldás kapcsoló
látható és állítható. A felhasználó a hivatalos feloldás hiányának tudatában
kér célzott feloldási kísérletet.

Közvetlen felhasználói korlát: fizetős feloldó eszközt nem kíván használni.
Az UnlockTool / „MTK Custom DA” javaslatát elvetette, és jelezte, hogy a DA
úttal szemben cáfolat / nem működés merült fel. Ez az út ezért nem része a
tervnek, és nem tekintjük bizonyítéknak a T509K DA aláírás-ellenőrzésének
megkerülésére.

## A felhasználótól kapott és saját eszközről ellenőrzött adatok

- Modell megnevezés: TCL T509K; a jelentés szerint `T509K_EEA`, eszközkód `Ant`.
- Android build-ID: `UP1A.231005.007`, Android 14 / SDK 34, `user`, `release-keys`.
- Teljes fingerprint:
  `TCL/T509K_EEA/Ant:14/UP1A.231005.007/BLEL:user/release-keys`.
- TCL incremental: `BLEL`; a jelentés biztonsági javítása: `2026-05-05`.
- A korábban megadott `29/06/2026` nem ezt a biztonsági javítási mezőt igazolja;
  a szerepe továbbra sem tisztázott.
- Aktív slot: `_b`; dinamikus partíciók és virtual A/B engedélyezve.
- Bootloader-fastboot igazolt: `is-userspace=no`, `unlocked=no`, `secure=yes`,
  `current-slot=b`, `slot-count=2`, `has-slot:boot=yes`.
- A `flashing get_unlock_ability` nyers válasza `unlock_ability = 16777216`
  (`0x1000000`), nem szabványos `0`/`1`. Ez gyártói nyom, nem automatikus
  feloldási engedély.

## Saját eszközről érkezett jelentések – 2026-11-12

A felhasználó privát Drive-feltöltéséből a következő riportok kerültek átnézésre.
A nyers letöltések a repo helyi, ignore-olt `tools/tcl505/reports/drive-20261112/`
mappájában vannak; nem részei a verziókezelt forrásnak.

| Jelentés | Eredmény |
| --- | --- |
| `tcl505-adb-20261112T221946.034201Z` | Sikertelen korai próba: az adb nem található. |
| `tcl505-adb-20261112T222022.236849Z` | Szintén adb-útvonal hiba; a későbbi futtatás felváltja. |
| `tcl505-adb-20261112T222342.690395Z.txt/.json` | Sikeres ADB kapcsolat, 50/50 sikeres csak olvasó parancs. |
| `tcl505-files-20261112T222142.785332Z` | Sikertelen korai fájlmásolás: az adb nem található. |
| `tcl505-files-20261112T222403.989395Z` | Sikeres kapcsolat; 35 célból 3 `ok`, 3 `denied`, 29 `missing`. |
| `tcl505-fastboot-20261112T230415.434433Z.txt/.json` | Sikeres bootloader-fastboot kapcsolat; 15/15 parancs OK, 10/13 változó `ok`, 2 távoli `GetVar Variable Not found`, 1 gyártói alias a 0.3.0-ban félreértelmezve. |

A fastboot jelentés 2026-11-12 23:04:15 UTC-kor érkezett Drive-ra. A TXT MD5
kivonata `ca437cba29983f333abe7b9e36128e73`, a JSON MD5 kivonata
`b3db8e91ed72d94e8b6bf12f5a8fa8da`; mindkettő egyezik a Drive metaadatával.
A 0.3.0 szöveges riportja a gyártói `unlock_ability = ...` választ `missing`-ként
írta ki, mert a parser csak a `get_unlock_ability: ...` alakot kereste. A nyers
JSON parancsnaplója megőrizte a választ; a 0.3.1 ezt javítja. A telefonon a
program nem végzett feloldást, flashelést, törlést vagy újraindítást.
A felhasználó 2026-11-12-i kézi ADB pull kimenete
szerint `/vendor/etc/init/hw/init.project.rc` sikeresen letöltődött (4303 byte),
majd Drive-ra került. A letöltött példány MD5 kivonata
`02b4656df0a358c5831cf3cdbad5bb46`, ami egyezik a Drive metaadatával.
A `/FWUpgradeInit.rc` pull `No such file or directory` választ adott a normál
Android fájlrendszerben; ez önmagában nem hiba és nem ok kerülő útra.
A későbbi kézi pullból `/vendor/etc/init/hw/init.mtkgki.rc` is megérkezett
Drive-ra (293 byte); MD5 kivonata `84360d0b82283826957d38c998b659d8`,
ami egyezik a Drive metaadatával.

A sikeres fájlmásolás három szerkesztett másolatának
SHA-256 kivonata újraszámolva megegyezik a `manifest.json` értékeivel:

- `/vendor/etc/fstab.mt6765`: 4614 byte,
  `86d17fa33b40c1d3a2c3af1ef6ed8c89c430dbfbe37c96cf48fb21aae8027dba`.
- `/vendor/etc/init/hw/init.mt6765.rc`: 44512 byte,
  `1268f2fa3998451cd8ddf5ac49fe743c437283c04ccf85eb3731414acc5fc0f6`.
- `/vendor/etc/init/hw/init.mt6765.usb.rc`: 46400 byte,
  `b379f669e0bd2c7912bb470693af91c52908f13cc81e270d6fa2359baba4192f`.

A `build.prop` változatok közül három `denied`, a többi jelölt `missing`; ez nem
jogosultságeszkalációra ok, hanem a tényleges shell-hozzáférési korlát rögzítése.

### Az `init.project.rc` elemzése

A Drive-ról letöltött `init.project.rc` 4303 byte / 125 sor, SHA-256 kivonata:
`96aaa90b873506b79cf4aa2349ac9a5da7cf23dee73a52877b052d635c265b72`.
A fájl az `ANT` projekt hardver-/szolgáltatás-specifikus init beállításait tartalmazza:
NFC, Focaltech érintő, kamera AF eszközök, USB-OTG, SPM, remosaic, töltés- és
memóriahangolás. Négy importja:

```text
/vendor/etc/init/hw/init.mtkgki.rc
/vendor/etc/init/hw/init.nfc.rc
vendor/etc/init/hw/init.focaltech.rc
init.mt6765.usb.rc
```

A teljes szövegben nincs `token`, `auth`, `unlock`, `fastboot`, `bootloader`,
`verified`, `verity`, `avb`, `seccfg`, `oembin`, `oemconfig`, `preloader`, `brom`,
`secure`, `factory`, `meta` vagy `download` előfordulás. Ez nem bizonyít semmilyen
bootloader-feloldási vagy rootengedélyt; a korábbi ADB-token nyom az
`init.mt6765.rc`-ben marad. Az `init.project.rc` nem vezetett új, közvetlen
feloldási ágra. A három új import közül csak az `init.mtkgki.rc` általános MTK/GKI
szempontból érdekes; NFC/érintő specifikus társaik nem elsődleges feloldási nyomok.

### Az `init.mtkgki.rc` elemzése

A Drive-ról letöltött `init.mtkgki.rc` 293 byte / 11 sor, SHA-256 kivonata:
`0c676a47dcac01e30dca4bf5dd7debff613cbb804b13553d7f4befe820e567ec`.
Egyetlen szolgáltatást definiál:

```text
service insmod_sh /vendor/bin/init.insmod.sh /vendor/etc/init.insmod.${ro.hardware}.cfg
    class main
    user root
    group root system
    disabled
    oneshot
```

majd `early-init` fázisban elindítja. Ez a vendor kernelmodulok betöltésének
szokásos MTK/GKI mechanizmusa. A `user root` itt egy init-szolgáltatás futtatási
felhasználója, nem ADB root és nem bootloader-feloldási engedély. A fájlban nincs
token/auth/unlock/fastboot/bootloader/AVB/seccfg/preloader/brom nyom. A hivatkozott
`init.insmod.${ro.hardware}.cfg` a `ro.hardware=mt6765` alapján valószínűleg
`/vendor/etc/init.insmod.mt6765.cfg`, de ez modulbetöltési lista, nem elsődleges
feloldási ág.

### A bootloader-fastboot jelentés elemzése

A `tcl505-fastboot-20261112T230415.434433Z` riport szerint a kapcsolat valódi
bootloader-fastboot volt, nem fastbootd. A legfontosabb nyers válaszok:

| Változó / lekérdezés | Érték | Következtetés |
| --- | --- | --- |
| `version` | `0.5` | fastboot protokollváltozat. |
| `version-bootloader` | `ant-105dcf2-20250627113919-20260519003434` | pontos bootloader-build nyom. |
| `product` | `ant` | egyezik az ADB oldali eszkózkóddal. |
| `secure` | `yes` | secure bootloader állapot. |
| `unlocked` | `no` | a bootloader zárolt. |
| `is-userspace` | `no` | nem fastbootd, hanem bootloader-fastboot. |
| `current-slot` | `b` | egyezik az ADB oldali `_b` slottal. |
| `slot-count` | `2` | A/B slotok. |
| `has-slot:boot` | `yes` | a boot slotolt. |
| `partition-type:boot` | `GetVar Variable Not found` | a változó nem kérdezhető le; nem partíció-hiány bizonyítéka. |
| `partition-size:boot` | `GetVar Variable Not found` | a változó nem kérdezhető le; nem partíció-hiány bizonyítéka. |
| `max-download-size` | `0x8000000` | 128 MiB letöltési keret, nem feloldási engedély. |
| `flashing get_unlock_ability` | `unlock_ability = 16777216` | nem szabványos `0`/`1` válasz. |

A `16777216` decimális érték `0x1000000`. Az AOSP szabványos feloldási
engedélyként `0`/`1` értéket ír le; a nem szabványos érték nem fordítható le
automatikusan `1`-re. Közösségi MTK útmutatókban a `16777216` érték engedélyező
válaszként is szerepel, például Oukitel/Doogee készülékeknél:
<https://www.rigacci.org/wiki/doku.php/doc/appunti/hardware/oukitel_wp12>,
<https://www.rigacci.org/wiki/doku.php/doc/appunti/hardware/doogee_x93>.
TCL ellenpélda is ismert: a TCL 20B ugyanezt az értéket adta, majd a
`fastboot flashing unlock` és `unlock_critical` `not allowed in locked state`
válasszal elutasításra került:
<https://xdaforums.com/t/tcl-20b-subforum.4444445/>.
Ezért a mostani érték gyártói nyom, nem igazolt T509K feloldási engedély.

A 0.3.0 parser csak a `get_unlock_ability: ...` alakot kereste, ezért a TXT-ben
`missing` jelent meg. A JSON parancsnaplója megőrizte a nyers választ. A 0.3.1
felismeri a `get_unlock_ability` és `unlock_ability` kulcsot, `:` és `=`
elválasztóval, megőrzi a nyers értéket, és a nem `0`/`1` választ külön figyelmeztetésként
kezeli. A `GetVar Variable Not found` válasz a 0.3.1-ben `unsupported`, nem `error`.
A javítás offline regressziós tesztekkel fedett; a telefonon nem történt módosítás.

### Külső tanács értékelése: DeepSeek-javaslat

A felhasználó által idézett külső tanács több ponton nem egyezik a rögzített
bizonyítékokkal:

1. **A `(missing)` nem eszközoldali tiltás volt.** A 0.3.0 parser nem ismerte fel
   a gyártói `unlock_ability = 16777216` választ. A nyers JSON-ban a válasz
   megvan, a 0.3.1 már `ok` státusszal rögzíti. Ebből nem következik, hogy a
   fastboot út zsákutca; az sem következik, hogy a feloldás engedélyezett.
2. **A fastboot oldal nincs lezárva a lekérdezések szintjén.** A bootloader-fastboot
   elérhető, `is-userspace=no`, `unlocked=no`, `secure=yes`. Szabványos
   `fastboot flashing unlock` parancsot nem futtattunk, így annak sikeréről vagy
   elutasításáról nincs saját mérés.
3. **A BROM/Preloader szint nincs igazolva ezen a példányon.** A „ledobta magát”
   jelenség utalhat USB újraindulásra / preloader ablakra, de nem bizonyít
   BROM-exploitot, SLA/DAA megkerülést vagy írható `seccfg` hozzáférést. A másik
   T509K `BLC4` példány `BROM disabled` naplója nem vihető át erre a `BLEL`
   példányra.
4. **A `seccfg` módosítása nem automatikus következő lépés.** A `seccfg` a
   boot/security konfiguráció része; írása zárolt, ellenőrzött bootláncú eszközön
   adatvesztést, bootloopot vagy helyreállítási kényszert okozhat. Csak igazolt
   hozzáférési út, mentés, helyreállítási lehetőség és külön jóváhagyás után
   mérlegelhető.
5. **Fizetős eszköz / Custom DA kizárva.** A felhasználó nem kíván fizetős
   eszközt használni, és a DA úttal szemben nem működés/cáfolat merült fel.
   Az UnlockTool vagy más zárt eszköz állított támogatása nem bizonyíték a
   saját T509K/BLEL firmware DA aláírás-ellenőrzésének megkerülésére.

Következtetés: a külső tanács nem írja felül a saját riportokat. A fastboot oldalt
nem szabad lezártnak tekinteni a parserhiba miatt, de a BROM/Preloader/`seccfg`
utat sem szabad bizonyított fő támadási felületként kezelni. Mindkét irány csak
külön, bizonyíték alapú döntéssel folytatható.

### Mit igazol a három rendszerfájl?

Az `init.mt6765.rc` 1153–1157. sora saját, erre az eszközre jellemző TCL Token ágat
mutat:

```text
#[SYSD SYS][Token]Begin added by zhiqiang.mo for LUNAS-3802 on 2023-04-27
on boot && property:ro.boot.adbtoken=true
    setprop persist.sys.usb.config adb
    setprop sys.usb.config adb
#[SYSD SYS][Token]End added by zhiqiang.mo for LUNAS-3802 on 2023-04-27
```

Ez közvetlen eszközoldali bizonyíték egy ADB-kapcsolódó tokenjelző kezelésére,
nem bootloader-feloldási vagy rootengedély. Ugyanez a fájl importálja a
`/vendor/etc/init/hw/init.project.rc` és `/FWUpgradeInit.rc` fájlokat; ezek célzott,
csak olvasó lekérése a következő indokolt lépés, nem tetszőleges könyvtárbejárás.

A `fstab.mt6765` AVB-t, logikai partíciókat és `slotselect` jelzőket mutat a
rendszerpartícióknál, valamint metadata/file encryption beállítást az `/data`
F2FS kötetnél. A `seccfg`, `efuse`, `lk` és `vbmeta` bejegyzések partíció-hozzárendelések,
nem a tartalmuk, nem az efuse tényleges állapota és nem írható hozzáférés bizonyítékai.
Az USB `.rc` Android-gadget konfigurációkat ír le; önmagában nem igazol
bootloader-fastbootot vagy authboot protokollt.

### Mit nem bizonyítanak a mostani jelentések?

- A `ro.boot.flash.locked=1`, `verifiedbootstate=green`, `veritymode=enforcing`
  és `vbmeta.device_state=locked` zárolt, ellenőrzött bootállapotot jelez.
- A `sys.oem_unlock_allowed=1` a beállítási kapcsoló állapota, nem a bootloader
  `get_unlock_ability` válasza.
- A `com.tcl.token` csomag jelen van, de nem lett elindítva, tokent nem kért,
  gyártói szerverhez nem fordult.
- A `ro.boot.*token` mezők nem adtak kiértékelhető választ; ez nem `false`.
- A saját eszközön nem történt BROM/SLA/DAA mérés. A másik T509K példány
  `BLC4` firmware-ének és `BROM disabled` naplójának eredményei nem vehetők át
  erre a `BLEL` példányra.
- A bootloader-fastboot `unlocked=no` és `secure=yes` választ adott; a
  `unlock_ability = 16777216` nem szabványos engedélyjelző, és nem igazolja,
  hogy a TCL feloldóparancsot elfogadja.

## Négy külön biztonsági réteg

| Réteg | Mit véd? | Mit nem bizonyít önmagában? |
| --- | --- | --- |
| MediaTek SBC | A korai bootlánc aláírását. | Azt, hogy az Android bootloader zárolt vagy feloldott. |
| MediaTek SLA/DAA | A letöltési kapcsolatot, illetve a betölthető Download Agentet. | Azt, hogy a fastboot feloldást engedélyezi. |
| TCL fastboot/auth/token | A gyártó saját flashelési/feloldási engedélyezését. | Azt, hogy minden TCL-modell ugyanazt a protokollt használja. |
| Android Verified Boot / dm-verity | Az Android-képek és partíciók integritását a bootolásnál. | Azt, hogy egy valóban feloldott bootloaderen minden egyedi kép azonnal bootloopolna. |

A MediaTek hivatalos, Genio platformra írt dokumentációja szerint az SBC/DAA
bekapcsolása eFuse-alapú; a BootROM a gyártói bizalmi gyökérrel ellenőrzi a
hitelesítési adatot és a DA aláírását. Ez általános platformháttér, nem T509K-teszt:
<https://mediatek.gitlab.io/aiot/doc/aiot-dev-guide/master/sw/yocto/secure-boot.html>.

Az AOSP szerint a szabványos feloldásnál a bootloader `get_unlock_ability`
engedélyt vár, a feloldás felhasználói megerősítést és adat törlését igényli.
Feloldott állapotban az indítási állapot `orange`; az AVB ilyenkor nem kezeli
minden aláírási/ellenőrzési hibát végzetesként. Ettől egy nem kompatibilis kép
még lehet indíthatatlan. Források:
<https://source.android.com/docs/core/architecture/bootloader/locking_unlocking>,
<https://source.android.com/docs/security/features/verifiedboot/boot-flow>,
<https://android.googlesource.com/platform/external/avb/+/master/README.md>.

## Ellenőrzött kiindulópontok

1. A T509K a TCL 505 európai változataként szerepel, MT6765 / Helio G36
   platformú eszközön: <https://www.deviceinfohw.ru/devices/item.php?item=105256>.
2. A TCL 505 hivatalos támogatási oldala a vizsgálatakkor
   `Mobile_Upgrade_S_Gotu2_v2.6.0_Setup.zip` letöltését kínálta:
   <https://www.tcl.com/global/en/support-mobile/model/tcl-505>.
   Ez firmware-frissítő eszköz, nem igazolt bootloader-feloldó. A pontosan
   illeszkedő firmware és a működő helyreállítás külön ellenőrzendő.
3. Korábbi T509K beszámoló sikertelen fastboot/unlock próbálkozásokat és
   bootloopot említ. Egyedi, régi beszámoló, nem általános tiltás bizonyítéka:
   <https://www.reddit.com/r/androidroot/comments/1f33dre/tcl_505_t509k_root/>.
4. Közösségi TCL/MTK út módosított `oembin` képet és további MTK-specifikus
   módosításokat ír le. T509K-ra igazolt siker nincs a most ellenőrzött anyagban;
   más modellek értékei nem másolhatók át vakon:
   <https://www.reddit.com/r/androidroot/comments/1n5ptjm/guide_to_unlocking_tcl_devices_and_additional_info/>.
5. Az MTKClient forrásában van MT6765 konfiguráció, de ez nem igazolja a konkrét
   TCL firmware elérhetőségét vagy sérülékenységét:
   <https://github.com/bkerler/mtkclient>.
   A helyben átnézett main commit: `118a000a83ea31c4f427fe5225abfe964546e05e`.
   A `brom_config.py` MT6765 bejegyzése önmagában csak chipkonfiguráció.
   Ebben a változatban nincs `mtk detect` parancs; a félrevezető webes
   példák helyett a tényleges `./mtk.py` parancslistát kell használni.
6. Friss, másik MT6765 modellnél is nyitott hozzáférési kérdés mutatja, hogy a
   chipazonosító nem garancia. Ez nem T509K-teszt:
   <https://github.com/bkerler/mtkclient/issues/398>.

## Új, modellközeli bizonyíték: T509K szerviznapló

Forrás: <https://www.martview-forum.com/threads/tcl-t509k-frp-bypass-done.143592/>.
A 2025-09-29-i, Pandora 9.6 alatt készült nyilvános napló TCL T509K modellt jelöl.
Fontos sorai szó szerint:

```text
Device found at COM10 [PRELOADER]
Get HW code from device... 0766
Get sec config... OK [00000007]
Active sec flags: [SBC SLA DAA]
[EFUSE INFO]: BROM disabled !!!
Display ID : UP1A.231005.007
Security Patch : 2024-10-05
Firmware Version : BLC4
```

Értelmezési korlátok:

- Ez egy másik példány, régebbi biztonsági javítási szinttel. Az egyező Android
  build-ID nem bizonyít azonos teljes TCL firmware-t.
- A napló szerint a kapcsolat PRELOADER úton működött, aktív SBC/SLA/DAA mellett.
  A `BROM disabled` sor óvatosságra int a gombkombinációs BROM-exploittal szemben;
  nem helyettesíti a saját telefon USB-módjának és céljának mérését.
- A művelet FRP-kezelés volt, nem bootloader-feloldás vagy root. Nem bizonyít
  általános feloldást, és nem ad át felhasználható gyártói hitelesítést.
- A napló nem azonosítja nyilvánosan a DA-t és az auth-folyamat minden részletét.
  Abból, hogy egy kereskedelmi eszköz DA-t töltött, nem következik, hogy az
  MTKClient tetszőleges DA-val működni fog ezen a firmware-en.

## TCL authboot/token: mi ismert és mi nem?

A közösségi „wall of shame” TCL része authbootot és szerveres engedélyezést ír le:
<https://github.com/zenfyrdev/bootloader-unlock-wall-of-shame/blob/main/brands/tcl/README.md>.
Ez közösségi összefoglaló, erősen BlackBerry/TCL általánosítással. Önmagában nem
bizonyítja, hogy a T509K minden fastboot-lekérdezése távoli szerverhez fordul.

Más TCL-modelleknél a `com.tcl.token` alkalmazás visszafejtéséből származó
közösségi adatok `ro.boot.oemtoken`, `ro.boot.fastboottoken`, `ro.boot.roottoken`
és további logikai jelzőket mutatnak:
<https://xdaforums.com/t/growing-ever-closer-to-root-bootloader-unlock-new-info.4477911/>,
<https://xdaforums.com/t/rooting-the-tcl-10l.4158671/page-3>.
Ugyanitt szerepel a `ro.boot.tksn`, illetve egy régi TCL tokenkiszolgáló elérhetősége.
A korábbi „server is gone” beszámolók nem friss, saját elérhetőségi mérések.

Következtetés: ezek konkrétan ellenőrizhető nyomok, de más modellből származnak.
A diagnosztika csak a jelzőket és a csomagjelenlétet vizsgálja; a `ro.boot.tksn` értékét
nem gyűjti. Nem indít tokenalkalmazást, nem igényel tokent, és nem próbál meg
gyártói szerverként működni. Egy `true` jelző nem igazolt feloldási engedély;
egy hiányzó jelző vagy csomag pedig nem cáfolja a bootloader saját authbootját.

A SIM-/hálózati feloldás és az FRP-kezelés nem bootloader-feloldás. Az ezekre
vonatkozó kereskedelmi eszközök állításai nem kerültek átvételre.

## Fájlmásolás elemzéshez

A 0.3.0 csomag külön `tcl505_files.py` modult kapott. Ez nem APK-kat gyűjt, hanem
rögzített engedélylistán szereplő, normál ADB shell felhasználó által olvasható
szöveges rendszerfájlokat: `build.prop` változatokat, `fstab` jelölteket és néhány
`init`/token-related `.rc` fájlt. A másolatokat szerkesztett szövegként, SHA-256
kivonattal és `manifest.json` jegyzékkel menti, majd ZIP-be csomagolja.

A modul nem kér rootot, nem olvas `/data` vagy `/sdcard` tartalmat, nem olvas nyers
partíciót, nem ír a telefonra és nem tölt fel. A `denied`/`missing` eredményt
rögzíti, nem kerüli meg. Mélyebb partícióképek (`lk`, `preloader`, `vbmeta`, `boot`,
`oembin`) normál ADB-ből általában nem olvashatók; ezekhez külön, ellenőrzött
hozzáférési út kellene.

A felhasználó feltöltheti a ZIP-et privát Google Drive mappába vagy nyilvános
GitHub repó/release linkjére. A Drive-csatlakozás aktív; a GitHub alkalmazáscsatlakozás
nem támogatott ebben a beszélgetésben, ezért privát GitHub helyett Drive ajánlott.

## Döntési sorrend

1. A 0.3.0 olvasó programmal pontos firmware-, zároltság- és token-nyom-azonosítás.
   **ADB oldalon elkészült:** `BLEL`, `2026-05-05`, zárolt/green/enforcing állapot,
   `com.tcl.token` jelenlét és saját init-fájlban ADB-token ág.
2. A `tcl505_files.py` célzott fájlmásolása és elemzése. **Elkészült:** három
   olvasható rendszerkonfiguráció; a denied/missing eredmények rögzítve.
3. A most kapott init-fájlból azonosított importok célzott lekérése.
   `/vendor/etc/init/hw/init.project.rc`: megérkezett és elemezve; hardveres
   projekt-init, közvetlen token/unlock nyom nélkül.
   `/FWUpgradeInit.rc`: normál Androidban `missing`; nincs további próbálkozás.
   `/vendor/etc/init/hw/init.mtkgki.rc`: megérkezett és elemezve; csak
   kernelmodul-betöltő init szolgáltatás, közvetlen token/unlock nyom nélkül.
4. A bootloader-fastboot tényleges elérhetőségének és lekérdezéseinek ellenőrzése.
   **Elkészült:** `is-userspace=no`, `unlocked=no`, `secure=yes`, `current-slot=b`;
   a `flashing get_unlock_ability` nyers válasza `unlock_ability = 16777216`.
   A fastbootd eredménye nem azonos a bootloader-fastboot eredményével.
5. Valódi bootloader-fastboot + szabványos `get_unlock_ability=1` esetén egyszeri
   szabványos feloldási kísérlet mérlegelése. Előtte mentés, illeszkedő
   helyreállítási út, az adatvesztés tudomásulvétele és külön jóváhagyás szükséges.
   Nem szabványos érték (`16777216` / `0x1000000`) esetén nincs automatikus
   engedélyértelmezés: előbb a pontos firmware/bootloader/token-kezelés elemzése,
   mentés és helyreállítási út kell; egyszeri szabványos próba csak külön
   jóváhagyással mérlegelhető.
6. `0`, nem támogatott lekérdezés vagy hiányzó fastboot esetén nincs unlock-találgatás.
   A pontos firmware bootloader/token-kezelésének vizsgálata következik.
7. MediaTek-hozzáférés csak külön engedéllyel, a saját eszköz tényleges USB-módjának
   és a hitelesített letöltési követelményeknek megfelelően. **A opció választva:**
   a 0.4.0 passzív USB-figyelő (`tcl505_usb_watch.py`) elkészült; ez csak PnP
   eseményeket/VID-PID-t rögzít, nem nyit meg eszközt és nem módosít. A valós
   Windows USB észlelés a felhasználó gépén még hátra van. A BROM-exploit nem
   alapértelmezett feltevés; a sikertelen handshake nem ok a flashelésre.
   Fizetős eszköz és zárt „Custom DA” út kizárva; a DA-állítások nem bizonyítékai
   a saját T509K/BLEL firmware megkerülésének.
8. Csak igazolt eljárással, mentéssel és külön jóváhagyással módosító modul.
   Más TCL-modell `oembin`/`seccfg` értékei nem írhatók át ellenőrzés nélkül.
   `seccfg` írás nem automatikus következő lépés, és nem helyettesíti a
   bootloader oldali engedélyezés tisztázását.
9. Feloldás után a pontos gyári `boot.img`/`init_boot.img`, slot és AVB-konfiguráció
   vizsgálata, majd célzott rootelés. Ez még nem készült el.

## Passzív USB-mód figyelő – A opció (0.4.0)

A felhasználó a DeepSeek-féle BROM/`seccfg`/UnlockTool tanács helyett az
**A opciót** választotta: passzív, csak-olvasó Windows USB-mód figyelés.
A 0.4.0 csomag új modulja a `tcl505_usb_watch.py` (v0.1.0), indítója a
`TCL505-USBfigyelo.cmd`.

### Mit csinál?

- Windows `cfgmgr32` PnP API: `CM_Register_Notification` (DEVICEINSTANCE,
  ALL_DEVICE_INSTANCES) **előbb** regisztrál, utána `CM_Get_Device_ID_ListW`
  (USB enumerátor + PRESENT) baseline pillanatképet készít.
- A callback csak sorba tesz; a worker szál dolgozik fel (describe, tracker).
- Rendszeres (1 s) pillanatképek reconciliálják a jelenlévő USB eszközöket.
- VID/PID osztályozás: `0E8D:0003` BROM jelölt, `0E8D:2000/201D/20FF/3000/6000`
  preloader jelölt, `0E8D:2001` preloader-vagy-DA jelölt, `1BBB:0C01` TCL ADB
  jelölt (a saját eszköz `init.mt6765.usb.rc` 5. és 127. sora alapján).
- Láthatósági időtartam munkamenetenként, UTC + relatív időbélyeggel.
- Eszközleírás/osztály/szolgáltatás metaadat redakció után; instance-azonosító
  csak futásonként sózott kivonatként (`instance_key`).
- `reports/tcl505-usb-<időbélyeg>/` mappa: `report.json`, `report.txt`,
  `manifest.json` (SHA-256), `README.txt`; mellette azonos nevű `.zip`.

### Mit NEM csinál?

- Nem nyit meg eszközhandle-t (`CreateFile`), nem nyit COM portot, nem küld
  USB transzfert.
- Nem futtat ADB/fastboot/MTK parancsot, nem telepít drivert, nem tölt be DA-t,
  nem futtat exploitot, nem ír partíciót, nem indítja újra a telefont.
- Nem próbál gombkombinációkat; a telefon módját a felhasználó állítja kézzel.
- Nem tölt fel adatot; a ZIP-et a felhasználó tölti fel elemzésre.

### Értelmezési korlátok

- A VID/PID egyezés **jelölt**, nem bizonyíték BROM-exploitra, DA betöltésre,
  SLA/DAA megkerülésre vagy írható `seccfg` hozzáférésre.
- A láthatósági idő Windows PnP idő, nem pontos preloader handshake idő.
- A jelölt hiánya nem bizonyítja, hogy nincs preloader ablak (PnP késleltetés,
  nagyon rövid ablak kimaradhat).
- A Windows PnP backend mockolt offline tesztekkel **és** 2026-11-13-án valós
  Windows futásokkal ellenőrzött (lásd a „Valós USB-figyelő mérések” szakaszt);
  a mért ablakok preloader szintűek, BROM nem. A preloader **protokoll**
  (handshake, DA) továbbra sincs tesztelve.

### Operátor-markerek – a „nem tudom, melyik gomb volt” probléma megoldása

A 2026-11-13-i mérések visszatérő korlátja volt, hogy a jelentés csak a futás
**végén** készül, és benne csak relatív másodpercek szerepelnek. A felhasználó
ezért nem tudta megmondani, melyik USB-ablakhoz melyik gombnyomás tartozott.

A 0.4.1 (modul 0.2.0) ezt a `MarkerReader` szállal oldja meg:

- a figyelő futása közben a program folyamatosan olvassa a billentyűzetet;
- minden Enter egy **marker**: a program azonnal kiírja a mérés kezdetétől
  számított másodpercet és az UTC-időt, majd elmenti a beírt címkét;
- a `report.json`-ba `markers` tömb kerül (max. 200 marker, 120 karakter,
  redakció + vezérlőkarakter-tisztítás után);
- a `report.txt`-ben külön **Operátor-markerek** szakasz van, és minden jelölt
  munkamenet mellett szerepel az utolsó előtte lévő marker
  (`előző marker: "Vol+ bedugas" (+2.6 s)`), valamint az ablakon belülre eső
  markerek;
- `--no-markers` kapcsoló, ha a kimenet fájlba megy vagy nincs interaktív
  terminál; a marker-olvasó hibája nem teszi hiányossá a mérést, de külön
  figyelmeztetés kerül az értelmezésbe.

**Amit ez nem old meg:** a program továbbra sem látja a gombokat. A marker a
te állításod arról, mit csináltál abban a pillanatban; az ablak-hozzárendelés
időzítési segítség, nem bizonyíték. Ha egy próbában több ablak jelenik meg,
mindegyik ugyanazt a markert kapja.

### 4. futás (16:51:22–16:53:23 UTC, 120 s) – markerek élesben

Az első markerrel végzett valós futás (`0e8d`-jelöltek, egy marker):

| # | látható ablak (rel.) | VID:PID | osztály | hossz | marker-kapcsolat |
|---|---|---|---|---|---|
| 1 | 17.81 – 20.31 | `0E8D:2000` | USBDevice / WinUSB | 2.50 s | nincs előtte marker |
| 2 | 43.58 – 46.10 | `0E8D:2000` | USBDevice / WinUSB | 2.52 s | `Vol+ bedugas` (+13.29 s) |
| 3 | 65.24 – 67.75 | `0E8D:2000` | USBDevice / WinUSB | 2.52 s | `Vol+ bedugas` (+34.94 s) |
| 4 | 92.16 – 111.55 | `0E8D:20FF` | HIDClass / HidUsb | **19.40 s** | `Vol+ bedugas` (+61.86 s) |

`0E8D:0003` (BROM) nem jelent meg; a marker 30.295 s-nál volt, az első ablak
17.81 s-nál (tehát a marker előtt) kezdődött.

**Új megfigyelés: a `20FF` ablak hossza 0.89–3.80 s helyett 19.4 s lett.**
A korábbi futásokban a `20FF` mindig 1–4 s-ig látszott; itt 19.4 s-ig. Ez
megerősíti, hogy a `20FF` HID-osztályú mód **képes hosszan fennmaradni**, és
hogy a láthatósági idő nagyon változó — a „rövid ablak” nem törvényszerű.
Ez még mindig **nem BROM**: a `20FF` preloader-oldali HID-mód.

### Hibajavítás: leállási összeomlás (`_enter_buffered_busy`)

A 4. futás végén a program ezzel állt le:

```text
Fatal Python error: _enter_buffered_busy: could not acquire lock for
<_io.BufferedReader name='<stdin>'> at interpreter shutdown, possibly due to
daemon threads
```

**Ok:** a marker-olvasó daemon szál a `sys.stdin.buffer.readline()`-ben várakozik;
az interpreter leállásakor a `sys.stdin` pufferét akarja lezárni, de a zár a
szálé. Ezt Linuxon FIFO-val reprodukáltam (parkolt daemon szál + normál kilépés
→ ugyanaz a fatal error), majd a javítással ugyanabban a szcenárióban nem
jelentkezik.

**Javítás (0.4.3, modul 0.3.0):**

1. a `collect_watch` a `finally`-ban előbb `join(0.3)`-mal behúzza a már
   beolvasott sorokat, majd `cancel()`-t hív;
2. a `cancel()` beállít egy `_cancelled` jelzőt, így a szál **soha többé nem
   olvas** a stdinről (a blokkolt `readline()` bent marad, de új olvasás nincs);
3. a `main()` a jelentés kiírása után, ha marker-szál indult, `os._exit()`-tel
   lép ki, így az interpreter már nem próbálja lezárni a `sys.stdin` puffert.

A jelentés és a ZIP a hiba előtt is elkészült (`complete: true`), tehát adat
nem veszett el — de a nem nulla kilépési kód és a hibaüzenet zavaró volt.

### Élő kijelzés (0.4.3)

A felhasználó visszajelzése nyomán a figyelő már **futás közben** kiírja a
jelölt eszközök megjelenését és eltűnését, a láthatósági idővel:

```text
[   17.810s] MEGJELENT USB\VID_0E8D&PID_2000  (mediatek_preloader_candidate)  "MT65xx Preloader"
[   20.310s] ELTUNT   USB\VID_0E8D&PID_2000  (mediatek_preloader_candidate)  (2.500 s)
```

Csak `0E8D:*`/`1BBB:*` eszközök jelennek meg, hogy a periféria-események ne
nyomják el a marker-promptot.

### Tesztelés

A 0.4.3 csomag **118 offline teszt** futott le Linux/Python 3.11 környezetben
(47 probe + 15 files + 56 usb_watch). A USB-figyelő 56 tesztje szimulált PnP
backenddel, órával és eseményekkel fut; Windows API hívás nem történik.
A markereket, az élő kijelzést és a leállítási sorrendet 23 teszt fedi
(szöveg, cap, redakció, ablak-hozzárendelés, zárt/hibás stdin,
`--no-markers` alapértelmezés, `os._exit` ág, cancel utáni olvasásmentesség).
A `.cmd` indító ASCII + CRLF ellenőrzése offline teszt része.

## Valós USB-figyelő mérések – 2026-11-13

A passzív figyelő két valós futása érkezett a felhasználó Windows gépéről
(letöltött, SHA-256-tal ellenőrzött `report.json` / `report.txt` /
`manifest.json`; a manifestben rögzített hash-ek a letöltött fájlokkal
egyeznek). A nyers kivonatok a `reports/drive-20261113/` mappában vannak
(git-ignored), a Drive-mappák:
`tcl505-usb-20261113T084039.418537Z` és `tcl505-usb-20261113T094533.636771Z`.

### 1. futás (08:38:39–08:40:39 UTC, 120 s) – nem teszteli a kérdést

- Kezdeti és végső USB eszköz: 6/6, esemény: 6, munkamenet: 6.
- Az egyetlen jelölt a teljes ablakban `USB\VID_1BBB&PID_0C01`
  (`tcl_adb_usb_candidate`), `still_present_at_end`, 120.004 s.
- **Értelmezés:** a telefon a futás alatt végig csatlakoztatva és ADB-vel
  futó Android állapotban volt. Kikapcsolt telefon preloader-ablakáról ez a
  futás **semmit nem mond**; negatív eredményként nem használható.

### 2. futás (09:43:33–09:45:33 UTC, 120 s) – valós preloader-ablak

- Kezdeti és végső USB eszköz: 5/6, pillanatkép: 120, esemény: 17,
  munkamenet: 10, eldobott esemény: 0, callback hiba: 0, `complete: true`.
- Kezdetkor **nincs** `1BBB:0C01` a listában: a kábel ekkor le volt húzva,
  a baseline tiszta. A többi eszköz a gép saját perifériája
  (Intel Bluetooth, integrált kamera, egy HID eszköz).

| # | látható ablak (rel.) | VID:PID | osztály / szolgáltatás | leírás | hossz |
|---|---|---|---|---|---|
| 1 | 31.025 – 33.408 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 2.38 s |
| 2 | 57.623 – 58.861 | `0E8D:20FF` | HIDClass / HidUsb | USB beviteli eszköz | 1.24 s |
| 3 | 80.228 – 82.740 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 2.51 s |
| 4 | 107.042 – 110.839 | `0E8D:20FF` | HIDClass / HidUsb | USB beviteli eszköz | 3.80 s |
| 5 | 118.385 – 120.008 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 1.62 s (ablak végén is jelen) |

- Mindegyik munkamenet `removed` okkal zárult (kivéve az 5.-et, amely a
  futás végén még látszott); `0E8D:0003` (**BROM**) **egyszer sem** jelent meg.
- Az `instance_key` eszközönként stabil és ismétlődik
  (`0E8D:2000` → `6567c95e814f4f50`, `0E8D:20FF` → `2bb21933dda3cd29`),
  tehát ugyanaz az eszköz tért vissza többször; nyers instance-azonosító
  vagy serial nem került a jelentésbe.

### Amit ez bizonyít

1. **A kézi preloader-ablak létezik ezen a telefonon.** A `0E8D:2000`
   (`MT65xx Preloader`) kétszer-háromszor, 2–3 másodpercre megjelent, és a
   Windows WinUSB-kompatibilis drivert rendelt hozzá. Ez a 0.3.0/0.4.0
   elemzés addigi nyitott kérdését lezárja: nincs szükség testpontra a
   preloader szintű USB-megjelenéshez.
2. **A `0E8D:20FF` is MediaTek preloader-oldali USB mód, nem BROM.** A
   mtkclient `config/usb_ids.py` a `0x20FF`-et `MTK Preloader`-ként listázza
   (`0x0003` az egyetlen BROM-azonosító). A HID-osztályú enumeráció
   következmény: a `0x20FF` HID-interfészen a szokásos BROM handshake nem
   értelmezhető; közösségi esetek ugyanezt a módot "preloader, de a handshake
   elakad" tünetként írják le.
3. **BROM (`0E8D:0003`) nem érhető el a most kipróbált kombinációkkal.**
   A MT6765 nem szerepel az mtkclient V6 patchelt-BROM listáján, tehát a
   BROM-út elvileg nyitott lenne, de a mért ablakok csak preloader szintig
   jutottak. Ez nem bizonyítja, hogy BROM egyáltalán nem érhető el; azt
   bizonyítja, hogy a mostani kísérletek nem érték el.

### Amit ez NEM bizonyít

- A két futás naplója **nem tartalmazza, melyik gombkombináció melyik
  ablakhoz tartozott**. A négy ablakhoz négy különböző kézi próbát kell
  hozzárendelni, különben a kombinációk hatása nem izolálható.
- Preloader-megjelenés ≠ DA betöltés, ≠ SLA/DAA megkerülés, ≠ írható
  `seccfg`, ≠ feloldható bootloader. A figyelő nem nyitott eszközt, így a
  preloader protokoll egyáltalán nem futott le.
- A láthatósági idő Windows PnP idő; a tényleges preloader handshake-ablak
  ennél rövidebb is lehet (a driver kötése késleltet).

### Következő mérés: címkézett próbasorrend

Egyetlen 180–300 másodperces futás, próbánként ~40 másodperces réssel, a
próbák időpontjának feljegyzésével, és minden próba előtt **teljes
kikapcsolás** (Power 10–15 s, rezgésig), kábel kihúzva:

1. gomb nélkül, csak USB-bedugás (preloader-várakozás);
2. Hangerő FEL nyomva + USB-bedugás;
3. Hangerő LE nyomva + USB-bedugás;
4. Hangerő FEL + Hangerő LE nyomva + USB-bedugás.

Fontos: a T509K szervizkézikönyv 4.3 pontja szerint a **Power + Hangerő FEL**
a **Recovery** menüt hozza, nem BROM-ot; a recovery `Wipe data/factory reset`
pontját nem szabad megerősíteni (adattörlés). A próbasorrend ezért nem
tartalmaz Power + VolUp lépést.

Ha a címkézett futásban is csak `2000`/`20FF` jelenik meg `0003` nélkül, a
következő döntési pont a preloader protokoll (mtkclient preloader-ág,
`--preloader` / DA) elemzése — ez már eszközmegnyitással járó, külön
jóváhagyást igénylő lépés, nem passzív megfigyelés.

### 3. futás (10:03:46–10:05:46 UTC, 120 s) – LK fastboot ablak

Kezdeti és végső USB eszköz: 5/5, pillanatkép: 121, esemény: 22,
munkamenet: 11, eldobott esemény: 0, callback hiba: 0, `complete: true`.
A baseline ismét tiszta (a telefon `1BBB:0C01`-je nem volt jelen).

| # | látható ablak (rel.) | VID:PID | osztály / szolgáltatás | leírás | hossz |
|---|---|---|---|---|---|
| 1 | 9.00 – 11.50 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 2.50 s |
| 2 | 36.25 – 38.76 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 2.51 s |
| 3 | 63.03 – 63.93 | `0E8D:20FF` | HIDClass / HidUsb | USB beviteli eszköz | 0.89 s |
| 4 | 74.55 – 77.06 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 2.51 s |
| 5 | 101.90 – 102.47 | `0E8D:2000` | USBDevice / WinUSB | MT65xx Preloader | 0.57 s |
| 6 | 107.92 – 111.83 | **`0E8D:201C`** | AndroidUsbDeviceClass / WinUSB | **Android Bootloader Interface** | 3.91 s |

A felhasználó szerint ez a futás a **Hangerő FEL** gombos próbához tartozott.
A napló maga nem tartalmaz gombcímkét, ezért a hat ablak és a konkrét
gombállapot hozzárendelése továbbra sem izolált.

**Új eredmény: `0E8D:201C` = MediaTek LK fastboot.** Három független forrás
azonosítja így:

- a `phildabill/onn-t405a-Bootloader-unlock` repó kifejezetten
  „`0E8D:201C` = LK Fastboot”-ként tárgyalja, és a `getvar:is-userspace`
  `OKAYno` válaszával különíti el az Android fastbootd-től;
- az `Informatic/xiaomi-x04g-research` szerint a „Reboot to bootloader”
  `0e8d:201c` eszközt ad (szemben a fastbootd `18d1:4ee0` azonosítójával);
- a varaprasadh.dev Rabbit R1-esete `0e8d:201c`-t mutat, miközben a telefon
  már fastboot módban volt.

Ezen kívül a MediaTek `android_winusb.inf` a `201C`-t
`%SingleAdbInterface%`-ként tartja nyilván „Android ADB Interface” néven, a
Windows-eszközleírás pedig `Android Bootloader Interface` volt — a leírásnév
önmagában nem dönti el a módot, a PID és a `getvar is-userspace` igen.

**Következmény:** a bootloader-fastboot ezen a telefonon nem csak
`adb reboot bootloader`-rel érhető el, hanem kézi gombkombinációval is. Ez
fontos, mert a 0.3.1-ben mért `unlock_ability = 16777216` és a `secure=yes`
bootloader-oldali állapot mostantól kézi úton is megközelíthető anélkül, hogy
Androidot kellene bootolni. **Ez nem BROM**, és nem változtat azon, hogy a
`16777216` nem AOSP `1`, tehát nem feloldási engedély.

### Frissített következtetés a gombkombinációkról

A három futás alapján a `0E8D:2000` preloader-ablak **gomb nélkül és
hangerőgombokkal is** megjelenik; a `0E8D:201C` LK fastboot ablak egyszer,
a Hangerő FEL-es próbában jelent meg. A `0E8D:0003` BROM egyik futásban sem
jelent meg.

A további lépés **nem** újabb vak gombpróba, hanem a címkézett futás
(fenti táblázat, egy ablak = egy próba), mert enélkül nem lehet eldönteni,
melyik kombináció melyik módot hozza. A BROM-út ezután is nyitott kérdés;
a `0E8D:2000` preloader protokollja (mtkclient preloader-ág) külön,
jóváhagyást igénylő lépés.

## Tesztelési határ

A 0.4.3 csomag 118 offline, szimulált eszközválaszos és szimulált PnP backendes
tesztje Linux/Python 3.11 alatt sikeres. 2026-11-12-én a felhasználó saját
T509K-ján, Windows/USB környezetben az ADB diagnosztika, a célzott fájlmásolás
és a csak olvasó bootloader-fastboot lekérdezés sikeres jelentést készített;
ezt a felhasználói riportok és az újraszámolt fájlkivonatok igazolják.
A 0.3.0 fastboot riportjának gyártói `unlock_ability = ...` válaszát a 0.3.1
parserjavítása és regressziós tesztek fedik.

A 0.4.0 USB-figyelő Windows PnP backendje **2026-11-13-án valós Windows
környezetben is lefutott** (két, egyenként 120 s-os mérés): a PnP események,
a WinUSB/HidUsb kötés és a láthatósági időtartamok rögzítése működött,
`complete: true`, eldobott esemény nélkül. A mért MediaTek ablakok
preloader szintűek (`0E8D:2000`, `0E8D:20FF`); BROM (`0E8D:0003`) nem
jelent meg. MediaTek BROM/preloader **protokoll** kapcsolat (handshake, DA
betöltés) és bármely módosító művelet továbbra sincs tesztelve. A program nem
bizonyít feloldhatóságot, és nem hajt végre feloldást vagy rootolást.
