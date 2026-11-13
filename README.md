# uj_projekt

## TCL 505 / T509K eszközvizsgálat

A [`tools/tcl505`](tools/tcl505/README.hu.md) mappában egy windowsos, csak olvasó
ADB/fastboot diagnosztikai eszköz található. A cél egy későbbi, a konkrét
firmware-hez illeszkedő bootloader-feloldási eljárás megalapozása.
A 0.3.0 változat a TCL token-jelzőket és a tokencsomag jelenlétét is vizsgálja,
és külön, opcionális ADB fájlmásolót ad célzott rendszerkonfigurációk elemzéshez.
A 0.3.1 a fastboot gyártói `unlock_ability = ...` válaszát is rögzítja, és a
nem szabványos 0/1 értéket nem tekinti feloldási engedélynek.
A 0.4.0 passzív Windows USB/PnP figyelőt ad (`tcl505_usb_watch.py`): kikapcsolt
telefon és kézi gombkombinációk mellett azt rögzíti, hogy megjelenik-e MediaTek
preloader/BROM USB eszköz, milyen VID/PID-vel és mennyi ideig. Eszközhandle
megnyitása, USB transzfer, driver telepítés, exploit/DA, partícióírás és
újraindítás nélkül.
2026-11-12-én saját T509K-ról származó ADB-, fájlmásolási és bootloader-fastboot
jelentések érkeztek; az eredményeket a
[kutatási jegyzet](tools/tcl505/KUTATASI_JEGYZET.md) rögzíti.

**A jelenlegi változat nem oldja fel a bootloadert, nem flashel, nem töröl és nem
indítja újra a telefont.** Nem tartalmaz feltört gyártói kulcsot vagy más eszközről
származó partíciós képet. A bootloader-fastboot elérése igazolt; a MediaTek
BROM/preloader hozzáférés és bármely módosító művelet továbbra sincs igazolva.
A USB-figyelő Windows PnP backendje offline, mockolt tesztekkel és 2026-11-13-án
valós Windows mérésekkel is ellenőrzött; a mért MediaTek ablakok preloader
szintűek (`0E8D:2000`, `0E8D:20FF`), BROM (`0E8D:0003`) nem jelent meg.
