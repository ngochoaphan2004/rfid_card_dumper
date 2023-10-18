# RFID Card Dumper

-   Framework: [ESP-IDF](https://github.com/espressif/esp-idf)
-   Hardware
    -   [ESP32-DevKitC](https://www.espressif.com/en/products/devkits/esp32-devkitc)
    -   [RFID-RC522](https://www.google.com/search?q=rfid-rc522)
-   Connection
    | **RFID-RC522** | **ESP32-DevKitC** |
    |:--------------:|:-----------------:|
    | 3.3V | 3V3 |
    | RST | Not Connect |
    | GND | GND |
    | IRQ | Not Connect |
    | MISO | IO19 (VSPI_MISO) |
    | MOSI | IO23 (VSPI_MOSI) |
    | SCK | IO18 (VSPI_SCK) |
    | SDA | IO5 (VSPI_SS) |
-   Supported commands
    -   REQA
    -   ANTICOLLISION and SELECT
    -   HLTA
    -   MIFARE Authentication with Key A/B
    -   MIFARE Read (not yet)
    -   MIFARE Write (not yet)
    -   MIFARE Decrement (not yet)
    -   MIFARE Increment (not yet)
    -   MIFARE Restore (not yet)
    -   MIFARE Transfer (not yet)
-   References
    -   [ESP32-DevKitC Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/hw-reference/esp32/get-started-devkitc.html)
    -   [ESP-IDF Get Started](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/)
    -   [MFRC522 Datasheet](https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf)
    -   [MIFARE Classic EV1 1K Datasheet](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)
    -   [ISO:IEC 14443-3](http://www.emutag.com/iso/14443-3.pdf) (out of date)
    -   [Arduino_MFRC522v2](https://github.com/OSSLibraries/Arduino_MFRC522v2)
