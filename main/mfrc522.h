#pragma once

#include "esp_err.h"
#include "driver/spi_master.h"

#define MIFARE_KEY_SIZE 6

typedef enum
{
    PICC_TYPE_RFU,
    PICC_TYPE_MIFARE_1K,
    PICC_TYPE_MIFARE_2K,
    PICC_TYPE_MIFARE_4K,
    PICC_TYPE_MIFARE_MINI,
    PICC_TYPE_MIFARE_PLUS_2K_SL2,
    PICC_TYPE_MIFARE_PLUS_4K_SL2,
    PICC_TYPE_TAGNPLAY,
    PICC_TYPE_SMARTMX_MIFARE_1K,
    PICC_TYPE_SMARTMX_MIFARE_4K,
    PICC_TYPE_ISO14443_3,
    PICC_TYPE_ISO14443_4,
    PICC_TYPE_UNKNOWN,
} picc_type_t;

typedef struct
{
    spi_host_device_t host;
    int sc_io_num;
    int sclk_io_num;
    int miso_io_num;
    int mosi_io_num;
} mfrc522_config_t;

struct mfrc522_t
{
    spi_device_handle_t spi_handle;
};
typedef struct mfrc522_t *mfrc522_handle_t;

typedef struct
{
    uint8_t data[10];
    uint8_t size;
    uint8_t sak;
} mfrc522_picc_uid_t;
/**
 * Create a handle
 */
mfrc522_handle_t mfrc522_create(const mfrc522_config_t *config);

/**
 * ISO/IEC 14443-3, 6.4.1 REQA and WUPA commands
 */
esp_err_t mfrc522_picc_reqa(mfrc522_handle_t handle);
/**
 * ISO/IEC 14443-3, 6.5.3 Anticollision and Select
 */
esp_err_t mfrc522_picc_select(mfrc522_handle_t handle, mfrc522_picc_uid_t *uid);
esp_err_t mfrc522_picc_get_uid(mfrc522_handle_t handle, mfrc522_picc_uid_t *uid);
/**
 * ISO/IEC 14443-3, 6.4.3 HLTA command
 */
esp_err_t mfrc522_picc_hlta(mfrc522_handle_t handle);

/**
 * Get type of selected PICC(
 * The details of PICC types are described in AN10833 (https://www.nxp.com/docs/en/application-note/AN10833.pdf)
 */
picc_type_t mfrc522_picc_get_type(mfrc522_picc_uid_t *uid);

/**
 * Execute MFAuthent command to enable a secure communication to any MIFARE Mini, MIFARE 1K and MIFARE 4K card.
 * The details of MFAuthent are described in section 10.3.1.9 of MFRC522 datasheet (https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf#page=72)
 */
esp_err_t mfrc522_mifare_auth_a(mfrc522_handle_t handle, uint8_t block_addr, const uint8_t *key, mfrc522_picc_uid_t *uid);
esp_err_t mfrc522_mifare_auth_b(mfrc522_handle_t handle, uint8_t block_addr, const uint8_t *key, mfrc522_picc_uid_t *uid);
esp_err_t mfrc522_mifare_is_crypto_on(mfrc522_handle_t handle);
esp_err_t mfrc522_mifare_crypto_off(mfrc522_handle_t handle);