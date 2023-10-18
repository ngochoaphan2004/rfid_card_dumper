#include <stdio.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mfrc522.h"

static const char *PICC_TYPES[] = {
    "RFU",
    "MIFARE Classic 1K",
    "MIFARE Classic 2K",
    "MIFARE Classic 4K",
    "MIFARE Mini",
    "MIFARE Plus 2K in SL2",
    "MIFARE Plus 4K in SL2",
    "TagNPlay",
    "SmartMX with MIFARE Classic 1K",
    "SmartMX with MIFARE Classic 4K",
    "ISO 14443-3",
    "ISO 14443-4",
    "Unknown",
};

static mfrc522_handle_t mfrc522_handle = NULL;

static mfrc522_picc_uid_t uid = {0};

static void dump_info(mfrc522_handle_t handle, mfrc522_picc_uid_t *uid)
{
    picc_type_t type = mfrc522_picc_get_type(uid);
    ESP_LOGI("PICC Type", "%s", PICC_TYPES[type]);
    ESP_LOG_BUFFER_HEX("Card UID", uid->data, uid->size);
    ESP_LOGI("Card SAK", "%02x", uid->sak);
    for (uint8_t i = 0; i < 16; i++)
    {
        if (mfrc522_mifare_auth_a(mfrc522_handle, i, (const uint8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uid) != ESP_OK)
        {
            ESP_LOGE("MFAuthent", "Block %d -> failed", i);
        }
        else
        {
            ESP_LOGI("MFAuthent", "Block %d -> success", i);
        }
    }
    mfrc522_picc_hlta(mfrc522_handle);
    mfrc522_mifare_crypto_off(mfrc522_handle);
}

void app_main(void)
{
    mfrc522_handle = mfrc522_create(&(mfrc522_config_t){
        .host = VSPI_HOST,
        .sc_io_num = 5,    // VSPICS0
        .sclk_io_num = 18, // VSPICLK
        .miso_io_num = 19, // VSPIQ
        .mosi_io_num = 23, // VSPID
    });
    if (mfrc522_handle == NULL)
        return;
    while (1)
    {
        if (mfrc522_picc_reqa(mfrc522_handle) == ESP_OK)
        {
            if (mfrc522_picc_get_uid(mfrc522_handle, &uid) == ESP_OK)
            {
                dump_info(mfrc522_handle, &uid);
            }
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}