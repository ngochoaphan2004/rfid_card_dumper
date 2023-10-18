#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mfrc522.h"

static const char *TAG = "mfrc522";

#define MFRC522_ERR_BASE

#define __RETURN_IF_ERR(x)                                                          \
    do                                                                              \
    {                                                                               \
        esp_err_t err_rc_ = (x);                                                    \
        if (unlikely(err_rc_ != ESP_OK))                                            \
        {                                                                           \
            ESP_LOGE(__FUNCTION__, "[#%d] %s", __LINE__, esp_err_to_name(err_rc_)); \
            return err_rc_;                                                         \
        }                                                                           \
    } while (0)

#define __GOTO_IF_ERR(x, goto_tag)                                                  \
    do                                                                              \
    {                                                                               \
        esp_err_t err_rc_ = (x);                                                    \
        if (unlikely(err_rc_ != ESP_OK))                                            \
        {                                                                           \
            ESP_LOGE(__FUNCTION__, "[#%d] %s", __LINE__, esp_err_to_name(err_rc_)); \
            goto goto_tag;                                                          \
        }                                                                           \
    } while (0)

#define __GOTO_IF(x, goto_tag, ret_) \
    do                               \
    {                                \
        if ((x))                     \
        {                            \
            ret = ret_;              \
            goto goto_tag;           \
        }                            \
    } while (0)

typedef enum __mfrc522_cmd_t
{
    MFRC522_CMD_IDLE = 0x00,               // no action, cancels current command execution
    MFRC522_CMD_MEM = 0x01,                // stores 25 bytes into the internal buffer
    MFRC522_CMD_GENERATE_RANDOM_ID = 0x02, // generates a 10-byte random ID number
    MFRC522_CMD_CALC_CRC = 0x03,           // activates the CRC coprocessor or performs a self test
    MFRC522_CMD_TRANSMIT = 0x04,           // transmits data from the FIFO buffer
    MFRC522_CMD_NO_CMD_CHANGE = 0x07,      // no command change, can be used to modify the CommandReg register bits without affecting the command, for example, the PowerDown bit
    MFRC522_CMD_RECEIVE = 0x08,            // activates the receiver circuits
    MFRC522_CMD_TRANSCEIVE = 0x0c,         // transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
    MFRC522_CMD_MF_AUTHENT = 0x0e,         // performs the MIFARE standard authentication as a reader
    MFRC522_CMD_SOFT_RESET = 0x0f,         // resets the MFRC522
} mfrc522_cmd_t;

typedef enum __mfrc522_reg_t
{
    MFRC522_REG_COMMAND = 0x01,
    MFRC522_REG_COM_IRQ_EN = 0x02,
    MFRC522_REG_COM_IRQ = 0x04,
    MFRC522_REG_DIV_IRQ = 0x05,
    MFRC522_REG_ERROR = 0x06,
    MFRC522_REG_STATUS1 = 0x07,
    MFRC522_REG_STATUS2 = 0x08,
    MFRC522_REG_FIFO_DATA = 0x09,
    MFRC522_REG_FIFO_LEVEL = 0x0a,
    MFRC522_REG_CONTROL = 0x0c,
    MFRC522_REG_BIT_FRAMING = 0x0d,
    MFRC522_REG_COL = 0x0e,
    MFRC522_REG_MODE = 0x11,
    MFRC522_REG_TX_MODE = 0x12,
    MFRC522_REG_RX_MODE = 0x13,
    MFRC522_REG_TX_CONTROL = 0x14,
    MFRC522_REG_TX_ASK = 0x15,
    MFRC522_REG_CRC_RESULT_MSB = 0x21,
    MFRC522_REG_CRC_RESULT_LSB = 0x22,
    MFRC522_REG_MOD_WIDTH = 0x24,
    MFRC522_REG_TMODE = 0x2a,
    MFRC522_REG_TPRESCALER = 0x2b,
    MFRC522_REG_TRELOAD_HI = 0x2c,
    MFRC522_REG_TRELOAD_LO = 0x2d,
} mfrc522_reg_t;

#define MFRC522_COM_IRQ_TX (1 << 6)
#define MFRC522_COM_IRQ_RX (1 << 5)
#define MFRC522_COM_IRQ_IDLE (1 << 4)
#define MFRC522_COM_IRQ_ERROR (1 << 1)
#define MFRC522_COM_IRQ_TIMER (1)
#define MFRC522_COM_IRQ_RX_DONE (MFRC522_COM_IRQ_RX | MFRC522_COM_IRQ_IDLE | MFRC522_COM_IRQ_TIMER)

typedef enum __mifare_cmd_t
{
    MIFARE_CMD_AUTH_A = 0x60,
    MIFARE_CMD_AUTH_B = 0x61,
} mifare_cmd_t;

typedef struct __mfrc522_picc_response_t
{
    uint8_t *buffer;
    uint8_t size;
    uint8_t valid_bits;
    struct
    {
        uint8_t pos : 5;
        uint8_t pos_not_valid : 1;
        uint8_t detected : 1;
        uint8_t : 1;
    } collision;

} mfrc522_picc_response_t;

static esp_err_t mfrc522_reg_read_n(mfrc522_handle_t handle, uint8_t addr, void *buffer, uint8_t size)
{
    __RETURN_IF_ERR(spi_device_transmit(handle->spi_handle,
                                        &(spi_transaction_t){
                                            .flags = SPI_TRANS_USE_TXDATA,
                                            .length = 8,
                                            .tx_data[0] = ((addr << 1) & 0x7e) | 0x80,
                                        }));
    __RETURN_IF_ERR(spi_device_transmit(handle->spi_handle,
                                        &(spi_transaction_t){
                                            .flags = 0,
                                            .length = 8,
                                            .rxlength = 8 * size,
                                            .rx_buffer = buffer,
                                        }));
    return ESP_OK;
}

static inline uint8_t mfrc522_reg_read(mfrc522_handle_t handle, uint8_t addr)
{
    uint8_t reg_val;
    ESP_ERROR_CHECK(mfrc522_reg_read_n(handle, addr, &reg_val, 1));
    return reg_val;
}

static esp_err_t mfrc522_reg_write_n(mfrc522_handle_t handle, uint8_t addr, const void *data, uint8_t size)
{
    esp_err_t ret;
    uint8_t *buffer = (uint8_t *)malloc(size + 1);
    buffer[0] = (addr << 1) & 0x7e;
    memcpy(buffer + 1, data, size);
    ret = spi_device_transmit(handle->spi_handle,
                              &(spi_transaction_t){
                                  .length = (size + 1) * 8,
                                  .tx_buffer = buffer,
                              });
    free(buffer);
    return ret;
}

static inline esp_err_t mfrc522_reg_write(mfrc522_handle_t handle, uint8_t addr, uint8_t val)
{
    return mfrc522_reg_write_n(handle, addr, &val, 1);
}

static inline uint8_t mfrc522_reg_bit_is_set(mfrc522_handle_t handle, uint8_t addr, uint8_t mask)
{
    return mfrc522_reg_read(handle, addr) & mask;
}

static inline esp_err_t mfrc522_reg_clear_bits(mfrc522_handle_t handle, uint8_t addr, uint8_t mask)
{
    return mfrc522_reg_write(handle, addr, mfrc522_reg_read(handle, addr) & (~mask));
}

static inline esp_err_t mfrc522_reg_set_bits(mfrc522_handle_t handle, uint8_t addr, uint8_t mask)
{
    return mfrc522_reg_write(handle, addr, mfrc522_reg_read(handle, addr) | mask);
}

static void mfrc522_soft_reset(mfrc522_handle_t handle)
{
    if (mfrc522_reg_write(handle, MFRC522_REG_COMMAND, MFRC522_CMD_SOFT_RESET))
    {
        uint16_t timeout = 3000;
        while (mfrc522_reg_bit_is_set(handle, MFRC522_REG_COMMAND, 1U << 4) && timeout)
            timeout--;
    }
}

static inline esp_err_t mfrc522_antenna_on(mfrc522_handle_t handle)
{
    return mfrc522_reg_set_bits(handle, MFRC522_REG_TX_CONTROL, 0x03);
}

static esp_err_t mfrc522_execute_command(mfrc522_handle_t handle, mfrc522_cmd_t cmd, const uint8_t *data, uint8_t size, uint8_t irq_mask, uint8_t tx_last_bits, uint8_t rx_align, mfrc522_picc_response_t *response)
{
    if (response == NULL)
        return ESP_ERR_INVALID_ARG;
    memset(response, 0, sizeof(mfrc522_picc_response_t));
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_COMMAND, MFRC522_CMD_IDLE)); // stop active cmd
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_COM_IRQ, 0x7f));             // clear all irqs
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_COM_IRQ_EN, irq_mask));      // enable irqs
    __RETURN_IF_ERR(mfrc522_reg_set_bits(handle, MFRC522_REG_FIFO_LEVEL, 0x80));       // flush fifo buffer
    __RETURN_IF_ERR(mfrc522_reg_write_n(handle, MFRC522_REG_FIFO_DATA, data, size));
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_BIT_FRAMING, (rx_align << 4) | tx_last_bits));
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_COMMAND, cmd));
    if (cmd == MFRC522_CMD_TRANSCEIVE)
        __RETURN_IF_ERR(mfrc522_reg_set_bits(handle, MFRC522_REG_BIT_FRAMING, 0x80)); // starts the transmission of data

    uint8_t reg_val;

    uint16_t timeout;
    for (timeout = 2000; timeout > 0; timeout--)
    {
        reg_val = mfrc522_reg_read(handle, MFRC522_REG_COM_IRQ);
        ESP_LOGI(TAG, "CMD: 0x%02x / MFRC522_REG_COM_IRQ: 0x%02x / IRQ_MASK: 0x%02x", cmd, reg_val, irq_mask);
        if (reg_val & irq_mask) // one of masked IRQs has been set
        {
            if (reg_val & MFRC522_COM_IRQ_TIMER) // Timeout after 25ms without data received
                timeout = 0;
            break;
        }
    };
    if (cmd == MFRC522_CMD_TRANSCEIVE)
        __RETURN_IF_ERR(mfrc522_reg_clear_bits(handle, MFRC522_REG_BIT_FRAMING, 0x80));
    if (!timeout)
        return ESP_ERR_TIMEOUT;
    reg_val = mfrc522_reg_read(handle, MFRC522_REG_ERROR);
    if (reg_val & 0x13)
    {
        ESP_LOGE(TAG, "MFRC522_REG_ERROR: 0x%02x", reg_val);
        return ESP_FAIL;
    }
    response->collision.detected = (reg_val & 0x08) != 0;
    if (response->collision.detected)
    {
        reg_val = mfrc522_reg_read(handle, MFRC522_REG_COL);
        response->collision.pos_not_valid = (reg_val & 0x20) == 0x20;
        response->collision.pos = reg_val & 0x1f;
    }
    if (cmd == MFRC522_CMD_TRANSCEIVE)
    {
        response->size = mfrc522_reg_read(handle, MFRC522_REG_FIFO_LEVEL);
        response->valid_bits = mfrc522_reg_read(handle, MFRC522_REG_CONTROL) & 0x07;
        if (response->size)
        {
            response->buffer = (uint8_t *)malloc(response->size);
            for (uint8_t i = 0; i < response->size; i++)
                response->buffer[i] = mfrc522_reg_read(handle, MFRC522_REG_FIFO_DATA);
        }
    }
    return ESP_OK;
}

static inline esp_err_t mfrc522_transceive(mfrc522_handle_t handle, const uint8_t *data, uint8_t size, uint8_t tx_last_bits, uint8_t rx_align, mfrc522_picc_response_t *response)
{
    return mfrc522_execute_command(handle, MFRC522_CMD_TRANSCEIVE, data, size, MFRC522_COM_IRQ_RX_DONE, tx_last_bits, rx_align, response);
}

static esp_err_t mfrc522_calculate_crc_verify(mfrc522_handle_t handle, const uint8_t *data, uint8_t size, uint8_t *crc_out, uint8_t crc_size, uint8_t verify)
{
    if (crc_size < 2)
        return ESP_ERR_NO_MEM;
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_COMMAND, MFRC522_CMD_IDLE)); // stop active cmd
    __RETURN_IF_ERR(mfrc522_reg_clear_bits(handle, MFRC522_REG_DIV_IRQ, 0x04));        // clear CRCIRq
    __RETURN_IF_ERR(mfrc522_reg_set_bits(handle, MFRC522_REG_FIFO_LEVEL, 0x80));       // flush fifo buffer
    __RETURN_IF_ERR(mfrc522_reg_write_n(handle, MFRC522_REG_FIFO_DATA, data, size));   // write data to fifo buffer
    __RETURN_IF_ERR(mfrc522_reg_write(handle, MFRC522_REG_COMMAND, MFRC522_CMD_CALC_CRC));
    uint8_t reg_val;
    uint16_t timeout;
    for (timeout = 2000; timeout > 0; timeout--)
    {
        reg_val = mfrc522_reg_read(handle, MFRC522_REG_DIV_IRQ);
        if (reg_val & 0x04)
            break;
    }
    if (!timeout)
        return ESP_ERR_TIMEOUT;
    if (verify)
    {
        return crc_out[0] == mfrc522_reg_read(handle, MFRC522_REG_CRC_RESULT_LSB) && crc_out[1] == mfrc522_reg_read(handle, MFRC522_REG_CRC_RESULT_MSB) ? ESP_OK : ESP_ERR_INVALID_CRC;
    }
    else
    {
        crc_out[0] = mfrc522_reg_read(handle, MFRC522_REG_CRC_RESULT_LSB);
        crc_out[1] = mfrc522_reg_read(handle, MFRC522_REG_CRC_RESULT_MSB);
        return ESP_OK;
    }
}

inline static esp_err_t mfrc522_calculate_crc(mfrc522_handle_t handle, const uint8_t *data, uint8_t size, uint8_t *crc_out, uint8_t crc_size)
{
    return mfrc522_calculate_crc_verify(handle, data, size, crc_out, crc_size, false);
}

inline static esp_err_t mfrc522_verify_crc(mfrc522_handle_t handle, const uint8_t *data, uint8_t size, uint8_t *crc, uint8_t crc_size)
{
    return mfrc522_calculate_crc_verify(handle, data, size, crc, crc_size, true);
}

mfrc522_handle_t mfrc522_create(const mfrc522_config_t *config)
{

    mfrc522_handle_t handle_out = calloc(1, sizeof(struct mfrc522_t));

    spi_bus_config_t spi_bus_cfg = {
        .miso_io_num = config->miso_io_num,
        .mosi_io_num = config->mosi_io_num,
        .sclk_io_num = config->sclk_io_num,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 1024,
    };
    spi_device_interface_config_t spi_dev_cfg = {
        .clock_speed_hz = 5000000,
        .mode = 0,
        .spics_io_num = config->sc_io_num,
        .queue_size = 7,
        .flags = 0,
    };

    __GOTO_IF_ERR(spi_bus_initialize(config->host, &spi_bus_cfg, SPI_DMA_DISABLED), err_ret);
    __GOTO_IF_ERR(spi_bus_add_device(config->host, &spi_dev_cfg, &(handle_out->spi_handle)), err_ret);

    mfrc522_soft_reset(handle_out);

    // Reset to default
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_TX_MODE, 0x00), err_ret); // TxSpeed = 106 kBd
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_RX_MODE, 0x00), err_ret); // RxSpeed = 106 kBd
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_MOD_WIDTH, 0x26), err_ret);

    // Test communication
    if (mfrc522_reg_read(handle_out, MFRC522_REG_MOD_WIDTH) != 0x26)
    {
        ESP_LOGE(__FUNCTION__, "[#%d] Failed to communicate with device", __LINE__);
        goto err_ret;
    }

    // timer starts automatically at the end of the transmission in all communication modes at all speeds
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_TMODE, 0x80), err_ret);
    // TPreScaler = 0x0a9 (169), ftimer = 40kHz, period = 25us
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_TPRESCALER, 0xa9), err_ret);
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_TRELOAD_HI, 0x03), err_ret);
    // TReloadVal = 0x3e7 (999), total delay time (td) = 25ms
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_TRELOAD_LO, 0xe7), err_ret);
    // forces a 100 % ASK modulation independent of the ModGsPReg register setting
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_TX_ASK, 0x40), err_ret);
    // CRCPreset = 0x6363, ISO 14443-3 part 6.2.4
    __GOTO_IF_ERR(mfrc522_reg_write(handle_out, MFRC522_REG_MODE, 0x3d), err_ret);

    __GOTO_IF_ERR(mfrc522_antenna_on(handle_out), err_ret);

    return handle_out;
err_ret:
    free(handle_out);
    return NULL;
}

esp_err_t mfrc522_picc_reqa(mfrc522_handle_t handle)
{
    esp_err_t ret;
    mfrc522_picc_response_t response = {.buffer = NULL};
    if ((ret = mfrc522_transceive(handle, (const uint8_t[]){0x26}, 1, 0x7, 0, &response)))
        return ret;

    if (response.buffer)
    {
        free(response.buffer);
        response.buffer = NULL;
    }
    return response.size == 2 && response.valid_bits == 0 ? ESP_OK : ESP_FAIL;
}

/**
 * ISO/IEC 14443-3, 6.5.3 Anticollision and Select
 *
 * SEL1 = 0x93 - Select cascade level 1
 * SEL2 = 0x95 - Select cascade level 2
 * SEL3 = 0x97 - Select cascade level 3
 * CT   = 0x88 - Cascade Tag, to indicate a following cascade level
 * BCC  = Block Check Character, it is calculated as exclusive-or over the 4 previous bytes
 *
 * Single size UID
 *     UID CL1 - <UID0> <UID1> <UID2> <UID3>
 *
 * Double size UID
 *     UID CL1 - <CT> <UID0> <UID1> <UID2>
 *     UID CL2 - <UID3> <UID4> <UID5> <UID6>
 *
 * Triple size UID
 *     UID CL1 - <CT> <UID0> <UID1> <UID2>
 *     UID CL2 - <CT> <UID3> <UID4> <UID5>
 *     UID CL3 - <UID6> <UID7> <UID8> <UID9>
 *
 * 1. Start
 * 2. Transmit ANTICOLLISION command - SELn <NVB=0x20>
 * 3. Receive UID CLn
 * If there is no collision (i.e., the received UID CLn matches the expected UID CLn):
 *     4. Transmit SELECT command - SELn <NVB=0x70> <UID CLn> <BCC> <CRC0> <CRC1>
 *     5. End of anticollision loop
 * Else (i.e., there is a collision):
 *     6. Determine the position of the first collision (col)
 *     7. Transmit ANTICOLLISION command - SELn <NVB=0x20+col> <UID CLn> <CRC0> <CRC1>
 *     8. Go to step 3
 * 9. End
 */
esp_err_t mfrc522_picc_select(mfrc522_handle_t handle, mfrc522_picc_uid_t *uid)
{
    esp_err_t ret;
    uint8_t buffer[9] = {0};
    uint8_t buffer_size = 0;
    uint8_t current_cl = 1;
    uint8_t uid_complete = false;
    uint8_t uid_index = 0;
    uint8_t uid_valid_bits = 0;
    mfrc522_picc_response_t response = {.buffer = NULL};
    do
    {
        switch (current_cl)
        {
        case 1:
            buffer[0] = 0x93;
            uid_index = 0;
            if (uid->size > 4)
                uid_valid_bits = 24; // with CT
            else if (uid->size == 4)
                uid_valid_bits = 32;
            break;
        case 2:
            buffer[0] = 0x95;
            uid_index = 3;
            if (uid->size > 7)
                uid_valid_bits = 24; // with CT
            else if (uid->size == 7)
                uid_valid_bits = 32;
            break;
        case 3:
            buffer[0] = 0x97;
            uid_index = 6;
            if (uid->size == 10)
                uid_valid_bits = 32;
            break;
        default:
            return ESP_ERR_INVALID_STATE;
        }

        if (uid_valid_bits == 24 || uid_valid_bits == 32)
        {
            if (buffer[1] != 0x20) // not ANTICOLLISION -> SELECT
            {
                if (uid_valid_bits == 24)
                {
                    buffer[2] = 0x88; // CT
                    memcpy(buffer + 3, uid->data + uid_index, 3);
                }
                else
                {
                    memcpy(buffer + 2, uid->data + uid_index, 4);
                }
            }
            buffer[1] = 0x70;
            buffer[6] = buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5];
            __GOTO_IF_ERR(ret = mfrc522_calculate_crc(handle, buffer, 7, buffer + 7, 2), err_ret);
            buffer_size = 9;
        }
        else if (uid_valid_bits == 0)
        {
            buffer[1] = 0x20;
            buffer_size = 2;
        }
        else
        {
            // collision.detected
            // NOT YET IMPLEMENTED
        }

        // ESP_LOGI("PID", "{.size = %d, uid_valid_bits = %d}", buffer_size, uid_valid_bits);
        // ESP_LOG_BUFFER_HEX("PID*", buffer, sizeof(buffer));
        __RETURN_IF_ERR(mfrc522_transceive(handle, buffer, buffer_size, 0, 0, &response));
        if (response.buffer)
        {
            // ESP_LOGI("PICC", "{.size = %d, .valid_bits = %d, .collision.detected = %d, .collision.pos = %d}", response.size, response.valid_bits, response.collision.detected, response.collision.pos);
            // ESP_LOG_BUFFER_HEX("PICC*", response.buffer, response.size);
            if (response.collision.detected)
            {
                // collision.detected
                // NOT YET IMPLEMENTED
            }
            else
            {
                if (buffer[1] == 0x70) // SELECT command
                {
                    __GOTO_IF(response.size != 3, err_ret, ESP_ERR_INVALID_SIZE);
                    __GOTO_IF_ERR(ret = mfrc522_verify_crc(handle, response.buffer, 1, response.buffer + 1, 2), err_ret);
                    if ((response.buffer[0] & 0x04) == 0x04)
                    {
                        current_cl++;
                        uid_valid_bits = 0;
                    }
                    else
                    {
                        uid_complete = true;
                        uid->sak = response.buffer[0];
                        if (uid_valid_bits == 24)
                        {
                            memcpy(uid->data + uid_index, buffer + 3, 3);
                            uid->size = uid_index + 3;
                        }
                        else
                        {
                            memcpy(uid->data + uid_index, buffer + 2, 4);
                            uid->size = uid_index + 4;
                        }
                    }
                }
                else // ANTICOLLISION command
                {
                    __GOTO_IF(response.size != 5, err_ret, ESP_ERR_INVALID_SIZE);
                    memcpy(buffer + 2, response.buffer, 5);
                    uid_valid_bits = response.buffer[0] == 0x88 ? 24 : 32;
                }
            }

            free(response.buffer);
            response.buffer = NULL;
        }
    } while (!uid_complete);

    return ESP_OK;
err_ret:
    if (response.buffer)
        free(response.buffer);
    return ret;
}

inline esp_err_t mfrc522_picc_get_uid(mfrc522_handle_t handle, mfrc522_picc_uid_t *uid)
{
    uid->size = 0;
    return mfrc522_picc_select(handle, uid);
}

esp_err_t mfrc522_picc_hlta(mfrc522_handle_t handle)
{
    esp_err_t ret;
    mfrc522_picc_response_t response = {.buffer = NULL};
    uint8_t buffer[4] = {0x50, 0};
    __RETURN_IF_ERR(mfrc522_calculate_crc(handle, buffer, 2, buffer + 2, 2));
    if ((ret = mfrc522_transceive(handle, buffer, 4, 0, 0, &response)) == ESP_OK && response.buffer)
    {
        free(response.buffer);
        return ESP_FAIL;
    }
    if (ret == ESP_ERR_TIMEOUT)
        return ESP_OK;
    return ret;
}

picc_type_t mfrc522_picc_get_type(mfrc522_picc_uid_t *uid)
{
    uint8_t sak = uid->sak & 0x3b;
    if (sak & 0x02)
        return PICC_TYPE_RFU;
    switch (sak)
    {
    case 0x19:
        return PICC_TYPE_MIFARE_2K;
    case 0x09:
        return PICC_TYPE_MIFARE_MINI;
    case 0x10:
        return PICC_TYPE_MIFARE_PLUS_2K_SL2;
    case 0x11:
        return PICC_TYPE_MIFARE_PLUS_4K_SL2;
    case 0x01:
        return PICC_TYPE_TAGNPLAY;
    case 0x08:
        // if(RATS)
        //      GetVersion -> ...
        // else
        return PICC_TYPE_MIFARE_1K;
    case 0x28:
        return PICC_TYPE_SMARTMX_MIFARE_1K;
    case 0x18:
        // if(RATS)
        //      GetVersion -> ...
        // else
        return PICC_TYPE_MIFARE_4K;
    case 0x38:
        return PICC_TYPE_SMARTMX_MIFARE_4K;
    case 0x00:
        return PICC_TYPE_ISO14443_3;
    case 0x20:
        return PICC_TYPE_ISO14443_4;
    default:
        return PICC_TYPE_UNKNOWN;
    }
}

static esp_err_t mfrc522_mifare_auth(mfrc522_handle_t handle, uint8_t command, uint8_t block_addr, const uint8_t *key, mfrc522_picc_uid_t *uid)
{
    if (uid->size < 4)
        return ESP_ERR_INVALID_ARG;
    mfrc522_picc_response_t response = {.buffer = NULL};
    uint8_t buffer[2 + MIFARE_KEY_SIZE + 4] = {0};
    buffer[0] = command;
    buffer[1] = block_addr;
    memcpy(buffer + 2, key, MIFARE_KEY_SIZE);
    memcpy(buffer + 2 + MIFARE_KEY_SIZE, uid->data, 4);
    __RETURN_IF_ERR(mfrc522_execute_command(handle, MFRC522_CMD_MF_AUTHENT, buffer, sizeof(buffer), MFRC522_COM_IRQ_IDLE, 0, 0, &response));
    if (response.buffer)
        free(response.buffer);
    return mfrc522_mifare_is_crypto_on(handle);
}

inline esp_err_t mfrc522_mifare_auth_a(mfrc522_handle_t handle, uint8_t block_addr, const uint8_t *key, mfrc522_picc_uid_t *uid)
{
    return mfrc522_mifare_auth(handle, MIFARE_CMD_AUTH_A, block_addr, key, uid);
}

inline esp_err_t mfrc522_mifare_auth_b(mfrc522_handle_t handle, uint8_t block_addr, const uint8_t *key, mfrc522_picc_uid_t *uid)
{
    return mfrc522_mifare_auth(handle, MIFARE_CMD_AUTH_B, block_addr, key, uid);
}

inline esp_err_t mfrc522_mifare_is_crypto_on(mfrc522_handle_t handle)
{
    return (mfrc522_reg_read(handle, MFRC522_REG_STATUS2) & 0x08) == 0x08 ? ESP_OK : ESP_FAIL;
}

inline esp_err_t mfrc522_mifare_crypto_off(mfrc522_handle_t handle)
{
    return mfrc522_reg_clear_bits(handle, MFRC522_REG_STATUS2, 0x08);
}