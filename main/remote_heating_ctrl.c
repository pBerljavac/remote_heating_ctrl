/* ESP HTTP Client Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <sys/param.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_system.h"

#include "esp_adc/adc_continuous.h"

#include "esp_http_client.h"

//HTTP CONFIG
#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

//ADC READ CONFIG
#define ADC_READ_UNIT                    ADC_UNIT_1
#define ADC_READ_CONV_MODE               ADC_CONV_SINGLE_UNIT_1
#define ADC_READ_ATTEN                   ADC_ATTEN_DB_12
#define ADC_READ_BIT_WIDTH               SOC_ADC_DIGI_MAX_BITWIDTH
#define ADC_READ_LEN 256

static TaskHandle_t s_task_handle;
static QueueHandle_t g_temp_queue = NULL;

static const char *TAG = "ROOM_TEMP"; //hmm

typedef enum HeatgCtrlSt
{
    HEATG_CTRL_ST_INIT = 0,
    HEATG_CTRL_ST_OFF,
    HEATG_CTRL_ST_IDLE,
    HEATG_CTRL_ST_HEATING,
    HEATG_CTRL_ST_DEBUG,
    HEATG_CTRL_ST_ERROR
} tHeatgCtrlSt;

//Helper function
int8_t roundint8f(float value) {
    return (int8_t)(value + (value >= 0 ? 0.5f : -0.5f));
}

/* Root cert for howsmyssl.com, taken from howsmyssl_com_root_cert.pem

   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

   The CA root cert is the last cert given in the chain of certs.

   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const char howsmyssl_com_root_cert_pem_start[] asm("_binary_howsmyssl_com_root_cert_pem_start");
extern const char howsmyssl_com_root_cert_pem_end[]   asm("_binary_howsmyssl_com_root_cert_pem_end");

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;  // Buffer to store response of http request from event handler
    static int output_len;       // Stores number of bytes read
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Clean the buffer in case of a new request
            if (output_len == 0 && evt->user_data) {
                // we are just starting to copy the output data into the use
                memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
            }
            /*
             *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
             *  However, event handler can also be used in case chunked encoding is used.
             */
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                int copy_len = 0;
                if (evt->user_data) {
                    // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                    copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                    if (copy_len) {
                        memcpy(evt->user_data + output_len, evt->data, copy_len);
                    }
                } else {
                    int content_len = esp_http_client_get_content_length(evt->client);
                    if (output_buffer == NULL) {
                        // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                        output_buffer = (char *) calloc(content_len + 1, sizeof(char));
                        output_len = 0;
                        if (output_buffer == NULL) {
                            ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                            return ESP_FAIL;
                        }
                    }
                    copy_len = MIN(evt->data_len, (content_len - output_len));
                    if (copy_len) {
                        memcpy(output_buffer + output_len, evt->data, copy_len);
                    }
                }
                output_len += copy_len;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
#if CONFIG_EXAMPLE_ENABLE_RESPONSE_BUFFER_DUMP
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
#endif
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            esp_http_client_set_header(evt->client, "From", "user@example.com");
            esp_http_client_set_header(evt->client, "Accept", "text/html");
            esp_http_client_set_redirection(evt->client);
            break;
    }
    return ESP_OK;
}

static void http_rest_with_url(void)
{
    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};
    /**
     * NOTE: All the configuration parameters for http_client must be specified either in URL or as host and path parameters.
     * If host and path parameters are not set, query parameter will be ignored. In such cases,
     * query parameter should be specified in URL.
     *
     * If URL as well as host and path parameters are specified, values of host and path will be considered.
     */
    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/get",
        .query = "esp",
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
    ESP_LOG_BUFFER_HEX(TAG, local_response_buffer, strlen(local_response_buffer));

    // POST
    const char *post_data = "{\"field1\":\"value1\"}";
    esp_http_client_set_url(client, "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/post");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    //PUT
    esp_http_client_set_url(client, "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/put");
    esp_http_client_set_method(client, HTTP_METHOD_PUT);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP PUT Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP PUT request failed: %s", esp_err_to_name(err));
    }

    //PATCH
    esp_http_client_set_url(client, "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/patch");
    esp_http_client_set_method(client, HTTP_METHOD_PATCH);
    esp_http_client_set_post_field(client, NULL, 0);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP PATCH Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP PATCH request failed: %s", esp_err_to_name(err));
    }

    //DELETE
    esp_http_client_set_url(client, "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/delete");
    esp_http_client_set_method(client, HTTP_METHOD_DELETE);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP DELETE Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP DELETE request failed: %s", esp_err_to_name(err));
    }

    //HEAD
    esp_http_client_set_url(client, "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/get");
    esp_http_client_set_method(client, HTTP_METHOD_HEAD);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP HEAD Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP HEAD request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

static uint8_t http_rest_with_url_get_set_temp(void)
{
    uint8_t tSet = 0;

    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/set-temperature",
        .query = NULL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return 99u;
    }

    // Set method to GET (keep default) and add the JSON body
    const char *post_data = "{\"type\": \"Normal\"}";
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    // Display hex data
    // ESP_LOG_BUFFER_HEX(TAG, local_response_buffer, strlen(local_response_buffer));

    // // Display response as readable text - only for debug
    // if (strlen(local_response_buffer) > 0) {
    //     local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = '\0';  // Ensure null termination
    //     ESP_LOGI(TAG, "Response: %s", local_response_buffer);
    // } else {
    //     ESP_LOGI(TAG, "Empty response");
    // }

    // Parse JSON response to extract the "value" field
    // sscanf(local_response_buffer, "{\"value\": %hhu", &tSet); //Simplified version that didnt work
    const char *value_str = strstr(local_response_buffer, "\"value\"");
    if (value_str != NULL) {
        // Find the colon after "value"
        value_str = strchr(value_str, ':');
        if (value_str != NULL) {
            // Parse the number (skip the colon and any whitespace)
            sscanf(value_str + 1, "%hhu", &tSet);
            // ESP_LOGI(TAG, "Parsed temperature value: %u", tSet);
        }
    } else {
        ESP_LOGE(TAG, "Could not find 'value' field in JSON response");
    }

    esp_http_client_cleanup(client);

    return tSet;
}

static void http_rest_with_url_get_op_mod(char *opMod, size_t opMod_size)
{
    // static char opMod[64] = {0};  // Static buffer to store operation mode
    // memset(opMod, 0, sizeof(opMod));  // Clear buffer before use

    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/operation-mode",
        .query = NULL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        strcpy(opMod, "");
        return;
    }

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    // Display response as readable text - only for debug
    // if (strlen(local_response_buffer) > 0) {
    //     local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = '\0';  // Ensure null termination
    //     ESP_LOGI(TAG, "Response: %s", local_response_buffer);
    // } else {
    //     ESP_LOGI(TAG, "Empty response");
    // }

    // Parse JSON response to extract the "mode" field
    const char *mode_str = strstr(local_response_buffer, "\"mode\"");
    if (mode_str != NULL) {
        // Find the colon after "mode"
        mode_str = strchr(mode_str, ':');
        if (mode_str != NULL) {
            // Find the opening quote of the value
            mode_str = strchr(mode_str, '\"');
            if (mode_str != NULL) {
                mode_str++;  // Skip the opening quote
                // Find the closing quote and extract the string
                const char *end_quote = strchr(mode_str, '\"');
                if (end_quote != NULL) {
                    int len = end_quote - mode_str;
                    if (len < (int)opMod_size) {
                        strncpy(opMod, mode_str, len);
                        opMod[len] = '\0';  // Null terminate
                        // ESP_LOGI(TAG, "Parsed operation mode: %s", opMod);
                    } else {
                        ESP_LOGE(TAG, "Operation mode string too long");
                    }
                }
            }
        }
    } else {
        ESP_LOGE(TAG, "Could not find 'mode' field in JSON response");
    }

    esp_http_client_cleanup(client);
}

static void http_rest_with_url_get_ctrl_sts(void)
{
    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/control-status",
        .query = NULL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return;
    }

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    // Display hex data
    // ESP_LOG_BUFFER_HEX(TAG, local_response_buffer, strlen(local_response_buffer));

    // Display response as readable text
    if (strlen(local_response_buffer) > 0) {
        local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = '\0';  // Ensure null termination
        ESP_LOGI(TAG, "Response: %s", local_response_buffer);
    } else {
        ESP_LOGI(TAG, "Empty response");
    }

    esp_http_client_cleanup(client);
}

// //OVERRIDEN TO Control individually
// static void http_rest_with_url_post_op_mode(void)
// {
//     // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
//     // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
//     char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

//     esp_http_client_config_t config = {
//         .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
//         .path = "/operation-mode",
//         .query = NULL,
//         .event_handler = _http_event_handler,
//         .user_data = local_response_buffer,        // Pass address of local buffer to get response
//         .disable_auto_redirect = true,
//     };
//     ESP_LOGI(TAG, "HTTP request with url =>");
//     esp_http_client_handle_t client = esp_http_client_init(&config);

//     if (client == NULL) {
//         ESP_LOGE(TAG, "Failed to initialize HTTP client");
//         return;
//     }

//     // POST
//     const char *post_data = "{\"mode\":\"Control individually\"}";
//     // const char *post_data = "{\"mode\":\"Weekly program\"}";
//     esp_http_client_set_method(client, HTTP_METHOD_POST);
//     esp_http_client_set_header(client, "Content-Type", "application/json");
//     esp_http_client_set_post_field(client, post_data, strlen(post_data));
//     esp_err_t err = esp_http_client_perform(client);
//     if (err == ESP_OK) {
//         ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
//                 esp_http_client_get_status_code(client),
//                 esp_http_client_get_content_length(client));
//     } else {
//         ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
//     }

//     esp_http_client_cleanup(client);
// }

//OVERRIDEN TO Control individually
static void http_rest_with_url_post_op_mode(char *opModeReq)
{
    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/operation-mode",
        .query = NULL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return;
    }

    // POST
    char post_data[128];
    snprintf(post_data, sizeof(post_data), "{\"mode\":\"%s\"}", opModeReq);
    // const char *post_data = "{\"mode\":\"Control individually\"}";
    // const char *post_data = "{\"mode\":\"Weekly program\"}";
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

static void http_rest_with_url_post_set_temp(uint8_t temperature_value)
{
    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};

    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/set-temperature",
        .query = NULL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        // Pass address of local buffer to get response
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return;
    }

    // POST
    char post_data[128];
    snprintf(post_data, sizeof(post_data), "{\"type\":\"Normal\",\"value\":%u}", temperature_value);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

static void http_rest_with_hostname_path(void)
{
    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/get",
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP request with hostname and path =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // GET
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    // POST
    const char *post_data = "field1=value1&field2=value2";
    esp_http_client_set_url(client, "/post");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    //PUT
    esp_http_client_set_url(client, "/put");
    esp_http_client_set_method(client, HTTP_METHOD_PUT);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP PUT Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP PUT request failed: %s", esp_err_to_name(err));
    }

    //PATCH
    esp_http_client_set_url(client, "/patch");
    esp_http_client_set_method(client, HTTP_METHOD_PATCH);
    esp_http_client_set_post_field(client, NULL, 0);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP PATCH Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP PATCH request failed: %s", esp_err_to_name(err));
    }

    //DELETE
    esp_http_client_set_url(client, "/delete");
    esp_http_client_set_method(client, HTTP_METHOD_DELETE);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP DELETE Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP DELETE request failed: %s", esp_err_to_name(err));
    }

    //HEAD
    esp_http_client_set_url(client, "/get");
    esp_http_client_set_method(client, HTTP_METHOD_HEAD);
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP HEAD Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP HEAD request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

#if CONFIG_ESP_HTTP_CLIENT_ENABLE_BASIC_AUTH
static void http_auth_basic(void)
{
    /**
     * Note: `max_authorization_retries` in esp_http_client_config_t
     * can be used to configure number of retry attempts to be performed
     * in case unauthorized status code is received.
     *
     * To disable authorization retries, set max_authorization_retries to -1.
     */
    esp_http_client_config_t config = {
        .url = "http://user:passwd@"CONFIG_EXAMPLE_HTTP_ENDPOINT"/basic-auth/user/passwd",
        .event_handler = _http_event_handler,
        .auth_type = HTTP_AUTH_TYPE_BASIC,
        .max_authorization_retries = -1,
    };
    ESP_LOGI(TAG, "HTTP Basic Auth request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Basic Auth Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_auth_basic_redirect(void)
{
    esp_http_client_config_t config = {
        .url = "http://user:passwd@"CONFIG_EXAMPLE_HTTP_ENDPOINT"/basic-auth/user/passwd",
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP Basic Auth redirect request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Basic Auth redirect Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}
#endif

#if CONFIG_ESP_HTTP_CLIENT_ENABLE_DIGEST_AUTH
static void http_auth_digest_md5(void)
{
    esp_http_client_config_t config = {
        .url = "http://user:passwd@"CONFIG_EXAMPLE_HTTP_ENDPOINT"/digest-auth/auth/user/passwd/MD5/never",
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP MD5 Digest Auth request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP MD5 Digest Auth Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error performing http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_auth_digest_sha256(void)
{
    esp_http_client_config_t config = {
        .url = "http://user:passwd@"CONFIG_EXAMPLE_HTTP_ENDPOINT"/digest-auth/auth/user/passwd/SHA-256/never",
        .event_handler = _http_event_handler,
        .buffer_size_tx = 1024, // Increase buffer size as header size will increase as it contains SHA-256.
    };
    ESP_LOGI(TAG, "HTTP SHA256 Digest Auth request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP SHA256 Digest Auth Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error performing http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}
#endif

#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
static void https_with_url(void)
{
    esp_http_client_config_t config = {
        .url = "https://www.howsmyssl.com",
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    ESP_LOGI(TAG, "HTTPS request with url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}
#endif // CONFIG_MBEDTLS_CERTIFICATE_BUNDLE

static void https_with_hostname_path(void)
{
    esp_http_client_config_t config = {
        .host = "www.howsmyssl.com",
        .path = "/",
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .event_handler = _http_event_handler,
        .cert_pem = howsmyssl_com_root_cert_pem_start,
    };
    ESP_LOGI(TAG, "HTTPS request with hostname and path =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_encoded_query(void)
{
    esp_http_client_config_t config = {
        .host = CONFIG_EXAMPLE_HTTP_ENDPOINT,
        .path = "/get",
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP GET request with encoded query =>");

    static const char query_val[] = "ABC xyz!012@#%&";
    char query_val_enc[64] = {0};

    uint32_t enc_len = example_uri_encode(query_val_enc, query_val, strlen(query_val));
    if (enc_len > 0) {
        ESP_LOG_BUFFER_HEXDUMP(TAG, query_val_enc, enc_len, ESP_LOG_DEBUG);
        config.query = query_val_enc;
    }

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
}

static void http_relative_redirect(void)
{
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/relative-redirect/3",
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP Relative path redirect request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Relative path redirect Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_absolute_redirect(void)
{
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/absolute-redirect/3",
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP Absolute path redirect request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Absolute path redirect Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_absolute_redirect_manual(void)
{
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/absolute-redirect/3",
        .event_handler = _http_event_handler,
        .disable_auto_redirect = true,
    };
    ESP_LOGI(TAG, "HTTP Absolute path redirect (manual) request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Absolute path redirect (manual) Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_redirect_to_https(void)
{
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/redirect-to?url=https://www.howsmyssl.com",
        .event_handler = _http_event_handler,
        .cert_pem = howsmyssl_com_root_cert_pem_start,
    };
    ESP_LOGI(TAG, "HTTP redirect to HTTPS request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP redirect to HTTPS Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}


static void http_download_chunk(void)
{
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/stream-bytes/8912",
        .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTP chunk encoding request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP chunk encoding Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void http_perform_as_stream_reader(void)
{
    char *buffer = malloc(MAX_HTTP_RECV_BUFFER + 1);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Cannot malloc http receive buffer");
        return;
    }
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/get",
    };
    ESP_LOGI(TAG, "HTTP Stream reader request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err;
    if ((err = esp_http_client_open(client, 0)) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        free(buffer);
        return;
    }
    int content_length =  esp_http_client_fetch_headers(client);
    int total_read_len = 0, read_len;
    if (total_read_len < content_length && content_length <= MAX_HTTP_RECV_BUFFER) {
        read_len = esp_http_client_read(client, buffer, content_length);
        if (read_len <= 0) {
            ESP_LOGE(TAG, "Error read data");
        }
        buffer[read_len] = 0;
        ESP_LOGD(TAG, "read_len = %d", read_len);
    }
    ESP_LOGI(TAG, "HTTP Stream reader Status = %d, content_length = %"PRId64,
                    esp_http_client_get_status_code(client),
                    esp_http_client_get_content_length(client));
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    free(buffer);
}

#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
static void https_async(void)
{
    esp_http_client_config_t config = {
        .url = "https://postman-echo.com/post",
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .is_async = true,
        .timeout_ms = 5000,
    };
    ESP_LOGI(TAG, "HTTPS async requests =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err;
    const char *post_data = "Using a Palantír requires a person with great strength of will and wisdom. The Palantíri were meant to "
                            "be used by the Dúnedain to communicate throughout the Realms in Exile. During the War of the Ring, "
                            "the Palantíri were used by many individuals. Sauron used the Ithil-stone to take advantage of the users "
                            "of the other two stones, the Orthanc-stone and Anor-stone, but was also susceptible to deception himself.";
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    while (1) {
        err = esp_http_client_perform(client);
        if (err != ESP_ERR_HTTP_EAGAIN) {
            break;
        }
    }
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);

    // Test HTTP_METHOD_HEAD with is_async enabled
    config.url = "https://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/get";
    config.event_handler = _http_event_handler;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.is_async = true;
    config.timeout_ms = 5000;

    client = esp_http_client_init(&config);
    esp_http_client_set_method(client, HTTP_METHOD_HEAD);

    while (1) {
        err = esp_http_client_perform(client);
        if (err != ESP_ERR_HTTP_EAGAIN) {
            break;
        }
    }
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}
#endif

static void https_with_invalid_url(void)
{
    esp_http_client_config_t config = {
            .url = "https://not.existent.url",
            .event_handler = _http_event_handler,
    };
    ESP_LOGI(TAG, "HTTPS request with invalid url =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, content_length = %"PRId64,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

/*
 *  http_native_request() demonstrates use of low level APIs to connect to a server,
 *  make a http request and read response. Event handler is not used in this case.
 *  Note: This approach should only be used in case use of low level APIs is required.
 *  The easiest way is to use esp_http_perform()
 */
static void http_native_request(void)
{
    // Declare local_response_buffer with size (MAX_HTTP_OUTPUT_BUFFER + 1) to prevent out of bound access when
    // it is used by functions like strlen(). The buffer should only be used upto size MAX_HTTP_OUTPUT_BUFFER
    char output_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};   // Buffer to store response of http request
    int content_length = 0;
    esp_http_client_config_t config = {
        .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/get",
    };
    ESP_LOGI(TAG, "HTTP native request =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // GET Request
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, data_read);
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    esp_http_client_close(client);

    // POST Request
    const char *post_data = "{\"field1\":\"value1\"}";
    esp_http_client_set_url(client, "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/post");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    err = esp_http_client_open(client, strlen(post_data));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        int wlen = esp_http_client_write(client, post_data, strlen(post_data));
        if (wlen < 0) {
            ESP_LOGE(TAG, "Write failed");
        }
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, strlen(output_buffer));
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    esp_http_client_cleanup(client);
}

#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
static void http_partial_download(void)
{
    esp_http_client_config_t config = {
        .url = "https://dl.espressif.com/dl/esp-idf/ci/esp_http_client_demo.txt",
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    ESP_LOGI(TAG, "HTTP partial download =>");
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // Download a file excluding first 10 bytes
    esp_http_client_set_header(client, "Range", "bytes=10-");
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
    }

    // Download last 10 bytes of a file
    esp_http_client_set_header(client, "Range", "bytes=-10");
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
    }

    // Download 10 bytes from 11 to 20
    esp_http_client_set_header(client, "Range", "bytes=11-20");
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}
#endif // CONFIG_MBEDTLS_CERTIFICATE_BUNDLE

static void http_test_task(void *pvParameters)
{
    http_rest_with_url();
    http_rest_with_hostname_path();
#if CONFIG_ESP_HTTP_CLIENT_ENABLE_BASIC_AUTH
    http_auth_basic();
    http_auth_basic_redirect();
#endif
#if CONFIG_ESP_HTTP_CLIENT_ENABLE_DIGEST_AUTH
    http_auth_digest_md5();
    http_auth_digest_sha256();
#endif
    http_encoded_query();
    http_relative_redirect();
    http_absolute_redirect();
    http_absolute_redirect_manual();
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    https_with_url();
#endif
    https_with_hostname_path();
    http_redirect_to_https();
    http_download_chunk();
    http_perform_as_stream_reader();
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    https_async();
#endif
    https_with_invalid_url();
    http_native_request();
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    http_partial_download();
#endif

    ESP_LOGI(TAG, "Finish http example");
#if !CONFIG_IDF_TARGET_LINUX
    vTaskDelete(NULL);
#endif
}

static void http_test_task_mod(void *pvParameters)
{
    static tHeatgCtrlSt heatgCtrlSt = HEATG_CTRL_ST_INIT;
    static char opMod[64] = {0};  // Static buffer to store operation mode
    memset(opMod, 0, sizeof(opMod));  // Clear buffer before use
    uint8_t tSet = 0;

    while (1)
    {
        //Periodically check status to update visualization
        // //Get control status
        // http_rest_with_url_get_ctrl_sts();

        //Get room temperature
        float roomTemp = 0.0f;
        uint8_t tSnsr = 0u;
        if (xQueueReceive(g_temp_queue, &roomTemp, 0))
        {
            tSnsr = roundint8f(roomTemp);
        }

        switch (heatgCtrlSt)
        {
            case HEATG_CTRL_ST_INIT:
                //Transition action
                if (0 == CONFIG_ENA_REMOTE_CTRL_DEBUG)
                {
                    heatgCtrlSt = HEATG_CTRL_ST_OFF;
                }
                else
                {
                    heatgCtrlSt = HEATG_CTRL_ST_DEBUG;
                }
                break;

            case HEATG_CTRL_ST_OFF:
                //In-state action

                //Check operation mode
                http_rest_with_url_get_op_mod(opMod, sizeof(opMod));
                if (strcmp(opMod, "Weekly program") != 0) {
                    //Post operation mode if not correct
                    http_rest_with_url_post_op_mode("Weekly program");
                    ESP_LOGI(TAG, "Operation mode changed to: Weekly program");
                }

                //Transition action
                if (1 == CONFIG_ENA_REMOTE_CTRL)
                {
                    heatgCtrlSt = HEATG_CTRL_ST_IDLE;
                }
                break;

            case HEATG_CTRL_ST_IDLE:
                //In-state action

                //Check operation mode
                http_rest_with_url_get_op_mod(opMod, sizeof(opMod));
                if (strcmp(opMod, "Control individually") != 0) {
                    //Post operation mode if not correct
                    http_rest_with_url_post_op_mode("Control individually");
                    ESP_LOGI(TAG, "Operation mode changed to: Control individually");
                }

                //Check set temperature
                tSet = http_rest_with_url_get_set_temp(); //Not working the best? Log and check
                ESP_LOGI(TAG, "Set temperature retrieved: %u deg C", tSet);
                //Post set temperature
                if (tSet != 15u)
                {
                    http_rest_with_url_post_set_temp(15u);
                    ESP_LOGI(TAG, "Heater set temperature adjusted to 15 deg C");
                }

                //Transition action
                if (0 == CONFIG_ENA_REMOTE_CTRL)
                {
                    heatgCtrlSt = HEATG_CTRL_ST_OFF;
                }
                else if (tSnsr < CONFIG_T_THRES_LOWR)
                {
                    heatgCtrlSt = HEATG_CTRL_ST_HEATING;
                }
                break;

            case HEATG_CTRL_ST_HEATING:
                //In-state action

                //Check operation mode
                http_rest_with_url_get_op_mod(opMod, sizeof(opMod));
                if (strcmp(opMod, "Control individually") != 0) {
                    //Post operation mode if not correct
                    http_rest_with_url_post_op_mode("Control individually");
                    ESP_LOGI(TAG, "Operation mode changed to: Control individually");
                }

                //Check set temperature
                tSet = http_rest_with_url_get_set_temp();
                ESP_LOGI(TAG, "Set temperature retrieved: %u deg C", tSet);
                //Post set temperature
                if (tSet != 25u)
                {
                    http_rest_with_url_post_set_temp(25u);
                    ESP_LOGI(TAG, "Heater set temperature adjusted to 25 deg C");
                }

                //Transition action
                if (0 == CONFIG_ENA_REMOTE_CTRL)
                {
                    heatgCtrlSt = HEATG_CTRL_ST_OFF;
                }
                else if (tSnsr > CONFIG_T_THRES_UPPR)
                {
                    heatgCtrlSt = HEATG_CTRL_ST_IDLE;
                }
                break;

            case HEATG_CTRL_ST_DEBUG:
                //In-state action

                //Get control status
                http_rest_with_url_get_ctrl_sts();

                //Post operation mode
                http_rest_with_url_post_op_mode("Control individually");
                // http_rest_with_url_post_op_mode("Weekly program");

                //Get control status
                http_rest_with_url_get_ctrl_sts();

                //Post set temperature
                // http_rest_with_url_post_set_temp(15u);
                http_rest_with_url_post_set_temp(25u);

                //Get control status
                http_rest_with_url_get_ctrl_sts();

                // //Transition action
                // heatgCtrlSt = HEATG_CTRL_ST_OFF;
                break;

            case HEATG_CTRL_ST_ERROR:
                //TO DO
                break;

            default:
                //Transition action
                heatgCtrlSt = HEATG_CTRL_ST_OFF;
                break;
        }

        vTaskDelay(CONFIG_DISPLAY_PERIOD / portTICK_PERIOD_MS);
    }
// #if !CONFIG_IDF_TARGET_LINUX
//         vTaskDelete(NULL);
// #endif
}

static bool IRAM_ATTR s_conv_done_cb(adc_continuous_handle_t handle, const adc_continuous_evt_data_t *edata, void *user_data)
{
    BaseType_t mustYield = pdFALSE;
    //Notify that ADC continuous driver has done enough number of conversions
    vTaskNotifyGiveFromISR(s_task_handle, &mustYield);

    return (mustYield == pdTRUE);
}

static void continuous_adc_init(adc_channel_t channel, uint8_t channel_num, adc_continuous_handle_t *out_handle)
{
    adc_continuous_handle_t handle = NULL;

    adc_continuous_handle_cfg_t adc_config = {
        .max_store_buf_size = 1024,
        .conv_frame_size = ADC_READ_LEN,
    };
    ESP_ERROR_CHECK(adc_continuous_new_handle(&adc_config, &handle));

    adc_continuous_config_t dig_cfg = {
        .sample_freq_hz = 20 * 1000,
        .conv_mode = ADC_READ_CONV_MODE,
    };

    adc_digi_pattern_config_t adc_pattern[SOC_ADC_PATT_LEN_MAX] = {0};
    dig_cfg.pattern_num = channel_num;
    for (int i = 0; i < channel_num; i++) {
        adc_pattern[i].atten = ADC_READ_ATTEN;
        adc_pattern[i].channel = channel & 0x7;
        adc_pattern[i].unit = ADC_READ_UNIT;
        adc_pattern[i].bit_width = ADC_READ_BIT_WIDTH;

        ESP_LOGI(TAG, "adc_pattern[%d].atten is :%"PRIx8, i, adc_pattern[i].atten);
        ESP_LOGI(TAG, "adc_pattern[%d].channel is :%"PRIx8, i, adc_pattern[i].channel);
        ESP_LOGI(TAG, "adc_pattern[%d].unit is :%"PRIx8, i, adc_pattern[i].unit);
    }
    dig_cfg.adc_pattern = adc_pattern;
    ESP_ERROR_CHECK(adc_continuous_config(handle, &dig_cfg));

    *out_handle = handle;
}

void adc_read(void *pvParameters)
{
    esp_err_t ret;
    uint32_t ret_num = 0;
    uint8_t result[ADC_READ_LEN] = {0};
    memset(result, 0xcc, ADC_READ_LEN);

    static adc_channel_t channel = ADC_CHANNEL_3;

    adc_continuous_handle_t handle = NULL;
    continuous_adc_init(channel, sizeof(channel) / sizeof(adc_channel_t), &handle);

    adc_continuous_evt_cbs_t cbs = {
        .on_conv_done = s_conv_done_cb,
    };
    ESP_ERROR_CHECK(adc_continuous_register_event_callbacks(handle, &cbs, NULL));
    ESP_ERROR_CHECK(adc_continuous_start(handle));

    while (1)
    {
        /**
         * This is to show you the way to use the ADC continuous mode driver event callback.
         * This `ulTaskNotifyTake` will block when the data processing in the task is fast.
         * However in this example, the data processing (print) is slow, so you barely block here.
         *
         * Without using this event callback (to notify this task), you can still just call
         * `adc_continuous_read()` here in a loop, with/without a certain block timeout.
         */
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        while (1)
        {
            float roomTemp = 0.f;

            ret = adc_continuous_read(handle, result, ADC_READ_LEN, &ret_num, 0);
            if (ret == ESP_OK)
            {
                // ESP_LOGI("TASK", "ret is %x, ret_num is %"PRIu32" bytes", ret, ret_num);

                adc_continuous_data_t parsed_data[ret_num / SOC_ADC_DIGI_RESULT_BYTES];
                uint32_t num_parsed_samples = 0;

                esp_err_t parse_ret = adc_continuous_parse_data(handle, result, ret_num, parsed_data, &num_parsed_samples);
                if (parse_ret == ESP_OK)
                {
                    // for (int i = 0; i < num_parsed_samples; i++)
                    // {
                    //     if (parsed_data[i].valid)
                    //     {
                    //         float roomTemp = (float)(parsed_data[i].raw_data) * 0.1f;

                    //         ESP_LOGI(TAG, "ADC%d, Channel: %d, Room temperature: %.01f",
                    //                  parsed_data[i].unit + 1,
                    //                  parsed_data[i].channel,
                    //                  roomTemp);
                    //     }
                    //     else
                    //     {
                    //         ESP_LOGW(TAG, "Invalid data [ADC%d_Ch%d_%"PRIu32"]",
                    //                  parsed_data[i].unit + 1,
                    //                  parsed_data[i].channel,
                    //                  parsed_data[i].raw_data);
                    //     }
                    // }

                    //Rough reading of just the last data sample
                    if (parsed_data[num_parsed_samples - 1].valid)
                    {
                        roomTemp = (float)(parsed_data[num_parsed_samples - 1].raw_data) * 0.1f;

                        ESP_LOGI(TAG, "ADC%d, Channel: %d, Room temperature: %.01f deg C",
                                    parsed_data[num_parsed_samples - 1].unit + 1,
                                    parsed_data[num_parsed_samples - 1].channel,
                                    roomTemp);
                    }
                    else
                    {
                        ESP_LOGW(TAG, "Invalid data [ADC%d_Ch%d_%"PRIu32"]",
                                    parsed_data[num_parsed_samples - 1].unit + 1,
                                    parsed_data[num_parsed_samples - 1].channel,
                                    parsed_data[num_parsed_samples - 1].raw_data);
                    }
                }
                else
                {
                    ESP_LOGE(TAG, "Data parsing failed: %s", esp_err_to_name(parse_ret));
                }

                xQueueOverwrite(g_temp_queue, &roomTemp);

                /**
                 * Because printing is slow, so every time you call `ulTaskNotifyTake`, it will immediately return.
                 * To avoid a task watchdog timeout, add a delay here. When you replace the way you process the data,
                 * usually you don't need this delay (as this task will block for a while).
                 */
                vTaskDelay(CONFIG_DISPLAY_PERIOD / portTICK_PERIOD_MS);
            }
            else if (ret == ESP_ERR_TIMEOUT)
            {
                //We try to read `ADC_READ_LEN` until API returns timeout, which means there's no available data
                break;
            }
        }
    }

    ESP_ERROR_CHECK(adc_continuous_stop(handle));
    ESP_ERROR_CHECK(adc_continuous_deinit(handle));
}

void app_main(void)
{
    //Memory initialization
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Create a queue to handle task communication
    g_temp_queue = xQueueCreate(1, sizeof(float));

    //Network device task init
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
    ESP_LOGI(TAG, "Connected to AP, begin http example");

#if CONFIG_IDF_TARGET_LINUX
    http_test_task_mod(NULL);
#else
    //Sensor operation on core 1
    xTaskCreatePinnedToCore(&adc_read, "adc_read", 4096, NULL, 3, &s_task_handle, 1);
    //WiFi operation on core 0 - TO DO: Keep reading status and only update command via http task when needed
    xTaskCreatePinnedToCore(&http_test_task_mod, "http_test_task_mod", 8192, NULL, 5, NULL, 0);
#endif
}
