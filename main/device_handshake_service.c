#include "device_handshake_service.h"
#include "device_handshake_http.h"
#include "wifi_service.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "tls_trust_anchor.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"

/* 沿用本工程的本地私有头文件约定；此文件被 Git 忽略。
 * NVS device_boot/config 整条记录优先，绝不混用两套身份的字段。 */
#if __has_include("device_handshake_local_config.h")
#include "device_handshake_local_config.h"
#endif
#ifndef DEVICE_HANDSHAKE_LOCAL_JSON
#define DEVICE_HANDSHAKE_LOCAL_JSON "{\"enabled\":false}"
#endif
#ifndef DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS
#define DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS 300u
#endif
#ifndef DEVICE_HANDSHAKE_WIFI_TOKEN_REUSE_SECONDS
#define DEVICE_HANDSHAKE_WIFI_TOKEN_REUSE_SECONDS 120u
#endif
#ifndef DEVICE_HANDSHAKE_CACHE_MARGIN_SECONDS
#define DEVICE_HANDSHAKE_CACHE_MARGIN_SECONDS 300u
#endif
#ifndef DEVICE_HANDSHAKE_CACHE_UNSYNCED_BEFORE_UNIX_MS
#define DEVICE_HANDSHAKE_CACHE_UNSYNCED_BEFORE_UNIX_MS 1700000000000LL
#endif
#ifndef DEVICE_HANDSHAKE_LOG_WS_TOKEN
#define DEVICE_HANDSHAKE_LOG_WS_TOKEN 0
#endif
_Static_assert(DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS > 0 &&
               DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS <= UINT32_MAX,
               "WebSocket refresh margin must be a positive number of seconds");
_Static_assert(DEVICE_HANDSHAKE_WIFI_TOKEN_REUSE_SECONDS <= DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS,
               "Wi-Fi reuse window must stay inside the token refresh margin");
_Static_assert(DEVICE_HANDSHAKE_CACHE_MARGIN_SECONDS > 0 &&
               DEVICE_HANDSHAKE_CACHE_MARGIN_SECONDS <= UINT32_MAX,
               "Cached credential margin must be a positive number of seconds");
_Static_assert(DEVICE_HANDSHAKE_CACHE_UNSYNCED_BEFORE_UNIX_MS > 0,
               "Unsynced cached credential threshold must be positive");

static const char *TAG = "device_handshake";
#define DEVICE_HANDSHAKE_CACHE_NAMESPACE "device_boot"
#define DEVICE_HANDSHAKE_CACHE_META_KEY "ws_meta_v4"
#define DEVICE_HANDSHAKE_CACHE_MQTT_KEY "ws_mqtt_v4"
#define DEVICE_HANDSHAKE_CACHE_WS_KEY "ws_ws_v4"
#define DEVICE_HANDSHAKE_CACHE_FW_KEY "ws_fw_v4"
#define DEVICE_HANDSHAKE_CACHE_MAGIC 0x44335753u
#define DEVICE_HANDSHAKE_CACHE_VERSION 4u
static device_handshake_config_t *s_config;
static device_handshake_schedule_t s_schedule;
static bool s_initialized, s_pending, s_disabled;
static bool s_preconnect_started;
static QueueHandle_t s_jobs, s_results;
static esp_event_handler_instance_t s_wifi_handler, s_ip_handler;
/* 回调只改变 epoch，不触碰主任务的状态或做网络 I/O。
 * 即使主任务来不及处理一次很短的断线再重连，旧 HTTP 结果也会失效。 */
static atomic_uint s_network_epoch, s_cancel_generation;
static unsigned s_seen_epoch;
static unsigned s_mqtt_epoch;
static int64_t s_last_online_ms;

typedef struct {
    unsigned network_epoch;
    uint32_t generation;
    int64_t acquired_ms; /* 请求开始的单调时间；不是可被校时修改的系统时间。 */
    int64_t acquired_unix_ms; /* 保存凭据时的 UTC 时间，用于跨重启判断 TTL。 */
    bool from_cache;
    device_handshake_config_t config; /* 请求拥有独立副本，refresh 可安全替换主配置。 */
    device_handshake_result_t result;
} handshake_attempt_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    int64_t acquired_unix_ms;
    char device_id[65];
    uint32_t expires_in;
} cached_handshake_blob_t;

typedef struct {
    char server_time[40];
    uint64_t server_time_ms;
    device_mqtt_configuration_t mqtt;
} cached_handshake_mqtt_blob_t;

typedef struct {
    char url[PROTO_WS_URL_MAX + 1];
    char token[PROTO_AUTH_TOKEN_MAX + 1];
} cached_handshake_ws_blob_t;

typedef struct {
    char version[65];
    char url[1025];
} cached_handshake_fw_blob_t;

static handshake_attempt_t *s_snapshot;

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

static int64_t unix_now_ms(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return -1;
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static bool system_time_unsynced(int64_t current_unix_ms)
{
    return current_unix_ms > 0 && current_unix_ms < DEVICE_HANDSHAKE_CACHE_UNSYNCED_BEFORE_UNIX_MS;
}

static void release_attempt(handshake_attempt_t *attempt)
{
    if (!attempt) return;
    device_handshake_wipe(attempt, sizeof(*attempt));
    free(attempt);
}

static void clear_snapshot(void)
{
    release_attempt(s_snapshot);
    s_snapshot = NULL;
}

static bool cached_credentials_valid(const device_handshake_response_t *response,
                                     int64_t acquired_unix_ms,
                                     bool allow_unsynced)
{
    if (!response || !response->websocket.url[0] || !response->websocket.token[0] ||
        acquired_unix_ms <= 0 || response->websocket.expires_in == 0) return false;
    int64_t current_unix_ms = unix_now_ms();
    int64_t remaining = device_handshake_token_remaining_ms(
        response->websocket.expires_in, acquired_unix_ms, current_unix_ms);
    if (allow_unsynced && system_time_unsynced(current_unix_ms) &&
        current_unix_ms < acquired_unix_ms) {
        remaining = (int64_t)response->websocket.expires_in * 1000;
    }
    return remaining >= (int64_t)DEVICE_HANDSHAKE_CACHE_MARGIN_SECONDS * 1000;
}

void device_handshake_service_clear_cached_credentials(void)
{
    nvs_handle_t handle = 0;
    if (nvs_open(DEVICE_HANDSHAKE_CACHE_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return;
    nvs_erase_key(handle, DEVICE_HANDSHAKE_CACHE_META_KEY);
    nvs_erase_key(handle, DEVICE_HANDSHAKE_CACHE_MQTT_KEY);
    nvs_erase_key(handle, DEVICE_HANDSHAKE_CACHE_WS_KEY);
    nvs_erase_key(handle, DEVICE_HANDSHAKE_CACHE_FW_KEY);
    nvs_commit(handle);
    nvs_close(handle);
}

static void save_cached_credentials(const handshake_attempt_t *attempt)
{
    if (!attempt || !attempt->result.success || !s_config || attempt->from_cache) return;
    const device_handshake_response_t *response = &attempt->result.response;
    if (strcmp(s_config->device_id, response->mqtt.username) != 0 ||
        !device_handshake_id_valid(response->mqtt.username)) return;
    if (response->server_time_ms <= 0) return;
    int64_t acquired_unix_ms = response->server_time_ms;
    if (!cached_credentials_valid(response, acquired_unix_ms, false)) {
        ESP_LOGW(TAG, "Cached credentials skipped: server time token window too short");
        return;
    }
    cached_handshake_blob_t blob = {
        .magic = DEVICE_HANDSHAKE_CACHE_MAGIC,
        .version = DEVICE_HANDSHAKE_CACHE_VERSION,
        .acquired_unix_ms = acquired_unix_ms,
        .expires_in = response->websocket.expires_in,
    };
    snprintf(blob.device_id, sizeof(blob.device_id), "%s", s_config->device_id);
    cached_handshake_mqtt_blob_t mqtt_blob = {0};
    snprintf(mqtt_blob.server_time, sizeof(mqtt_blob.server_time), "%s", response->server_time);
    mqtt_blob.server_time_ms = (uint64_t)response->server_time_ms;
    mqtt_blob.mqtt = response->mqtt;
    cached_handshake_ws_blob_t ws_blob = {0};
    snprintf(ws_blob.url, sizeof(ws_blob.url), "%s", response->websocket.url);
    snprintf(ws_blob.token, sizeof(ws_blob.token), "%s", response->websocket.token);
    cached_handshake_fw_blob_t fw_blob = {0};
    snprintf(fw_blob.version, sizeof(fw_blob.version), "%s", response->firmware.version);
    snprintf(fw_blob.url, sizeof(fw_blob.url), "%s", response->firmware.url);
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(DEVICE_HANDSHAKE_CACHE_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Cache open failed: %s", esp_err_to_name(err));
        return;
    }
    err = nvs_set_blob(handle, DEVICE_HANDSHAKE_CACHE_META_KEY, &blob, sizeof(blob));
    if (err == ESP_OK) err = nvs_set_blob(handle, DEVICE_HANDSHAKE_CACHE_MQTT_KEY, &mqtt_blob, sizeof(mqtt_blob));
    if (err == ESP_OK) err = nvs_set_blob(handle, DEVICE_HANDSHAKE_CACHE_WS_KEY, &ws_blob, sizeof(ws_blob));
    if (err == ESP_OK) err = nvs_set_blob(handle, DEVICE_HANDSHAKE_CACHE_FW_KEY, &fw_blob, sizeof(fw_blob));
    if (err == ESP_OK) {
        esp_err_t commit_err = nvs_commit(handle);
        if (commit_err != ESP_OK) err = commit_err;
    }
    nvs_close(handle);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Cached WS/MQTT credentials for cold-start preconnect");
    else
        ESP_LOGW(TAG, "Cache write failed: blob=%u bytes, %s",
                 (unsigned)(sizeof(blob) + sizeof(mqtt_blob) + sizeof(ws_blob) + sizeof(fw_blob)),
                 esp_err_to_name(err));
}

static bool load_cached_credentials(handshake_attempt_t **attempt_out)
{
    if (!attempt_out) return false;
    nvs_handle_t handle = 0;
    if (nvs_open(DEVICE_HANDSHAKE_CACHE_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) return false;
    cached_handshake_blob_t blob = {0};
    cached_handshake_mqtt_blob_t mqtt_blob = {0};
    cached_handshake_ws_blob_t ws_blob = {0};
    cached_handshake_fw_blob_t fw_blob = {0};
    size_t meta_len = sizeof(blob), mqtt_len = sizeof(mqtt_blob);
    size_t ws_len = sizeof(ws_blob), fw_len = sizeof(fw_blob);
    esp_err_t err = nvs_get_blob(handle, DEVICE_HANDSHAKE_CACHE_META_KEY, &blob, &meta_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, DEVICE_HANDSHAKE_CACHE_MQTT_KEY, &mqtt_blob, &mqtt_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, DEVICE_HANDSHAKE_CACHE_WS_KEY, &ws_blob, &ws_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, DEVICE_HANDSHAKE_CACHE_FW_KEY, &fw_blob, &fw_len);
    nvs_close(handle);
    if (err != ESP_OK || meta_len != sizeof(blob) || mqtt_len != sizeof(mqtt_blob) ||
        ws_len != sizeof(ws_blob) || fw_len != sizeof(fw_blob)) {
        return false;
    }
    handshake_attempt_t *attempt = device_handshake_alloc(sizeof(*attempt));
    if (!attempt) {
        device_handshake_wipe(&mqtt_blob, sizeof(mqtt_blob));
        device_handshake_wipe(&ws_blob, sizeof(ws_blob));
        return false;
    }
    bool ok = blob.magic == DEVICE_HANDSHAKE_CACHE_MAGIC &&
              blob.version == DEVICE_HANDSHAKE_CACHE_VERSION &&
              s_config && blob.device_id[0] &&
              strcmp(blob.device_id, s_config->device_id) == 0 &&
              strcmp(mqtt_blob.mqtt.username, s_config->device_id) == 0 &&
              ws_blob.url[0] && ws_blob.token[0] && blob.expires_in &&
              device_handshake_id_valid(mqtt_blob.mqtt.username);
    if (ok) {
        memset(attempt, 0, sizeof(*attempt));
        attempt->result.success = true;
        attempt->result.reason = "cached_credentials";
        attempt->result.response.server_time_ms = (int64_t)mqtt_blob.server_time_ms;
        snprintf(attempt->result.response.server_time,
                 sizeof(attempt->result.response.server_time), "%s", mqtt_blob.server_time);
        attempt->result.response.mqtt = mqtt_blob.mqtt;
        snprintf(attempt->result.response.websocket.url,
                 sizeof(attempt->result.response.websocket.url), "%s", ws_blob.url);
        snprintf(attempt->result.response.websocket.token,
                 sizeof(attempt->result.response.websocket.token), "%s", ws_blob.token);
        attempt->result.response.websocket.expires_in = blob.expires_in;
        snprintf(attempt->result.response.firmware.version,
                 sizeof(attempt->result.response.firmware.version), "%s", fw_blob.version);
        snprintf(attempt->result.response.firmware.url,
                 sizeof(attempt->result.response.firmware.url), "%s", fw_blob.url);
        attempt->acquired_unix_ms = blob.acquired_unix_ms;
        attempt->from_cache = true;
        attempt->network_epoch = atomic_load(&s_network_epoch);
        attempt->generation = s_schedule.generation;
        ok = cached_credentials_valid(&attempt->result.response, blob.acquired_unix_ms, true);
    }
    device_handshake_wipe(&mqtt_blob, sizeof(mqtt_blob));
    device_handshake_wipe(&ws_blob, sizeof(ws_blob));
    if (!ok) {
        release_attempt(attempt);
        return false;
    }
    attempt->acquired_ms = now_ms();
    *attempt_out = attempt;
    return true;
}

static void on_network_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)data;
    if ((base == WIFI_EVENT && (id == WIFI_EVENT_STA_DISCONNECTED || id == WIFI_EVENT_STA_STOP)) ||
        (base == IP_EVENT && (id == IP_EVENT_STA_GOT_IP || id == IP_EVENT_STA_LOST_IP)))
        atomic_fetch_add(&s_network_epoch, 1);
}

static bool snapshot_token_usable(bool require_fresh_network)
{
    if (!s_snapshot || s_schedule.blocked || !s_snapshot->result.success) return false;
    if (require_fresh_network && !s_snapshot->from_cache &&
        s_seen_epoch != atomic_load(&s_network_epoch)) return false;
    int64_t remaining;
    if (s_snapshot->from_cache) {
        int64_t current_unix_ms = unix_now_ms();
        remaining = device_handshake_token_remaining_ms(
            s_snapshot->result.response.websocket.expires_in,
            s_snapshot->acquired_unix_ms, current_unix_ms);
        if (system_time_unsynced(current_unix_ms) &&
            current_unix_ms < s_snapshot->acquired_unix_ms) {
            remaining = (int64_t)s_snapshot->result.response.websocket.expires_in * 1000;
        }
    } else {
        remaining = device_handshake_token_remaining_ms(
            s_snapshot->result.response.websocket.expires_in,
            s_snapshot->acquired_ms, now_ms());
    }
    return remaining >= (int64_t)DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS * 1000;
}

/* 独立 namespace 是平台出厂身份；不读写 korvo_cfg/device_id（旧 YMOS 身份）。
 * NVS 错误必须显式失败，不能默默退回固件内的另一台设备凭据。 */
static esp_err_t load_config(device_handshake_config_t *config)
{
    char *json = device_handshake_alloc(DEVICE_HANDSHAKE_CONFIG_MAX + 1);
    if (!json) return ESP_ERR_NO_MEM;
    const char *reason = "nvs_read_failed";
    const char *source = "NVS";
    nvs_handle_t handle = 0;
    size_t len = 0;
    esp_err_t err = nvs_open("device_boot", NVS_READONLY, &handle);
    if (err == ESP_OK) {
        err = nvs_get_str(handle, "config", NULL, &len);
        if (err == ESP_OK) {
            if (len < 2 || len > DEVICE_HANDSHAKE_CONFIG_MAX + 1) err = ESP_ERR_INVALID_SIZE;
            else err = nvs_get_str(handle, "config", json, &len);
        }
        nvs_close(handle);
    }
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        source = "local default";
        len = sizeof(DEVICE_HANDSHAKE_LOCAL_JSON);
        if (len > DEVICE_HANDSHAKE_CONFIG_MAX + 1) err = ESP_ERR_INVALID_SIZE;
        else { memcpy(json, DEVICE_HANDSHAKE_LOCAL_JSON, len); err = ESP_OK; }
    }
    if (err == ESP_OK && (len < 2 || json[len - 1] != 0 || strlen(json) + 1 != len))
        err = ESP_ERR_INVALID_SIZE;
    if (err == ESP_OK && !device_handshake_parse_config(json, len - 1, config, &reason))
        err = ESP_ERR_INVALID_ARG;
    device_handshake_wipe(json, DEVICE_HANDSHAKE_CONFIG_MAX + 1);
    free(json);
    if (err != ESP_OK) ESP_LOGE(TAG, "Configuration blocked: %s (%s)", reason, esp_err_to_name(err));
    else ESP_LOGI(TAG, "%s via %s", config->enabled ? "Configured; waiting for Wi-Fi" : "Disabled", source);
    return err;
}

typedef struct {
    handshake_attempt_t *attempt;
    esp_http_client_handle_t client;
} handshake_http_context_t;

static bool http_cancelled(void *context)
{
    handshake_attempt_t *attempt = ((handshake_http_context_t *)context)->attempt;
    return attempt->network_epoch != atomic_load(&s_network_epoch) ||
           attempt->generation != atomic_load(&s_cancel_generation);
}

static int64_t http_now_ms(void *context) { (void)context; return now_ms(); }

static bool http_begin(void *context, const char *url, const device_handshake_header_t *headers,
                       size_t count, const char *body, int *status, int64_t *content_length)
{
    handshake_http_context_t *http = context;
    handshake_attempt_t *attempt = http->attempt;
    int64_t step_start = now_ms();
    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 5000,
        .disable_auto_redirect = true,
        .keep_alive_enable = false,
        .buffer_size = 1024,
        .buffer_size_tx = 1024,
#ifdef DEVICE_PLATFORM_TLS_CA
        .crt_bundle_attach = NULL,
        .cert_pem = tls_trust_anchor_ca_pem(),
#else
        .crt_bundle_attach = esp_crt_bundle_attach,
#endif
    };
    http->client = esp_http_client_init(&config);
    if (!http->client) return false;
    for (size_t i = 0; i < count; ++i)
        if (esp_http_client_set_header(http->client, headers[i].name, headers[i].value) != ESP_OK)
            return false;
    attempt->result.init_ms = now_ms() - step_start;
    step_start = now_ms();
    if (http_cancelled(context) || esp_http_client_open(http->client, (int)strlen(body)) != ESP_OK)
        return false;
    attempt->result.open_ms = now_ms() - step_start;
    step_start = now_ms();
    size_t sent = 0, body_len = strlen(body);
    while (sent < body_len) {
        if (http_cancelled(context)) return false;
        int n = esp_http_client_write(http->client, body + sent, (int)(body_len - sent));
        if (n <= 0 || (size_t)n > body_len - sent) return false;
        sent += (size_t)n;
    }
    attempt->result.write_ms = now_ms() - step_start;
    step_start = now_ms();
    if (http_cancelled(context)) return false;
    int64_t length = esp_http_client_fetch_headers(http->client);
    attempt->result.headers_ms = now_ms() - step_start;
    if (length < 0) return false;
    *status = esp_http_client_get_status_code(http->client);
    /* chunked/关闭连接定界时长度未知；不能将 fetch_headers 的 0 当作空 body。 */
    *content_length = esp_http_client_is_chunked_response(http->client) ? -1 :
                      esp_http_client_get_content_length(http->client);
    return *status >= 100;
}

static int http_read(void *context, char *buffer, size_t size)
{
    return esp_http_client_read(((handshake_http_context_t *)context)->client, buffer, (int)size);
}

static bool http_complete(void *context)
{
    return esp_http_client_is_complete_data_received(((handshake_http_context_t *)context)->client);
}

static void http_close(void *context)
{
    handshake_http_context_t *http = context;
    if (http->client) esp_http_client_cleanup(http->client);
    http->client = NULL;
}

static void handshake_worker(void *arg)
{
    (void)arg;
    while (1) {
        handshake_attempt_t *attempt = NULL;
        if (xQueueReceive(s_jobs, &attempt, portMAX_DELAY) != pdTRUE) continue;
        handshake_http_context_t context = { .attempt = attempt };
        device_handshake_http_t http = {
            .context = &context, .begin = http_begin, .read = http_read,
            .complete = http_complete, .close = http_close,
            .cancelled = http_cancelled, .now_ms = http_now_ms,
        };
        char mac[18] = {0};
        wifi_service_get_mac_str(mac, sizeof(mac), ESP_MAC_WIFI_STA);
        wifi_service_set_net_active(true);
        device_handshake_exchange(&http, &attempt->config, esp_app_get_description()->version,
                                   mac, &attempt->result);
        wifi_service_set_net_active(false);
        device_handshake_wipe(&attempt->config, sizeof(attempt->config));
        /* 只有一个 outstanding 请求，队列长度 1；结果发布时 HTTP 已彻底释放。
         * 所有权从 worker 转给 main_task，生产者之后不得访问 attempt。 */
        xQueueSend(s_results, &attempt, portMAX_DELAY);
    }
}

static bool ensure_worker(void)
{
    if (s_jobs) return true;
    s_jobs = xQueueCreate(1, sizeof(handshake_attempt_t *));
    s_results = xQueueCreate(1, sizeof(handshake_attempt_t *));
    if (s_jobs && s_results &&
        xTaskCreatePinnedToCore(handshake_worker, "device_http", 8192, NULL, 2, NULL, 0) == pdPASS)
        return true;
    if (s_jobs) vQueueDelete(s_jobs);
    if (s_results) vQueueDelete(s_results);
    s_jobs = s_results = NULL;
    return false;
}

esp_err_t device_handshake_service_refresh(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    handshake_attempt_t *cached = s_snapshot && s_snapshot->from_cache ? s_snapshot : NULL;
    if (cached) s_snapshot = NULL;
    ++s_mqtt_epoch;
    s_disabled = false; /* 读取失败必须阻止语音，不能回退到旧 key。 */
    device_handshake_refresh(&s_schedule);
    atomic_store(&s_cancel_generation, s_schedule.generation);
    if (cached) release_attempt(cached);
    else clear_snapshot();
    if (!s_config) s_config = device_handshake_alloc(sizeof(*s_config));
    if (!s_config) { s_schedule.blocked = true; return ESP_ERR_NO_MEM; }
    device_handshake_wipe(s_config, sizeof(*s_config));
    esp_err_t err = load_config(s_config);
    s_disabled = err == ESP_OK && !s_config->enabled;
    if (err != ESP_OK) s_schedule.blocked = true;
    if (err != ESP_OK || !s_config->enabled) {
        device_handshake_wipe(s_config, sizeof(*s_config));
        free(s_config);
        s_config = NULL;
        if (s_snapshot) { release_attempt(s_snapshot); s_snapshot = NULL; }
    }
    return err;
}

esp_err_t device_handshake_service_init(void)
{
    if (s_initialized) return ESP_OK;
    esp_err_t err = esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        on_network_event, NULL, &s_wifi_handler);
    if (err != ESP_OK) return err;
    err = esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID,
                                              on_network_event, NULL, &s_ip_handler);
    if (err != ESP_OK) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, s_wifi_handler);
        return err;
    }
    /* IDF HTTP_CLIENT 的 DEBUG 会输出请求头；避免 PSK 随调试日志泄露。 */
    esp_log_level_set("HTTP_CLIENT", ESP_LOG_INFO);
    s_initialized = true;
    err = device_handshake_service_refresh();
    if (err != ESP_OK || !s_config || !s_config->enabled) return err;
    if (load_cached_credentials(&s_snapshot)) {
        s_schedule.ready = true;
        atomic_store(&s_cancel_generation, s_schedule.generation);
        s_last_online_ms = now_ms();
        ESP_LOGI(TAG, "Loaded cached credentials from NVS (WS/MQTT ready for fast preconnect)");
    }
    return err;
}

const device_handshake_response_t *device_handshake_service_get_configuration(void)
{
    if (!s_snapshot) return NULL;
    if (s_snapshot->from_cache) {
        if (!snapshot_token_usable(false)) return NULL;
        return &s_snapshot->result.response;
    }
    if (!s_schedule.online) return NULL;
    bool fresh_network = s_snapshot->from_cache ||
                         s_seen_epoch == atomic_load(&s_network_epoch);
    if (!snapshot_token_usable(false)) return NULL;
    if (!s_schedule.ready) {
        if (!fresh_network) return NULL;
        if (now_ms() - s_last_online_ms > (int64_t)DEVICE_HANDSHAKE_WIFI_TOKEN_REUSE_SECONDS * 1000)
            return NULL;
        ESP_LOGW(TAG, "Reusing cached credentials during HTTP refresh (remaining window=%lld s)",
                 (long long)((now_ms() - s_snapshot->acquired_ms) / 1000));
    }
    return &s_snapshot->result.response;
}

bool device_handshake_service_is_enabled(void) { return !s_disabled; }
bool device_handshake_service_is_blocked(void) { return !s_initialized || s_schedule.blocked; }
unsigned device_handshake_service_mqtt_epoch(void) { return s_mqtt_epoch; }

bool device_handshake_service_renew_credentials(void)
{
    if (!s_initialized || s_disabled || !device_handshake_renew(&s_schedule)) return false;
    atomic_store(&s_cancel_generation, s_schedule.generation);
    clear_snapshot();
    return true;
}

device_ws_readiness_t device_handshake_service_prepare_websocket(
    const device_handshake_response_t **configuration)
{
    if (!configuration) return DEVICE_WS_BLOCKED;
    *configuration = NULL;
    if (!s_initialized) return DEVICE_WS_BLOCKED;
    if (s_disabled) return DEVICE_WS_DISABLED;
    if (!s_config || s_schedule.blocked) return DEVICE_WS_BLOCKED;
    bool cached = s_snapshot && s_snapshot->from_cache;
    const device_handshake_response_t *ready = device_handshake_service_get_configuration();
    if (!ready) return DEVICE_WS_WAITING;
    if (cached) {
        if (strcmp(s_config->device_id, ready->mqtt.username) != 0) {
            device_handshake_service_clear_cached_credentials();
            clear_snapshot();
            return DEVICE_WS_WAITING;
        }
        if (!cached_credentials_valid(ready, s_snapshot->acquired_unix_ms, true)) {
            device_handshake_service_clear_cached_credentials();
            clear_snapshot();
            device_handshake_service_renew_credentials();
            return DEVICE_WS_WAITING;
        }
        int64_t unix_remaining = device_handshake_token_remaining_ms(
            ready->websocket.expires_in, s_snapshot->acquired_unix_ms, unix_now_ms());
        if (unix_remaining < 0) unix_remaining = ready->websocket.expires_in * 1000;
        ESP_LOGI(TAG, "Using cached WS credentials for fast preconnect (remaining=%lld s)",
                 (long long)(unix_remaining / 1000));
    } else {
        int64_t remaining = device_handshake_token_remaining_ms(
            ready->websocket.expires_in, s_snapshot->acquired_ms, now_ms());
        if (remaining < (int64_t)DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS * 1000) {
            ESP_LOGI(TAG, "WebSocket token near expiry (%lld s); renewing before connect",
                     (long long)(remaining / 1000));
            device_handshake_service_renew_credentials();
            return DEVICE_WS_WAITING;
        }
    }
    *configuration = ready;
    return DEVICE_WS_READY;
}

void device_handshake_service_poll(bool network_available)
{
    if (!s_initialized) return;
    unsigned epoch = atomic_load(&s_network_epoch);
    if (network_available) s_last_online_ms = now_ms();
    if (epoch != s_seen_epoch || network_available != s_schedule.online) {
        ++s_mqtt_epoch;
        s_seen_epoch = epoch;
        device_handshake_network_changed(&s_schedule, network_available);
        atomic_store(&s_cancel_generation, s_schedule.generation);
        /* 短时 Wi-Fi 抖动不清除仍有效的快照：D3 可先用缓存 token 建 WSS 预连接，
         * 同时后台继续 HTTP 刷新。永久错误的结果仍要清掉，防止误用旧凭据。 */
        if (s_schedule.blocked) clear_snapshot();
        if (!network_available) s_preconnect_started = false;
    }
    handshake_attempt_t *finished = NULL;
    if (s_results && xQueueReceive(s_results, &finished, 0) == pdTRUE) {
        s_pending = false;
        device_handshake_result_t *result = &finished->result;
        /* 新发 token 已不足安全窗口时停止并明确报错，避免 HTTP 200 续期风暴。 */
        if (result->success && device_handshake_token_remaining_ms(
                result->response.websocket.expires_in, finished->acquired_ms, now_ms()) <
                (int64_t)DEVICE_HANDSHAKE_WS_REFRESH_MARGIN_SECONDS * 1000) {
            result->success = false;
            result->reason = "websocket_token_lifetime_too_short";
        }
        bool current = finished->network_epoch == atomic_load(&s_network_epoch) &&
                       device_handshake_complete(&s_schedule, finished->generation,
                                                  result->status, result->success, now_ms());
        if (!current) ESP_LOGI(TAG, "Discarded obsolete HTTP result");
        else if (result->success) {
            clear_snapshot();
            s_snapshot = finished;
            struct timeval tv = {
                .tv_sec = result->response.server_time_ms / 1000,
                .tv_usec = (result->response.server_time_ms % 1000) * 1000,
            };
            if (settimeofday(&tv, NULL) != 0) ESP_LOGW(TAG, "Server time could not be applied");
            save_cached_credentials(finished);
            ESP_LOGI(TAG, "HTTP handshake ready; MQTT/WS configuration validated (RAM only); WS token TTL=%lu s",
                     (unsigned long)result->response.websocket.expires_in);
            ESP_LOGI(TAG, "HTTP handshake timing: connect=%lld ms read=%lld ms queue=%lld ms total=%lld ms",
                     (long long)result->connect_ms, (long long)result->read_ms,
                     (long long)(now_ms() - finished->acquired_ms -
                                 result->connect_ms - result->read_ms),
                     (long long)(now_ms() - finished->acquired_ms));
            ESP_LOGI(TAG,
                     "HTTP connect detail: init=%lld ms open=%lld ms write=%lld ms headers=%lld ms",
                     (long long)result->init_ms, (long long)result->open_ms,
                     (long long)result->write_ms, (long long)result->headers_ms);
#if DEVICE_HANDSHAKE_LOG_WS_TOKEN
            /* 用户显式要求的串口联调诊断；仅私有配置开启，量产必须关闭。
             * 每次成功握手打印一次，绝不输出 PSK、MQTT password 或完整响应。 */
            ESP_LOGW(TAG, "DEV ONLY websocket.token=%s", result->response.websocket.token);
#endif
        } else if (s_schedule.blocked) {
            device_handshake_service_clear_cached_credentials();
            ESP_LOGE(TAG, "HTTP %d: %s; stopped until explicit configuration refresh/reboot",
                     result->status, result->reason);
        } else {
            ESP_LOGW(TAG, "HTTP %d: %s; retry in %u ms", result->status, result->reason,
                     device_handshake_retry_delay_ms(s_schedule.failures));
        }
        if (finished != s_snapshot) release_attempt(finished);
    }
    if (!s_config || !s_config->enabled || s_pending || !device_handshake_due(&s_schedule, now_ms()))
        return;
    if (!s_preconnect_started && s_snapshot && s_snapshot->from_cache)
        s_preconnect_started = true;
    if (s_preconnect_started) {
        device_handshake_refresh(&s_schedule);
        atomic_store(&s_cancel_generation, s_schedule.generation);
    }
    handshake_attempt_t *attempt = ensure_worker() ? device_handshake_alloc(sizeof(*attempt)) : NULL;
    if (!attempt) {
        device_handshake_complete(&s_schedule, s_schedule.generation, 0, false, now_ms());
        ESP_LOGW(TAG, "HTTP worker allocation failed; retry in %u ms",
                 device_handshake_retry_delay_ms(s_schedule.failures));
        return;
    }
    attempt->config = *s_config;
    attempt->generation = s_schedule.generation;
    attempt->acquired_ms = now_ms();
    attempt->acquired_unix_ms = unix_now_ms();
    attempt->network_epoch = s_seen_epoch;
    if (xQueueSend(s_jobs, &attempt, 0) != pdTRUE) {
        release_attempt(attempt);
        device_handshake_complete(&s_schedule, s_schedule.generation, 0, false, now_ms());
        return;
    }
    s_pending = true;
    ESP_LOGI(TAG, "HTTP handshake started");
}
