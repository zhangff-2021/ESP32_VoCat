#include "ws_service.h"
#include "audio_out.h"
#include "proto_service.h"
#include "ws_rx_policy.h"
#include "event_bus.h"
#include "cfg_service.h"
#include "board_config.h"
#include "esp_crt_bundle.h"
#include "tls_trust_anchor.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "psa/crypto.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

static const char *TAG = "ws_service";
static esp_websocket_client_handle_t client;
static atomic_int state = WS_STATE_DISCONNECTED;
static atomic_uint generation = 1;
static bool client_started;
static bool preconnect_auth_sent;
static uint32_t preconnect_expires_in;
static proto_ws_credentials_t *credentials; /* 主任务设置；RX 仅在 playback_lock 下读取。 */
static bool credentials_from_handshake;
static uint8_t *frame;
static size_t frame_size, received;
static int opcode;
static QueueHandle_t rx_queue;
static SemaphoreHandle_t playback_lock;
static TaskHandle_t rx_task;
static uint32_t rx_drop_count;
static atomic_size_t rx_bytes;
static uint32_t played_frames, queue_wait_max_ms; /* playback_lock / worker */
static atomic_uint rx_audio_packets, rx_audio_last_ms, rx_audio_gap_max_ms;
static atomic_uint rx_packet_sequence;
/* 主任务只读取短快照，不等待解码/PCM 背压，也不依赖事件总线容量。 */
static portMUX_TYPE speech_lock = portMUX_INITIALIZER_UNLOCKED;
static ws_speech_status_t speech_status;
static bool speech_sequence_seen;
static uint32_t speech_sequence;
/* 任务编号只用于首次鉴权；连接后的收发路径与普通会话相同。 */
static char reminder_device_id[65];
static char reminder_task_ids[PROTO_REMINDER_TASK_IDS_MAX][129];
static size_t reminder_task_count;
static char transfer_device_id[65];
static char transfer_join_ticket[PROTO_TRANSFER_TICKET_MAX + 1];
static bool transfer_prepared;
typedef struct {
    uint8_t *data;
    size_t len;
    int opcode;
    uint32_t generation;
    uint32_t received_ms;
    uint32_t sequence;
} rx_frame_t;

/* 完整 WS 消息重组后记录供数间隔；没有按回答轮次关闭的接收窗口。 */
static void observe_rx_packet(rx_frame_t *packet)
{
    packet->received_ms = (uint32_t)(esp_timer_get_time() / 1000);
    packet->sequence = atomic_fetch_add(&rx_packet_sequence, 1) + 1;
    if (packet->opcode != 2) return;
    uint32_t previous = atomic_exchange(&rx_audio_last_ms, packet->received_ms);
    uint32_t sequence = atomic_fetch_add(&rx_audio_packets, 1);
    uint32_t gap = packet->received_ms - previous;
    if (sequence && previous && gap > atomic_load(&rx_audio_gap_max_ms))
        atomic_store(&rx_audio_gap_max_ms, gap);
}

static void publish(app_event_id_t id, uint32_t gen)
{
    /* Integer generation tag, not a borrowed pointer. */
    if (gen == atomic_load(&generation))
        event_bus_publish(id, (void *)(uintptr_t)gen, 0);
}
uint32_t ws_service_generation(void) { return atomic_load(&generation); }
static bool current(const rx_frame_t *packet)
{
    return packet->generation == atomic_load(&generation) &&
           (state == WS_STATE_CONNECTED || state == WS_STATE_AUTHING);
}

static void reset_speech_status(void)
{
    portENTER_CRITICAL(&speech_lock);
    speech_status = (ws_speech_status_t){0};
    speech_sequence_seen = false;
    portEXIT_CRITICAL(&speech_lock);
}

void ws_service_get_speech_status(ws_speech_status_t *status)
{
    if (!status) return;
    portENTER_CRITICAL(&speech_lock);
    *status = speech_status;
    portEXIT_CRITICAL(&speech_lock);
}

static bool observe_speech_event(proto_event_t event, const rx_frame_t *packet)
{
    bool started = event == PROTO_EVT_SPEECH_STARTED;
    if (!started && event != PROTO_EVT_SPEECH_STOPPED) return false;
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    bool changed = false, consumed = false;
    portENTER_CRITICAL(&speech_lock);
    if (packet->generation == atomic_load(&generation) && state == WS_STATE_CONNECTED) {
        consumed = true;
        /* 认证期间已排队的旧事件不得覆盖接收快通道处理的新事件。 */
        if (!speech_sequence_seen || (int32_t)(packet->sequence - speech_sequence) > 0) {
            speech_sequence_seen = true;
            speech_sequence = packet->sequence;
            /* 首次 stop 也记录：auth 后的 start 可能还在旧队列里。
             * 已有 stop 且仍未开始新讲话时，重复 stop 不续期。 */
            if (speech_status.speaking != started || (!started && !speech_status.stopped_ms)) {
                speech_status.speaking = started;
                if (!started) speech_status.stopped_ms = now ? now : UINT32_MAX;
                changed = true;
            }
        }
    }
    portEXIT_CRITICAL(&speech_lock);
    if (changed) ESP_LOGI(TAG, "Platform speech %s; idle timer %s",
                         started ? "started" : "stopped",
                         started ? "paused" : "eligible after downlink silence");
    return consumed;
}

/* 仅在连接生命周期边界采样，不逐音频帧扫描堆。按内存能力分别记录最大
 * 连续块与总量，避免把“PSRAM 充足”误当成“内部 RAM 足够建立 TLS”。
 * minimum_free_bytes 是开机以来的低水位；不同阶段快照用于实板判断泄漏/碎片。 */
static void log_connection_memory(const char *phase)
{
    multi_heap_info_t internal, external;
    heap_caps_get_info(&internal, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    heap_caps_get_info(&external, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    ESP_LOGI(TAG, "Connection heap [%s]: internal free=%u largest=%u min=%u; PSRAM free=%u largest=%u min=%u",
             phase, (unsigned)internal.total_free_bytes, (unsigned)internal.largest_free_block,
             (unsigned)internal.minimum_free_bytes, (unsigned)external.total_free_bytes,
             (unsigned)external.largest_free_block, (unsigned)external.minimum_free_bytes);
}

/* 仅在鉴权发送前计算一次，输入就是本次将发送的 token，而非固件默认值。
 * 只记录长度和 SHA-256 指纹；不输出密钥原文/鉴权 JSON，也不改变鉴权结果。
 * ESP-IDF 6.1 在系统启动时初始化 PSA；诊断失败只告警，不阻断原有语音流程。 */
static void log_auth_token_fingerprint(const char *token, const char *source)
{
    uint8_t digest[32];
    size_t digest_len = 0, token_len = strlen(token);
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)token,
                                          token_len, digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS || digest_len != sizeof(digest)) {
        ESP_LOGW(TAG, "Auth token fingerprint unavailable (status=%ld)", (long)status);
        return;
    }
    static const char hex[] = "0123456789abcdef";
    char fingerprint[sizeof(digest) * 2 + 1];
    for (size_t i = 0; i < sizeof(digest); ++i) {
        fingerprint[i * 2] = hex[digest[i] >> 4];
        fingerprint[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    fingerprint[sizeof(fingerprint) - 1] = '\0';
    ESP_LOGI(TAG, "Auth token: source=%s len=%u sha256=%s",
             source, (unsigned)token_len, fingerprint);
}

static void log_transport_error(const char *phase, const esp_websocket_event_data_t *event)
{
    if (!event) return;
    const esp_websocket_error_codes_t *error = &event->error_handle;
    /* 组件 1.8 的 ERROR 可能先于设置 TCP 错误类型；非 TCP 事件的 TLS/errno
     * 字段未初始化，禁止读取。随后 DISCONNECTED 才可能携带有效传输详情。
     * 不输出 data_ptr，避免组件错误文本带出请求头或凭据。 */
    if (error->error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
        ESP_LOGW(TAG, "Transport detail [%s]: socket=%d tls=0x%x stack=%d verify=0x%x http=%d",
                 phase, error->esp_transport_sock_errno, error->esp_tls_last_esp_err,
                 error->esp_tls_stack_err, error->esp_tls_cert_verify_flags,
                 error->esp_ws_handshake_status_code);
    } else if (error->error_type != WEBSOCKET_ERROR_TYPE_NONE) {
        ESP_LOGW(TAG, "Transport detail [%s]: type=%d close=%d",
                 phase, error->error_type, event->close_status_code);
    }
}

static void log_server_error(const proto_msg_t *msg)
{
    /* Do not dump JSON: the server may echo auth/input frames. */
    char message[193] = {0}, secret[256];
    size_t len = msg->error_msg_len > 0 ? (size_t)msg->error_msg_len : 0;
    if (len >= sizeof(message)) len = sizeof(message) - 1;
    if (len) memcpy(message, msg->error_msg, len);
    /* 提醒错误可能回显含 token 的 auth；只保留错误码。 */
    bool sensitive = reminder_task_count || transfer_prepared || strstr(message, "sk-") ||
                     strstr(message, "password") || strstr(message, "Bearer");
    const cfg_key_t keys[] = { CFG_KEY_ACOS_TOKEN, CFG_KEY_WIFI_PASSWORD };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        cfg_service_get_str(keys[i], secret, sizeof(secret), "");
        if (secret[0] && strstr(message, secret)) sensitive = true;
    }
    for (size_t i = 0; i < len; ++i)
        if ((unsigned char)message[i] < 32) message[i] = ' ';
    /* Codes are bounded and allowed only as plain identifiers. */
    char code[65] = {0};
    int n = msg->error_code_text_len;
    if (n > 64) n = 64;
    for (int i = 0; i < n; ++i) {
        char c = msg->error_code_text[i];
        code[i] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_') ? c : '?';
    }
    ESP_LOGW(TAG, "Server error: code=%d/%s message=%s", msg->error_code, code,
             sensitive ? "[redacted]" : message);
}

static void release_rx_frame(uint8_t *data, size_t len)
{
    if (!data) return;
    free(data);
    atomic_fetch_sub(&rx_bytes, len + 1);
}

static void drop_audio(void)
{
    if ((++rx_drop_count & 31u) == 1u)
        ESP_LOGW(TAG, "Audio backlog limit: dropped %lu incoming frames; connection retained",
                 (unsigned long)rx_drop_count);
}

static void enqueue_rx_frame(rx_frame_t *packet)
{
    if (xQueueSend(rx_queue, packet, 0) == pdTRUE) return;
    release_rx_frame(packet->data, packet->len);
    if (packet->opcode == 2) drop_audio();
    else {
        /* Audio leaves reserved slots. A control-only overflow is a real
         * protocol failure: never silently lose authentication or connection errors. */
        ESP_LOGE(TAG, "Control queue exhausted; recovering session");
        publish(EV_WS_ERROR, packet->generation);
    }
}

static void handle_frame(const rx_frame_t *packet)
{
    if (!current(packet)) return;
    uint32_t queue_ms = (uint32_t)(esp_timer_get_time() / 1000) - packet->received_ms;
    if (queue_ms > queue_wait_max_ms) queue_wait_max_ms = queue_ms;
    xSemaphoreTake(playback_lock, portMAX_DELAY);
    if (!current(packet)) { xSemaphoreGive(playback_lock); return; }
    if (packet->opcode == 2) {
        /* 认证后始终接收音频。平台停止回答时仅停止供数，已有缓存自然播完。 */
        if (state == WS_STATE_CONNECTED) {
            audio_out_set_streaming(true);
            int samples = audio_out_play_opus(packet->data, packet->len);
            if (samples < 0) {
                /* 用户结束会话可解除 PCM 背压；不能把正常关闭变成再次重连。 */
                if (current(packet) && !audio_out_stop_requested())
                    publish(EV_WS_SERVER_ERROR, packet->generation);
            } else if (samples > 0 && ++played_frames == 1) {
                ESP_LOGI(TAG, "Continuous audio accepted; microphone upload remains active");
            }
        }
        xSemaphoreGive(playback_lock);
        return;
    }
    proto_msg_t msg;
    proto_result_t result = proto_parse_json((char *)packet->data, &msg);
    if (result != PROTO_OK) {
        if (result != PROTO_ERR_UNKNOWN_TYPE) {
            ESP_LOGW(TAG, "Invalid control frame: parse=%d bytes=%u", result, (unsigned)packet->len);
            if (state == WS_STATE_AUTHING) {
                state = WS_STATE_ERROR;
                publish(EV_WS_AUTH_FAILED, packet->generation);
            }
        }
        xSemaphoreGive(playback_lock); return;
    }
    if (msg.evt == PROTO_EVT_PROXY_CONNECTED && state == WS_STATE_AUTHING) {
        state = WS_STATE_CONNECTED;
        publish(EV_WS_AUTH_OK, packet->generation);
    } else if (msg.evt == PROTO_EVT_PROXY_CONNECTED && state == WS_STATE_PRECONNECTED) {
        state = WS_STATE_CONNECTED;
        publish(EV_WS_AUTH_OK, packet->generation);
    } else if (msg.evt == PROTO_EVT_PRECONNECT_READY &&
               (state == WS_STATE_AUTHING || state == WS_STATE_PRECONNECTED) && preconnect_auth_sent) {
        preconnect_auth_sent = false;
        preconnect_expires_in = msg.preconnect_expires_in;
        state = WS_STATE_PRECONNECTED;
        publish(EV_WS_PRECONNECT_READY, packet->generation);
    } else if (msg.evt == PROTO_EVT_ERROR) {
        log_server_error(&msg);
        bool auth_failed = state == WS_STATE_AUTHING || preconnect_auth_sent ||
                           proto_is_auth_error(&msg);
        state = WS_STATE_ERROR;
        reset_speech_status();
        publish(auth_failed ? EV_WS_AUTH_FAILED : EV_WS_SERVER_ERROR, packet->generation);
    }
    /* 只有认证尚未处理时的讲话通知才需经过 worker；禁止使用转录别名。 */
    if (strcmp(msg.raw_type, "input_audio_buffer.speech_started") == 0 ||
        strcmp(msg.raw_type, "input_audio_buffer.speech_stopped") == 0)
        observe_speech_event(msg.evt, packet);
    /* speech 只更新待机依据；response 通知不停止播放或更改收音。 */
    xSemaphoreGive(playback_lock);
}

static void receive_task(void *arg)
{
    (void)arg;
    rx_frame_t packet;
    uint32_t stats_ms = 0, stats_packets = 0, stats_generation = 0;
    while (true) {
        if (xQueueReceive(rx_queue, &packet, pdMS_TO_TICKS(10)) == pdTRUE) {
            handle_frame(&packet);
            release_rx_frame(packet.data, packet.len);
        }
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        uint32_t gen = atomic_load(&generation), count = atomic_load(&rx_audio_packets);
        if (gen != stats_generation) {
            stats_generation = gen; stats_packets = 0; stats_ms = now; queue_wait_max_ms = 0;
        }
        if (state == WS_STATE_CONNECTED && count != stats_packets && now - stats_ms >= 5000) {
            ESP_LOGI(TAG, "RX audio stats: received=%lu queued=%u gap_max_ms=%lu queue_wait_max_ms=%lu",
                     (unsigned long)count, (unsigned)uxQueueMessagesWaiting(rx_queue),
                     (unsigned long)atomic_load(&rx_audio_gap_max_ms), (unsigned long)queue_wait_max_ms);
            stats_ms = now; stats_packets = count; queue_wait_max_ms = 0;
            atomic_store(&rx_audio_gap_max_ms, 0);
        }
    }
    vTaskDelete(NULL);
}

static void on_ws(void *arg, esp_event_base_t base, int32_t id, void *event)
{
    (void)arg; (void)base;
    uint32_t gen = atomic_load(&generation);
    if (id == WEBSOCKET_EVENT_BEFORE_CONNECT) {
        /* 已创建网络任务/transport，尚未分配本轮 TLS 握手内存。 */
        log_connection_memory("before-tls");
    } else if (id == WEBSOCKET_EVENT_CONNECTED) {
        state = WS_STATE_AUTHING;
        preconnect_auth_sent = false;
        reset_speech_status();
        log_connection_memory("connected");
        publish(EV_WS_CONNECTED, gen);
    } else if (id == WEBSOCKET_EVENT_DISCONNECTED || id == WEBSOCKET_EVENT_CLOSED) {
        state = WS_STATE_DISCONNECTED;
        preconnect_auth_sent = false;
        reset_speech_status();
        log_transport_error("disconnected", event);
        release_rx_frame(frame, frame_size); frame = NULL; frame_size = received = 0;
        publish(EV_WS_DISCONNECTED, gen);
    } else if (id == WEBSOCKET_EVENT_ERROR) {
        state = WS_STATE_ERROR;
        preconnect_auth_sent = false;
        reset_speech_status();
        log_transport_error("error", event);
        log_connection_memory("transport-error");
        publish(EV_WS_ERROR, gen);
    } else if (id == WEBSOCKET_EVENT_DATA) {
        esp_websocket_event_data_t *data = event;
        if (data->op_code != 1 && data->op_code != 2) return;
        if (data->payload_len <= 0 || data->payload_len > 65536 ||
            data->data_len < 0 || data->payload_offset < 0) return;
        if (data->payload_offset == 0) {
            release_rx_frame(frame, frame_size); frame = NULL; received = 0;
            frame_size = data->payload_len; opcode = data->op_code;
            size_t used = atomic_load(&rx_bytes);
            if (opcode == 2 && !ws_rx_audio_fits(uxQueueMessagesWaiting(rx_queue),
                                                used, frame_size + 1)) {
                drop_audio();
                return;
            }
            if (used + frame_size + 1 <= WS_RX_AUDIO_BYTES + WS_RX_CONTROL_BYTES)
                frame = heap_caps_malloc(frame_size + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!frame) {
                if (opcode == 2) drop_audio();
                else publish(EV_WS_ERROR, gen);
                return;
            }
            atomic_fetch_add(&rx_bytes, frame_size + 1);
        }
        if (!frame || (size_t)data->payload_offset != received ||
            received + (size_t)data->data_len > frame_size) return;
        memcpy(frame + received, data->data_ptr, data->data_len);
        received += data->data_len;
        if (received == frame_size) {
            frame[received] = 0;
            rx_frame_t packet = {.data=frame, .len=received, .opcode=opcode, .generation=gen};
            observe_rx_packet(&packet);
            /* 讲话边界不能被 PCM 背压/音频积压延迟。二进制热路径不解析 JSON。
             * 认证前仍保留 FIFO 顺序；后续 worker 用序号防止旧事件反向覆盖。 */
            bool speech_handled = packet.opcode == 1 && state == WS_STATE_CONNECTED &&
                observe_speech_event(proto_parse_speech_event((char *)packet.data), &packet);
            if (speech_handled) release_rx_frame(packet.data, packet.len);
            else enqueue_rx_frame(&packet);
            frame = NULL; frame_size = received = 0;
        }
    }
}

static esp_websocket_client_handle_t create_client(const char *uri)
{
    esp_websocket_client_config_t cfg = {
        .uri = uri, .disable_auto_reconnect = true, .network_timeout_ms = 10000,
        .task_stack = 6144, /* 有界 JSON 解析和协议字段副本，避免默认栈过紧。 */
#ifdef DEVICE_PLATFORM_TLS_CA
        .crt_bundle_attach = NULL,
        .cert_pem = tls_trust_anchor_ca_pem(),
#else
        .crt_bundle_attach = esp_crt_bundle_attach,
#endif
        /* WebSocket-level keepalive: send a ping every 20s so server idle timeout
         * does not silently close the connection. PONG timeout 30s before we
         * declare the link dead. (esp_websocket_client v1.8.0) */
        .ping_interval_sec = 20,
        .pingpong_timeout_sec = 30,
        .disable_pingpong_discon = false,
        /* TCP-level keepalive (slower safety net). */
        .keep_alive_enable = true,
        .keep_alive_idle = 30,
        .keep_alive_interval = 10,
        .keep_alive_count = 3,
    };
    esp_websocket_client_handle_t created = esp_websocket_client_init(&cfg);
    if (created && esp_websocket_register_events(created, WEBSOCKET_EVENT_ANY, on_ws, NULL) != ESP_OK) {
        esp_websocket_client_destroy(created);
        return NULL;
    }
    return created;
}

static void release_credentials(proto_ws_credentials_t *value)
{
    if (!value) return;
    volatile unsigned char *p = (volatile unsigned char *)value;
    for (size_t i = 0; i < sizeof(*value); ++i) p[i] = 0;
    free(value);
}

esp_err_t ws_service_set_credentials(const char *url, const char *token)
{
    if (!client || client_started || state != WS_STATE_DISCONNECTED) return ESP_ERR_INVALID_STATE;
    if ((url == NULL) != (token == NULL)) return ESP_ERR_INVALID_ARG;
    if (url && (!*url || !*token || strlen(url) > PROTO_WS_URL_MAX ||
                strlen(token) > PROTO_AUTH_TOKEN_MAX)) return ESP_ERR_INVALID_SIZE;
    proto_ws_credentials_t *next = heap_caps_calloc(1, sizeof(*next), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!next) return ESP_ERR_NO_MEM;
    if (url) {
        memcpy(next->url, url, strlen(url) + 1);
        memcpy(next->token, token, strlen(token) + 1);
    } else {
        /* 仅由主任务在平台握手明确关闭时选择；不是网络/HTTP 失败时的兜底。 */
        cfg_service_get_str(CFG_KEY_WS_URL, next->url, sizeof(next->url), ACOS_WS_URL);
        cfg_service_get_str(CFG_KEY_ACOS_TOKEN, next->token, sizeof(next->token), "");
    }
    if (!next->url[0] || !next->token[0]) { release_credentials(next); return ESP_ERR_INVALID_ARG; }
    if (!credentials || strcmp(credentials->url, next->url) != 0) {
        /* URL 改变时重建已停止的 transport，避免组件 set_uri 遗留旧端口/路径。
         * 新对象准备成功后才替换；失败时保留旧对象但调用者不得开始连接。 */
        esp_websocket_client_handle_t replacement = create_client(next->url);
        if (!replacement) { release_credentials(next); return ESP_ERR_NO_MEM; }
        esp_err_t err = esp_websocket_client_destroy(client);
        if (err != ESP_OK) {
            esp_websocket_client_destroy(replacement);
            release_credentials(next);
            return err;
        }
        client = replacement;
    }
    release_credentials(credentials);
    credentials = next;
    credentials_from_handshake = url != NULL;
    return ESP_OK;
}

esp_err_t ws_service_init(void)
{
    if (client) return ESP_OK;
    playback_lock = xSemaphoreCreateMutex();
    rx_queue = xQueueCreateWithCaps(WS_RX_FRAMES, sizeof(rx_frame_t),
                                   MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!playback_lock || !rx_queue) goto fail;
    char uri[256];
    cfg_service_get_str(CFG_KEY_WS_URL, uri, sizeof(uri), ACOS_WS_URL);
    client = create_client(uri);
    if (!client) goto fail;
    /* 解码与 AFE fetch 同为 5，PCM 输出为 6；编码已移至 core 0/priority 4。 */
    if (xTaskCreatePinnedToCore(receive_task, "ws_rx_audio", 8192, NULL, 5, &rx_task, 1) != pdPASS) goto fail;
    ESP_LOGI(TAG, "Full-duplex tasks: encode=core0/prio4 decode=core1/prio5 pcm=core1/prio6");
#if CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC
    ESP_LOGI(TAG, "TLS allocator: PSRAM (SDK); certificate verification enabled");
#else
    ESP_LOGW(TAG, "TLS allocator is not PSRAM; check mbedTLS memory configuration for this board");
#endif
#if CONFIG_ESP_WS_CLIENT_SEPARATE_TX_LOCK
    ESP_LOGI(TAG, "WebSocket independent TX lock enabled; full-duplex upload");
#else
#error "Full-duplex audio requires CONFIG_ESP_WS_CLIENT_SEPARATE_TX_LOCK"
#endif
    ESP_LOGI(TAG, "RX buffer: %u frames, %u KiB Opus budget in PSRAM; %u control slots reserved",
             WS_RX_FRAMES, WS_RX_AUDIO_BYTES / 1024u, WS_RX_CONTROL_RESERVE);
    return ESP_OK;
fail:
    if (client) { esp_websocket_client_destroy(client); client = NULL; }
    if (rx_queue) { vQueueDeleteWithCaps(rx_queue); rx_queue = NULL; }
    if (playback_lock) { vSemaphoreDelete(playback_lock); playback_lock = NULL; }
    return ESP_ERR_NO_MEM;
}
esp_err_t ws_service_connect(void)
{
    if (!client || !credentials) return ESP_ERR_INVALID_STATE;
    if (client_started) return ESP_OK;
    state = WS_STATE_CONNECTING;
    preconnect_auth_sent = false;
    preconnect_expires_in = 0;
    reset_speech_status();
    esp_err_t err = esp_websocket_client_start(client);
    if (err == ESP_OK) client_started = true;
    else {
        state = WS_STATE_ERROR;
        log_connection_memory("start-failed");
    }
    return err;
}
esp_err_t ws_service_authenticate(void)
{
    if (!client || !credentials ||
        (state != WS_STATE_AUTHING && state != WS_STATE_PRECONNECTED)) return ESP_ERR_INVALID_STATE;
    if (preconnect_auth_sent) return ESP_ERR_INVALID_STATE;
    const char *token = credentials->token;
    log_auth_token_fingerprint(token, credentials_from_handshake ?
                              "HTTP/handshake/websocket.token" : "NVS/korvo_cfg/acos_token");
    size_t capacity = transfer_prepared ? PROTO_TRANSFER_AUTH_FRAME_SIZE :
                      reminder_task_count ? PROTO_REMINDER_AUTH_FRAME_SIZE : strlen(token) * 6 + 32;
    char *auth = heap_caps_malloc(capacity, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!auth) return ESP_ERR_NO_MEM;
    const char *ids[PROTO_REMINDER_TASK_IDS_MAX];
    for (size_t i = 0; i < reminder_task_count; ++i) ids[i] = reminder_task_ids[i];
    size_t len = 0;
    if (transfer_prepared) {
        char ticket[PROTO_TRANSFER_TICKET_MAX + 1];
        snprintf(ticket, sizeof(ticket), "%s", transfer_join_ticket);
        memset(transfer_join_ticket, 0, sizeof(transfer_join_ticket));
        transfer_prepared = false;
        len = proto_build_transfer_auth_frame(auth, capacity, token, transfer_device_id, ticket);
        memset(ticket, 0, sizeof(ticket));
    } else if (reminder_task_count) {
        len = proto_build_reminder_auth_frame(auth, capacity, token, reminder_device_id, ids, reminder_task_count);
    } else {
        len = proto_build_auth_frame(auth, capacity, token);
    }
    esp_err_t err = len && esp_websocket_client_send_text(client, auth, len, pdMS_TO_TICKS(1000)) == (int)len
                    ? ESP_OK : ESP_FAIL;
    if (err == ESP_OK && reminder_task_count)
        ESP_LOGI(TAG, "Reminder auth sent: device_id=%s task_count=%u (token redacted)",
                 reminder_device_id, (unsigned)reminder_task_count);
    volatile char *wipe = auth;
    for (size_t i = 0; i < capacity; ++i) wipe[i] = 0;
    free(auth);
    return err;
}

esp_err_t ws_service_preconnect(void)
{
    if (!client || !credentials || state != WS_STATE_AUTHING || reminder_task_count)
        return ESP_ERR_INVALID_STATE;
    if (preconnect_auth_sent) return ESP_ERR_INVALID_STATE;
    const char *token = credentials->token;
    log_auth_token_fingerprint(token, credentials_from_handshake ?
                              "HTTP/handshake/websocket.token" : "NVS/korvo_cfg/acos_token");
    size_t capacity = strlen(token) * 6 + 48;
    char *auth = heap_caps_malloc(capacity, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!auth) return ESP_ERR_NO_MEM;
    size_t len = proto_build_preconnect_auth_frame(auth, capacity, token);
    esp_err_t err = len && esp_websocket_client_send_text(client, auth, len, pdMS_TO_TICKS(1000)) == (int)len
                    ? ESP_OK : ESP_FAIL;
    if (err == ESP_OK) preconnect_auth_sent = true;
    volatile char *wipe = auth;
    for (size_t i = 0; i < capacity; ++i) wipe[i] = 0;
    free(auth);
    return err;
}

esp_err_t ws_service_activate_preconnect(void)
{
    if (!client || !credentials || state != WS_STATE_PRECONNECTED) return ESP_ERR_INVALID_STATE;
    preconnect_auth_sent = false;
    preconnect_expires_in = 0;
    state = WS_STATE_AUTHING;
    esp_err_t err = ws_service_authenticate();
    if (err != ESP_OK) state = WS_STATE_PRECONNECTED;
    return err;
}

uint32_t ws_service_get_preconnect_expires_in(void) { return preconnect_expires_in; }

esp_err_t ws_service_disconnect(void)
{
    if (!client) return ESP_ERR_INVALID_STATE;
    bool was_started = client_started;
    state = WS_STATE_DISCONNECTED;
    preconnect_auth_sent = false;
    preconnect_expires_in = 0;
    reset_speech_status();
    /* 先解除 worker 的 PCM 背压，再等待 transport/播放器锁，避免关闭互等。 */
    audio_out_request_stop();
    if (client_started) {
        esp_err_t err = esp_websocket_client_stop(client);
        /* Component 1.8 returns ESP_FAIL if its task already stopped after
         * a transport failure (auto reconnect is disabled). That is success
         * for this idempotent main-task stop, not a reason to loop forever. */
        if (err != ESP_OK && err != ESP_FAIL) return err;
        client_started = false;
    }
    atomic_fetch_add(&generation, 1);
    xSemaphoreTake(playback_lock, portMAX_DELAY);
    state = WS_STATE_DISCONNECTED;
    preconnect_auth_sent = false;
    preconnect_expires_in = 0;
    reminder_device_id[0] = 0;
    memset(reminder_task_ids, 0, sizeof(reminder_task_ids));
    reminder_task_count = 0;
    transfer_device_id[0] = 0;
    memset(transfer_join_ticket, 0, sizeof(transfer_join_ticket));
    transfer_prepared = false;
    played_frames = 0;
    audio_out_stop();
    xSemaphoreGive(playback_lock);
    rx_frame_t packet;
    while (xQueueReceive(rx_queue, &packet, 0) == pdTRUE) release_rx_frame(packet.data, packet.len);
    release_rx_frame(frame, frame_size); frame = NULL; frame_size = received = 0;
    rx_drop_count = 0;
    atomic_store(&rx_audio_packets, 0); atomic_store(&rx_audio_last_ms, 0);
    atomic_store(&rx_audio_gap_max_ms, 0);
    /* stop 已等待 transport 关闭；任务栈的最终回收由空闲任务完成，下一次
     * before-tls 快照也要一起比较，不能单凭此处的差值就认定内存泄漏。 */
    if (was_started) log_connection_memory("after-stop");
    return ESP_OK;
}
esp_err_t ws_service_deinit(void)
{
    if (!client) return ESP_OK;
    esp_err_t err = ws_service_disconnect();
    if (err != ESP_OK) return err;
    xSemaphoreTake(playback_lock, portMAX_DELAY);
    if (rx_task) { vTaskDelete(rx_task); rx_task = NULL; }
    xSemaphoreGive(playback_lock);
    esp_websocket_client_destroy(client); client = NULL;
    release_credentials(credentials); credentials = NULL;
    credentials_from_handshake = false;
    vQueueDeleteWithCaps(rx_queue); rx_queue = NULL;
    vSemaphoreDelete(playback_lock); playback_lock = NULL;
    return ESP_OK;
}
ws_conn_state_t ws_service_get_state(void) { return state; }
esp_websocket_client_handle_t ws_service_get_client(void) { return client; }
esp_err_t ws_service_send_json(const char *text)
{
    if (!client || state != WS_STATE_CONNECTED) return ESP_ERR_INVALID_STATE;
    if (!text) return ESP_ERR_INVALID_ARG;
    size_t len = strlen(text);
    int sent = esp_websocket_client_send_text(client, text, len, pdMS_TO_TICKS(1000));
    if (sent == (int)len) return ESP_OK;
    int poll_write = -1;
    esp_transport_handle_t transport = esp_websocket_client_get_transport(client);
    if (transport) poll_write = esp_transport_poll_write(transport, 0);
    ESP_LOGE(TAG, "send_json failed: len=%u sent=%d state=%d generation=%u connected=%d poll_write=%d",
             (unsigned)len, sent, atomic_load(&state), atomic_load(&generation),
             esp_websocket_client_is_connected(client), poll_write);
    return ESP_FAIL;
}
esp_err_t ws_service_send_opus_frame(const uint8_t *data, size_t len)
{
    if (!data || !len || len > WS_OPUS_FRAME_MAX_BYTES) return ESP_ERR_INVALID_ARG;
    if (state != WS_STATE_CONNECTED) return ESP_ERR_INVALID_STATE;
    /* 固定 50 包/秒的热路径不反复 malloc/free。缓冲仅由单个 audio_in
     * 任务使用；原子标记只拒绝并发误用，不等待、不阻塞其他控制消息。 */
    static char encoded[4 * ((WS_OPUS_FRAME_MAX_BYTES + 2) / 3) + 1];
    static char json[sizeof(encoded) + 256];
    static atomic_flag busy = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set(&busy)) return ESP_ERR_INVALID_STATE;
    size_t written;
    esp_err_t err = ESP_FAIL;
    if (mbedtls_base64_encode((unsigned char *)encoded, sizeof(encoded), &written, data, len) == 0) {
        encoded[written] = 0;
        if (proto_build_input_audio_append(json, sizeof(json), encoded, NULL)) err = ws_service_send_json(json);
    }
    atomic_flag_clear(&busy);
    return err;
}
esp_err_t ws_service_prepare_reminder(const char *device_id,
                                      const char *const *task_ids, size_t task_count)
{
    if (!device_id || !device_id[0] || strlen(device_id) >= sizeof(reminder_device_id) ||
        !task_ids || !task_count || task_count > PROTO_REMINDER_TASK_IDS_MAX)
        return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < task_count; ++i) {
        if (!task_ids[i] || !task_ids[i][0] || strlen(task_ids[i]) > 128) return ESP_ERR_INVALID_ARG;
        for (const unsigned char *p = (const unsigned char *)task_ids[i]; *p; ++p)
            if (*p < '0' || *p > '9') return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(playback_lock, portMAX_DELAY);
    if ((state != WS_STATE_DISCONNECTED && state != WS_STATE_PRECONNECTED) ||
        (state == WS_STATE_DISCONNECTED && client_started) || reminder_task_count || transfer_prepared) {
        xSemaphoreGive(playback_lock);
        return ESP_ERR_INVALID_STATE;
    }
    strcpy(reminder_device_id, device_id);
    for (size_t i = 0; i < task_count; ++i) strcpy(reminder_task_ids[i], task_ids[i]);
    reminder_task_count = task_count;
    xSemaphoreGive(playback_lock);
    ESP_LOGI(TAG, "Reminder WebSocket auth prepared: task_count=%u", (unsigned)task_count);
    return ESP_OK;
}

esp_err_t ws_service_prepare_transfer(const char *device_id, const char *join_ticket)
{
    if (!device_id || !device_id[0] || strlen(device_id) >= sizeof(transfer_device_id) ||
        !join_ticket || strncmp(join_ticket, "v2.", 3) != 0 ||
        !join_ticket[3] || strlen(join_ticket) > PROTO_TRANSFER_TICKET_MAX)
        return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(playback_lock, portMAX_DELAY);
    if ((state != WS_STATE_DISCONNECTED && state != WS_STATE_PRECONNECTED) ||
        (state == WS_STATE_DISCONNECTED && client_started) ||
        reminder_task_count || transfer_prepared) {
        xSemaphoreGive(playback_lock);
        return ESP_ERR_INVALID_STATE;
    }
    snprintf(transfer_device_id, sizeof(transfer_device_id), "%s", device_id);
    snprintf(transfer_join_ticket, sizeof(transfer_join_ticket), "%s", join_ticket);
    transfer_prepared = true;
    xSemaphoreGive(playback_lock);
    ESP_LOGI(TAG, "Transfer WebSocket auth prepared: ticket redacted");
    return ESP_OK;
}
