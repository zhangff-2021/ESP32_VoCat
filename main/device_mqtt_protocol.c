#include "device_mqtt_protocol.h"
#include "device_handshake.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64_value(char ch)
{
    const char *pos = strchr(b64_alphabet, ch);
    return pos ? (int)(pos - b64_alphabet) : -1;
}

static bool base64url_decode(const char *input, size_t input_len,
                             unsigned char *output, size_t output_capacity,
                             size_t *output_len)
{
    if (!input || !output || !output_len || input_len % 4 == 1) return false;
    size_t written = 0;
    int bits = 0;
    int accumulator = 0;
    for (size_t i = 0; i < input_len; ++i) {
        if (input[i] == '=') break;
        int value = b64_value(input[i]);
        if (value < 0) return false;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (written >= output_capacity) return false;
            output[written++] = (unsigned char)((accumulator >> bits) & 0xff);
        }
    }
    *output_len = written;
    return true;
}

static bool join_ticket_shape_valid(const char *ticket)
{
    if (!ticket || strncmp(ticket, "v2.", 3) != 0 || !ticket[3]) return false;
    const char *second = strchr(ticket + 3, '.');
    if (!second || second == ticket + 3) return false;
    return second[1] != 0 && strchr(second + 1, '.') == NULL &&
           strlen(ticket) <= DEVICE_TASK_TICKET_MAX;
}

static bool join_ticket_jti(const char *ticket, char *jti, size_t jti_size)
{
    if (!jti || !jti_size || !join_ticket_shape_valid(ticket)) return false;
    const char *second = strchr(ticket + 3, '.');
    size_t payload_len = (size_t)(second - (ticket + 3));
    unsigned char decoded[1024];
    size_t decoded_len = 0;
    if (!base64url_decode(ticket + 3, payload_len, decoded,
                          sizeof(decoded) - 1, &decoded_len)) return false;
    decoded[decoded_len] = 0;
    cJSON *payload = cJSON_Parse((const char *)decoded);
    if (!payload) return false;
    const cJSON *claim = cJSON_GetObjectItemCaseSensitive(payload, "j");
    bool ok = cJSON_IsString(claim) && claim->valuestring && claim->valuestring[0] &&
              strlen(claim->valuestring) < jti_size;
    if (ok) snprintf(jti, jti_size, "%s", claim->valuestring);
    cJSON_Delete(payload);
    memset(decoded, 0, sizeof(decoded));
    return ok;
}

static bool task_id_valid(const char *id)
{
    if (!id || !*id || strlen(id) > DEVICE_TASK_ID_MAX) return false;
    for (const unsigned char *p = (const unsigned char *)id; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    return true;
}

static bool json_flat(const char *json, size_t length)
{
    if (!json || !length || length > DEVICE_TASK_PAYLOAD_MAX) return false;
    bool quoted = false;
    int depth = 0;
    for (size_t i = 0; i < length; ++i) {
        if (!json[i]) return false;
        if (quoted && json[i] == '\\') {
            if (++i == length) return false;
            if (json[i] == 'u' && length - i >= 5 && !memcmp(json + i + 1, "0000", 4)) return false;
        } else if (json[i] == '"') quoted = !quoted;
        else if (!quoted) {
            if (json[i] == '[' || json[i] == ']') return false;
            if (json[i] == '{' && ++depth > 1) return false;
            if (json[i] == '}' && --depth < 0) return false;
        }
    }
    return !quoted && depth == 0;
}

bool device_mqtt_parse_task(const char *json, size_t length, device_mqtt_task_t *task)
{
    if (!json || !task || !length || length > DEVICE_TASK_PAYLOAD_MAX ||
        !json_flat(json, length)) return false;
    memset(task, 0, sizeof(*task));
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(json, length, &end, false);
    if (!root) return false;
    while (end < json + length && strchr(" \t\r\n", *end)) ++end;
    bool ok = end == json + length && cJSON_IsObject(root);
    const cJSON *kind = cJSON_GetObjectItemCaseSensitive(root, "kind");
    bool transfer_kind = kind && cJSON_IsString(kind) &&
                         !strcmp(kind->valuestring, "transfer");
    for (const cJSON *field = root->child; ok && field; field = field->next) {
        /* 平台转接载荷带数字型 timeout_sec；提醒载荷必须全字段是字符串。 */
        bool numeric_allowed = transfer_kind && field->string &&
            !strcmp(field->string, "timeout_sec") && cJSON_IsNumber(field);
        if (!cJSON_IsString(field) && !numeric_allowed) { ok = false; break; }
        for (const cJSON *other = field->next; other; other = other->next)
            if (!strcmp(field->string, other->string)) ok = false;
    }
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "task_id");
    const cJSON *content = cJSON_GetObjectItemCaseSensitive(root, "content");
    const cJSON *fire = cJSON_GetObjectItemCaseSensitive(root, "fire_at");
    const cJSON *ticket = cJSON_GetObjectItemCaseSensitive(root, "join_ticket");
    const cJSON *jti = cJSON_GetObjectItemCaseSensitive(root, "jti");
    int64_t unused_time;
    if (ok && kind && cJSON_IsString(kind) && !strcmp(kind->valuestring, "transfer")) {
        ok = cJSON_IsString(id) && id->valuestring[0] &&
             strlen(id->valuestring) <= DEVICE_TASK_ID_MAX &&
             cJSON_IsString(ticket) && join_ticket_shape_valid(ticket->valuestring);
        if (ok) {
            strcpy(task->id, id->valuestring);
            strcpy(task->join_ticket, ticket->valuestring);
            if (jti && cJSON_IsString(jti) && jti->valuestring[0] &&
                strlen(jti->valuestring) < sizeof(task->jti)) {
                strcpy(task->jti, jti->valuestring);
            } else if (!join_ticket_jti(ticket->valuestring, task->jti, sizeof(task->jti))) {
                ok = false;
            }
        }
    } else {
        ok = ok && cJSON_IsString(id) && task_id_valid(id->valuestring) &&
             cJSON_IsString(kind) && !strcmp(kind->valuestring, "reminder") &&
             cJSON_IsString(content) && content->valuestring[0] &&
             cJSON_IsString(fire) && device_handshake_parse_time(fire->valuestring, &unused_time);
        if (ok) strcpy(task->id, id->valuestring);
    }
    cJSON_Delete(root);
    if (!ok) memset(task, 0, sizeof(*task));
    return ok;
}

device_mqtt_fragment_result_t device_mqtt_assemble(device_mqtt_assembly_t *s,
    bool allowed, size_t total, size_t offset, const char *data, size_t length)
{
    if (!offset) {
        s->used = s->total = 0;
        if (allowed && total && total <= DEVICE_TASK_PAYLOAD_MAX) s->total = total;
    }
    if (!s->total || total != s->total || offset != s->used || !data || !length ||
        offset > total || length > total - offset || memchr(data, 0, length)) {
        s->used = s->total = 0;
        return DEVICE_MQTT_FRAGMENT_REJECTED;
    }
    memcpy(s->data + offset, data, length);
    s->used += length;
    s->data[s->used] = 0;
    if (s->used < total) return DEVICE_MQTT_FRAGMENT_MORE;
    s->total = 0;
    return DEVICE_MQTT_FRAGMENT_COMPLETE;
}

void device_mqtt_retry_failed(device_mqtt_retry_t *s, int connack, int64_t now, uint32_t random)
{
    if (s->failures < 7) ++s->failures;
    if ((connack == 4 || connack == 5) && ++s->auth_failures >= 5) s->blocked = true;
    unsigned delay = s->failures >= 7 ? 60000u : 1000u << (s->failures - 1);
    delay = delay * (80u + random % 41u) / 100u;
    if (delay > 60000u) delay = 60000u;
    s->retry_at_ms = now + delay;
}
void device_mqtt_retry_wake(device_mqtt_retry_t *s)
{
    if (s->blocked) memset(s, 0, sizeof(*s));
}
int device_mqtt_suback(const unsigned char *data, size_t length)
{
    return data && length == 1 && data[0] <= 2 ? data[0] : -1;
}
