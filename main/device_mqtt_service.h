#ifndef DEVICE_MQTT_SERVICE_H
#define DEVICE_MQTT_SERVICE_H
#include "device_handshake.h"
#include "device_mqtt_protocol.h"
#include "esp_err.h"

/* 主任务初始化/轮询。worker 独占 MQTT 生命周期、任务队列和 NVS；
 * 回调仅复制有界事件，不调用音频、HTTP、Flash 或应用状态机。 */
esp_err_t device_mqtt_service_init(void);
void device_mqtt_service_poll(bool enabled, unsigned configuration_epoch,
                              const device_handshake_response_t *configuration);
/* 主任务允许通知交接：待机准备连接，或已有鉴权会话；连接中/配网时暂停。 */
void device_mqtt_service_set_dispatch_allowed(bool allowed);
/* 主任务允许 worker 真正启动 MQTT TLS：D3 预连接 ready 后才放行，避免与 WSS TLS/唤醒 AFE 抢资源。 */
void device_mqtt_service_set_network_active(bool active);
/* 仅真实用户唤醒解除 CONNACK 4/5 五次失败的熔断；任务/定时轮询不解除。 */
void device_mqtt_service_on_wake(void);
typedef struct {
    char device_id[65];
    unsigned count;
    char task_ids[DEVICE_TASK_QUEUE_SIZE][DEVICE_TASK_ID_MAX + 1];
    char join_ticket[DEVICE_TASK_TICKET_MAX + 1];
    char jti[128];
} device_mqtt_delivery_t;
/* worker 保存通知后供主任务领取；返回对象必须恰好 release 一次。
 * handled=true：已有鉴权会话接管，或用户明确取消，消费本地通知；
 * false：保留通知，等待用户唤醒、网络恢复或新通知后再交接，避免自唤醒循环。
 * 两者均不代表播报结果，不发送业务 ACK。
 * 已有会话时平台直接推音频，主任务无需为这些 ID 再发 WebSocket 请求。 */
device_mqtt_delivery_t *device_mqtt_service_take_tasks(void);
void device_mqtt_service_release_tasks(device_mqtt_delivery_t *tasks, bool handled);
/* 设备侧无法服务本次 MQTT 入站呼叫：在 ACK 主题回报失败原因。 */
void device_mqtt_service_report_inbound_failure(const device_mqtt_delivery_t *tasks,
                                                const char *reason, bool retryable);
bool device_mqtt_service_voice_enabled(void);
#endif
