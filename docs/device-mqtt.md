# 设备 MQTT 与统一语音会话

适用工程：ESP32_VoCatXKorvo。2026-11-18 按用户与平台最新确认更新。
MQTT 沿用 3.1.1 / TLS；语音使用现有 WebSocket / Opus。
本次规则替代旧文档中的“等待播报结束、设备回播放 ACK、忙时排队”。

## 模块职责

| 文件 | 职责 |
| --- | --- |
| `main/device_mqtt_protocol.c/.h` | 任务 JSON 校验、分片重组、连接退避、SUBACK 检查 |
| `main/device_mqtt_storage.c/.h` | 待处理通知的紧凑持久化，兼容旧记录 |
| `main/device_mqtt_service.c/.h` | MQTT 生命周期、状态上报、通知队列及主任务交接 |
| `main/app_main.c` | 通知唤醒、会话连接和触屏/双向静默退出 |
| `main/ws_service.c` | 鉴权和连续双向音频；任务优先级与播报结果由平台管理 |

## 连接与状态上报

地址、client ID、用户名、密码、发布/订阅主题使用 HTTP 握手结果。
证书位于 `main/certs/device_mqtt_ca.pem`；校验证书链与主机名，不跳过 TLS 验证。
缺少 CA 时明确禁用 MQTT，不使用明文连接兜底。
私有配置保留在被 Git 忽略的 `main/device_mqtt_local_config.h`。

MQTT 在待机保持连接。断网使用有抖动的 1～60 秒退避恢复；
CONNACK 4/5 连续拒绝五次后等待真实用户唤醒或重启，避免鉴权重连风暴。
每次连接重新订阅，SUBACK 拒绝会明确报错，不反复重连。

使用握手的 `mqtt.publish_topic`，连接后立即上报，此后每 60 秒一次：
QoS 1、retain=false，最多一条状态等待 PUBACK。

```json
{
  "firmware_version": "1.0.0-vocat",
  "board": "esp-vocat-v1.2",
  "ip": "192.168.1.23",
  "rssi": -58
}
```

`Status queued` 表示客户端入队，`Status PUBACK` 表示 broker 已接收。
MQTT 的协议 PUBACK 与原来的业务播放结果 ACK 是两件事；前者正常保留。

## 下行任务通知

使用握手的 `mqtt.subscribe_topic`，平台发送 QoS 1、retain=false：

```json
{
  "task_id": "42",
  "kind": "reminder",
  "content": "该吃午饭了",
  "fire_at": "2026-11-18T04:00:00.000Z"
}
```

- `task_id` 是不透明数字字符串，最长 128 字节，保留前导零。
- 校验完整 JSON、字段和 UTC 时间格式；不因本机时间或任务迟到直接丢弃。
- 不转发原文、不执行本地 TTS；平台拥有提醒内容。
- 最多保留 8 条待处理通知，只存 ID、接收时间和设备归属。
- 重复业务由平台处理。设备不维护“已播报成功”历史，也不按任务 ID 拒绝重复通知。
- 队列有界；满时日志提示，既有通知仍可继续交接，不扩大缓存。
- 收到通知先保存，保存成功才交给主任务。NVS 写失败每 5 秒重试，不改动其他用户配置。

## 转接通知（另一个主题）

2026-11-22 新增：通话中有人点名这台设备时，平台会往**另一个主题**
`devices/{id}/transfer` 发一条通知，设备拿通知里的房间票据连 WS，
**加入客户正在通话的那个房间**。

⚠️ 这条通知**不是**提醒：不播内容、不回 ACK，流程见
[转设备：下行呼入通知与房间票据握手](device-transfer.md)。

## 语音会话

**待机收到通知**：主任务领取批次并唤醒设备，建立 WebSocket。
沿用既有提醒首帧鉴权，携带任务 ID：

```json
{
  "type": "auth",
  "api_key": "<HTTP握手返回的websocket.token>",
  "device_id": "<本设备号>",
  "task_ids": ["42"]
}
```

鉴权成功立即连续上传麦克风，同时接收平台推送音频。
提醒可被平台语音打断；设备播放完已收到的缓存，不发送 `response.cancel`。
之后保持同一个双向会话，不因提醒播放结束退回待机。

**已有鉴权会话收到通知**：平台直接向当前 WebSocket 推送音频。
设备不发任务请求，不重复 auth，不重连，不等待前一段播放完成。
主任务只消费本地通知，优先级与重复任务由平台处理。
连接过程中到达的其他通知先保存，连接就绪后立即交接。

设备不依赖 `speech_started` / `speech_stopped` / `audio.done` / `response.done`
决定音频是否可播。start/stop 仅标记平台判断的用户讲话状态；用户未讲话且下行
有效声音结束后连续安静 30 秒，或用户触屏结束时关闭 WebSocket，
平台据此挂断并释放电话、模型会话和播报。MQTT 继续在线。

## 通知交接与持久化

`device_mqtt_service_take_tasks()` 返回服务持有的批次，主任务必须归还一次：

- `release_tasks(tasks, true)`：已有鉴权会话接管，或用户明确取消，消费本地通知。
- `release_tasks(tasks, false)`：连接最终失败，保留通知；等用户唤醒、网络/配置恢复或新通知后再交接，避免无限自唤醒。

这只是本地通知生命周期，**不表示播报成功或失败**。
设备不再发布 `devices/{device_id}/ack`，不发送 `audio_received`。
平台负责播报完成情况、重复处理及需要时的重新投递。

队首快照归还时只移除该批次；之后到达的通知即使 ID 相同也保留。
设备身份切换后，旧会话返回的批次不能删除新身份的通知。
保存消费结果失败时暂停后续交接并重试；此时掉电可能再次恢复旧通知，平台负责去重。

NVS 使用原 `device_tasks/pending_v1` 键和 MQP2 紧凑格式。
旧固定结构体也可读取，迁移写成功前保留旧值；旧播放状态读取后归零，不再参与业务。
`played_v1` 旧成功历史不读取、不继续写入，不擦除，避免无关数据破坏。
不改变分区，不需要全片擦除。旧固件回退会恢复旧逻辑，需注意协议差异。

## 验证

主机测试：`scripts/check_device_mqtt.py`，覆盖实际生产解析、服务、存储函数，
模拟 broker/NVS，不读取设备私有凭据、不连接生产平台。
测试不模拟真实 Flash 页 GC、TLS 并发、设备声学或用户听感。
实板步骤见 [联调清单](device-mqtt-checklist.md)。
