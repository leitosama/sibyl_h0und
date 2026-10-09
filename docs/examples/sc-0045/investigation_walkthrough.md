# SC-0045: пример расследования для участника

## Исходные условия

В начале эпизода участник получает **alert**, набор тулов и пустой последний результат. Экспорт `scenario_investigation.json` — отдельный учебный снимок видимой структуры сценария; он не является начальным наблюдением агента в обычном прогоне.

### Alert без изменений

```json
{
  "alert_description": "Process C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe (PID: 6120) was started on host NB-AIVANOVA (IP: 10.45.50.102) at 2024-06-12T09:03:00+00:00",
  "trigger_entities": [
    {
      "id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "type": "host",
      "properties": {
        "hostname": "NB-AIVANOVA",
        "ad_object_id": "0e3ab56f-96a7-584b-81fe-f51b38479451",
        "platform": "windows",
        "os": "Windows 11 Enterprise",
        "os_version": "10.0 (26100)",
        "ip": "10.45.50.102",
        "ip_addresses": null,
        "mac_addresses": null,
        "architecture": null,
        "domain": "corp.local",
        "role": "workstation",
        "is_virtual_machine": null,
        "boot_time": null
      },
      "host_id": null,
      "timestamps": [
        "2024-06-12T00:00:00+00:00",
        "2024-06-12T09:00:07+00:00"
      ]
    },
    {
      "id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "type": "windows_process",
      "properties": {
        "pid": 6120,
        "parent_pid": 4360,
        "parent_image": "C:\\Windows\\explorer.exe",
        "image_path": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "cmdline": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "cwd": "C:\\Users\\a.ivanova\\Desktop\\",
        "powershell_host": null,
        "powershell_version": null,
        "user_sid": "S-1-5-21-1443991235-1188304862-3207093139-4501",
        "user": "CORP\\a.ivanova",
        "integrity_level": "medium",
        "session_id": 2,
        "logon_id": "0x7a2c4",
        "is_elevated": null,
        "sha256": "c3f5a9b1d2e47608a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
        "sha1": "E2A20F58FE089BFC697039885BA84021C0C0D134",
        "md5": "BE47FB0D29D50FA051A165691EF021BB",
        "original_filename": null,
        "digital_signature": null,
        "signed": null,
        "signer": null,
        "company": null,
        "product": null,
        "file_description": null,
        "file_version": null,
        "token_privileges": null,
        "start_time": "2024-06-12T09:03:00+00:00",
        "end_time": null,
        "loaded_modules": null
      },
      "host_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamps": [
        "2024-06-12T09:03:00+00:00",
        "2024-06-12T09:03:02+00:00"
      ]
    }
  ],
  "trigger_relations": [
    {
      "id": "575565ce-4a1b-5210-83a8-223b2e4493a0",
      "type": "hosts",
      "source_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "target_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    }
  ]
}
```

### Первичное чтение alert

Из alert известны PID 6120 и parent PID 4360 на NB-AIVANOVA. `cmdline` содержит только путь к Diagnosis.exe без аргументов; по ней одной нет отдельного подозрительного действия. Есть SHA-256, поэтому первый шаг — найти совпадающий файл в доступном графе. У процесса `signed: null` и `digital_signature: null`: статус подписи пока неизвестен. Учётная запись CORP\a.ivanova, `session_id=2` и `logon_id=0x7a2c4` позволяют затем проверить пользователя и тип входа, но сам alert ещё не говорит, был ли вход интерактивным или удалённым.

### Доступные ресурсы

Видимый граф содержит 16 сущностей и 28 связей. Политика допускает контекст AD: 1 учётная запись, 2 компьютера, 2 группы. Другие контекстные коллекции в этом сценарии пусты, включая TI, DNS, proxy и журналы VPN. AD становится доступен через ID объекта и `get_ad_object_info`.

| Тул | Назначение |
|---|---|
| `finish_investigation` | Передача вердикта, артефактов и reasoning; завершение эпизода. |
| `get_ad_object_info` | Карточка объекта AD и ближайшие ссылки на другие объекты. |
| `get_entity` | Детали сущности и ID входящих и исходящих связей. |
| `get_relation` | Детали одной связи и ID её концов. |
| `search` | Поиск сущностей и связей по видимым атрибутам или ID; выдача постраничная. |

Для этого прогона `max_possible_reward = 50.0` и `reference_tool_calls = 9` (включая финальный вызов). Начальная награда за объекты в alert: **2.0**. Ниже показаны только суммарные награды за вызовы, без внутренних весов и разбивки.

## Маршрут расследования

### 1. `search`

**Что хотим выяснить:** есть ли в доступном графе файл с SHA-256 из alert и что известно о его подписи.

**Гипотеза:** тот же хеш может встретиться у файловой сущности; тогда путь и свойство подписи можно сопоставить с процессом.

**Почему этот вызов и параметры:** SHA-256 взят непосредственно из alert. `search` ищет совпадения в графе, а не запрашивает TI. Поле `signed: null` в alert пока означает отсутствие сведений, а не отсутствие подписи.

**Проверка в ответе:** сверяем хеш и полный путь файла с процессом; отдельно читаем `windows_file.signed`.

**Аргументы**

```json
{
  "query": "c3f5a9b1d2e47608a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
  "reasoning": "В alert есть SHA-256 Diagnosis.exe, а signed у процесса не определён. Ищу совпадения хеша в доступном графе, чтобы найти файловый объект и проверить его свойства; это не проверка репутации хеша."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
      "type": "windows_file",
      "properties": {
        "path": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "size_bytes": null,
        "sha256": "c3f5a9b1d2e47608a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
        "sha1": "E2A20F58FE089BFC697039885BA84021C0C0D134",
        "md5": "BE47FB0D29D50FA051A165691EF021BB",
        "file_type": "executable",
        "path_type": "local",
        "remote_host": null,
        "unc_path": null,
        "zone_identifier": null,
        "owner_sid": null,
        "created_at": null,
        "modification_time": null,
        "ads_name": null,
        "signed": false,
        "lnk_target_cmdline": null,
        "script_text": null,
        "is_executable": true
      },
      "host_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamps": [
        "2024-06-12T09:02:30+00:00"
      ]
    },
    {
      "kind": "entity",
      "id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "type": "windows_process",
      "properties": {
        "pid": 6120,
        "parent_pid": 4360,
        "parent_image": "C:\\Windows\\explorer.exe",
        "image_path": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "cmdline": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "cwd": "C:\\Users\\a.ivanova\\Desktop\\",
        "powershell_host": null,
        "powershell_version": null,
        "user_sid": "S-1-5-21-1443991235-1188304862-3207093139-4501",
        "user": "CORP\\a.ivanova",
        "integrity_level": "medium",
        "session_id": 2,
        "logon_id": "0x7a2c4",
        "is_elevated": null,
        "sha256": "c3f5a9b1d2e47608a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
        "sha1": "E2A20F58FE089BFC697039885BA84021C0C0D134",
        "md5": "BE47FB0D29D50FA051A165691EF021BB",
        "original_filename": null,
        "digital_signature": null,
        "signed": null,
        "signer": null,
        "company": null,
        "product": null,
        "file_description": null,
        "file_version": null,
        "token_privileges": null,
        "start_time": "2024-06-12T09:03:00+00:00",
        "end_time": null,
        "loaded_modules": null
      },
      "host_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamps": [
        "2024-06-12T09:03:00+00:00",
        "2024-06-12T09:03:02+00:00"
      ]
    }
  ]
}
```

Награда за вызов: **1.0**. Накопленная награда с учётом alert: **3.0**.

### 2. `search`

**Что хотим выяснить:** какие события и объекты непосредственно связаны с запущенным процессом.

**Гипотеза:** у процесса могут быть связи запуска, пользователя или сети; их наличие и направление ещё предстоит проверить.

**Почему этот вызов и параметры:** ID процесса взят из alert. Поиск по точному ID показывает сам процесс и его связи без предположений о соседних объектах.

**Проверка в ответе:** отмечаем `win_process_create`, `runs_process` и `connected_to` и сохраняем ID концов найденных связей.

**Аргументы**

```json
{
  "query": "befe11af-28cd-5fde-8f4e-311febd53eac",
  "reasoning": "Файл с тем же путём и хешем найден; у него signed=false. Проверяю связи процесса из alert: кто его создал, от чьего имени он работал и есть ли связанное сетевое событие."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "type": "windows_process",
      "properties": {
        "pid": 6120,
        "parent_pid": 4360,
        "parent_image": "C:\\Windows\\explorer.exe",
        "image_path": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "cmdline": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "cwd": "C:\\Users\\a.ivanova\\Desktop\\",
        "powershell_host": null,
        "powershell_version": null,
        "user_sid": "S-1-5-21-1443991235-1188304862-3207093139-4501",
        "user": "CORP\\a.ivanova",
        "integrity_level": "medium",
        "session_id": 2,
        "logon_id": "0x7a2c4",
        "is_elevated": null,
        "sha256": "c3f5a9b1d2e47608a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
        "sha1": "E2A20F58FE089BFC697039885BA84021C0C0D134",
        "md5": "BE47FB0D29D50FA051A165691EF021BB",
        "original_filename": null,
        "digital_signature": null,
        "signed": null,
        "signer": null,
        "company": null,
        "product": null,
        "file_description": null,
        "file_version": null,
        "token_privileges": null,
        "start_time": "2024-06-12T09:03:00+00:00",
        "end_time": null,
        "loaded_modules": null
      },
      "host_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamps": [
        "2024-06-12T09:03:00+00:00",
        "2024-06-12T09:03:02+00:00"
      ]
    },
    {
      "kind": "relation",
      "id": "218a3b38-fc37-57c0-82ef-1dc50b7eefad",
      "type": "win_process_create",
      "source_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "target_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "timestamp": "2024-06-12T09:03:00+00:00",
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "49b60905-78a3-575c-bc18-cbaf7094873e",
      "type": "connected_to",
      "source_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "target_id": "57c95e94-bb01-5856-a031-2cdc39ab3070",
      "timestamp": "2024-06-12T09:03:02+00:00",
      "log_sources": [
        "Sysmon-3"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "575565ce-4a1b-5210-83a8-223b2e4493a0",
      "type": "hosts",
      "source_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "target_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "e767a571-f99d-5a8e-b81f-234cedacc381",
      "type": "runs_process",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    }
  ]
}
```

Награда за вызов: **0.0**. Накопленная награда с учётом alert: **3.0**.

### 3. `search`

**Что хотим выяснить:** какое именно соединение связано с `Diagnosis.exe` и куда оно направлено.

**Гипотеза:** связь `connected_to` может вести к исходящему соединению; направление, адрес и порт известны только после получения сетевой сущности.

**Почему этот вызов и параметры:** `target_id` взят из связи предыдущего ответа. Поиск точного ID исключает смешение с другими соединениями хоста.

**Проверка в ответе:** сверяем источник связи с ID процесса, а у соединения читаем `direction`, `dst_ip`, `dst_port` и `timestamp`. Сам по себе внешний IP не является TI-вердиктом.

**Аргументы**

```json
{
  "query": "57c95e94-bb01-5856-a031-2cdc39ab3070",
  "reasoning": "У процесса есть связь connected_to. Открываю связанное сетевое событие по target_id, чтобы проверить направление, назначение и время."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "57c95e94-bb01-5856-a031-2cdc39ab3070",
      "type": "network_connection",
      "properties": {
        "src_ip": "10.45.50.102",
        "src_port": 50110,
        "dst_ip": "154.89.152.59",
        "dst_port": 443,
        "fqdn": null,
        "http": null,
        "protocol": "tcp",
        "direction": "outbound",
        "initiated": null,
        "community_id": null,
        "connection_state": null,
        "timestamp": "2024-06-12T09:03:02+00:00",
        "bytes_sent": null,
        "bytes_received": null,
        "socket_family": null,
        "socket_type": null,
        "resolution": "raw_ip",
        "query_status": null,
        "response_addresses": null,
        "query_type": null,
        "dns_timestamp": null,
        "initiator_stack": null
      },
      "host_id": "70415d51-3f2b-583b-96ed-cb9406a950a8",
      "timestamps": [
        "2024-06-12T09:03:02+00:00"
      ]
    },
    {
      "kind": "relation",
      "id": "49b60905-78a3-575c-bc18-cbaf7094873e",
      "type": "connected_to",
      "source_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "target_id": "57c95e94-bb01-5856-a031-2cdc39ab3070",
      "timestamp": "2024-06-12T09:03:02+00:00",
      "log_sources": [
        "Sysmon-3"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "3b228587-e463-5ce7-8a1f-7f01e38e8dd8",
      "type": "hosts",
      "source_id": "70415d51-3f2b-583b-96ed-cb9406a950a8",
      "target_id": "57c95e94-bb01-5856-a031-2cdc39ab3070",
      "timestamp": null,
      "log_sources": [
        "ground_truth_only"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    }
  ]
}
```

Награда за вызов: **1.0**. Накопленная награда с учётом alert: **4.0**.

### 4. `search`

**Что хотим выяснить:** кто записал исполняемый файл и связано ли это с его запуском.

**Гипотеза:** файл мог быть записан до запуска тем же процессом, который указан источником `win_process_create`; это проверяется по ID связей и времени.

**Почему этот вызов и параметры:** ID файла получен в первом ответе. Поиск его связей позволяет увидеть `wrote_file` и источник записи.

**Проверка в ответе:** сравниваем `wrote_file.source_id` с `win_process_create.source_id`, затем время записи со временем запуска из alert.

**Аргументы**

```json
{
  "query": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
  "reasoning": "Файл с хешем из alert найден, а процесс сделал внешнее соединение. Проверяю, есть ли событие записи файла и совпадает ли записавший процесс с родителем запуска."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
      "type": "windows_file",
      "properties": {
        "path": "C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe",
        "size_bytes": null,
        "sha256": "c3f5a9b1d2e47608a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
        "sha1": "E2A20F58FE089BFC697039885BA84021C0C0D134",
        "md5": "BE47FB0D29D50FA051A165691EF021BB",
        "file_type": "executable",
        "path_type": "local",
        "remote_host": null,
        "unc_path": null,
        "zone_identifier": null,
        "owner_sid": null,
        "created_at": null,
        "modification_time": null,
        "ads_name": null,
        "signed": false,
        "lnk_target_cmdline": null,
        "script_text": null,
        "is_executable": true
      },
      "host_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamps": [
        "2024-06-12T09:02:30+00:00"
      ]
    },
    {
      "kind": "relation",
      "id": "d45d1d43-bd96-5b1d-8a1b-c7d66f40da6f",
      "type": "wrote_file",
      "source_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "target_id": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
      "timestamp": "2024-06-12T09:02:30+00:00",
      "log_sources": [
        "Sysmon-11",
        "Sysmon-29"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "cb4349df-4f56-5e7b-92cb-af637e67a32f",
      "type": "hosts",
      "source_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "target_id": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
      "timestamp": null,
      "log_sources": [
        "Sysmon-11"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    }
  ]
}
```

Награда за вызов: **0.0**. Накопленная награда с учётом alert: **4.0**.

### 5. `search`

**Что хотим выяснить:** действительно ли общий источник записи и запуска — `Explorer.EXE`, и совпадают ли его пользователь и сессия с процессом из alert.

**Гипотеза:** родитель по `win_process_create` может быть тем же `explorer.exe`, который указан в alert; его `session_id` и `logon_id` позволят искать конкретный вход.

**Почему этот вызов и параметры:** `source_id` взят из двух независимо найденных связей: `wrote_file` и `win_process_create`. Поиск этого ID раскрывает атрибуты родителя и его связи.

**Проверка в ответе:** сверяем PID, `image_path`, `user_sid`, `session_id`, `logon_id` и время запуска родителя с alert.

**Аргументы**

```json
{
  "query": "8e86f2e0-394d-50ed-8363-7744ee708da0",
  "reasoning": "Одна сущность записала файл и затем создала Diagnosis.exe. Проверяю, что это за родительский процесс и в какой пользовательской сессии он работал."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "type": "windows_process",
      "properties": {
        "pid": 4360,
        "parent_pid": 4312,
        "parent_image": "C:\\Windows\\System32\\userinit.exe",
        "image_path": "C:\\Windows\\explorer.exe",
        "cmdline": "C:\\Windows\\Explorer.EXE",
        "cwd": "C:\\Users\\a.ivanova\\",
        "powershell_host": null,
        "powershell_version": null,
        "user_sid": "S-1-5-21-1443991235-1188304862-3207093139-4501",
        "user": "CORP\\a.ivanova",
        "integrity_level": "medium",
        "session_id": 2,
        "logon_id": "0x7a2c4",
        "is_elevated": null,
        "sha256": "A5C7C78F380354CDF4A226DF8988A9CF3422BF052542368B6B2FB29DF5F7916B",
        "sha1": "BCC5AF9A5B7D8172F9C5FD6600D65DC264025B7E",
        "md5": "8C2702FDBBC44E9C4950E54D55D3957E",
        "original_filename": "EXPLORER.EXE",
        "digital_signature": null,
        "signed": true,
        "signer": "Microsoft Windows",
        "company": "Microsoft Corporation",
        "product": "Microsoft® Windows® Operating System",
        "file_description": "Windows Explorer",
        "file_version": "10.0.19041.1949 (WinBuild.160101.0800)",
        "token_privileges": null,
        "start_time": "2024-06-12T09:00:10+00:00",
        "end_time": null,
        "loaded_modules": null
      },
      "host_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamps": [
        "2024-06-12T09:00:10+00:00",
        "2024-06-12T09:02:30+00:00",
        "2024-06-12T09:03:00+00:00"
      ]
    },
    {
      "kind": "relation",
      "id": "915cbaef-e4e8-5831-97f5-941c29ca94bb",
      "type": "win_process_create",
      "source_id": "a40f537b-a7b2-505c-960d-00028d49a9ed",
      "target_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "timestamp": "2024-06-12T09:00:10+00:00",
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "d45d1d43-bd96-5b1d-8a1b-c7d66f40da6f",
      "type": "wrote_file",
      "source_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "target_id": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
      "timestamp": "2024-06-12T09:02:30+00:00",
      "log_sources": [
        "Sysmon-11",
        "Sysmon-29"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "218a3b38-fc37-57c0-82ef-1dc50b7eefad",
      "type": "win_process_create",
      "source_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "target_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "timestamp": "2024-06-12T09:03:00+00:00",
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "25fbb6bd-6a16-557f-a2e3-545acd46dd01",
      "type": "hosts",
      "source_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "target_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "b2a0c6d9-2612-530e-bd76-c75f477aac82",
      "type": "runs_process",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    }
  ]
}
```

Награда за вызов: **0.0**. Накопленная награда с учётом alert: **4.0**.

### 6. `search`

**Что хотим выяснить:** какая учётная запись связана с процессом и есть ли у неё наблюдаемое событие входа на этот хост.

**Гипотеза:** пользователь из `runs_process` может иметь связь `logged_on_to`; её тип и `logon_id` нужно сопоставить с процессами, прежде чем назвать сессию удалённой.

**Почему этот вызов и параметры:** ID пользователя — `source_id` связи `runs_process` из шага 2. `search` по нему одновременно возвращает свойства пользователя и относящиеся к нему связи, включая возможный вход.

**Проверка в ответе:** сравниваем SID с alert, а у `logged_on_to` проверяем целевой хост, тип входа, `logon_id` и исходный IP.

**Аргументы**

```json
{
  "query": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
  "reasoning": "У процесса из alert известна связь runs_process с пользователем; родитель работает под тем же SID. Проверяю карточку пользователя и наличие события входа для этой учётной записи."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "type": "windows_user",
      "properties": {
        "sid": "S-1-5-21-1443991235-1188304862-3207093139-4501",
        "ad_object_id": "4a983190-a4e9-5165-9f41-330d03b09579",
        "username": "a.ivanova",
        "domain": "CORP",
        "account_type": "domain",
        "session_type": null,
        "is_privileged": null,
        "is_service_account": null,
        "privileges": null,
        "group_memberships": [
          "Domain Users",
          "Accounting"
        ]
      },
      "host_id": null,
      "timestamps": [
        "2024-06-12T09:00:07+00:00"
      ]
    },
    {
      "kind": "relation",
      "id": "a9c9c20d-8f3a-5521-9c57-dbec8cea1825",
      "type": "logged_on_to",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamp": "2024-06-12T09:00:07+00:00",
      "log_sources": [
        "WinEvt-4624"
      ],
      "properties": null,
      "logon_properties": {
        "logon_type": "remote_interactive",
        "source_ip": "10.45.200.50",
        "source_port": 49153,
        "source_host": null,
        "auth_package": null,
        "source_logon_id": null,
        "protocol": null,
        "exe": null,
        "terminal": null,
        "auth_failed": null,
        "explicit_credentials": null,
        "logon_id": "0x7a2c4",
        "linked_logon_id": null,
        "elevated_token": null,
        "status_code": null,
        "pre_auth_type": null,
        "kerberos_realm": null,
        "impersonation_level": null,
        "virtual_account": null,
        "user_initiated": null
      },
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "11e4c6f2-afb2-5c40-89ba-62dfab0b291a",
      "type": "runs_process",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "a40f537b-a7b2-505c-960d-00028d49a9ed",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "b2a0c6d9-2612-530e-bd76-c75f477aac82",
      "type": "runs_process",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "8e86f2e0-394d-50ed-8363-7744ee708da0",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    },
    {
      "kind": "relation",
      "id": "e767a571-f99d-5a8e-b81f-234cedacc381",
      "type": "runs_process",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
      "timestamp": null,
      "log_sources": [
        "Sysmon-1",
        "WinEvt-4688"
      ],
      "properties": null,
      "logon_properties": null,
      "access_properties": null
    }
  ]
}
```

Награда за вызов: **1.0**. Накопленная награда с учётом alert: **5.0**.

### 7. `search`

**Что хотим выяснить:** подтверждается ли удалённый интерактивный вход сетевым соединением и что известно об устройстве-источнике.

**Гипотеза:** адресу `source_ip` из `logged_on_to` может соответствовать входящее TCP/3389 на хост из alert; без этого события тип входа не доказывает конкретный сетевой путь.

**Почему этот вызов и параметры:** IP взят из связи входа предыдущего шага. Поиск по нему сопоставляет событие входа с сетевой телеметрией и видимой сущностью источника.

**Проверка в ответе:** сверяем `src_ip`, `src_port`, `dst_ip`, `dst_port` и время с `logged_on_to`; наличие исходного хоста не доказывает, что он скомпрометирован.

**Аргументы**

```json
{
  "query": "10.45.200.50",
  "reasoning": "Для той же учётной записи и logon_id найден RemoteInteractive-вход с конкретного IP. Проверяю, видно ли соответствующее входящее соединение на TCP/3389 и какой источник указан в графе."
}
```

**Фактический результат**

```json
{
  "current_page_id": 1,
  "next_page_id": null,
  "results": [
    {
      "kind": "entity",
      "id": "4d760b1b-0b84-500f-a891-f144ebd55a5d",
      "type": "network_connection",
      "properties": {
        "src_ip": "10.45.200.50",
        "src_port": 49153,
        "dst_ip": "10.45.50.102",
        "dst_port": 3389,
        "fqdn": null,
        "http": null,
        "protocol": "tcp",
        "direction": "inbound",
        "initiated": null,
        "community_id": null,
        "connection_state": null,
        "timestamp": "2024-06-12T09:00:02+00:00",
        "bytes_sent": null,
        "bytes_received": null,
        "socket_family": null,
        "socket_type": null,
        "resolution": "raw_ip",
        "query_status": null,
        "response_addresses": null,
        "query_type": null,
        "dns_timestamp": null,
        "initiator_stack": null
      },
      "host_id": "54f2c381-91b8-5af9-bbeb-0a4582b2ae02",
      "timestamps": [
        "2024-06-12T09:00:02+00:00"
      ]
    },
    {
      "kind": "relation",
      "id": "a9c9c20d-8f3a-5521-9c57-dbec8cea1825",
      "type": "logged_on_to",
      "source_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
      "target_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
      "timestamp": "2024-06-12T09:00:07+00:00",
      "log_sources": [
        "WinEvt-4624"
      ],
      "properties": null,
      "logon_properties": {
        "logon_type": "remote_interactive",
        "source_ip": "10.45.200.50",
        "source_port": 49153,
        "source_host": null,
        "auth_package": null,
        "source_logon_id": null,
        "protocol": null,
        "exe": null,
        "terminal": null,
        "auth_failed": null,
        "explicit_credentials": null,
        "logon_id": "0x7a2c4",
        "linked_logon_id": null,
        "elevated_token": null,
        "status_code": null,
        "pre_auth_type": null,
        "kerberos_realm": null,
        "impersonation_level": null,
        "virtual_account": null,
        "user_initiated": null
      },
      "access_properties": null
    },
    {
      "kind": "entity",
      "id": "54f2c381-91b8-5af9-bbeb-0a4582b2ae02",
      "type": "host",
      "properties": {
        "hostname": "DESKTOP-7F3K9Q2",
        "ad_object_id": null,
        "platform": "windows",
        "os": null,
        "os_version": null,
        "ip": "10.45.200.50",
        "ip_addresses": null,
        "mac_addresses": null,
        "architecture": null,
        "domain": null,
        "role": "workstation",
        "is_virtual_machine": null,
        "boot_time": null
      },
      "host_id": null,
      "timestamps": []
    }
  ]
}
```

Награда за вызов: **0.0**. Накопленная награда с учётом alert: **5.0**.

### 8. `get_ad_object_info`

**Что хотим выяснить:** какова роль учётной записи в AD и активна ли она.

**Гипотеза:** AD-данные могут уточнить группу и должность пользователя, но сами по себе не объясняют причину запуска файла.

**Почему этот вызов и параметры:** `ad_object_id` взят из найденной сущности `windows_user`. Точный ID исключает угадывание по имени.

**Проверка в ответе:** сопоставляем `sam_account_name` с именем пользователя, смотрим `enabled`, группы и должность; не считаем штатное членство доказательством безопасности.

**Аргументы**

```json
{
  "ad_object_id": "4a983190-a4e9-5165-9f41-330d03b09579",
  "reasoning": "Пользователь процесса и RemoteInteractive-входа установлен. Проверяю его AD-карточку, чтобы описать роль и состояние учётной записи, не выводя их из имени."
}
```

**Фактический результат**

```json
{
  "id": "4a983190-a4e9-5165-9f41-330d03b09579",
  "kind": "account",
  "sam_account_name": "a.ivanova",
  "object_sid": "S-1-5-21-1443991235-1188304862-3207093139-4501",
  "type": "user",
  "display_name": "Anna Ivanova",
  "upn": "a.ivanova@corp.local",
  "distinguished_name": "CN=Anna Ivanova,OU=Accounting,OU=Users,DC=corp,DC=local",
  "description": "Accounts-payable clerk, Accounting department. Standard user; no administrative group membership.",
  "enabled": true,
  "created": null,
  "modified": null,
  "password_last_set": null,
  "last_logon": "2024-06-12T09:00:07Z",
  "account_expires": null,
  "logon_count": null,
  "admin_count": null,
  "password_never_expires": null,
  "logon_workstations": null,
  "member_of_ids": [
    "e4848f35-9dd8-5665-956d-438881b634e3",
    "f7f92012-64ac-5a50-a58a-7dcdb6f6172d"
  ],
  "member_of_external_names": [],
  "service_principal_names": [],
  "department": "Accounting",
  "title": "Accountant (Accounts Payable)",
  "manager_id": null,
  "manager_dn": null,
  "managed_password_interval": null,
  "principals_allowed_to_retrieve_password_ids": [],
  "manager": null,
  "member_of": [
    {
      "id": "e4848f35-9dd8-5665-956d-438881b634e3",
      "kind": "group",
      "name": "Domain Users"
    },
    {
      "id": "f7f92012-64ac-5a50-a58a-7dcdb6f6172d",
      "kind": "group",
      "name": "Accounting"
    }
  ],
  "principals_allowed_to_retrieve_password": []
}
```

Награда за вызов: **0.0**. Накопленная награда с учётом alert: **5.0**.

### 9. `finish_investigation`

**Что хотим выяснить:** достаточно ли собранных наблюдений для итогового вердикта и конкретных мер реагирования.

**Гипотеза:** наблюдаемая цепочка входа, записи и запуска исполняемого файла и его исходящего соединения достаточна для вердикта `malicious`; данных об устройстве-источнике недостаточно для отдельного вывода о нём.

**Почему этот вызов и параметры:** `finish_investigation` получает вердикт, итоговый `reasoning` и пять ID, уже встреченных в alert или ответах тулов. Каждая пара `entity_id` + `kind` указывает на конкретный объект и действие.

**Почему именно эти пары:**

- Рабочая станция `NB-AIVANOVA` (`67ba75fb-76b7-593a-96b2-e42d7f348ffe`) → `host_to_isolate`: на ней принят RDP-вход, записан и запущен файл, от неё вышло соединение к внешнему адресу. Это хост с наблюдаемой активностью инцидента; его изоляция сдерживает дальнейшую внешнюю связь.
- Учётная запись `CORP\a.ivanova` (`830ce742-9f44-5e2f-b91a-0a79d9f36d91`) → `identity_to_rotate`: связь `logged_on_to` показывает RDP-вход под ней, а SID совпадает с `user_sid` процесса. Смена пароля и отзыв сессий закрывают повторный доступ через ту же учётную запись; способ получения пароля здесь не предполагается.
- Файл `Diagnosis.exe` (`8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa`) → `file_to_delete`: `wrote_file` показывает запись Explorer.EXE до запуска; путь и хеш совпадают с исполняемым образом процесса. Его нужно изъять или поместить в карантин, сохранив копию и хеш для анализа.
- Исходящее соединение к `154.89.152.59:443` (`57c95e94-bb01-5856-a031-2cdc39ab3070`) → `network_block`: связь `connected_to` привязывает его к `Diagnosis.exe`; блокировка назначения прерывает наблюдаемый внешний канал. Артефактом является именно соединение, поскольку его адрес и порт известны из телеметрии.
- Процесс `Diagnosis.exe` (`befe11af-28cd-5fde-8f4e-311febd53eac`) → `process_observed`: в alert и графе есть PID, пользователь, родитель Explorer.EXE, время запуска и связь с внешним соединением. Это самостоятельное доказательство исполнения для форензики; изоляция хоста и изъятие файла закрывают меры сдерживания.

Устройство-источник с IP `10.45.200.50` не включено как `host_to_isolate`: доступные результаты не показывают на нём запуск этого файла или иную вредоносную активность, а возможность управлять этим устройством не установлена.

**Проверка в ответе:** отчёт принят, эпизод завершён.

**Аргументы**

```json
{
  "submission": {
    "verdict": "malicious",
    "ir_artifacts": [
      {
        "entity_id": "67ba75fb-76b7-593a-96b2-e42d7f348ffe",
        "kind": "host_to_isolate"
      },
      {
        "entity_id": "830ce742-9f44-5e2f-b91a-0a79d9f36d91",
        "kind": "identity_to_rotate"
      },
      {
        "entity_id": "8c7ab0d7-74a2-5e3b-a243-5b8dfe155caa",
        "kind": "file_to_delete"
      },
      {
        "entity_id": "57c95e94-bb01-5856-a031-2cdc39ab3070",
        "kind": "network_block"
      },
      {
        "entity_id": "befe11af-28cd-5fde-8f4e-311febd53eac",
        "kind": "process_observed"
      }
    ],
    "reasoning": "На NB-AIVANOVA с адреса 10.45.200.50 произошёл вход CORP\\a.ivanova по RDP: событие RemoteInteractive с тем же logon_id сопоставлено с входящим TCP/3389. В этой сессии Explorer.EXE записал C:\\Users\\a.ivanova\\Desktop\\Diagnosis.exe в 09:02:30, затем запустил его в 09:03:00. У файла совпадают путь и SHA-256 с процессом; для файла указано signed=false. Процесс Diagnosis.exe установил исходящее TCP-соединение с 154.89.152.59:443 в 09:03:02. Совокупность появления и запуска неподписанного исполняемого файла после удалённого входа и немедленной внешней связи обосновывает вердикт malicious. Репутация хеша и адреса в доступных данных не проверена; содержимое соединения и способ передачи файла не наблюдаются. На NB-AIVANOVA наблюдается вся цепочка, поэтому хост нужно изолировать (host_to_isolate). Сессии CORP\\a.ivanova следует отозвать и сменить пароль (identity_to_rotate), так как под этой учётной записью произошли вход и запуск. Diagnosis.exe следует изъять с сохранением копии для анализа (file_to_delete). Наблюдаемое соединение с 154.89.152.59:443 следует заблокировать (network_block). Процесс Diagnosis.exe фиксируется как доказательство исполнения и сетевой связи (process_observed). Данных о процессах на устройстве-источнике и происхождении учётных данных нет, поэтому отдельный вывод о нём не делается."
  }
}
```

**Фактический результат**

```json
"Report accepted"
```

Награда за вызов: **45.0**. Накопленная награда с учётом alert: **50.0**.

## Что используется и что остаётся за пределами вывода

Вывод опирается на путь и хеш процесса, его PID, parent PID, SID, session_id и logon_id; совпадение пути и хеша с файловой сущностью и её signed=false; время и источники wrote_file и win_process_create; направление, адреса, порты и время соединений; тип, IP и logon_id события logged_on_to; SID, состояние и группы учётной записи в AD. ID связей соединяют процесс с внешним TCP, файл с Explorer.EXE, а учётную запись и сессию — с удалённым входом.

Поиск SHA-256 здесь находит совпадения внутри графа; он не запрашивает репутацию. В сценарии нет TI-данных для хеша или внешнего IP, поэтому их известная вредоносность не установлена. Порт 443 не доказывает HTTPS, TLS или управляющий протокол. Cmdline не содержит аргументов и не является самостоятельным индикатором. Для файла signed=false установлен только после первого поиска; signed=null у процесса в alert не означает отсутствие подписи. Отсутствие DNS и других событий в учебном графе не доказывает их отсутствия вне него. Известны адрес и имя устройства-источника, но нет его процессной телеметрии, журнала VPN, обычной географии входов пользователя или данных о происхождении учётных данных. Способ передачи файла по RDP не наблюдается. Дополнительное изучение этих вопросов потребовало бы других данных; штатное членство в AD не отменяет наблюдаемую подозрительную цепочку.

**Итог:** 9 вызовов, награда **50.0 / 50.0**, quality **1.0**, efficiency **1.0** по локальной конфигурации прогона.
