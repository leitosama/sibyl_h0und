# Разработка

## Окружение

Нужны Python 3.11+ и [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env.h0und2   # токен для разработки, AGENT_NAME=h0und2
cp .env.example .env.h0und1   # токен для зачёта,     AGENT_NAME=h0und1
```

В профилях задаются `SCENARIO_RUNTIME_TOKEN` (с сайта соревнования) и
`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_DEFAULT_MODEL` (от провайдера). Все
`.env*`, кроме `.env.example`, игнорируются git'ом.

Запуск:

```bash
uv run --env-file .env.h0und2 h0und   # разработка и бенчи до 10 октября
uv run --env-file .env.h0und1 h0und   # зачёт 10 октября
```

`--env-file` обязателен: gRPC берёт `GRPC_DNS_RESOLVER` из окружения процесса.
Если рядом лежит обычный `.env`, `settings.py` дочитывает из него значения,
которых нет в профиле. Чтобы не путаться, держим только профили.

## Проверки

То же, что гоняет CI (`.github/workflows/ci.yml`), без сети и ключей:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

## Порядок работы

- Каждая задача делается в отдельной ветке и уходит PR'ом в `main`. PR
  смотрит человек.
- Код, комментарии, docstring'и и сообщения коммитов пишем на английском,
  документацию в `docs/` — на русском.
- Перед PR проверки должны быть зелёными.
- `src/bluesec1_client/` и `proto/` не трогаем. Сгенерированный код
  обновляется только скриптом `scripts/generate_remote_proto.py`.

## Бенчи

- Тренируемся на арене `practice` (`SCENARIO_RUNTIME_ARENA=practice`).
  Одновременно открыт только один run, частота запусков ограничена.
- Сравниваем `total_reward`, `quality_score`, `efficiency_score` и `tool_calls`
  по задачам до и после изменения.
- В `tests/fixtures/` храним 1–2 обезличенные задачи с ответами инструментов
  для офлайн-тестов. Больше не нужно: полный дамп задач только перегрузит
  контекст.

## Трейсы

Каждый run пишет трейсы в каталог вне репозитория:
`$TRACE_DIR` (по умолчанию `~/.local/share/sibyl_h0und/traces/`). Отключить
запись можно через `TRACE_ENABLED=false`. Ошибка записи трейса не прерывает
run: в лог попадает предупреждение, событие пропускается.

Трейсы **не хранятся в репозитории**: они раздувают контекст агентов и
сессий разработки, а публиковать содержимое задач правила запрещают.
`traces/` и `*.trace.jsonl` на всякий случай добавлены в `.gitignore`.

### Формат

```
traces/
  20261005T120000Z_<run_id>/
    001_<task_id>.trace.jsonl     одна задача, одно событие на строку
    002_<task_id>.trace.jsonl
```

У каждой строки есть общие поля `ts`, `run_id`, `task_id`, `seq`, `step`,
`kind`, у вызовов ещё `duration_ms`. Рядом лежат короткие поля события, а сырые
данные — во вложенном `payload`.

| `kind` | Плоские поля | `payload` |
| --- | --- | --- |
| `task_start` | — | `run`: настройки run'а без секретов (модель, лимиты, арена); `task`: задача целиком, включая `observation` и `available_tools` |
| `llm_call` | `attempt`, `tokens` | `prefix`, `messages`: новые сообщения запроса (см. ниже), `raw_content` (ответ модели как есть) |
| `step` | `tool` | `step`: разобранный `NextStep` |
| `tool_call` | `tool`, `status`, `reward`, `terminated`, `truncated` или `error` | `arguments`, `response`: полный `ToolCallResult` от runtime |
| `tool_rejected` | `tool` | `arguments` вызова, отклонённого локально (инструмента нет в каталоге или GraphLedger не знает id), `feedback`: ответ модели |
| `tool_cached` | `tool` | `arguments` повторного вызова и `feedback`: прежний ответ из кэша GraphLedger |
| `task_end` | `completion_reason`, `total_reward`, `quality_score`, `efficiency_score`, `tool_calls`, `steps_taken`, `agent_steps`, `runtime_calls`, `llm_calls`, `llm_tokens`, `llm_ms`, `error` | `task_result` |

Один `llm_call` пишется на каждую попытку, включая ремонт невалидного ответа.
Запрос к LLM целиком не хранится: история растёт с каждым шагом, и полные
копии раздували трейс квадратично. `prefix` — сколько первых сообщений
запрос делит с предыдущим `llm_call` той же задачи, `messages` — сообщения
после них. Полный запрос шага N — это первые `prefix` сообщений запроса
N−1 плюс `messages`. Префикс может быть короче предыдущего запроса: после
ремонта следующий шаг идёт без неудачного ответа и инструкции ремонта.
Собирает полные запросы `sibyl_h0und.trace.llm_requests(events)`; в старых
трейсах `prefix` нет, и `messages` там — полный запрос.
Если агент упал, текст ошибки лежит в `error` у `task_end`. Ответы runtime
сохраняются целиком, поэтому по трейсу задачу потом можно проиграть офлайн.
Каждое событие дописывается в файл сразу, так что после падения остаётся всё,
что было до него.

### Просмотр

Отдельного просмотрщика в коде нет, хватает готовых инструментов. В
зависимости проекта они не входят, их ставят отдельно (`brew`, `apt` или
`uv tool install visidata`).

Одна задача по шагам:

```bash
T=~/.local/share/sibyl_h0und/traces/<run>/001_<task_id>.trace.jsonl
jq -r 'select(.kind=="step") | "\(.step) \(.tool): \(.payload.step.current_state)"' $T
jq -c 'select(.kind=="tool_call") | {step, tool, status, duration_ms, args: .payload.arguments}' $T
jq 'select(.kind=="llm_call" and .step==3) | .payload.messages' $T   # что добавилось в контекст LLM на шаге 3
vd $T     # visidata: таблица событий, Enter проваливается в payload
jless $T  # или fx: сворачиваемый JSON
```

Сводка по прогонам через DuckDB (`duckdb` CLI или `uv run --with duckdb python`):

```sql
-- итоги задач по всем run'ам
select run_id, task_id, completion_reason, total_reward, tool_calls, llm_tokens, duration_ms
from read_json_auto('~/.local/share/sibyl_h0und/traces/*/*.trace.jsonl', union_by_name=true)
where kind = 'task_end';

-- на какие инструменты уходят вызовы и время
select tool, count(*) as calls, avg(duration_ms) as avg_ms
from read_json_auto('~/.local/share/sibyl_h0und/traces/<run>/*.trace.jsonl', union_by_name=true)
where kind = 'tool_call'
group by tool order by calls desc;
```

Разбор задачи в сессии с Claude: даём `task_id` и путь к трейсу, читаем
нужные шаги и правим промпт или код в ветке.

Офлайн-проигрывание записанных задач пока только планируется. Ограничение:
записанная задача может ответить только на те вызовы, которые были в записи.
Если агент после правки идёт по другому пути, такую задачу нужно перепроверять
на арене.
