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
  Одновременно активно до 10 run'ов, в каждом по одной задаче, и не больше
  10 новых run'ов за 30 минут (см. [competition.md](competition.md)).
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

Формат событий определён в одном модуле, `sibyl_h0und.trace`: `TaskTrace`
пишет каждый `kind` своим методом, `read_task` читает те же события обратно
(так читает и replay). Поля можно добавлять, переименовывать нельзя: старые
трейсы должны читаться (ADR 0008).

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

### Покрытие словаря

`scripts/replay_knowledge.py` берёт из сохранённых трейсов термины, которые
увидел записанный агент (образы, `original_filename`, родительские образы,
имена хостов), и спрашивает о каждом словарь, тот же, что стоит за
`lookup_knowledge`. Без модели и runtime. Первый запуск вытаскивает из трейсов
задачу, вызовы с ответами, вердикт и оценки в кэш `replay/` рядом с каталогом
трейсов (по умолчанию `~/.local/share/sibyl_h0und/replay`; каталог трейсов
берётся из `$TRACE_DIR`, как у агента). Дальше читается только кэш.

```bash
uv run python scripts/replay_knowledge.py                  # источники по задачам
uv run python scripts/replay_knowledge.py --details        # термины подозрительных задач
uv run python scripts/replay_knowledge.py --save before    # запомнить результат
uv run python scripts/replay_knowledge.py --compare before # что изменилось после правки пакета
```

Новый источник сливаем после сравнения с `main`: `--save main` на `main`,
`--compare main` на ветке. Сравнение показывает, какие записи источник
добавил и где, и ловит источник, который отвечает там, где не должен.

Таблица показывает, на скольких подозрительных и прочих задачах у источника
есть запись о чём-то, что агент видел. Это покрытие словаря, а не оценка:
повлияла ли запись на вердикт, видно только на `practice` (ADR 0017).
Источник Nextron отвечает на любой путь, поэтому его строка почти всегда
полная.

### Пакеты знаний

Снимки собираются скриптами и коммитятся, сеть нужна только при сборке:

```bash
uv run python scripts/build_lolbas_pack.py                      # скачать и собрать
uv run python scripts/build_lolbas_pack.py --input lolbas.json  # из скачанного файла
```

Новый источник: скрипт `scripts/build_<имя>_pack.py`, запись в
`src/sibyl_h0und/knowledge/NOTICE`, чтение пакета в `vocabulary.py` и тесты на
запросы, которые находят его записи. Правил, оценивающих записи, нет.

Рантайм не говорит, был ли вердикт верным, поэтому «подозрительной» считаем
задачу с `quality_score` ниже `--wrong-below` (по умолчанию 0.2). Это
эвристика, порог подбираем по трейсам. Задачи разных run'ов считаются
отдельно: на `practice` id задач повторяются. Покрытие считается только по
терминам, которые видел записанный агент.
