# sibyl_h0und

ИИ-агенты для расследования инцидентов на соревновании
[BlueSec](https://bluesec.team/) от Positive Technologies. Агент получает алерт,
обходит граф улик через gRPC-инструменты runtime и выносит вердикт: атака с
артефактами для реагирования или легитимная активность с доказательствами.
Баллы дают за верный вердикт и полноту, а за каждый лишний вызов инструмента
их снимают.

Агентов два, код у них общий:

- **`h0und1`** — для бенчей и зачёта 10 октября 2026 (14:00–18:00 МСК);
- **`h0und2`** — для разработки и разбора задач.

## Быстрый старт

```bash
uv sync
cp .env.example .env.h0und2         # заполнить ключи runtime и LLM
uv run --env-file .env.h0und2 h0und2
```

Подробности — в [docs/development.md](docs/development.md).

## Документация

| Документ | О чём |
| --- | --- |
| [docs/competition.md](docs/competition.md) | правила, сроки, оценка, протокол runtime, инструменты |
| [docs/architecture.md](docs/architecture.md) | как устроены агенты сейчас и куда идём |
| [docs/development.md](docs/development.md) | окружение, проверки, порядок работы, бенчи, трейсы |
| [CLAUDE.md](CLAUDE.md) | инструкции для Claude Code |

## Структура

| Путь | Что это |
| --- | --- |
| `src/sibyl_h0und/` | наш агент: промпт, цикл рассуждений, схемы, CLI |
| `src/bluesec1_client/` | клиент runtime — копия от организаторов, не правим |
| `proto/` | gRPC-схема runtime |
| `tests/` | тесты без сети |

Основа — [базовый агент организаторов](https://github.com/False-Positive-Community/bluesec1-agent).

## Лицензия

GPL-3.0, см. [LICENSE](LICENSE).
