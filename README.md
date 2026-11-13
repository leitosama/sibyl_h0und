# sibyl_h0und

ИИ-агент для расследования инцидентов на соревновании
[BlueSec](https://bluesec.team/) от Positive Technologies. Агент получает алерт,
обходит граф улик через gRPC-инструменты runtime и выносит вердикт: атака с
артефактами для реагирования или легитимная активность с доказательствами.
Баллы дают за верный вердикт и полноту, а за каждый лишний вызов инструмента
их снимают.

Агент один — команда `h0und`. Запускается он под одним из двух токенов
runtime, у каждого свой профиль `.env`:

- **`h0und2`** — токен для разработки, им пользуемся до соревнования;
- **`h0und1`** — токен для зачёта 10 октября 2026 (финал прошёл 12:30–16:00
  МСК), его статистика начинается с чистого листа.

## Итог финала

**25-е место, 19,39 балла.** Агент `h0und1` на модели Qwen3.8-27B решил
40 из 40 задач за 45 минут 50 секунд. Для сравнения: первое место — 37,59,
второе и третье — 25,79 и 25,78, топ-10 — около 23–26 на фронтир-моделях.

Что говорили участники о подходах и силе моделей и какие уроки из этого
следуют для нас — в [docs/finals-review.md](docs/finals-review.md).

## Быстрый старт

```bash
uv sync
cp .env.example .env.h0und2         # заполнить ключи runtime и LLM
uv run --env-file .env.h0und2 h0und
```

Подробности — в [docs/development.md](docs/development.md).

## Документация

| Документ | О чём |
| --- | --- |
| [docs/competition.md](docs/competition.md) | правила, сроки, оценка, протокол runtime, инструменты |
| [docs/example-investigation.md](docs/example-investigation.md) | учебный пример расследования от организаторов и выводы из него |
| [docs/architecture.md](docs/architecture.md) | как устроены агенты сейчас и куда идём |
| [docs/development.md](docs/development.md) | окружение, проверки, порядок работы, бенчи, трейсы |
| [docs/finals-review.md](docs/finals-review.md) | итоги финала: подходы участников, сила моделей, уроки для нас |
| [CLAUDE.md](CLAUDE.md) | инструкции для Claude Code |

## Структура

| Путь | Что это |
| --- | --- |
| `src/sibyl_h0und/` | наш агент: промпт, цикл рассуждений, схемы, CLI |
| `src/bluesec1_client/` | клиент runtime — копия от организаторов, не правим |
| `proto/` | gRPC-схема runtime |
| `tests/` | тесты без сети |

Основа — [базовый агент организаторов](https://github.com/False-Positive-Community/bluesec1-agent).

## Материалы для разбора

Статьи, на которые ссылались в чате участников после финала. Ещё не
разобраны.

- [Статья организаторов о соревновании](https://habr.com/ru/companies/pt/articles/1085878/) (Хабр)
- [Опыт участника по итогам соревнований](https://habr.com/ru/articles/1093344/) (Хабр)
- Серия постов участника о bluesec1: части 1–2 (устройство задач, формула
  оценки, типичные ошибки агентов, недостатки базового харнесса) пересказаны в
  [docs/finals-review.md](docs/finals-review.md); обещаны часть 3 и пост с
  архитектурой решения.
- [Introducing System One models and Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev) — модели-классификаторы, которые пробовали вместо LLM
- [Let Me Speak Freely? A Study on the Impact of Format Restrictions on Performance of Large Language Models](https://arxiv.org/abs/2408.02442) — structured output против свободного ответа

## Лицензия

GPL-3.0, см. [LICENSE](LICENSE).
