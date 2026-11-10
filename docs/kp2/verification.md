# Проверка КП2: фактические результаты 10.11.2026

Финальный offline-набор: **19:04:37–19:05:04 МСК**
(16:04:37–16:05:04 UTC). **Реальных LLM-запросов — 0**.
Существующие demo и тесты переиспользованы. После этого прогона Python-код,
правила, датасеты, метрики и runtime-зависимости не менялись.

## Код и окружение

- [Публичный origin](https://github.com/Moostanger794/llm-security-gateway).
- HEAD на момент измерения: `01e6f23342a3d5d727f53891cbd57bb9601b9c7c`.
  Он проверен через Git, а не принят автоматически из старого отчёта.
- Ветка `kp2-preparation` создана от этого HEAD с сохранением текущего дерева.
- **dirty=true**: начальные изменения README, docs/kp2, demo и его тестов
  сохранены. Оба корневых файла заданий оставлены вне staging.
- Это SHA измеренного состояния кода, не SHA будущего коммита документации.
  Полные команды, версии и exit codes — [checks.json](evidence/checks.json).

Python 3.12.14; FastAPI 0.141.1; Starlette 1.6.0; Pydantic 2.13.5;
pydantic-settings 2.15.0; Uvicorn 0.53.0; HTTPX 0.28.1;
OpenAI SDK **2.54.0** (pin сохранён); pytest 9.1.1; AnyIO 4.15.1;
Ruff 0.16.8; pip 25.0.1. Существующая .venv не обновлялась.

## Выполненные проверки

| Проверка | Exit | Результат |
| --- | ---: | --- |
| `python -m pytest -q` | 0 | **634 passed**, 13,98 с, 2 warnings; включает 16 demo-тестов |
| `python -m ruff check .` | 0 | All checks passed |
| `python -m ruff format --check .` | 0 | 62 files already formatted |
| `python -m pip check` | 0 | No broken requirements found |
| `python scripts/smoke_prompt.py` | 0 | health + 6 analyze HTTP-проверок; штатный stop Uvicorn |
| `python scripts/smoke_llm.py` | 0 | offline_mock_not_model_quality, 3 MockTransport handoff |
| `python -m ai_security_gateway.evaluation.benchmark` | 0 | 64 записи, TP/TN/FP/FN=27/19/13/5 |
| `python -m ai_security_gateway.evaluation.comparison --mode rules --split all` | 0 | 32 записи, TP/TN/FP/FN=4/15/1/12, coverage=1 |
| `python scripts/kp2_demo.py` | 0 | ALLOW / BLOCK / BLOCK / ALLOW, provider attempts=0 |

`python` в таблице — проектный `.venv/Scripts/python.exe`.
Два warnings: Starlette deprecated httpx TestClient; AnyIO deprecated alias
BlockingPortal. Они не подавлялись, причины находятся в зависимостях.
Обновление runtime ради оформления в задачу не входит.

Для запуска скопирован прежний локальный audit driver в
`benchmark-reports/kp2-20261110/`, без изменения тестируемого кода.
Окружение дочерних процессов исключало ambient LLM_/OPENAI_, ключ и модель пусты,
оба opt-in флага false. Временный sitecustomize запрещал внешние DNS/connect/sendto,
включая дочерние Python-процессы. В основных логах blocked_external_attempts=0.
Pytest имеет собственный offline fixture, demo — собственный guard.
Старые ограничения Windows sandbox/socketpair учтены разрешённым локальным
запуском; используются отдельные temp/cache проекта. Внешняя сеть не нужна.

Тесты доказывают программные контракты, лимиты, приватность, fallback и cleanup,
а не реальную полноту защиты. MockTransport проверяет интеграцию, а не модель.
Исполнение инструментов и end-to-end ASR настоящего агента не проверяются.

## Метрики и границы интерпретации

Числа, определения и latency приведены в [отчёте, раздел 5](report.md),
а точные результаты — [injection-rules.json](evidence/injection-rules.json)
и [legacy-rules.json](evidence/legacy-rules.json).

- Injection v2.2: ASR proxy=12/16=75%; FPR=1/16=6,25%;
  benign ALLOW=15/16=93,75%. Mean=0,283478 ms; P95=0,450700 ms.
- Legacy v1 отдельно: ASR=5/32=15,625%; FPR=13/32=40,625%;
  benign ALLOW=19/32=59,375%. Mean=0,137791 ms; P95=0,262700 ms.
- Разные корпуса не являются сравнением версий алгоритма.
- ASR proxy считает прохождение фильтра, при текущей политике совпадает с FNR.
  FPR включает REQUIRE_CONFIRMATION. Один пример из 16 меняет долю на 6,25 п.п.
- Один проход без прогрева, perf_counter, P95 nearest rank. HTTP и модель не входят.
  Latency меняется между запусками; не является SLA.
- Качество, tokens, стоимость и latency настоящей LLM не измерены.
  Hybrid не может снизить FPR правил на тех же входах.

## Презентация и согласованность материалов

Создана настоящая [PPTX](../../deliverables/kp2/KP2_AI_Security_Gateway.pptx):
9 слайдов 16:9, из них основные 1–7, скрытые приложения 8–9.
Текст, таблицы и схема редактируемые; нативные таблицы на 2, 3, 6, 8.
Ссылка GitHub кликабельная на каждом слайде.
[Генератор и пересборка](build.md), [единый JSON-источник](slides.json).

OOXML integrity, геометрия, шрифт Arial, native tables и повторный импорт —
pass, без findings и warnings валидатора. Итоговые байты PPTX повторно импортированы,
все **9 слайдов отрендерены и просмотрены по отдельности**.
Текст читается, нежелательных пересечений и обрезки не обнаружено.
В Microsoft PowerPoint не открывалось; финальный показ на устройстве команды
нужно проверить. Локальные рендеры/receipt находятся в игнорируемом build/kp2.

Речь: **198 слов**, 108 секунд чистой речи + 12 секунд переходов, пять участников,
слайды последовательно 1–7. Это расчёт, не проведённая репетиция.
Значения из demo, benchmark, отчёта и слайдов сверены; скрытого улучшения правил нет.
Итоги проверки ссылок, структуры PPTX, хешей и отсутствия типичных секретов
сохранены в [artifacts.json](evidence/artifacts.json). Ограниченный скан маркеров
не является универсальным secret scanner.

## Данные, hashes и происхождение

Пересчитано strict loader: **24 synthetic + 8 adapted + 0 unmodified imported**.
Dev=17 (10 safe/7 attack), holdout=15 (6 safe/9 attack). Восемь adapted связаны
с четырьмя исходными BIPIA payload, все в группе `bipia-shared-response-wrapper`
и split=holdout. Группы/семейства не пересекают split; canonical input SHA
сверены loader. Это проверка локальных данных, не независимая проверка upstream.

SHA-256 фактических **CRLF-байтов рабочего дерева** финального запуска:

| Файл | Строк | SHA-256 |
| --- | ---: | --- |
| datasets/prompts/v1.jsonl | 24 (16 prompt + 8 text) | `c3857750c767fb08569cb859ddade237bf0bf97534b5bba0d85b60a21b5a4bc5` |
| datasets/emails/v1.jsonl | 20 | `a1f466b27e0c9baec059954ef7c774bbd7733c7036427323225b4ea03f6f470d` |
| datasets/urls/v1.jsonl | 20 | `5132168429cf1d22341eb9d80a47a8764d379df18e2da6b3007eb072fdfd36ec` |
| datasets/indirect_injection/dev.jsonl | 17 | `2006756bff9a80a35b4903871739478210ce2c9a4ba1e06497345c4660c06c40` |
| datasets/indirect_injection/holdout.jsonl | 15 | `f3222d6b3494fee0d6a83e0298c2fdfdf80632ba3881ae53bbe20ec146bc2dd3` |

`git ls-files --eol` показывает `i/lf w/crlf`. Дополнительно побайтово проверено:
замена CRLF на LF в каждом текущем JSONL даёт ровно `git show HEAD:<path>`.
Датасеты в этой задаче не изменены. Для LF-checkout SHA-256 текущих Git blobs:

```text
prompts/v1.jsonl           bfe49d1948eec701f538e150055af6554c1a77ccb83c66fcf141db2072235bac
emails/v1.jsonl            49f90b332cf0ce17fb48c72dfea78f1fb231342f7bc4bd74fa2cd5367757932a
urls/v1.jsonl              12afa5e9aefbc17734ac7c36c2378e2cdc3ca91e65accbd057e01bb352b918f3
indirect_injection/dev     7959e0cbebdc1b3d6d76d46a1a38b2dadb9d078ee63d018ed010a54715e76826
indirect_injection/holdout 51a063fc66b16b6f41101d829261e506afa9fe042f1be947600282ee44c1980f
```

Исторические injection SHA из Phase 6 совпадают с LF-версией. Исторические
legacy SHA в [evaluation.md](../evaluation.md) не совпадают ни с текущими CRLF,
ни с текущими Git LF-байтами: причину прежнего pre-publication snapshot здесь
не установили. `git diff 7a56b32 HEAD -- datasets/*/v1.jsonl` пуст, текущий rules
результат воспроизведён; старые hashes не выданы за новые доказательства.

По сохранённому [manifest](../../datasets/indirect_injection/manifest.json):
upstream `https://github.com/microsoft/BIPIA`, revision
`a004b69ec0dd446e0afd461d98cb5e96e120a5d0`, файл
`benchmark/text_attack_train.json`, исходный split `train`, Git blob
`190918308f4ef25d5f43d7c1b118bf3fe5dc61d2`.

| Исходный JSON pointer | Сохранённый SHA-256 исходной строки UTF-8 |
| --- | --- |
| `/Alphanumeric Substitution/0` | `893ef0ba7ed8dbe60faa6fea7f2d8d2c59a2cb291fd2ec30ac8ce414edc86e25` |
| `/Instruction/0` | `6cf8543112cc4e23a579e89f28a38cd09a3f7add329a7de10b7c861fe4d7986e` |
| `/Space Removal & Grouping/0` | `abeda7efcc2721dde41672a6f725e80957c430fbee92387750bdc0a16a4caac9` |
| `/Misspelling Intentionally/0` | `dc3ad4be5d325a3378436cbddf72113e2bdd06abaa5045ddbbb4d16ad12e1d38` |

Выбранный компонент — MIT по ранее сохранённому review лицензии; исключения
сторонних context datasets не переносятся на нашу выборку автоматически.
Copyright Microsoft и полный notice сохранены в
[BIPIA-LICENSE.txt](../../datasets/indirect_injection/BIPIA-LICENSE.txt), notice
есть на каждой строке. Отдельного файла `NOTICE` в этом корпусе нет.
EmailQA-контексты, LLMail-Inject и AgentDojo не импортированы/не запускались.
Сами исходные четыре payload отдельно не vendored; локально лежат адаптации и
metadata. **Удалённые Git blob/source SHA в этой задаче независимо не сверялись**,
`verify_injection_sources.py --download` не запускался. Локальная согласованность
metadata и input hashes не доказывает подлинность удалённых байтов.

## Остаточные пробелы

Вклад участников, причины переноса и самооценка требуют согласования;
предложения не объявлены подтверждёнными фактами. Номер команды и даты выступления/
финала не выдумывались. Форма не отправлялась. ToolGuardian, RuntimeMonitor,
UI и полноценный RedTeamRunner не реализованы. Live LLM и внешняя почта не проверялись.

Репозиторий публичный по проверке GitHub; видимость не менялась.
Код и материалы публикуются в draft PR, merge не выполняется.
Два локальных файла заданий остаются untracked и не удаляются.
