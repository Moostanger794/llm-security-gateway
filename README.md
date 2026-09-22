# AI Security Gateway

Экспериментальный defensive security gateway для LLM-приложений и AI-агентов.
Команда: **le royal monceau gatsby seance**.

Сейчас реализован только **PHASE 1 — Foundation**: FastAPI, health endpoint,
конфигурация, модели HTTP-ответов, logging и обработка ошибок. Анализа угроз,
LLM-интеграции, базы данных и benchmark пока нет. `/health` проверяет доступность
процесса, а не качество защиты.

## Установка

Требуется Python 3.12+ с pip и venv. Команды выполняются из корня репозитория.
Windows PowerShell (если `python` отсутствует в PATH, укажите полный путь к нему):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Активация окружения не обязательна. Для установки только backend используйте
`pip install -e .`. Зависимости определены в `pyproject.toml`; версии ограничены
диапазонами, lock-файл на этом этапе отсутствует.

## Конфигурация и запуск

Все настройки имеют значения по умолчанию; `.env` и API keys не требуются.
При необходимости скопируйте `.env.example` в `.env`.
Переменные окружения имеют приоритет над `.env` в текущем рабочем каталоге.

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `APP_NAME` | `AI Security Gateway` | Название приложения, 1–100 символов |
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR или CRITICAL |

Некорректные значения известных настроек вызывают понятную ошибку Pydantic
при запуске. Неизвестные поля `.env` игнорируются.

```powershell
.\.venv\Scripts\python.exe -m uvicorn ai_security_gateway.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Для Linux/macOS замените путь к интерпретатору на `.venv/bin/python`.
Для разработки можно добавить `--reload`. Остановка: Ctrl+C.
Swagger UI: <http://127.0.0.1:8000/docs>, OpenAPI: `/openapi.json`.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Ответ HTTP 200:

```json
{"status":"ok","service":"AI Security Gateway","version":"0.1.0"}
```

Каждый ответ содержит `X-Request-ID`, сгенерированный сервером. Ошибки имеют
формат `{"detail":"Not Found","request_id":"..."}`. Обрабатываются HTTP-ошибки,
ошибки валидации (422) и непредвиденные ошибки обработчиков (500). Внешнему
клиенту не передаются traceback и исходные значения некорректного запроса.
В Phase 1 нет endpoint, принимающего JSON; обработка JSON/валидации проверяется
через маршруты, создаваемые исключительно внутри тестов.

Логи приложения идут в stderr: request ID, HTTP-статус, время обработки,
тип непредвиденной ошибки, запуск/остановка. Тела, заголовки, URL и тексты
исключений не логируются. `--no-access-log` отключает отдельный access log Uvicorn,
который иначе может записывать query string.

## Проверки

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

Тесты проверяют конфигурацию, модели, health/OpenAPI, lifespan, ошибки,
изоляцию экземпляров приложения и отсутствие входных данных в логах.

## Структура

```text
src/ai_security_gateway/
  __init__.py             # версия пакета
  main.py                 # create_app, lifespan, request middleware
  api/
    routes.py             # GET /health
    schemas.py            # HealthResponse, ErrorResponse
    errors.py             # HTTP/validation errors
  core/
    config.py             # Settings
    logging.py            # logging configuration
tests/
  conftest.py
  unit/                   # настройки и модели
  api/                    # HTTP-контракты
  integration/            # lifecycle и logging
docs/
  architecture.md
  threat_model.md
.env.example
.gitignore
pyproject.toml
AGENTS.md
README.md
```

Используется стандартный src-layout с устанавливаемым пакетом
`ai_security_gateway`. Подробности: [архитектура](docs/architecture.md),
[модель угроз](docs/threat_model.md). Следующий этап — PHASE 2; его компоненты
в текущую реализацию не входят.
