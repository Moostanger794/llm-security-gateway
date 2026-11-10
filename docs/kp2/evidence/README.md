# Переносимые доказательства offline-проверки

Запуск 10.11.2026, **19:04:37–19:05:04 МСК** (16:04:37–16:05:04 UTC).
Исходный HEAD: `01e6f23342a3d5d727f53891cbd57bb9601b9c7c`;
ветка `kp2-preparation`, **dirty=true**: в дереве уже были README, demo,
тесты и материалы подготовки. SHA относится к коду на момент прогона,
а не к будущему коммиту этого пакета.

- [checks.json](checks.json): версии окружения, команды и exit codes.
- [injection-rules.json](injection-rules.json): полный rules-отчёт v2.2 с
  sample IDs, confusion matrix, действиями, latency, corpus hashes и конфигурацией.
- [legacy-rules.json](legacy-rules.json): отдельный benchmark v1.
- [../demo-output.txt](../demo-output.txt): фактический stdout + guard stderr.
- [artifacts.json](artifacts.json): хеши артефактов, результаты статических проверок.

Два JSON benchmark скопированы из результатов без пересчёта или ручной правки.
Они не содержат исходную почту, API-ключи или payload inputs.
`checks.json` хранит exit codes; итог pytest — 634 passed, 2 warnings.
Полные локальные логи находятся в игнорируемом `benchmark-reports/kp2-20261110/`.
Реальная LLM не вызывалась. MockTransport handoffs не являются сетевыми запросами.
Hashes относятся к байтам рабочего дерева; CRLF/LF может менять хеш при checkout.
