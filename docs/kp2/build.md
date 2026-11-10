# Сборка редактируемой PPTX

Готовый файл: [KP2_AI_Security_Gateway.pptx](../../deliverables/kp2/KP2_AI_Security_Gateway.pptx).
Источник содержания и геометрии — [slides.json](slides.json),
генератор — [build_kp2_deck.mjs](../../scripts/build_kp2_deck.mjs).
[slides.md](slides.md) автоматически формируется из того же источника.

Использован изолированный authoring runtime Codex: Node 24.22.1,
`@oai/artifact-tool` 2.8.129, шрифт Arial (доступен в Windows).
Runtime SDK проекта и pyproject не изменены. Зависимости оформления
не установлены в проектную .venv. Генератор не обращается к LLM или сети.

Для повторной сборки нужны пути к установленному bundled runtime,
возвращаемые load_workspace_dependencies, и установленному навыку Presentations.
Это отдельное условие пересборки: готовая PPTX редактируется в PowerPoint без них.
Произвольные системы без этого authoring runtime не объявляются поддержанными.

```powershell
# Заменить значения путями своей установки, не путями из чужого профиля.
$env:RUNTIME_NODE_MODULES = '<bundled node_modules>'
$env:ARTIFACT_TOOL_MODULE = Join-Path $env:RUNTIME_NODE_MODULES '@oai/artifact-tool/dist/artifact_tool.mjs'
$env:PRESENTATIONS_SKILL_DIR = '<каталог навыка presentations>'
$env:ARTIFACT_PYTHON = '<bundled python.exe>'
& '<bundled node.exe>' scripts/build_kp2_deck.mjs
```

Сборка создаёт отдельный датированный каталог `build/kp2/` (игнорируется Git),
проверяет OOXML, геометрию, шрифт, нативные таблицы и повторный импорт,
копирует проверенную PPTX в deliverables, повторно импортирует именно эти байты
и рендерит все 9 слайдов. Валидатор использует hardlink; Windows sandbox может
потребовать разрешённого локального запуска. Каталог последней сборки записан
в `build/kp2/latest-build.txt`. Служебные PNG и validation receipt в PR не входят.

После изменения содержания: пересобрать, просмотреть все слайды, сверить отчёт,
пересчитать речь и обновить hashes. Основные слайды 1–7 видимы, приложения 8–9
скрыты из обычного показа, доступны для вопросов. Нативные таблицы: 2, 3, 6, 8.
Ссылки на репозиторий кликабельные. Все данные, текст и схема редактируются.

Финальную PPTX нужно открыть на устройстве выступающего и проверить шрифты,
порядок показа и переключения. Рендер проверен через Artifact Tool; открытие
в Microsoft PowerPoint в ходе подготовки не выполнялось.
