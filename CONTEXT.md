# TGArtifacts — контекст для продолжения работы

## Что уже сделано

- `BaseModule` ABC в `tgartifacts/modules/base.py` — абстрактные свойства `name`, `description`, `help_text`, `requirements`, `dependencies`
- `check_requirements()` — проверяет наличие pip-пакетов, возвращает список отсутствующих
- `register_modules()` в `tgartifacts/modules/__init__.py` — autodiscovery + инжект `help_text` + обёртка команд с проверкой requirements
- `validate_dependencies()` — предупреждает если модуль ссылается на несуществующий модуль
- Все 9 модулей конвертированы в ABC, у каждого есть `help_text` с `\b` для click-форматирования

## Модули (9 штук)

| Пакет            | CLI-имя           | Зависимости    |
|------------------|-------------------|----------------|
| audit            | audit             | —              |
| bruteforce       | bruteforce        | —              |
| export_session   | export-session    | —              |
| extract_cache    | extract-cache     | —              |
| info             | info              | —              |
| list_plugins     | list-plugins      | —              |
| plugin           | plugin            | —              |
| scan             | scan              | —              |
| validate_session | validate-session  | требует telethon |

## Текущая задача: тест-кейсы и матрица тестов

### Структура tests/ (пустая, нужно создать)
```
tests/
├── fixtures/        # тестовые данные (tdata-заглушки, mock-файлы)
├── unit/            # unit-тесты модулей
└── integration/     # интеграционные тесты CLI
```

### Что покрывать

**Unit (для каждого модуля):**
- `name`, `description`, `help_text` — не пустые, правильный тип
- `check_requirements()` — корректно возвращает missing при отсутствии пакета
- `available_methods` — список строк

**Unit (BaseModule / система):**
- `discover_modules()` — находит все 9 модулей
- `validate_dependencies()` — предупреждает на missing dep, тихо при корректных
- `_wrap_with_requirements_check()` — бросает `ClickException` при missing deps

**Integration (CLI через `click.testing.CliRunner`):**
- Каждая команда: `--help` возвращает 0 и непустой текст
- validate-session без telethon: возвращает ошибку с подсказкой `pip install`
- Каждая команда с невалидным аргументом: возвращает ненулевой код

### Матрица тестов (шаблон)

| Модуль           | name/desc | help_text | check_reqs | CLI --help | CLI bad-args | CLI run |
|------------------|-----------|-----------|------------|------------|--------------|---------|
| audit            | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| bruteforce       | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| export_session   | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| extract_cache    | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| info             | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| list_plugins     | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| plugin           | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| scan             | [ ]       | [ ]       | [ ]        | [ ]        | [ ]          | [ ]     |
| validate_session | [ ]       | [ ]       | [req]      | [ ]        | [ ]          | [ ]     |
| discover_modules | —         | —         | —          | [ ]        | —            | [ ]     |
| validate_deps    | —         | —         | —          | —          | —            | [ ]     |

## Ключевые файлы

- `tgartifacts/modules/base.py` — BaseModule ABC
- `tgartifacts/modules/__init__.py` — discover, register, validate
- `tgartifacts/modules/<name>/__init__.py` — module instance (`module = ...`)
- `tgartifacts/modules/<name>/answer_cli.py` — click command (`command = ...`)
- `pyproject.toml` — extras для каждого модуля
- `tests/` — пустая, нужно наполнить
