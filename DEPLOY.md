# KukiLab Scanner — развертывание

Репозиторий движка: **https://github.com/kukilab/scanner** (организация `kukilab`). Три места назначения: **(A)** локальная папка на Mac, **(B)** GitHub-репозиторий сканера, **(C)** репозитории проверяемых навыков, **(D)** проект в Claude.

---

## Карта файлов

| Файл / папка | Что это |
|---|---|
| `src/kukilab_scanner.py` | Движок: Step 0 → Step 1 → Step 2 → вердикт → SARIF 2.1.0 |
| `action.yml` | Composite GitHub Action — `uses: kukilab/scanner@v1` |
| `requirements.txt`, `setup.sh`, `setup.ps1` | Зависимости и установка venv одним кликом |
| `.github/workflows/self-test.yml` | Самопроверка: clean → SAFE, malicious → BLOCK, SARIF валиден, action работает |
| `examples/demo-clean-skill/` | Эталонный безопасный навык |
| `examples/demo-malicious-skill/` | Тестовый вредоносный навык (zero-width, curl\|bash, HTML-комментарий, .env, crontab) — фикстура, не запускать |
| `templates/kukilab-scan.yml` | Workflow для **проверяемых** репозиториев (использует action) |
| `templates/ai-skill-readme-template-v2.md` | README с бейджами безопасности для авторов навыков |
| `templates/ai-skill-security-checklist.md` | Ручной чек-лист аудита |
| `docs/llm-threat-taxonomy-prompt-guide.md` | Таксономия P-01..P-10, промпт Step 2 |
| `docs/case-erp-pilot-2026-11-09.md` | Первый реальный аудит (ERP Pilot) — пример отчёта |
| `cicd/github-action-sarif-integration-guide.md` | Заметка по SARIF и Code Scanning |
| `LICENSE` | MIT |

---

## A. Локальная папка (Mac)

Копия репозитория лежит в `~/Downloads/Active_Hybrid_Scanner_Project` (историческое имя папки; внутри уже KukiLab). Проверка:

```bash
cd ~/Downloads/Active_Hybrid_Scanner_Project
bash setup.sh                      # создаст venv, поставит зависимости
source venv/bin/activate
python src/kukilab_scanner.py examples/demo-clean-skill       # → SAFE
python src/kukilab_scanner.py examples/demo-malicious-skill   # → BLOCK, exit 2
```

Проверить реальный навык:

```bash
python src/kukilab_scanner.py /путь/к/навыку --sarif results.sarif --json results.json
python src/kukilab_scanner.py /путь/к/навыку --fix          # очистка Unicode + allowed-tools
ANTHROPIC_API_KEY=sk-ant-... python src/kukilab_scanner.py /путь/к/навыку   # Step 2 через API
```

Ключи CLI: `--fix`, `--sarif FILE`, `--json FILE`, `--markdown FILE`, `--quiet`, `--no-llm`, `--model`, `--fail-on BLOCK|CAUTION|NEVER`, `--cache FILE` (пропуск неизмененных пакетов по SHA-256), `--force`, `--baseline` (применить подавления из проверяемого репозитория; по умолчанию они не применяются).

---

## B. GitHub-репозиторий сканера — `kukilab/scanner`

Создан 10.11.2026, публичный. Что осталось сделать руками в Settings:

1. **General → Pull Requests → Automatically delete head branches** — включить.
2. **Code security → Dependabot version updates** — `pip`, weekly (покрывает пункт «еженедельный аудит зависимостей»).
3. После первого стабильного состояния — создать релиз/тег `v1`, чтобы проверяемые репозитории могли писать `uses: kukilab/scanner@v1` и публиковать action в GitHub Marketplace (кнопка «Draft a release» → «Publish this Action to the GitHub Marketplace»).

Структура репозитория:

```
scanner/
├── README.md · DEPLOY.md · LICENSE · requirements.txt · setup.sh · setup.ps1 · .gitignore
├── action.yml                                   ← composite action
├── .github/workflows/self-test.yml
├── src/kukilab_scanner.py
├── examples/{demo-clean-skill, demo-malicious-skill}/
├── templates/{kukilab-scan.yml, ai-skill-readme-template-v2.md, ai-skill-security-checklist.md}
├── docs/{llm-threat-taxonomy-prompt-guide.md, case-erp-pilot-2026-11-09.md}
└── cicd/github-action-sarif-integration-guide.md
```

---

## C. Репозиторий проверяемого навыка (каждый)

1. Скопировать `templates/kukilab-scan.yml` в проверяемый репозиторий как **`.github/workflows/kukilab-scan.yml`** — он уже ссылается на `kukilab/scanner@v1`, править ничего не нужно.
2. (Опционально, для настоящего LLM-пасса) **Settings → Secrets and variables → Actions → New repository secret**: имя `ANTHROPIC_API_KEY`. Без ключа Step 2 работает на офлайн-эвристиках и сборка не падает.
3. **Settings → Code security → Code scanning** — убедиться, что включено (на публичных репозиториях включено по умолчанию; на приватных нужен GitHub Advanced Security — тогда шаг upload-sarif можно убрать, отчёт всё равно будет в Summary и артефакте).
4. Чтобы PR блокировался при вердикте BLOCK: **Settings → Branches → Branch protection rule** для `main` → *Require status checks to pass* → выбрать `KukiLab Step 0 / 1 / 2`.

После первого запуска:
- вкладка **Actions** → в Summary появится Markdown-отчет сканера;
- вкладка **Security → Code scanning alerts** → находки с номерами строк и правилами P-01..P-10 / LP3 / AST7;
- в README навыка вставить бейдж из `templates/ai-skill-readme-template-v2.md`.

Минимальный вариант без шаблона — три строки в любом workflow:

```yaml
- uses: kukilab/scanner@v1
  with:
    path: .
```

---

## D. Проект в Claude

| Блок панели | Что сделать |
|---|---|
| **Anweisungen** | Вставить полный системный промпт из раздела 1 конфигуратора, заменив «Active Hybrid Scanner Engine» на «KukiLab Scanner». |
| **Kontext** | Уже загружены: таксономия, чек-лист, SARIF-гайд, README-шаблон, DEPLOY.md, отчёт по ERP Pilot. Исходник грузить не нужно — он живет в GitHub. |
| **Gedächtnis** | Правила аудита (LP3, белый список вызовов, Unicode, база хэшей) уже в памяти проекта. |
| **Geplant** | Реализовано в GitHub Actions (`self-test.yml`, `kukilab-scan.yml` с `upload-sarif@v3`) + Dependabot weekly. |

---

## Что умеет движок (кратко)

- **Step 0** — удаляет U+200B..U+200D, U+2060, U+FEFF, U+00AD, BIDI U+202A..U+202E / U+2066..U+2069, NFC-нормализация; BOM в начале файла не считается угрозой.
- **Step 1** — манифест (name, description, `allowed-tools` → LP3 с автогенерацией по коду), 25 regex-сигнатур P-03..P-07/P-10, AST-анализ Python (`getattr/eval/exec/__import__` с динамическим аргументом → AST7). Размер пакета не штрафуется; кириллица не считается аномалией (AE4).
- **Step 2** — HTML-комментарии с императивами (P-02), промт-инъекции и scope creep на en/ru/de (P-01, P-09), подстрекательство к установке с чужих URL (P-06); при наличии `ANTHROPIC_API_KEY` — вызов Claude по эталонному промпту из таксономии (вход упакован в `<document>` как недоверенные данные, ответ строго JSON).
- **Вердикт** — BLOCK: P-01/P-03/P-05/P-10 HIGH+ с уверенностью ≥0.70, либо risk ≥70; CAUTION: P-02/P-06/P-08/P-09 MEDIUM+ ≥0.60, отсутствие allowed-tools, risk 25–69; иначе SAFE.
- **Вывод** — Markdown (stdout / `--markdown`), JSON, SARIF 2.1.0 (`rules[]` с `security-severity`, `results[]` с `region.startLine/startColumn/snippet`, `partialFingerprints`).
- **Кэш** — `--cache FILE`: SHA-256 всего пакета; неизмененный пакет не сканируется повторно, отчет берется из кэша.
- **Baseline-подавления** — проверенные ложные срабатывания фиксируются в `.kukilab.yaml` (в каталоге навыка или до двух уровней выше) в формате `rules: [{id, path, message, reason}]` (glob-маски); существующие `.skillspector/<навык>.yaml` читаются в том же формате. Подавленные находки не влияют на вердикт, показываются отдельным разделом и уходят в SARIF как `suppressions` (`kind: external`, `status: accepted`). Подавления применяются только с флагом `--baseline` (в Action: `extra-args: --baseline`): файл лежит в проверяемом репозитории, и без явного согласия того, кто запускает проверку, им можно было бы скрыть собственные находки. Если файл найден, а флага нет, отчёт сообщает, сколько правил не применено.

## Известное ограничение

Документация **о безопасности** (чек-листы, таксономии, статьи) цитирует атакующие паттерны (`curl | bash`, «ignore previous instructions», `.env`) и в офлайн-режиме получает BLOCK — статические правила не отличают цитату от инструкции. Для Markdown-файлов уверенность уже понижена на 20 %, но полностью этот шум снимает только Step 2 через API (правило «примеры в обучающей документации не считаются аномалией» заложено в промпт). Сканер предназначен для **навыков**, а не для whitepaper'ов; папку `docs/` этого репозитория им проверять не нужно.
