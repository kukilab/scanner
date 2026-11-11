# KukiLab Scanner

[![Scanner self-test](https://github.com/kukilab/scanner/actions/workflows/self-test.yml/badge.svg)](https://github.com/kukilab/scanner/actions/workflows/self-test.yml)
[![KukiLab](https://kukilab.dev/badge/github.com/kukilab/scanner/skills/kukilab-scan.svg)](https://kukilab.dev/?check=https%3A%2F%2Fgithub.com%2Fkukilab%2Fscanner%2Ftree%2FHEAD%2Fskills%2Fkukilab-scan)
[![Skillverdict](https://app.skillverdict.dev/badge/github.com/kukilab/scanner/skills/kukilab-scan.svg)](https://app.skillverdict.dev/github.com/kukilab/scanner/skills/kukilab-scan)
[![License: MIT](https://img.shields.io/github/license/kukilab/scanner?color=brightgreen)](LICENSE)

**KukiLab** — гибридный сканер безопасности AI-навыков (Claude Code Skills, Codex, MCP), который не только находит проблемы, но и доводит навык до состояния **SAFE**: `--fix` чистит Unicode-стеганографию и дописывает декларацию `allowed-tools`, SARIF-отчёт попадает в GitHub Security, а CI-гейт останавливает опасный PR.

Три этапа: **Step 0** активная очистка Unicode (zero-width, BIDI, BOM, NFC) → **Step 1** статическая проверка манифеста и кода без штрафа за объём и без шума на кириллице (AE4) → **Step 2** семантический анализ прозы (офлайн-эвристики en/ru/de или Claude через API). Вердикты `SAFE / CAUTION / BLOCK`.

## Быстрый старт

```bash
git clone https://github.com/kukilab/scanner.git && cd scanner
bash setup.sh && source venv/bin/activate
python src/kukilab_scanner.py /path/to/skill                     # отчёт в stdout
python src/kukilab_scanner.py /path/to/skill --fix               # очистка + allowed-tools
python src/kukilab_scanner.py /path/to/skill --sarif results.sarif --json results.json
```

## Скилл для агента

```bash
npx skills add kukilab/scanner --skill kukilab-scan
```

Исходник навыка: [`skills/kukilab-scan`](https://github.com/kukilab/scanner/tree/main/skills/kukilab-scan).

Навык `kukilab-scan` запускает Step 0 и Step 1 скриптом, а Step 2 (семантику прозы) выполняет сам агент — без ключей API и внешних сервисов. Движок подтягивается из этого репозитория по релизу `v1.0.0`, репозиторий, тег и коммит записаны в `skills/kukilab-scan/engine.json`, скрипт сверяет коммит перед запуском. Плейбук ремонта до SAFE — в [`skills/kukilab-scan/references/fix-playbook.md`](skills/kukilab-scan/references/fix-playbook.md).

## GitHub Action

```yaml
- uses: kukilab/scanner@v1
  with:
    path: .
    fail-on: BLOCK                      # BLOCK | CAUTION | NEVER
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}   # опционально
```

Полный workflow с загрузкой SARIF в Security → Code scanning: [`templates/kukilab-scan.yml`](templates/kukilab-scan.yml). Пошаговое развертывание: [`DEPLOY.md`](DEPLOY.md).

## Бейдж для README

Живой бейдж навыка отдаёт [kukilab.dev](https://kukilab.dev): вставьте ссылку на навык в «Проверить по ссылке» и скопируйте строку из блока «Бейдж для README».

- **STATIC PASSED** — статическая проверка на сайте пройдена (Step 0, Step 1, офлайн-эвристики Step 2). Ключ API не нужен.
- **SAFE** — пройден и смысловой проход Step 2. Его запускает готовый рабочий процесс в репозитории навыка, с вашим ключом API Anthropic:

```yaml
# .github/workflows/kukilab-safe.yml
name: KukiLab SAFE
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  safe:
    uses: kukilab/scanner/.github/workflows/safe.yml@v1
    with:
      path: my-skill          # папка с SKILL.md; "." для навыка в корне
    secrets:
      anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Рабочий процесс сообщает результат на kukilab.dev вместе с токеном, который подписывает GitHub: он подтверждает репозиторий, коммит и то, что выполнялся именно этот файл. Сервис сам пересчитывает статическую часть на том же коммите. SAFE действует для проверенного коммита: после нового коммита бейдж показывает STATIC PASSED, пока рабочий процесс не отработает снова. Ключ API на kukilab.dev не передаётся.

## Таксономия

| Код | Угроза | | Код | Угроза |
|---|---|---|---|---|
| P-01 | Instruction Override | | P-06 | Fake Prerequisites Installer |
| P-02 | Hidden Instructions in HTML Comments | | P-07 | Obfuscated Commands |
| P-03 | Data Exfiltration via Network | | P-08 | Zero-Width Steganography |
| P-04 | Unsanitized Remote Execution | | P-09 | Broad Trigger & Scope Creep |
| P-05 | Credential Harvesting | | P-10 | Persistence Creation |
| LP3 | Missing `allowed-tools` | | AST7 | Dynamic attribute access (Python) |

Подробно: [`docs/llm-threat-taxonomy-prompt-guide.md`](docs/llm-threat-taxonomy-prompt-guide.md). Пример реального аудита: [`docs/case-erp-pilot-2026-11-09.md`](docs/case-erp-pilot-2026-11-09.md).

## Содержимое

| Путь | Назначение |
|---|---|
| `src/kukilab_scanner.py` | Движок (только стандартная библиотека; `pyyaml` опционально) |
| `action.yml` | Composite GitHub Action |
| [`skills/kukilab-scan/`](https://github.com/kukilab/scanner/tree/main/skills/kukilab-scan) | Навык для Claude Code / Codex: аудит и ремонт с хост-LLM Step 2 |
| `examples/demo-clean-skill/` | Эталон безопасного навыка → `SAFE` |
| `examples/demo-malicious-skill/` | Тестовый вредоносный навык → `BLOCK` (фикстура для self-test) |
| `templates/` | Workflow для проверяемых репозиториев, README-шаблон с бейджами, чек-лист |
| `docs/`, `cicd/` | Таксономия, кейсы, заметки по SARIF |

## Коды возврата

`0` SAFE · `1` CAUTION (только при `--fail-on CAUTION`) · `2` BLOCK · `3` путь не найден.

## Лицензия

MIT © 2026 Andrey Trukhachev (KukiLab).
