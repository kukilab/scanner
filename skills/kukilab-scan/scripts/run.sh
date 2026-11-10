#!/usr/bin/env bash
# KukiLab Scan — запуск движка по закреплённой версии.
# Движок не хранится в навыке. Откуда он берётся, записано в engine.json рядом с SKILL.md:
# репозиторий, тег релиза и коммит. Скрипт клонирует этот тег в .kukilab/engine рядом с
# проверяемым проектом, сверяет коммит с записанным и при несовпадении останавливается.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["repository"], d["tag"], d["commit"])' "$SKILL_DIR/engine.json")"
read -r REPOSITORY TAG COMMIT <<<"$PIN"
ENGINE_DIR="${KUKILAB_ENGINE_DIR:-$PWD/.kukilab/engine}"
if [ ! -f "$ENGINE_DIR/src/kukilab_scanner.py" ]; then
  mkdir -p "$(dirname "$ENGINE_DIR")"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" "$REPOSITORY" "$ENGINE_DIR"
fi
if [ -d "$ENGINE_DIR/.git" ]; then
  HEAD_COMMIT="$(git -C "$ENGINE_DIR" rev-parse HEAD)"
  if [ "$HEAD_COMMIT" != "$COMMIT" ]; then
    echo "kukilab-scan: коммит движка $HEAD_COMMIT не совпадает с записанным в engine.json $COMMIT ($TAG). Запуск остановлен." >&2
    exit 4
  fi
fi
exec python3 "$ENGINE_DIR/src/kukilab_scanner.py" "$@"
