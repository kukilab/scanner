#!/usr/bin/env bash
# KukiLab Scan — запуск движка по закреплённой версии.
# Движок не хранится в навыке: он клонируется из github.com/kukilab/scanner в .kukilab/engine
# рядом с проверяемым проектом и переиспользуется при следующих запусках.
# По умолчанию берётся релиз v1.0.0, и его коммит сверяется с PIN: если тег передвинут, запуск останавливается.
# Другую версию можно задать явно: KUKILAB_VERSION=<тег> (сверка коммита тогда не выполняется).
set -euo pipefail
PIN_TAG="v1.0.0"
PIN_COMMIT="7cd856df5144542815af19ee5935d5ef79b03c6f"
TAG="${KUKILAB_VERSION:-$PIN_TAG}"
ENGINE_DIR="${KUKILAB_ENGINE_DIR:-$PWD/.kukilab/engine}"
if [ ! -f "$ENGINE_DIR/src/kukilab_scanner.py" ]; then
  mkdir -p "$(dirname "$ENGINE_DIR")"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" https://github.com/kukilab/scanner.git "$ENGINE_DIR"
fi
if [ "$TAG" = "$PIN_TAG" ] && [ -d "$ENGINE_DIR/.git" ]; then
  HEAD_COMMIT="$(git -C "$ENGINE_DIR" rev-parse HEAD)"
  if [ "$HEAD_COMMIT" != "$PIN_COMMIT" ]; then
    echo "kukilab-scan: коммит движка $HEAD_COMMIT не совпадает с закреплённым $PIN_COMMIT ($PIN_TAG). Запуск остановлен." >&2
    exit 4
  fi
fi
exec python3 "$ENGINE_DIR/src/kukilab_scanner.py" "$@"
