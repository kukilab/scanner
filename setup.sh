#!/usr/bin/env bash
# KukiLab Scanner - One-Click Setup Script (macOS / Linux)
set -e
echo "=== 🛡️ KukiLab Scanner: One-Click Setup ==="
if command -v python3 &>/dev/null; then PYTHON_CMD="python3"; elif command -v python &>/dev/null; then PYTHON_CMD="python"; else echo "❌ Python 3 is not installed or not found in PATH."; exit 1; fi
echo "--> Found Python: $($PYTHON_CMD --version)"
if [ ! -d "venv" ]; then echo "--> Creating virtual environment in ./venv ..."; $PYTHON_CMD -m venv venv; else echo "--> Virtual environment ./venv already exists."; fi
echo "--> Activating virtual environment..."; source venv/bin/activate
echo "--> Installing dependencies (pyyaml, requests)..."; pip install --upgrade pip --quiet; pip install -r requirements.txt --quiet
echo ""; echo "=== ✅ Setup Completed Successfully! ==="; echo ""
echo "To activate the environment in your shell, run:"; echo "    source venv/bin/activate"; echo ""
echo "To check the installation on the bundled demo skill:"; echo "    python src/kukilab_scanner.py examples/demo-clean-skill"; echo ""
echo "To scan your own skill, replace ~/my-skill with the folder that holds its SKILL.md:"; echo "    python src/kukilab_scanner.py ~/my-skill"
echo "The same with auto-fix (changes the skill's files):"; echo "    python src/kukilab_scanner.py ~/my-skill --fix"; echo ""
