#!/usr/bin/env bash
# loop/run.sh — внешний луп M1→M4. Гейт здесь только ВЫЗЫВАЕТСЯ; критериев готовности в скрипте нет (гайд §2.4).
# Неинтерактивен. Никогда не пушит и не деплоит (гайд §5.2). Коммит итерации — только при ALLOW_LOOP_COMMITS=1.
set -Eeuo pipefail

cd "$(dirname "$0")/.."

MISSION="loop/mission.md"
LOG="loop/run.log"
CLAIM="loop/claim.txt"
DONE_MARKER="loop/ROADMAP_DONE"
MAX_ITERS="${MAX_ITERS:-15}"

case "$MAX_ITERS" in
  ''|*[!0-9]*) echo "MAX_ITERS должен быть целым числом, получено: $MAX_ITERS" >&2; exit 1 ;;
esac
[ "$MAX_ITERS" -ge 1 ] || { echo "MAX_ITERS должен быть >= 1" >&2; exit 1; }
[ -f "$MISSION" ] || { echo "нет $MISSION — миссия обязана существовать и не меняться между итерациями" >&2; exit 1; }
git rev-parse --git-dir >/dev/null 2>&1 || { echo "не git-репозиторий: $(pwd)" >&2; exit 1; }

mkdir -p loop

done_claims() {
  # loop/claim.txt игнорируется гитом (.gitignore) — в коммит не попадает.
  awk '/^STATUS: DONE/{n++} END{print n+0}' "$CLAIM" 2>/dev/null || echo 0
}

last_iteration() {
  awk '$1 == "##" && $2 == "iteration" && $3 ~ /^[0-9]+$/ { if ($3 > max) max = $3 } END { print max + 0 }' ATTEMPTS.md
}

# Коммит итерации разрешён только с ALLOW_LOOP_COMMITS=1 (политика пользователя).
commit_iteration() {
  local i="$1"
  if [ "${ALLOW_LOOP_COMMITS:-0}" != "1" ]; then
    echo "loop: iteration $i — ALLOW_LOOP_COMMITS != 1" >>"$LOG"
    return 1
  fi
  if ! git add -A >>"$LOG" 2>&1; then
    echo "loop: iteration $i — git add failed" >>"$LOG"
    return 1
  fi
  if git diff --cached --quiet; then
    echo "loop: iteration $i — нечего коммитить (пустой дифф)" >>"$LOG"
    return 0
  fi
  if ! git commit -m "loop: iteration $i (gate=green)" >>"$LOG" 2>&1; then
    echo "loop: iteration $i — git commit failed" >>"$LOG"
    return 1
  fi
}

START_ITER=$(( $(last_iteration) + 1 ))
if [ "$START_ITER" -gt "$MAX_ITERS" ]; then
  echo "STOP: MAX_ITERS=$MAX_ITERS уже исчерпан; следующая итерация — $START_ITER" | tee -a "$LOG"
  exit 4
fi

for ((i = START_ITER; i <= MAX_ITERS; i++)); do
  echo "=== iteration $i ===" | tee -a "$LOG"

  # Заголовок существует до запуска агента: его фактические пункты попадут в правильную итерацию.
  {
    echo
    echo "## iteration $i"
  } >>ATTEMPTS.md

  # Свежая сессия на итерацию. Задание не меняется; состояние — только git + ATTEMPTS.md + DECISIONS.md.
  pi -p "$(cat "$MISSION")" >>"$LOG" 2>&1 || echo "loop: агент завершился с кодом $? (iteration $i)" >>"$LOG"

  # ГЕЙТ. Единственная команда готовности.
  gate=red
  if mise run check >>"$LOG" 2>&1; then gate=green; fi

  {
    echo "- gate: $gate"
    echo "- dirty paths: $(git status --short | wc -l | tr -d ' '); tracked diff: $(git diff --stat | tail -1)"
    echo "- заявлений STATUS: DONE: $(done_claims)"
    echo "- ROADMAP_DONE: $([ -f "$DONE_MARKER" ] && echo есть || echo нет)"
  } >>ATTEMPTS.md

  # Красный гейт не коммитится и не накапливается как долг (гайд §6.3).
  if [ "$gate" != green ]; then
    echo "STOP: gate=red на итерации $i — коммита нет, разбирать вручную ($LOG)" | tee -a "$LOG"
    exit 2
  fi

  # Стоп-условие из двух частей: зелёный гейт И явный ROADMAP_DONE.
  if [ -f "$DONE_MARKER" ]; then
    if commit_iteration "$i"; then
      echo "stop: gate green + ROADMAP_DONE на итерации $i" | tee -a "$LOG"
      exit 0
    fi
    echo "STOP: gate green + ROADMAP_DONE на итерации $i, но коммит не выполнен; см. $LOG" | tee -a "$LOG"
    exit 3
  fi

  if ! commit_iteration "$i"; then
    echo "STOP: итерация $i зелёная, но коммит не выполнен; см. $LOG" | tee -a "$LOG"
    echo "      Проверь git-состояние. Для автоматических коммитов требуется ALLOW_LOOP_COMMITS=1." | tee -a "$LOG"
    exit 3
  fi
done

echo "STOP: MAX_ITERS=$MAX_ITERS исчерпан; ROADMAP_DONE не появился" | tee -a "$LOG"
exit 4
