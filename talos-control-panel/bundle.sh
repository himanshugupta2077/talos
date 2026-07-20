#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# bundle.sh
#
# Bundles source code into a single file + index, sized for handing to an
# AI instead of pointing it at a whole repo. Two modes:
#
#   commit  - given a git commit, bundles every file that commit touched
#             (diff and/or full post-commit content)
#   dir     - given a directory, recursively bundles every file inside it
#             (full content)
#
# Each mode produces the same two files in <output-dir>:
#   index.md   - manifest: file, status/size, line counts, binary flag
#   bundle.txt - all file contents/diffs appended, in index order, each
#                behind a "FILE #N: <path>" marker line
#
# Usage:
#   ./bundle.sh commit <commit-ish> <output-dir> [--diff-only|--full-only|--both]
#   ./bundle.sh dir    <input-dir>  <output-dir>
#
# Examples:
#   ./bundle.sh commit bba424363f777eb27d3e62dd5f0a541b0194dc42 ./ai-review
#   ./bundle.sh dir    ./src ./ai-review
# ---------------------------------------------------------------------------

usage() {
  cat <<'EOF'
Usage:
  bundle.sh commit <commit-ish> <output-dir> [mode]
  bundle.sh dir    <input-dir>  <output-dir>

  commit mode:
    <commit-ish>   Any git commit reference (SHA, branch, tag, HEAD~2, etc.)
    <output-dir>   Directory to write index.md + bundle.txt into (created if missing)
    mode           --diff-only  : only unified diffs
                   --full-only  : only full post-commit file content
                   --both       : both (default)

  dir mode:
    <input-dir>    Directory to bundle recursively (all files under it, minus .git)
    <output-dir>   Directory to write index.md + bundle.txt into (created if missing)

Examples:
  bundle.sh commit bba424363f777eb27d3e62dd5f0a541b0194dc42 ./ai-review
  bundle.sh dir ./src ./ai-review
EOF
}

is_binary_file() {
  local f="$1"
  if command -v file >/dev/null 2>&1; then
    local enc
    enc="$(file --mime-encoding -b "$f" 2>/dev/null || echo "binary")"
    [[ "$enc" == "binary" ]]
  else
    ! grep -Iq . "$f" 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# commit mode
# ---------------------------------------------------------------------------
do_commit_mode() {
  local COMMIT="$1" OUTDIR="$2" MODE="${3:---both}"

  case "$MODE" in
    --diff-only|--full-only|--both) ;;
    *) echo "Unknown mode: $MODE" >&2; usage; exit 1 ;;
  esac

  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "Error: not inside a git repository." >&2
    exit 1
  }

  local FULL_SHA
  FULL_SHA="$(git rev-parse --verify "${COMMIT}^{commit}" 2>/dev/null)" || {
    echo "Error: '$COMMIT' is not a valid commit in this repo." >&2
    exit 1
  }

  local PARENT
  PARENT="$(git rev-parse --verify "${FULL_SHA}^" 2>/dev/null || echo "")"

  mkdir -p "$OUTDIR"
  local INDEX_FILE="$OUTDIR/index.md"
  local BUNDLE_FILE="$OUTDIR/bundle.txt"
  : > "$INDEX_FILE"
  : > "$BUNDLE_FILE"

  local COMMIT_SUBJECT COMMIT_AUTHOR COMMIT_DATE
  COMMIT_SUBJECT="$(git log -1 --format='%s' "$FULL_SHA")"
  COMMIT_AUTHOR="$(git log -1 --format='%an <%ae>' "$FULL_SHA")"
  COMMIT_DATE="$(git log -1 --format='%ad' --date=iso "$FULL_SHA")"

  {
    echo "# Commit Bundle Index"
    echo
    echo "- Commit: \`$FULL_SHA\`"
    echo "- Subject: $COMMIT_SUBJECT"
    echo "- Author: $COMMIT_AUTHOR"
    echo "- Date: $COMMIT_DATE"
    echo "- Mode: $MODE"
    echo "- Bundle file: \`$(basename "$BUNDLE_FILE")\`"
    echo
    echo "Each row below is one file changed in this commit. Full contents/diffs"
    echo "for every file are appended, in this same order, inside the bundle"
    echo "file — look for the matching \`FILE #N:\` marker line."
    echo
    printf '| # | Status | File | +Lines | -Lines | Total Lines (after) | Binary |\n'
    printf '|---|--------|------|--------|--------|----------------------|--------|\n'
  } >> "$INDEX_FILE"

  {
    echo "COMMIT BUNDLE"
    echo "Commit: $FULL_SHA"
    echo "Subject: $COMMIT_SUBJECT"
    echo "Author: $COMMIT_AUTHOR"
    echo "Date: $COMMIT_DATE"
    echo "Mode: $MODE"
    echo "================================================================"
  } >> "$BUNDLE_FILE"

  local INDEX_NUM=0 STATUS FILE REST STATUS_LABEL OLDFILE
  local NUMSTAT_LINE ADDED REMOVED IS_BINARY TOTAL_LINES

  while IFS=$'\t' read -r STATUS FILE REST; do
    INDEX_NUM=$((INDEX_NUM+1))

    case "$STATUS" in
      R*|C*)
        OLDFILE="$FILE"
        FILE="$REST"
        STATUS_LABEL="Renamed ($STATUS): $OLDFILE -> $FILE"
        ;;
      A) STATUS_LABEL="Added" ;;
      M) STATUS_LABEL="Modified" ;;
      D) STATUS_LABEL="Deleted" ;;
      *) STATUS_LABEL="$STATUS" ;;
    esac

    NUMSTAT_LINE="$(git diff-tree -r --numstat -M "$FULL_SHA" -- "$FILE" 2>/dev/null | tail -n1)"
    ADDED="$(awk '{print $1}' <<<"$NUMSTAT_LINE")"
    REMOVED="$(awk '{print $2}' <<<"$NUMSTAT_LINE")"
    ADDED="${ADDED:-0}"
    REMOVED="${REMOVED:-0}"
    IS_BINARY="No"
    [[ "$ADDED" == "-" ]] && IS_BINARY="Yes"

    TOTAL_LINES="n/a"
    if [[ "$STATUS" != "D" && "$IS_BINARY" == "No" ]]; then
      TOTAL_LINES="$(git show "${FULL_SHA}:${FILE}" 2>/dev/null | wc -l | tr -d ' ')"
    fi

    printf '| %d | %s | `%s` | %s | %s | %s | %s |\n' \
      "$INDEX_NUM" "$STATUS_LABEL" "$FILE" "$ADDED" "$REMOVED" "$TOTAL_LINES" "$IS_BINARY" >> "$INDEX_FILE"

    {
      echo
      echo "================================================================"
      echo "FILE #$INDEX_NUM: $FILE"
      echo "STATUS: $STATUS_LABEL"
      echo "LINES: +$ADDED / -$REMOVED   TOTAL (after commit): $TOTAL_LINES   BINARY: $IS_BINARY"
      echo "================================================================"
    } >> "$BUNDLE_FILE"

    if [[ "$IS_BINARY" == "Yes" ]]; then
      echo "[binary file - content omitted]" >> "$BUNDLE_FILE"
      continue
    fi

    if [[ "$MODE" == "--diff-only" || "$MODE" == "--both" ]]; then
      {
        echo
        echo "--- DIFF ---"
        if [[ -n "$PARENT" ]]; then
          git diff -M "$PARENT" "$FULL_SHA" -- "$FILE"
        else
          git show "$FULL_SHA" -- "$FILE"
        fi
      } >> "$BUNDLE_FILE"
    fi

    if [[ "$MODE" == "--full-only" || "$MODE" == "--both" ]]; then
      {
        echo
        echo "--- FULL FILE CONTENT (post-commit) ---"
        if [[ "$STATUS" == "D" ]]; then
          echo "[file deleted in this commit - showing last known content, pre-deletion]"
          git show "${PARENT}:${FILE}" 2>/dev/null
        else
          git show "${FULL_SHA}:${FILE}" 2>/dev/null
        fi
      } >> "$BUNDLE_FILE"
    fi

  done < <(git diff-tree --no-commit-id --name-status -r -M "$FULL_SHA")

  {
    echo
    echo "Total files changed: $INDEX_NUM"
  } >> "$INDEX_FILE"

  echo "Done."
  echo "Index:  $INDEX_FILE"
  echo "Bundle: $BUNDLE_FILE"
}

# ---------------------------------------------------------------------------
# dir mode
# ---------------------------------------------------------------------------
do_dir_mode() {
  local INPUT_DIR="$1" OUTDIR="$2"

  [[ -d "$INPUT_DIR" ]] || {
    echo "Error: '$INPUT_DIR' is not a directory." >&2
    exit 1
  }

  local ABS_INPUT_DIR
  ABS_INPUT_DIR="$(cd "$INPUT_DIR" && pwd)"

  mkdir -p "$OUTDIR"
  local INDEX_FILE="$OUTDIR/index.md"
  local BUNDLE_FILE="$OUTDIR/bundle.txt"
  : > "$INDEX_FILE"
  : > "$BUNDLE_FILE"

  {
    echo "# Directory Bundle Index"
    echo
    echo "- Source directory: \`$ABS_INPUT_DIR\`"
    echo "- Bundle file: \`$(basename "$BUNDLE_FILE")\`"
    echo
    echo "Each row below is one file found recursively under the source directory."
    echo "Full contents for every file are appended, in this same order, inside"
    echo "the bundle file — look for the matching \`FILE #N:\` marker line."
    echo
    printf '| # | File | Lines | Size (bytes) | Binary |\n'
    printf '|---|------|-------|---------------|--------|\n'
  } >> "$INDEX_FILE"

  {
    echo "DIRECTORY BUNDLE"
    echo "Source directory: $ABS_INPUT_DIR"
    echo "================================================================"
  } >> "$BUNDLE_FILE"

  local INDEX_NUM=0 FILE REL_PATH SIZE BINARY LINES

  while IFS= read -r -d '' FILE; do
    # skip the output dir itself, in case it was created inside INPUT_DIR
    [[ "$FILE" == "$(cd "$OUTDIR" && pwd)"/* ]] && continue

    INDEX_NUM=$((INDEX_NUM+1))
    REL_PATH="${FILE#"$ABS_INPUT_DIR"/}"
    SIZE="$(stat -c%s "$FILE" 2>/dev/null || stat -f%z "$FILE" 2>/dev/null || echo "n/a")"

    BINARY="No"
    is_binary_file "$FILE" && BINARY="Yes"

    LINES="n/a"
    [[ "$BINARY" == "No" ]] && LINES="$(wc -l < "$FILE" | tr -d ' ')"

    printf '| %d | `%s` | %s | %s | %s |\n' "$INDEX_NUM" "$REL_PATH" "$LINES" "$SIZE" "$BINARY" >> "$INDEX_FILE"

    {
      echo
      echo "================================================================"
      echo "FILE #$INDEX_NUM: $REL_PATH"
      echo "LINES: $LINES   SIZE: $SIZE bytes   BINARY: $BINARY"
      echo "================================================================"
    } >> "$BUNDLE_FILE"

    if [[ "$BINARY" == "Yes" ]]; then
      echo "[binary file - content omitted]" >> "$BUNDLE_FILE"
    else
      echo >> "$BUNDLE_FILE"
      cat "$FILE" >> "$BUNDLE_FILE"
    fi
  done < <(find "$ABS_INPUT_DIR" -type f -not -path '*/.git/*' -print0 | sort -z)

  {
    echo
    echo "Total files bundled: $INDEX_NUM"
  } >> "$INDEX_FILE"

  echo "Done."
  echo "Index:  $INDEX_FILE"
  echo "Bundle: $BUNDLE_FILE"
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------
if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 1
fi

SUBCOMMAND="$1"
shift

case "$SUBCOMMAND" in
  commit)
    [[ $# -lt 2 ]] && { usage; exit 1; }
    do_commit_mode "$1" "$2" "${3:---both}"
    ;;
  dir)
    [[ $# -lt 2 ]] && { usage; exit 1; }
    do_dir_mode "$1" "$2"
    ;;
  *)
    echo "Unknown subcommand: $SUBCOMMAND" >&2
    usage
    exit 1
    ;;
esac