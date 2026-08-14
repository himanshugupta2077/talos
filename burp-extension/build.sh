#!/usr/bin/env bash
# Build talos-burp-1.2.2.jar without Gradle (javac + jar).
# Requires Java 17+. Downloads the Montoya API (compile-only) into .lib/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
API_VERSION="2025.8"
API_JAR="${ROOT}/.lib/montoya-api-${API_VERSION}.jar"
API_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${API_VERSION}/montoya-api-${API_VERSION}.jar"
OUT="${ROOT}/build/classes"
DEST_DIR="${ROOT}/build/libs"
DEST="${DEST_DIR}/talos-burp-1.2.2.jar"
SRC="${ROOT}/src/main/java"
RES="${ROOT}/src/main/resources"

mkdir -p "${ROOT}/.lib" "${OUT}" "${DEST_DIR}"

if [[ ! -f "${API_JAR}" ]]; then
  echo "Downloading Montoya API ${API_VERSION}…"
  curl -fsSL -o "${API_JAR}" "${API_URL}"
fi

mapfile -t sources < <(find "${SRC}" -name '*.java')
javac --release 17 -cp "${API_JAR}" -d "${OUT}" "${sources[@]}"
cp -a "${RES}/." "${OUT}/"
jar cf "${DEST}" -C "${OUT}" .
echo "Built ${DEST}"
