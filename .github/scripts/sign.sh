#!/bin/bash

set -Eeuo pipefail

echo "========================================"
echo "Bắt đầu ký IPA"
echo "IPA: ${IPA_PATH}"
echo "Certificate: ${CERT_DIR}"
echo "Request ID: ${REQUEST_ID}"
echo "========================================"

ROOT_DIR="$(pwd)"
WORK_DIR="${RUNNER_TEMP}/usersign-${REQUEST_ID}"
EXTRACT_DIR="${WORK_DIR}/extract"
PROFILE_INFO_DIR="${WORK_DIR}/profiles"

OUTPUT_IPA="${ROOT_DIR}/signed-${REQUEST_ID}.ipa"

cleanup() {
    if [[ -n "${KEYCHAIN_PATH:-}" ]]; then
        security delete-keychain "${KEYCHAIN_PATH}" >/dev/null 2>&1 || true
    fi

    rm -rf "${WORK_DIR}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

# ============================================================
# Kiểm tra dữ liệu đầu vào
# ============================================================

python3 <<'PY'
import json
import os
import pathlib
import re
import sys

root = pathlib.Path.cwd().resolve()
ipa = (root / os.environ["IPA_PATH"]).resolve()
cert = (root / os.environ["CERT_DIR"]).resolve()
request_id = os.environ["REQUEST_ID"]

if not re.fullmatch(r"[A-Za-z0-9_-]+", request_id):
    raise SystemExit("REQUEST_ID không hợp lệ")

try:
    ipa.relative_to(root / "ipa")
except ValueError:
    raise SystemExit("IPA phải nằm trong thư mục ipa")

try:
    cert.relative_to(root / "cert")
except ValueError:
    raise SystemExit("Chứng chỉ phải nằm trong thư mục cert")

if not ipa.is_file() or ipa.suffix.lower() != ".ipa":
    raise SystemExit("Không tìm thấy IPA hợp lệ")

if not cert.is_dir():
    raise SystemExit("Không tìm thấy thư mục chứng chỉ")

profiles = json.loads(os.environ["PROFILES_JSON"])

if not isinstance(profiles, list) or not profiles:
    raise SystemExit("Chưa chọn mobileprovision")

for profile_name in profiles:
    profile = (root / profile_name).resolve()

    try:
        profile.relative_to(cert)
    except ValueError:
        raise SystemExit(
            f"Mobileprovision không thuộc chứng chỉ đã chọn: {profile_name}"
        )

    if not profile.is_file() or profile.suffix.lower() != ".mobileprovision":
        raise SystemExit(f"Mobileprovision không hợp lệ: {profile_name}")
PY

rm -rf "${WORK_DIR}"
mkdir -p "${EXTRACT_DIR}"
mkdir -p "${PROFILE_INFO_DIR}"

# ============================================================
# Tìm P12
# ============================================================

P12_PATH="$(find "${CERT_DIR}" -maxdepth 1 -type f \
    \( -iname "*.p12" -o -iname "*.pfx" \) | head -n 1)"

if [[ -z "${P12_PATH}" ]]; then
    echo "Không tìm thấy file P12 trong ${CERT_DIR}"
    exit 1
fi

echo "Sử dụng P12: ${P12_PATH}"

# ============================================================
# Tạo keychain tạm và nhập P12
# ============================================================

KEYCHAIN_PASSWORD="$(openssl rand -hex 24)"
KEYCHAIN_PATH="${RUNNER_TEMP}/usersign-${REQUEST_ID}.keychain-db"

security create-keychain \
    -p "${KEYCHAIN_PASSWORD}" \
    "${KEYCHAIN_PATH}"

security set-keychain-settings \
    -lut 21600 \
    "${KEYCHAIN_PATH}"

security unlock-keychain \
    -p "${KEYCHAIN_PASSWORD}" \
    "${KEYCHAIN_PATH}"

security import "${P12_PATH}" \
    -k "${KEYCHAIN_PATH}" \
    -P "1" \
    -T /usr/bin/codesign \
    -T /usr/bin/security

security list-keychains \
    -d user \
    -s "${KEYCHAIN_PATH}"

security default-keychain \
    -d user \
    -s "${KEYCHAIN_PATH}"

security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s \
    -k "${KEYCHAIN_PASSWORD}" \
    "${KEYCHAIN_PATH}"

IDENTITY="$(
    security find-identity \
        -v \
        -p codesigning \
        "${KEYCHAIN_PATH}" |
    sed -n 's/.*"\(.*\)".*/\1/p' |
    head -n 1
)"

if [[ -z "${IDENTITY}" ]]; then
    echo "Không tìm thấy signing identity trong P12"
    exit 1
fi

echo "Signing identity: ${IDENTITY}"

# ============================================================
# Giải nén IPA
# ============================================================

echo "Đang giải nén IPA..."

unzip -q "${IPA_PATH}" -d "${EXTRACT_DIR}"

if [[ ! -d "${EXTRACT_DIR}/Payload" ]]; then
    echo "IPA không có thư mục Payload"
    exit 1
fi

MAIN_APP="$(find "${EXTRACT_DIR}/Payload" \
    -maxdepth 1 \
    -type d \
    -name "*.app" |
    head -n 1)"

if [[ -z "${MAIN_APP}" ]]; then
    echo "Không tìm thấy ứng dụng trong Payload"
    exit 1
fi

echo "Ứng dụng chính: ${MAIN_APP}"

# Xóa metadata không cần thiết
find "${EXTRACT_DIR}" -name ".DS_Store" -delete || true
find "${EXTRACT_DIR}" -name "__MACOSX" -type d -prune -exec rm -rf {} + || true

xattr -cr "${EXTRACT_DIR}" || true

# ============================================================
# Đọc các mobileprovision đã chọn
# ============================================================

python3 <<'PY'
import json
import os
import pathlib
import plistlib
import subprocess

root = pathlib.Path.cwd()
work = pathlib.Path(os.environ["PROFILE_INFO_DIR"])
selected = json.loads(os.environ["PROFILES_JSON"])

profile_map = []

for index, relative_path in enumerate(selected):
    source = root / relative_path
    decoded = work / f"{index}.plist"
    entitlements_file = work / f"{index}.entitlements.plist"

    with decoded.open("wb") as output:
        subprocess.run(
            ["security", "cms", "-D", "-i", str(source)],
            stdout=output,
            check=True
        )

    with decoded.open("rb") as file:
        profile = plistlib.load(file)

    entitlements = profile.get("Entitlements", {})
    app_identifier = (
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )

    teams = profile.get("TeamIdentifier", [])
    team_identifier = teams[0] if teams else ""

    with entitlements_file.open("wb") as file:
        plistlib.dump(entitlements, file)

    profile_map.append({
        "index": index,
        "source": str(source),
        "decoded": str(decoded),
        "entitlements": str(entitlements_file),
        "application_identifier": app_identifier,
        "team_identifier": team_identifier,
        "name": profile.get("Name", source.name),
        "uuid": profile.get("UUID", "")
    })

with (work / "map.json").open("w", encoding="utf-8") as file:
    json.dump(profile_map, file, ensure_ascii=False, indent=2)
PY

# ============================================================
# Hàm chọn profile phù hợp với Bundle ID
# ============================================================

select_profile_index() {
    local bundle_id="$1"

    BUNDLE_ID="${bundle_id}" python3 <<'PY'
import json
import os
import pathlib

bundle_id = os.environ["BUNDLE_ID"]
profile_dir = pathlib.Path(os.environ["PROFILE_INFO_DIR"])

with (profile_dir / "map.json").open(encoding="utf-8") as file:
    profiles = json.load(file)

best = None
best_score = -1

for profile in profiles:
    pattern = profile.get("application_identifier", "")
    team_id = profile.get("team_identifier", "")

    candidates = [bundle_id]

    if team_id:
        candidates.append(f"{team_id}.{bundle_id}")

    for candidate in candidates:
        score = -1

        if pattern == candidate:
            score = 100000 + len(pattern)
        elif pattern.endswith("*"):
            prefix = pattern[:-1]

            if candidate.startswith(prefix):
                score = len(prefix)

        if score > best_score:
            best_score = score
            best = profile

if best is None:
    raise SystemExit(1)

print(best["index"])
PY
}

# ============================================================
# Ký framework và dylib trước
# ============================================================

echo "Đang ký framework..."

python3 <<PY > "${WORK_DIR}/frameworks.txt"
import os

root = r"""${EXTRACT_DIR}/Payload"""
items = []

for current, dirs, files in os.walk(root):
    for directory in dirs:
        if directory.endswith(".framework"):
            items.append(os.path.join(current, directory))

items.sort(key=lambda value: value.count(os.sep), reverse=True)

for item in items:
    print(item)
PY

while IFS= read -r framework; do
    [[ -z "${framework}" ]] && continue

    echo "Ký framework: ${framework}"

    codesign \
        --force \
        --sign "${IDENTITY}" \
        --timestamp=none \
        --generate-entitlement-der \
        "${framework}"
done < "${WORK_DIR}/frameworks.txt"

echo "Đang ký dylib..."

find "${EXTRACT_DIR}/Payload" \
    -type f \
    -name "*.dylib" \
    -print |
while IFS= read -r dylib; do
    echo "Ký dylib: ${dylib}"

    codesign \
        --force \
        --sign "${IDENTITY}" \
        --timestamp=none \
        --generate-entitlement-der \
        "${dylib}"
done

# ============================================================
# Ký app và extension từ sâu ra ngoài
# ============================================================

python3 <<PY > "${WORK_DIR}/bundles.txt"
import os

root = r"""${EXTRACT_DIR}/Payload"""
items = []

for current, dirs, files in os.walk(root):
    for directory in dirs:
        if directory.endswith(".app") or directory.endswith(".appex"):
            items.append(os.path.join(current, directory))

items.sort(key=lambda value: value.count(os.sep), reverse=True)

for item in items:
    print(item)
PY

while IFS= read -r bundle; do
    [[ -z "${bundle}" ]] && continue

    INFO_PLIST="${bundle}/Info.plist"

    if [[ ! -f "${INFO_PLIST}" ]]; then
        echo "Không tìm thấy Info.plist: ${bundle}"
        exit 1
    fi

    BUNDLE_ID="$(
        /usr/libexec/PlistBuddy \
            -c "Print :CFBundleIdentifier" \
            "${INFO_PLIST}"
    )"

    echo "----------------------------------------"
    echo "Bundle: ${bundle}"
    echo "Bundle ID: ${BUNDLE_ID}"

    if ! PROFILE_INDEX="$(select_profile_index "${BUNDLE_ID}")"; then
        echo "Không tìm thấy mobileprovision phù hợp với ${BUNDLE_ID}"
        exit 1
    fi

    PROFILE_PATH="$(
        PROFILE_INDEX="${PROFILE_INDEX}" python3 <<'PY'
import json
import os
import pathlib

index = int(os.environ["PROFILE_INDEX"])
directory = pathlib.Path(os.environ["PROFILE_INFO_DIR"])

with (directory / "map.json").open(encoding="utf-8") as file:
    profiles = json.load(file)

print(profiles[index]["source"])
PY
    )"

    ENTITLEMENTS_PATH="${PROFILE_INFO_DIR}/${PROFILE_INDEX}.entitlements.plist"

    echo "Profile: ${PROFILE_PATH}"

    rm -rf "${bundle}/_CodeSignature"
    rm -f "${bundle}/embedded.mobileprovision"

    cp "${PROFILE_PATH}" "${bundle}/embedded.mobileprovision"

    codesign \
        --force \
        --sign "${IDENTITY}" \
        --entitlements "${ENTITLEMENTS_PATH}" \
        --timestamp=none \
        --generate-entitlement-der \
        "${bundle}"

    codesign --verify --verbose=2 "${bundle}"
done < "${WORK_DIR}/bundles.txt"

# ============================================================
# Kiểm tra app chính
# ============================================================

echo "Kiểm tra chữ ký app chính..."

codesign \
    --verify \
    --deep \
    --strict \
    --verbose=2 \
    "${MAIN_APP}"

# ============================================================
# Đóng gói bằng ZIP mức 9
# ============================================================

echo "Đang đóng gói IPA bằng zip -9..."

rm -f "${OUTPUT_IPA}"

cd "${EXTRACT_DIR}"

export COPYFILE_DISABLE=1

zip \
    -9 \
    -q \
    -r \
    -y \
    "${OUTPUT_IPA}" \
    Payload \
    -x "*.DS_Store" \
    -x "__MACOSX/*"

cd "${ROOT_DIR}"

if [[ ! -f "${OUTPUT_IPA}" ]]; then
    echo "Không tạo được IPA đầu ra"
    exit 1
fi

ORIGINAL_SIZE="$(stat -f%z "${IPA_PATH}")"
SIGNED_SIZE="$(stat -f%z "${OUTPUT_IPA}")"

echo "========================================"
echo "Ký IPA thành công"
echo "IPA gốc: ${ORIGINAL_SIZE} bytes"
echo "IPA đã ký: ${SIGNED_SIZE} bytes"
echo "Đầu ra: ${OUTPUT_IPA}"
echo "========================================"

