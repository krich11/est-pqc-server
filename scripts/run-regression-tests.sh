#!/usr/bin/env bash

set -u
set -o pipefail

EST_BASE_URL="https://192.168.200.120:8443"
WEBUI_URL="https://192.168.200.120:9443"
SSH_HOST="krich@192.168.200.120"
REMOTE_PROJECT_PATH="/home/krich/src/est-rust-server"
REPORT_PATH="test-results/regression-report.md"

WEBUI_ADMIN_USER="admin"
WEBUI_ADMIN_PASS="aruba123"
WEBUI_ALT_USER="krich"
WEBUI_ALT_PASS="mustang"

OPENSSL_BIN="${OPENSSL:-}"
if [[ -z "${OPENSSL_BIN}" ]]; then
  if [[ -x "/opt/homebrew/opt/openssl@3.5/bin/openssl" ]]; then
    OPENSSL_BIN="/opt/homebrew/opt/openssl@3.5/bin/openssl"
  else
    OPENSSL_BIN="openssl"
  fi
fi

CA_CERT_PATH="demo/demo-ca.crt"
CLIENT_CERT_PATH="demo/rsa-2048-client.crt"
CLIENT_KEY_PATH="demo/rsa-2048-client.key"
TRUSTED_CA_PEM_PATH="demo/demo-ca.crt"
LEAF_P12_PATH="demo/rsa-2048-client.p12"
LEAF_P12_PASSWORD="changeit"

WEBUI_SCHEME="https"
WEBUI_HOST="192.168.200.120"
WEBUI_PORT="9443"

TMP_DIR=""
HTTP_STATUS=""
HTTP_BODY_FILE=""
HTTP_HEADERS_FILE=""

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

DRY_RUN=0
SHOW_HELP=0
SHOW_LIST=0

declare -a SELECTED_CATEGORIES=()
declare -a REPORT_ROWS=()
declare -a REPORT_NOTES=()

ALL_CATEGORIES=(
  "build"
  "est"
  "webui-auth"
  "webui-config"
  "webui-users"
  "webui-rules"
  "webui-certs"
  "webui-enrollment"
  "webui-systemd"
  "webui-gui"
)

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run-regression-tests.sh [OPTIONS] [CATEGORY...]

Options:
  --base-url URL              EST base URL
  --webui-url URL             WebUI base URL
  --ssh-host HOST             SSH target for EST artifact validation
  --remote-project-path PATH  Remote project path for EST artifact validation
  --admin-user USER           WebUI super-admin username
  --admin-pass PASS           WebUI super-admin password
  --alt-user USER             Secondary WebUI username
  --alt-pass PASS             Secondary WebUI password
  --leaf-p12 PATH             Leaf P12 file used for certificate store testing
  --leaf-p12-password PASS    Password for the leaf P12
  --trusted-ca-pem PATH       Trusted CA PEM file used for certificate store testing
  --report FILE               Markdown report output path
  --list                      List categories
  --dry-run                   Show selected categories without executing tests
  --help                      Show this help text

Categories:
  build
  est
  webui-auth
  webui-config
  webui-users
  webui-rules
  webui-certs
  webui-enrollment
  webui-systemd
  webui-gui
  all

Examples:
  ./scripts/run-regression-tests.sh all
  ./scripts/run-regression-tests.sh est webui-auth webui-certs
  ./scripts/run-regression-tests.sh --base-url https://192.168.200.120:8443 --webui-url https://192.168.200.120:9443 webui-gui
EOF
}

list_categories() {
  printf '%s\n' "${ALL_CATEGORIES[@]}"
}

set_webui_url() {
  local url="$1"
  WEBUI_URL="$url"
  WEBUI_SCHEME="${url%%://*}"
  local rest="${url#*://}"
  local host_port="${rest%%/*}"

  if [[ "${host_port}" == *:* ]]; then
    WEBUI_HOST="${host_port%%:*}"
    WEBUI_PORT="${host_port##*:}"
  else
    WEBUI_HOST="${host_port}"
    if [[ "${WEBUI_SCHEME}" == "https" ]]; then
      WEBUI_PORT="443"
    else
      WEBUI_PORT="80"
    fi
  fi
}

ensure_tmp_dir() {
  mkdir -p test-results
  if [[ -z "${TMP_DIR}" ]]; then
    TMP_DIR="$(mktemp -d test-results/regression.XXXXXX)"
  fi
}

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

record_note() {
  REPORT_NOTES+=("$1")
}

normalize_categories() {
  if [[ "${#SELECTED_CATEGORIES[@]}" -eq 0 ]]; then
    SELECTED_CATEGORIES=("all")
  fi

  local expanded=()
  local category
  for category in "${SELECTED_CATEGORIES[@]}"; do
    if [[ "${category}" == "all" ]]; then
      expanded=("${ALL_CATEGORIES[@]}")
      break
    fi
    expanded+=("${category}")
  done

  SELECTED_CATEGORIES=("${expanded[@]}")
}

is_known_category() {
  local target="$1"
  local category
  for category in "${ALL_CATEGORIES[@]}"; do
    if [[ "${category}" == "${target}" ]]; then
      return 0
    fi
  done
  return 1
}

assert_file_exists() {
  local path="$1"
  [[ -f "${path}" ]]
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  [[ "${haystack}" == *"${needle}"* ]]
}

assert_status() {
  local expected="$1"
  if [[ "${HTTP_STATUS}" != "${expected}" ]]; then
    echo "unexpected HTTP status: got ${HTTP_STATUS}, expected ${expected}" >&2
    if [[ -f "${HTTP_BODY_FILE}" ]]; then
      cat "${HTTP_BODY_FILE}" >&2
    fi
    return 1
  fi
}

http_request() {
  local method="$1"
  local url="$2"
  local auth="$3"
  local body="${4-}"

  ensure_tmp_dir

  HTTP_HEADERS_FILE="$(mktemp "${TMP_DIR}/headers.XXXXXX")"
  HTTP_BODY_FILE="$(mktemp "${TMP_DIR}/body.XXXXXX")"

  local -a curl_args=(
    --silent
    --show-error
    --output "${HTTP_BODY_FILE}"
    --dump-header "${HTTP_HEADERS_FILE}"
    --write-out "%{http_code}"
    -X "${method}"
  )

  case "${auth}" in
    none)
      ;;
    admin)
      curl_args+=(-u "${WEBUI_ADMIN_USER}:${WEBUI_ADMIN_PASS}")
      ;;
    alt)
      curl_args+=(-u "${WEBUI_ALT_USER}:${WEBUI_ALT_PASS}")
      ;;
    custom:*)
      curl_args+=(-u "${auth#custom:}")
      ;;
    *)
      echo "unsupported auth mode: ${auth}" >&2
      return 1
      ;;
  esac

  if [[ -n "${body}" ]]; then
    curl_args+=(-H "Content-Type: application/json" --data "${body}")
  fi

  if [[ "${WEBUI_SCHEME}" == "https" ]]; then
    curl_args+=(--insecure)
  fi

  HTTP_STATUS="$(curl "${curl_args[@]}" "${url}")"
}

json_from_http_body() {
  jq . "${HTTP_BODY_FILE}"
}

json_query() {
  local filter="$1"
  jq -r "${filter}" "${HTTP_BODY_FILE}"
}

extract_cert_cn_from_pem() {
  local path="$1"
  "${OPENSSL_BIN}" x509 -in "${path}" -noout -subject -nameopt RFC2253 |
    sed -E 's/^subject=//; s/.*CN=([^,\/]+).*/\1/'
}

extract_cert_fingerprint_from_pem() {
  local path="$1"
  "${OPENSSL_BIN}" x509 -in "${path}" -noout -fingerprint -sha256 |
    sed -E 's/^.*=//; s/://g' |
    tr 'A-Z' 'a-z'
}

extract_cert_cn_from_p12() {
  local path="$1"
  local password="$2"
  "${OPENSSL_BIN}" pkcs12 -in "${path}" -passin "pass:${password}" -clcerts -nokeys 2>/dev/null |
    "${OPENSSL_BIN}" x509 -noout -subject -nameopt RFC2253 |
    sed -E 's/^subject=//; s/.*CN=([^,\/]+).*/\1/'
}

extract_cert_fingerprint_from_p12() {
  local path="$1"
  local password="$2"
  "${OPENSSL_BIN}" pkcs12 -in "${path}" -passin "pass:${password}" -clcerts -nokeys 2>/dev/null |
    "${OPENSSL_BIN}" x509 -noout -fingerprint -sha256 |
    sed -E 's/^.*=//; s/://g' |
    tr 'A-Z' 'a-z'
}

base64_file() {
  python3 - "$1" <<'PY'
import base64
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
sys.stdout.write(base64.b64encode(path.read_bytes()).decode("ascii"))
PY
}

create_temp_untrusted_p12() {
  ensure_tmp_dir
  local untrusted_dir="${TMP_DIR}/untrusted"
  mkdir -p "${untrusted_dir}"

  "${OPENSSL_BIN}" req -x509 -newkey rsa:2048 -nodes \
    -subj "/CN=Regression Untrusted CA/O=EST Regression" \
    -keyout "${untrusted_dir}/ca.key" \
    -out "${untrusted_dir}/ca.crt" \
    -days 1 >/dev/null 2>&1

  "${OPENSSL_BIN}" req -newkey rsa:2048 -nodes \
    -subj "/CN=Regression Untrusted Leaf/O=EST Regression" \
    -keyout "${untrusted_dir}/leaf.key" \
    -out "${untrusted_dir}/leaf.csr" >/dev/null 2>&1

  "${OPENSSL_BIN}" x509 -req \
    -in "${untrusted_dir}/leaf.csr" \
    -CA "${untrusted_dir}/ca.crt" \
    -CAkey "${untrusted_dir}/ca.key" \
    -CAcreateserial \
    -out "${untrusted_dir}/leaf.crt" \
    -days 1 >/dev/null 2>&1

  "${OPENSSL_BIN}" pkcs12 -export \
    -out "${untrusted_dir}/leaf.p12" \
    -inkey "${untrusted_dir}/leaf.key" \
    -in "${untrusted_dir}/leaf.crt" \
    -certfile "${untrusted_dir}/ca.crt" \
    -passout pass:untrusted >/dev/null 2>&1

  printf '%s\n' "${untrusted_dir}/leaf.p12"
}

create_temp_csr_der() {
  local cn="$1"
  ensure_tmp_dir
  local csr_prefix="${TMP_DIR}/${cn}"
  "${OPENSSL_BIN}" req -new -newkey rsa:2048 -nodes \
    -subj "/CN=${cn}/O=EST Regression/OU=QA" \
    -keyout "${csr_prefix}.key.pem" \
    -out "${csr_prefix}.csr.pem" >/dev/null 2>&1
  "${OPENSSL_BIN}" req \
    -in "${csr_prefix}.csr.pem" \
    -outform DER \
    -out "${csr_prefix}.csr.der" >/dev/null 2>&1
  printf '%s\n' "${csr_prefix}.csr.der"
}

est_submit_simpleenroll() {
  local csr_der_path="$1"
  local prefer_async="${2:-0}"

  ensure_tmp_dir

  local headers_path
  local body_path
  headers_path="$(mktemp "${TMP_DIR}/est.headers.XXXXXX")"
  body_path="$(mktemp "${TMP_DIR}/est.body.XXXXXX")"

  local -a curl_args=(
    --silent
    --show-error
    --http1.1
    --cacert "${CA_CERT_PATH}"
    --cert "${CLIENT_CERT_PATH}"
    --key "${CLIENT_KEY_PATH}"
    --header "Content-Type: application/pkcs10"
    --data-binary "@${csr_der_path}"
    --output "${body_path}"
    --dump-header "${headers_path}"
    --write-out "%{http_code}"
  )

  if [[ "${prefer_async}" == "1" ]]; then
    curl_args+=(--header "Prefer: respond-async")
  fi

  EST_HTTP_HEADERS_FILE="${headers_path}"
  EST_HTTP_BODY_FILE="${body_path}"
  EST_HTTP_STATUS="$(curl "${curl_args[@]}" "${EST_BASE_URL}/.well-known/est/simpleenroll")"
}

run_check() {
  local category="$1"
  local id="$2"
  local description="$3"
  local function_name="$4"

  ensure_tmp_dir

  local log_file="${TMP_DIR}/${id}.log"
  printf '[%s] %s\n' "${id}" "${description}"

  if "${function_name}" >"${log_file}" 2>&1; then
    PASS_COUNT=$((PASS_COUNT + 1))
    REPORT_ROWS+=("| ${category} | ${id} | PASS | ${description} | ${log_file} |")
    printf '  PASS\n'
    return 0
  fi

  FAIL_COUNT=$((FAIL_COUNT + 1))
  REPORT_ROWS+=("| ${category} | ${id} | FAIL | ${description} | ${log_file} |")
  printf '  FAIL\n'
  sed -n '1,120p' "${log_file}" >&2
  return 1
}

run_category_build() {
  run_check "build" "B-01" "cargo fmt --all --check" test_build_fmt
  run_check "build" "B-02" "cargo clippy --all-targets -- -D warnings" test_build_clippy
  run_check "build" "B-03" "cargo test" test_build_test
  run_check "build" "B-04" "node --check webui/static/app.js" test_build_node
  run_check "build" "B-05" "cargo build --release" test_build_release
}

run_category_est() {
  run_check "est" "E-ALL" "full EST RFC 7030 validation suite against QA server" test_est_full_suite
}

run_category_webui_auth() {
  run_check "webui-auth" "WA-01" "unauthenticated root returns Basic challenge" test_webui_auth_unauthenticated_root
  run_check "webui-auth" "WA-02" "invalid WebUI credentials are rejected" test_webui_auth_invalid_credentials
  run_check "webui-auth" "WA-03" "admin api/me succeeds" test_webui_auth_admin_me
  run_check "webui-auth" "WA-04" "secondary user api/me succeeds" test_webui_auth_alt_me
  run_check "webui-auth" "WA-05" "browser logout and account switching flow succeeds" test_webui_auth_browser_switch
}

run_category_webui_config() {
  run_check "webui-config" "WC-01" "configuration GET returns expected fields" test_webui_config_get
  run_check "webui-config" "WC-02" "configuration POST persists a temporary change and restore" test_webui_config_round_trip
}

run_category_webui_users() {
  run_check "webui-users" "WU-01" "user listing, create, role, enable, password, own-password, and delete flow" test_webui_users_full_flow
}

run_category_webui_rules() {
  run_check "webui-rules" "WR-01" "rules GET and POST round-trip with temporary rule" test_webui_rules_round_trip
}

run_category_webui_certs() {
  run_check "webui-certs" "WCERT-01" "certificate store load, validate, view, list, and cleanup flow" test_webui_certificate_store_flow
}

run_category_webui_enrollment() {
  run_check "webui-enrollment" "WENR-01" "pending enrollment approve and reject flow through WebUI APIs" test_webui_enrollment_flow
}

run_category_webui_systemd() {
  run_check "webui-systemd" "WS-01" "systemd status endpoint returns est-server details" test_webui_systemd_status
  run_check "webui-systemd" "WS-02" "invalid systemd action returns 400" test_webui_systemd_invalid_action
  run_check "webui-systemd" "WS-03" "systemd restart action succeeds through WebUI API" test_webui_systemd_restart
}

run_category_webui_gui() {
  run_check "webui-gui" "WG-01" "browser navigation and GUI view coverage" test_webui_gui_navigation
}

test_build_fmt() {
  cargo fmt --all --check
}

test_build_clippy() {
  cargo clippy --all-targets -- -D warnings
}

test_build_test() {
  cargo test
}

test_build_node() {
  node --check webui/static/app.js
}

test_build_release() {
  cargo build --release
}

test_est_full_suite() {
  cargo run --release --bin test-client -- \
    --validate-all \
    --base-url "${EST_BASE_URL}" \
    --ssh-host "${SSH_HOST}" \
    --remote-project-path "${REMOTE_PROJECT_PATH}"
}

test_webui_auth_unauthenticated_root() {
  http_request "GET" "${WEBUI_URL}/" "none"
  assert_status "401"
  grep -qi '^www-authenticate: Basic realm="EST WebUI"' "${HTTP_HEADERS_FILE}"
}

test_webui_auth_invalid_credentials() {
  http_request "GET" "${WEBUI_URL}/api/me" "custom:${WEBUI_ADMIN_USER}:definitely-wrong-password"
  assert_status "401"
}

test_webui_auth_admin_me() {
  http_request "GET" "${WEBUI_URL}/api/me" "admin"
  assert_status "200"
  [[ "$(json_query '.username')" == "${WEBUI_ADMIN_USER}" ]]
}

test_webui_auth_alt_me() {
  http_request "GET" "${WEBUI_URL}/api/me" "alt"
  assert_status "200"
  [[ "$(json_query '.username')" == "${WEBUI_ALT_USER}" ]]
}

test_webui_auth_browser_switch() {
  WEBUI_HOST="${WEBUI_HOST}" \
  WEBUI_PORT="${WEBUI_PORT}" \
  WEBUI_SCHEME="${WEBUI_SCHEME}" \
  node scripts/browser-auth-switch-test.cjs
}

test_webui_config_get() {
  http_request "GET" "${WEBUI_URL}/api/config" "admin"
  assert_status "200"
  [[ "$(json_query '.listen_port')" == "8443" ]]
  [[ "$(json_query '.webui.listen_port')" == "9443" ]]
  [[ "$(json_query '.webui.systemd_unit_name')" == "est-server" ]]
}

test_webui_config_round_trip() {
  http_request "GET" "${WEBUI_URL}/api/config" "admin"
  assert_status "200"

  local original_json
  original_json="$(cat "${HTTP_BODY_FILE}")"

  local modified_json
  modified_json="$(jq '.max_request_body_bytes = (.max_request_body_bytes + 1)' "${HTTP_BODY_FILE}")"

  http_request "POST" "${WEBUI_URL}/api/config" "admin" "${modified_json}"
  assert_status "200"
  local changed_value
  changed_value="$(json_query '.max_request_body_bytes')"

  http_request "GET" "${WEBUI_URL}/api/config" "admin"
  assert_status "200"
  [[ "$(json_query '.max_request_body_bytes')" == "${changed_value}" ]]

  http_request "POST" "${WEBUI_URL}/api/config" "admin" "${original_json}"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/config" "admin"
  assert_status "200"
  [[ "$(json_query '.max_request_body_bytes')" == "$(printf '%s' "${original_json}" | jq -r '.max_request_body_bytes')" ]]
}

test_webui_users_full_flow() {
  local temp_user="regression-api-user-$(date +%s)"
  local temp_pass="TempPass!123"
  local changed_pass="ChangedPass!123"

  http_request "GET" "${WEBUI_URL}/api/users" "admin"
  assert_status "200"
  jq -e --arg username "${WEBUI_ADMIN_USER}" '.[] | select(.username == $username)' "${HTTP_BODY_FILE}" >/dev/null
  jq -e --arg username "${WEBUI_ALT_USER}" '.[] | select(.username == $username)' "${HTTP_BODY_FILE}" >/dev/null

  local create_payload
  create_payload="$(jq -nc --arg username "${temp_user}" --arg password "${temp_pass}" --arg role "admin" \
    '{username: $username, password: $password, role: $role}')"

  http_request "POST" "${WEBUI_URL}/api/users" "admin" "${create_payload}"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/users" "admin"
  assert_status "200"
  jq -e --arg username "${temp_user}" '.[] | select(.username == $username)' "${HTTP_BODY_FILE}" >/dev/null

  http_request "POST" "${WEBUI_URL}/api/users/${temp_user}/password" "admin" \
    "$(jq -nc --arg password "${changed_pass}" '{password: $password}')"
  assert_status "200"

  http_request "POST" "${WEBUI_URL}/api/users/${temp_user}/role" "admin" \
    "$(jq -nc --arg role "super-admin" '{role: $role}')"
  assert_status "200"

  http_request "POST" "${WEBUI_URL}/api/users/${temp_user}/enabled" "admin" \
    "$(jq -nc '{enabled: false}')"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/me" "custom:${temp_user}:${changed_pass}"
  assert_status "401"

  http_request "POST" "${WEBUI_URL}/api/users/${temp_user}/enabled" "admin" \
    "$(jq -nc '{enabled: true}')"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/me" "custom:${temp_user}:${changed_pass}"
  assert_status "200"

  http_request "POST" "${WEBUI_URL}/api/account/password" "custom:${temp_user}:${changed_pass}" \
    "$(jq -nc --arg current_password "${changed_pass}" --arg new_password "${temp_pass}" \
      '{current_password: $current_password, new_password: $new_password}')"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/me" "custom:${temp_user}:${temp_pass}"
  assert_status "200"

  http_request "POST" "${WEBUI_URL}/api/users/${temp_user}/delete" "admin"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/users" "admin"
  assert_status "200"
  ! jq -e --arg username "${temp_user}" '.[] | select(.username == $username)' "${HTTP_BODY_FILE}" >/dev/null
}

test_webui_rules_round_trip() {
  http_request "GET" "${WEBUI_URL}/api/rules" "admin"
  assert_status "200"

  local original_json
  original_json="$(cat "${HTTP_BODY_FILE}")"

  local temp_rule_name="regression-rule-$(date +%s)"
  local modified_json
  modified_json="$(jq --arg name "${temp_rule_name}" '.rules += [{
      name: $name,
      match_subject_cn: "^never-match-regression$",
      match_subject_ou: null,
      match_subject_o: null,
      match_san_dns: null,
      match_san_email: null,
      match_client_cert_issuer: null,
      match_key_type: null,
      action: "manual",
      reject_reason: null
    }]' "${HTTP_BODY_FILE}")"

  http_request "POST" "${WEBUI_URL}/api/rules" "admin" "${modified_json}"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/rules" "admin"
  assert_status "200"
  jq -e --arg name "${temp_rule_name}" '.rules[] | select(.name == $name)' "${HTTP_BODY_FILE}" >/dev/null

  http_request "POST" "${WEBUI_URL}/api/rules" "admin" "${original_json}"
  assert_status "200"

  http_request "GET" "${WEBUI_URL}/api/rules" "admin"
  assert_status "200"
  ! jq -e --arg name "${temp_rule_name}" '.rules[] | select(.name == $name)' "${HTTP_BODY_FILE}" >/dev/null
}

test_webui_certificate_store_flow() {
  local ca_cn
  local leaf_cn
  local ca_fingerprint
  local leaf_fingerprint
  local demo_ca_preexisting
  local demo_leaf_preexisting

  ca_cn="$(extract_cert_cn_from_pem "${TRUSTED_CA_PEM_PATH}")"
  leaf_cn="$(extract_cert_cn_from_p12 "${LEAF_P12_PATH}" "${LEAF_P12_PASSWORD}")"
  ca_fingerprint="$(extract_cert_fingerprint_from_pem "${TRUSTED_CA_PEM_PATH}")"
  leaf_fingerprint="$(extract_cert_fingerprint_from_p12 "${LEAF_P12_PATH}" "${LEAF_P12_PASSWORD}")"

  http_request "GET" "${WEBUI_URL}/api/certstore/ca" "admin"
  assert_status "200"
  if jq -e --arg fingerprint "${ca_fingerprint}" '.[] | select(.fingerprint == $fingerprint)' "${HTTP_BODY_FILE}" >/dev/null; then
    demo_ca_preexisting="yes"
  else
    demo_ca_preexisting="no"
  fi

  http_request "GET" "${WEBUI_URL}/api/certstore/leaf" "admin"
  assert_status "200"
  if jq -e --arg fingerprint "${leaf_fingerprint}" '.[] | select(.fingerprint == $fingerprint)' "${HTTP_BODY_FILE}" >/dev/null; then
    demo_leaf_preexisting="yes"
  else
    demo_leaf_preexisting="no"
  fi

  local negative_p12_path
  local negative_p12_password
  negative_p12_password="${LEAF_P12_PASSWORD}"
  negative_p12_path="${LEAF_P12_PATH}"

  if [[ "${demo_ca_preexisting}" == "yes" ]]; then
    negative_p12_path="$(create_temp_untrusted_p12)"
    negative_p12_password="untrusted"
  fi

  local negative_payload
  negative_payload="$(jq -nc \
    --arg filename "$(basename "${negative_p12_path}")" \
    --arg password "${negative_p12_password}" \
    --arg content_base64 "$(base64_file "${negative_p12_path}")" \
    '{filename: $filename, password: $password, content_base64: $content_base64}')"

  http_request "POST" "${WEBUI_URL}/api/certstore/leaf" "admin" "${negative_payload}"
  assert_status "400"
  grep -q "The Trusted CA must be loaded first." "${HTTP_BODY_FILE}"

  local trusted_ca_payload
  trusted_ca_payload="$(jq -nc \
    --arg filename "$(basename "${TRUSTED_CA_PEM_PATH}")" \
    --arg content_base64 "$(base64_file "${TRUSTED_CA_PEM_PATH}")" \
    '{filename: $filename, content_base64: $content_base64}')"

  http_request "POST" "${WEBUI_URL}/api/certstore/ca" "admin" "${trusted_ca_payload}"
  assert_status "200"
  [[ "$(json_query '.fingerprint')" == "${ca_fingerprint}" ]]

  http_request "GET" "${WEBUI_URL}/api/certstore/ca/${ca_fingerprint}" "admin"
  assert_status "200"
  grep -q "${ca_cn}" "${HTTP_BODY_FILE}"
  grep -q "BEGIN CERTIFICATE" "${HTTP_BODY_FILE}"

  local leaf_payload
  leaf_payload="$(jq -nc \
    --arg filename "$(basename "${LEAF_P12_PATH}")" \
    --arg password "${LEAF_P12_PASSWORD}" \
    --arg content_base64 "$(base64_file "${LEAF_P12_PATH}")" \
    '{filename: $filename, password: $password, content_base64: $content_base64}')"

  http_request "POST" "${WEBUI_URL}/api/certstore/leaf" "admin" "${leaf_payload}"
  assert_status "200"
  [[ "$(json_query '.fingerprint')" == "${leaf_fingerprint}" ]]

  http_request "GET" "${WEBUI_URL}/api/certstore/leaf" "admin"
  assert_status "200"
  jq -e --arg fingerprint "${leaf_fingerprint}" '.[] | select(.fingerprint == $fingerprint)' "${HTTP_BODY_FILE}" >/dev/null

  http_request "GET" "${WEBUI_URL}/api/certstore/leaf/${leaf_fingerprint}" "admin"
  assert_status "200"
  grep -q "${leaf_cn}" "${HTTP_BODY_FILE}"
  grep -q "BEGIN CERTIFICATE" "${HTTP_BODY_FILE}"

  if [[ "${demo_leaf_preexisting}" == "no" ]]; then
    http_request "DELETE" "${WEBUI_URL}/api/certstore/leaf/${leaf_fingerprint}" "admin"
    assert_status "204"
  fi

  if [[ "${demo_ca_preexisting}" == "no" ]]; then
    http_request "DELETE" "${WEBUI_URL}/api/certstore/ca/${ca_fingerprint}" "admin"
    assert_status "204"
  fi
}

test_webui_enrollment_flow() {
  http_request "GET" "${WEBUI_URL}/api/rules" "admin"
  assert_status "200"

  local original_rules_json
  original_rules_json="$(cat "${HTTP_BODY_FILE}")"

  local approve_cn="regression-approve-$(date +%s)"
  local reject_cn="regression-reject-$(date +%s)"
  local reject_reason="regression rejected on purpose"

  local modified_rules_json
  modified_rules_json="$(jq \
    --arg approve_name "regression-approve-rule" \
    --arg approve_cn "^${approve_cn}$" \
    --arg reject_name "regression-reject-rule" \
    --arg reject_cn "^${reject_cn}$" \
    '.rules = [
      {
        name: $approve_name,
        match_subject_cn: $approve_cn,
        match_subject_ou: null,
        match_subject_o: null,
        match_san_dns: null,
        match_san_email: null,
        match_client_cert_issuer: null,
        match_key_type: null,
        action: "manual",
        reject_reason: null
      },
      {
        name: $reject_name,
        match_subject_cn: $reject_cn,
        match_subject_ou: null,
        match_subject_o: null,
        match_san_dns: null,
        match_san_email: null,
        match_client_cert_issuer: null,
        match_key_type: null,
        action: "manual",
        reject_reason: null
      }
    ] + .rules' "${HTTP_BODY_FILE}")"

  http_request "POST" "${WEBUI_URL}/api/rules" "admin" "${modified_rules_json}"
  assert_status "200"

  local approve_csr_der
  local reject_csr_der
  approve_csr_der="$(create_temp_csr_der "${approve_cn}")"
  reject_csr_der="$(create_temp_csr_der "${reject_cn}")"

  est_submit_simpleenroll "${approve_csr_der}" 0
  [[ "${EST_HTTP_STATUS}" == "202" ]]

  est_submit_simpleenroll "${reject_csr_der}" 0
  [[ "${EST_HTTP_STATUS}" == "202" ]]

  http_request "GET" "${WEBUI_URL}/api/enrollment/pending" "admin"
  assert_status "200"

  local approve_operation
  local approve_artifact_id
  local reject_operation
  local reject_artifact_id

  approve_operation="$(jq -r --arg cn "${approve_cn}" '.[] | select(.context.subject_cn == $cn) | .operation' "${HTTP_BODY_FILE}" | head -n1)"
  approve_artifact_id="$(jq -r --arg cn "${approve_cn}" '.[] | select(.context.subject_cn == $cn) | .artifact_id' "${HTTP_BODY_FILE}" | head -n1)"
  reject_operation="$(jq -r --arg cn "${reject_cn}" '.[] | select(.context.subject_cn == $cn) | .operation' "${HTTP_BODY_FILE}" | head -n1)"
  reject_artifact_id="$(jq -r --arg cn "${reject_cn}" '.[] | select(.context.subject_cn == $cn) | .artifact_id' "${HTTP_BODY_FILE}" | head -n1)"

  [[ -n "${approve_operation}" && -n "${approve_artifact_id}" ]]
  [[ -n "${reject_operation}" && -n "${reject_artifact_id}" ]]

  http_request \
    "POST" \
    "${WEBUI_URL}/api/enrollment/pending/${approve_operation}/${approve_artifact_id}/approve" \
    "admin"
  assert_status "200"
  grep -qi "${approve_artifact_id}" "${HTTP_BODY_FILE}"

  http_request \
    "POST" \
    "${WEBUI_URL}/api/enrollment/pending/${reject_operation}/${reject_artifact_id}/reject" \
    "admin" \
    "$(jq -nc --arg reason "${reject_reason}" '{reason: $reason}')"
  assert_status "200"
  grep -qi "${reject_reason}" "${HTTP_BODY_FILE}"

  est_submit_simpleenroll "${approve_csr_der}" 0
  [[ "${EST_HTTP_STATUS}" == "200" ]]

  est_submit_simpleenroll "${reject_csr_der}" 0
  [[ "${EST_HTTP_STATUS}" != "200" ]]
  [[ "${EST_HTTP_STATUS}" != "202" ]]

  http_request "GET" "${WEBUI_URL}/api/enrollment/history" "admin"
  assert_status "200"
  jq -e --arg artifact_id "${approve_artifact_id}" '.[] | select(.artifact_id == $artifact_id)' "${HTTP_BODY_FILE}" >/dev/null

  http_request "POST" "${WEBUI_URL}/api/rules" "admin" "${original_rules_json}"
  assert_status "200"
}

test_webui_systemd_status() {
  http_request "GET" "${WEBUI_URL}/api/systemd/status" "admin"
  assert_status "200"
  [[ "$(json_query '.unit_name')" == "est-server" ]]
  [[ "$(json_query '.active_state')" == "active" ]]
}

test_webui_systemd_invalid_action() {
  http_request "POST" "${WEBUI_URL}/api/systemd/not-a-real-action" "admin"
  assert_status "400"
}

test_webui_systemd_restart() {
  http_request "POST" "${WEBUI_URL}/api/systemd/restart" "admin"
  assert_status "200"
  [[ "$(json_query '.action')" == "restart" ]]

  sleep 2

  http_request "GET" "${WEBUI_URL}/api/status" "admin"
  assert_status "200"
  [[ "$(json_query '.systemd_active_state')" == "active" ]]
}

test_webui_gui_navigation() {
  WEBUI_HOST="${WEBUI_HOST}" \
  WEBUI_PORT="${WEBUI_PORT}" \
  WEBUI_SCHEME="${WEBUI_SCHEME}" \
  WEBUI_ADMIN_USER="${WEBUI_ADMIN_USER}" \
  WEBUI_ADMIN_PASS="${WEBUI_ADMIN_PASS}" \
  node scripts/webui-regression-test.cjs
}

write_report() {
  mkdir -p "$(dirname "${REPORT_PATH}")"

  {
    echo "# Regression Test Report"
    echo
    echo "- EST base URL: \`${EST_BASE_URL}\`"
    echo "- WebUI URL: \`${WEBUI_URL}\`"
    echo "- SSH host: \`${SSH_HOST}\`"
    echo "- Report generated: \`$(date)\`"
    echo
    echo "## Summary"
    echo
    echo "- Passed: ${PASS_COUNT}"
    echo "- Failed: ${FAIL_COUNT}"
    echo "- Skipped: ${SKIP_COUNT}"
    echo
    echo "## Results"
    echo
    echo "| Category | ID | Status | Description | Log |"
    echo "|---|---|---|---|---|"
    printf '%s\n' "${REPORT_ROWS[@]}"
    if [[ "${#REPORT_NOTES[@]}" -gt 0 ]]; then
      echo
      echo "## Notes"
      echo
      local note
      for note in "${REPORT_NOTES[@]}"; do
        echo "- ${note}"
      done
    fi
  } >"${REPORT_PATH}"
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --base-url)
        EST_BASE_URL="$2"
        shift 2
        ;;
      --webui-url)
        set_webui_url "$2"
        shift 2
        ;;
      --ssh-host)
        SSH_HOST="$2"
        shift 2
        ;;
      --remote-project-path)
        REMOTE_PROJECT_PATH="$2"
        shift 2
        ;;
      --admin-user)
        WEBUI_ADMIN_USER="$2"
        shift 2
        ;;
      --admin-pass)
        WEBUI_ADMIN_PASS="$2"
        shift 2
        ;;
      --alt-user)
        WEBUI_ALT_USER="$2"
        shift 2
        ;;
      --alt-pass)
        WEBUI_ALT_PASS="$2"
        shift 2
        ;;
      --leaf-p12)
        LEAF_P12_PATH="$2"
        shift 2
        ;;
      --leaf-p12-password)
        LEAF_P12_PASSWORD="$2"
        shift 2
        ;;
      --trusted-ca-pem)
        TRUSTED_CA_PEM_PATH="$2"
        shift 2
        ;;
      --report)
        REPORT_PATH="$2"
        shift 2
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --list)
        SHOW_LIST=1
        shift
        ;;
      --help)
        SHOW_HELP=1
        shift
        ;;
      *)
        SELECTED_CATEGORIES+=("$1")
        shift
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  if [[ "${SHOW_HELP}" == "1" ]]; then
    usage
    exit 0
  fi

  if [[ "${SHOW_LIST}" == "1" ]]; then
    list_categories
    exit 0
  fi

  normalize_categories

  local category
  for category in "${SELECTED_CATEGORIES[@]}"; do
    if ! is_known_category "${category}"; then
      echo "unknown category: ${category}" >&2
      usage >&2
      exit 1
    fi
  done

  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '%s\n' "${SELECTED_CATEGORIES[@]}"
    exit 0
  fi

  ensure_tmp_dir

  record_note "QA WebUI on port 9443 is currently reachable over HTTPS at ${WEBUI_URL}."
  record_note "QA service restart method is systemctl via sudo systemctl restart est-server."
  record_note "QA WebUI credentials in active use for regression are ${WEBUI_ADMIN_USER}/*** and ${WEBUI_ALT_USER}/***."

  for category in "${SELECTED_CATEGORIES[@]}"; do
    case "${category}" in
      build)
        run_category_build
        ;;
      est)
        run_category_est
        ;;
      webui-auth)
        run_category_webui_auth
        ;;
      webui-config)
        run_category_webui_config
        ;;
      webui-users)
        run_category_webui_users
        ;;
      webui-rules)
        run_category_webui_rules
        ;;
      webui-certs)
        run_category_webui_certs
        ;;
      webui-enrollment)
        run_category_webui_enrollment
        ;;
      webui-systemd)
        run_category_webui_systemd
        ;;
      webui-gui)
        run_category_webui_gui
        ;;
    esac
  done

  write_report

  echo "Report written to ${REPORT_PATH}"
  echo "Passed: ${PASS_COUNT}"
  echo "Failed: ${FAIL_COUNT}"
  echo "Skipped: ${SKIP_COUNT}"

  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
  fi
}

main "$@"