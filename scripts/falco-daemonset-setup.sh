#!/usr/bin/env bash
# Installs cluster Falco via Helm, wires http_output to Medusa API,
# and preloads medusa_rules.yaml.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load optional .env from script dir or Medusa root
load_env() {
  local f
  for f in "${SCRIPT_DIR}/.env" "${MEDUSA_ROOT:-}/.env"; do
    if [[ -n "${f}" && -f "${f}" ]]; then
      set -a
      # shellcheck disable=SC1090
      source "${f}"
      set +a
      echo "Loaded env from ${f}"
      return 0
    fi
  done
}

usage() {
  cat <<'EOF'
Usage:
  falco-daemonset-setup.sh              Install/upgrade Falco for Medusa
  falco-daemonset-setup.sh --uninstall  Remove Falco Helm release
  falco-daemonset-setup.sh --help

Environment (see script header comments for full list):
  MEDUSA_ROOT, MEDUSA_API_HOST, MEDUSA_API_PORT, MEDUSA_API_PATH
  FALCO_RELEASE, FALCO_NAMESPACE, FALCO_DRIVER_KIND, ENABLE_K8S_META
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found in PATH" >&2; exit 1; }
}

detect_node_ip() {
  kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null \
    || kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null \
    || true
}

indent_rules() {
  local file="$1"
  sed 's/^/    /' "${file}"
}

uninstall_falco() {
  require_cmd helm
  require_cmd kubectl

  local ns="${FALCO_NAMESPACE:-falco}"
  local rel="${FALCO_RELEASE:-falco}"

  if helm status "${rel}" -n "${ns}" >/dev/null 2>&1; then
    echo "Uninstalling Helm release '${rel}' in namespace '${ns}'..."
    helm uninstall "${rel}" -n "${ns}"
  else
    echo "Release '${rel}' not found in namespace '${ns}'."
  fi
}

main() {
  local action="install"
  case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --uninstall) action="uninstall" ;;
    "") ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac

  load_env

  # Defaults
  MEDUSA_ROOT="${MEDUSA_ROOT:-/home/ubuntu/Medusa}"
  MEDUSA_API_PORT="${MEDUSA_API_PORT:-8000}"
  MEDUSA_API_PATH="${MEDUSA_API_PATH:-/alerts/falco}"
  FALCO_RELEASE="${FALCO_RELEASE:-falco}"
  FALCO_NAMESPACE="${FALCO_NAMESPACE:-falco}"
  FALCO_DRIVER_KIND="${FALCO_DRIVER_KIND:-modern_ebpf}"
  ENABLE_K8S_META="${ENABLE_K8S_META:-false}"
  SKIP_API_PREFLIGHT="${SKIP_API_PREFLIGHT:-false}"
  SKIP_MEDUSA_CHECK="${SKIP_MEDUSA_CHECK:-false}"
  MEDUSA_RULES_FILE="${MEDUSA_RULES_FILE:-${MEDUSA_ROOT}/infra/falco/rules/medusa_rules.yaml}"

  if [[ "${action}" == "uninstall" ]]; then
    uninstall_falco
    exit 0
  fi

  require_cmd kubectl
  require_cmd helm
  require_cmd curl

  if [[ ! -f "${MEDUSA_RULES_FILE}" ]]; then
    echo "ERROR: Rules file not found: ${MEDUSA_RULES_FILE}" >&2
    exit 1
  fi

  # Resolve API host
  if [[ -z "${MEDUSA_API_HOST:-}" ]]; then
    MEDUSA_API_HOST="$(detect_node_ip)"
  fi
  if [[ -z "${MEDUSA_API_HOST}" ]]; then
    echo "ERROR: Could not detect node IP. Set MEDUSA_API_HOST manually." >&2
    exit 1
  fi

  local webhook_url="http://${MEDUSA_API_HOST}:${MEDUSA_API_PORT}${MEDUSA_API_PATH}"
  local values_file
  values_file="$(mktemp /tmp/medusa-falco-values.XXXXXX.yaml)"

  echo "=== Medusa Falco installer ==="
  echo "Release:      ${FALCO_RELEASE}"
  echo "Namespace:    ${FALCO_NAMESPACE}"
  echo "Driver:       ${FALCO_DRIVER_KIND}"
  echo "Webhook URL:  ${webhook_url}"
  echo "Rules file:   ${MEDUSA_RULES_FILE}"
  echo "K8s meta:     ${ENABLE_K8S_META}"
  echo "Values file:  ${values_file}"


  # verify Medusa API is reachable
  if [[ "${SKIP_MEDUSA_CHECK}" != "true" ]]; then
    echo "Checking Medusa API at http://127.0.0.1:${MEDUSA_API_PORT}/health ..."
    if ! curl -sf "http://127.0.0.1:${MEDUSA_API_PORT}/health" >/dev/null; then
      echo "WARNING: Medusa API not reachable on localhost:${MEDUSA_API_PORT}."
      echo "         Start it with: docker compose up -d api postgres"
      echo "         Or set SKIP_MEDUSA_CHECK=true to continue anyway."
      exit 1
    fi
    echo "Medusa API health check OK."
  fi

  # verify cluster pods can reach the webhook URL
  if [[ "${SKIP_API_PREFLIGHT}" != "true" ]]; then
    echo "Checking cluster → API connectivity (${webhook_url}) ..."
  local preflight_ok=false
  if kubectl run medusa-falco-preflight \
      --rm -i --restart=Never \
      --image=curlimages/curl:8.11.1 \
      --command -- \
      curl -sf --max-time 5 "http://${MEDUSA_API_HOST}:${MEDUSA_API_PORT}/health" \
      >/dev/null 2>&1; then
    preflight_ok=true
  fi
  if [[ "${preflight_ok}" != "true" ]]; then
    echo "ERROR: A cluster pod cannot reach http://${MEDUSA_API_HOST}:${MEDUSA_API_PORT}/health"
    echo "       Fix networking or override MEDUSA_API_HOST."
    echo "       To skip: SKIP_API_PREFLIGHT=true"
    exit 1
  fi
    echo "Cluster connectivity check OK."
  fi

  # Build Helm values (temporary file only)
  cat > "${values_file}" <<EOF
driver:
  enabled: true
  kind: ${FALCO_DRIVER_KIND}

collectors:
  enabled: true
  containerEngine:
    enabled: true
  kubernetes:
    enabled: false

falcoctl:
  artifact:
    install:
      enabled: true
    follow:
      enabled: false
  config:
    artifact:
      install:
        refs:
          - falco-rules:5
        resolveDeps: true
      follow:
        refs: []

falco:
  rule_files:
    - /etc/falco/falco-rules.yaml
    - /etc/falco/rules.d
  load_plugins: []
  json_output: true
  json_include_output_property: true
  json_include_output_fields_property: true
  json_include_tags_property: true
  priority: warning
  stdout_output:
    enabled: true
  http_output:
    enabled: true
    url: "${webhook_url}"
    keep_alive: true

tty: true

customRules:
  medusa_rules.yaml: |-
EOF

  indent_rules "${MEDUSA_RULES_FILE}" >> "${values_file}"

  echo "Adding Helm repo..."
  helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
  helm repo update falcosecurity

  local helm_args=(
    upgrade --install "${FALCO_RELEASE}" falcosecurity/falco
    --namespace "${FALCO_NAMESPACE}"
    --create-namespace
    -f "${values_file}"
    --wait
    --timeout 10m
  )

  if [[ -n "${FALCO_CHART_VERSION:-}" ]]; then
    helm_args+=(--version "${FALCO_CHART_VERSION}")
  fi

  echo "Installing/upgrading Falco..."
  helm "${helm_args[@]}"

  echo
  echo "=== Falco pods ==="
  kubectl get pods -n "${FALCO_NAMESPACE}" -o wide

  echo
  echo "=== Done ==="
  echo "Trigger a test alert:"
  echo "  kubectl exec -it <pod> -n <ns> -- cat /etc/passwd"
  echo
  echo "Verify ingestion:"
  echo "  curl -s http://localhost:${MEDUSA_API_PORT}/alerts/ | jq ."
  echo
  echo "Watch Falco logs:"
  echo "  kubectl logs -n ${FALCO_NAMESPACE} -l app.kubernetes.io/name=falco --tail=50 -f"
  echo
  echo "Uninstall:"
  echo "  $0 --uninstall"
}

main "$@"