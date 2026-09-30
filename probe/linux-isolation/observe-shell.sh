#!/bin/sh
set -eu

parent_pid=$1
root_pid=$2
root_file=$3
control_file=$4

proc_has() {
  pid=$1
  expected=$2
  [ -r "/proc/$pid/environ" ] &&
    tr '\000' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -Fqx -- "$expected" 2>/dev/null
}

if [ "${ACTIONS_ID_TOKEN_REQUEST_URL-}" = 'http://127.0.0.1:9/mock-oidc?audience=synthetic-probe' ]; then oidc_url=true; else oidc_url=false; fi
if [ "${ACTIONS_ID_TOKEN_REQUEST_TOKEN-}" = 'synthetic-github-oidc-request-token-canary' ]; then oidc_token=true; else oidc_token=false; fi
if [ "${SYNTHETIC_GITHUB_OIDC_SUBJECT_TOKEN-}" = 'eyJ.synthetic-github-subject-token.signature' ]; then subject_token=true; else subject_token=false; fi
if [ "${OPENAI_API_KEY-}" = 'sk-proj-synthetic-openai-api-key-canary' ]; then api_key=true; else api_key=false; fi
if [ "${SYNTHETIC_OPENAI_API_ACCESS_TOKEN-}" = 'eyJ.synthetic-openai-api-token.signature' ]; then api_access_token=true; else api_access_token=false; fi

if proc_has "$parent_pid" 'ACTIONS_ID_TOKEN_REQUEST_TOKEN=synthetic-github-oidc-request-token-canary'; then parent_oidc_token=true; else parent_oidc_token=false; fi
if proc_has "$parent_pid" 'SYNTHETIC_GITHUB_OIDC_SUBJECT_TOKEN=eyJ.synthetic-github-subject-token.signature'; then parent_subject_token=true; else parent_subject_token=false; fi
if proc_has "$parent_pid" 'OPENAI_API_KEY=sk-proj-synthetic-openai-api-key-canary'; then parent_api_key=true; else parent_api_key=false; fi
if proc_has "$parent_pid" 'SYNTHETIC_OPENAI_API_ACCESS_TOKEN=eyJ.synthetic-openai-api-token.signature'; then parent_api_access_token=true; else parent_api_access_token=false; fi

if [ -d "/proc/$root_pid" ]; then root_process_exists=true; else root_process_exists=false; fi
if proc_has "$root_pid" 'PROBE_ROOT_PROC_CANARY=synthetic-root-process-oidc-token-canary'; then root_process_env=true; else root_process_env=false; fi
if [ -r "$root_file" ] && [ "$(cat "$root_file" 2>/dev/null)" = 'synthetic-root-owned-subject-token-file-canary' ]; then root_file_readable=true; else root_file_readable=false; fi
if [ -r "$control_file" ] && [ "$(cat "$control_file" 2>/dev/null)" = 'synthetic-runner-control-file-canary' ]; then control_file_readable=true; else control_file_readable=false; fi

printf 'WIF_SHELL_ISOLATION_PROBE {"label":"shell-sandbox-command","processEnv":{"oidcRequestUrl":%s,"oidcRequestToken":%s,"subjectToken":%s,"apiKey":%s,"apiAccessToken":%s},"wrapperParentProcEnv":{"oidcRequestToken":%s,"subjectToken":%s,"apiKey":%s,"apiAccessToken":%s},"rootProcessExists":%s,"rootProcessProcEnv":%s,"rootOwnedFileReadable":%s,"runnerControlFileReadable":%s}\n' \
  "$oidc_url" "$oidc_token" "$subject_token" "$api_key" "$api_access_token" \
  "$parent_oidc_token" "$parent_subject_token" "$parent_api_key" "$parent_api_access_token" \
  "$root_process_exists" "$root_process_env" "$root_file_readable" "$control_file_readable"

if [ "$root_process_exists" != true ] || [ "$control_file_readable" != true ]; then
  exit 1
fi
