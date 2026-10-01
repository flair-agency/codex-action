#!/bin/sh
set -eu

parent_pid=$1
root_pid=$2
root_file=$3
control_file=$4
label=$5
same_uid_pid=$6
same_uid_file=$7
expected_runner_uid=$8

case "$label" in
  direct-shell-control|shell-sandbox-command|shell-sandbox-inherited|shell-sandbox-scrubbed) ;;
  *) exit 2 ;;
esac

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
if [ -e "$root_file" ]; then root_file_path_exists=true; else root_file_path_exists=false; fi
root_file_stat="$(stat -c '%u %a' "$root_file" 2>/dev/null || true)"
if [ -n "$root_file_stat" ]; then root_file_metadata_readable=true; else root_file_metadata_readable=false; fi
root_file_owner="${root_file_stat%% *}"
root_file_mode="${root_file_stat#* }"
if [ "$root_file_owner" = 0 ]; then root_file_owner_is_root=true; else root_file_owner_is_root=false; fi
if [ "$root_file_mode" = 600 ]; then root_file_mode0600=true; else root_file_mode0600=false; fi
if [ -r "$root_file" ] && [ "$(cat "$root_file" 2>/dev/null)" = 'synthetic-root-owned-subject-token-file-canary' ]; then root_file_readable=true; else root_file_readable=false; fi
if [ -r "$control_file" ] && [ "$(cat "$control_file" 2>/dev/null)" = 'synthetic-runner-control-file-canary' ]; then control_file_readable=true; else control_file_readable=false; fi

if [ -d "/proc/$same_uid_pid" ]; then same_uid_pid_visible=true; else same_uid_pid_visible=false; fi
if proc_has "$same_uid_pid" 'SYNTHETIC_SAME_UID_AUTH_HOLDER=synthetic-same-uid-auth-holder-canary'; then same_uid_auth_env_readable=true; else same_uid_auth_env_readable=false; fi
same_uid_process_uid="$(id -u)"
same_uid_holder_uid="$(awk '$1 == "Uid:" { print $3; exit }' "/proc/$same_uid_pid/status" 2>/dev/null || true)"
if [ -n "$same_uid_holder_uid" ] && [ "$same_uid_holder_uid" = "$same_uid_process_uid" ] && [ "$same_uid_holder_uid" = "$expected_runner_uid" ]; then same_uid_uid_matches_process=true; else same_uid_uid_matches_process=false; fi
if [ -r "$same_uid_file" ] && [ "$(cat "$same_uid_file" 2>/dev/null)" = 'synthetic-same-uid-holder-file-canary' ]; then same_uid_file_readable=true; else same_uid_file_readable=false; fi
same_uid_file_mode="$(stat -c '%a' "$same_uid_file" 2>/dev/null || true)"
if [ "$same_uid_file_mode" = 600 ]; then same_uid_file_mode0600=true; else same_uid_file_mode0600=false; fi
same_uid_file_owner="$(stat -c '%u' "$same_uid_file" 2>/dev/null || true)"
if [ -n "$same_uid_file_owner" ] && [ "$same_uid_file_owner" = "$same_uid_process_uid" ] && [ "$same_uid_file_owner" = "$expected_runner_uid" ]; then same_uid_file_owner_matches_process=true; else same_uid_file_owner_matches_process=false; fi

printf 'WIF_SHELL_ISOLATION_PROBE {"label":"%s","processEnv":{"oidcRequestUrl":%s,"oidcRequestToken":%s,"subjectToken":%s,"apiKey":%s,"apiAccessToken":%s},"wrapperParentProcEnv":{"oidcRequestToken":%s,"subjectToken":%s,"apiKey":%s,"apiAccessToken":%s},"rootProcessExists":%s,"rootProcessProcEnv":%s,"rootFilePathExists":%s,"rootFileMetadataReadable":%s,"rootFileOwnerIsRoot":%s,"rootFileMode0600":%s,"rootOwnedFileReadable":%s,"runnerControlFileReadable":%s,"sameUidHolder":{"pidVisible":%s,"authEnvReadable":%s,"uidMatchesProcess":%s,"fileReadable":%s,"fileMode0600":%s,"fileOwnerMatchesProcess":%s}}\n' \
  "$label" \
  "$oidc_url" "$oidc_token" "$subject_token" "$api_key" "$api_access_token" \
  "$parent_oidc_token" "$parent_subject_token" "$parent_api_key" "$parent_api_access_token" \
  "$root_process_exists" "$root_process_env" "$root_file_path_exists" "$root_file_metadata_readable" \
  "$root_file_owner_is_root" "$root_file_mode0600" "$root_file_readable" "$control_file_readable" \
  "$same_uid_pid_visible" "$same_uid_auth_env_readable" "$same_uid_uid_matches_process" \
  "$same_uid_file_readable" "$same_uid_file_mode0600" "$same_uid_file_owner_matches_process"

if [ "$root_process_exists" != true ] || [ "$control_file_readable" != true ]; then
  exit 1
fi
