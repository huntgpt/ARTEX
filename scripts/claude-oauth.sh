#!/usr/bin/env bash
# Cross-platform Claude OAuth account switcher. Source this file so `use`
# affects the current terminal: source /path/to/claude-oauth.sh

_CLAUDE_OAUTH_SERVICE_PREFIX="artex-claude-oauth-"
_CLAUDE_OAUTH_STATE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/artex"
_CLAUDE_OAUTH_META_FILE="$_CLAUDE_OAUTH_STATE_DIR/claude-oauth-profiles.tsv"

_claude_oauth_need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'claude-oauth: required command not found: %s\n' "$1" >&2
    return 1
  }
}

_claude_oauth_valid_name() {
  case "${1:-}" in
    ''|*[!A-Za-z0-9._-]*) return 1 ;;
    *) return 0 ;;
  esac
}

_claude_oauth_backend() {
  case "$(uname -s 2>/dev/null)" in
    Darwin)
      _claude_oauth_need security || return 1
      printf 'keychain\n'
      ;;
    Linux)
      if ! command -v secret-tool >/dev/null 2>&1; then
        printf '%s\n' \
          'claude-oauth: Linux requires Secret Service and secret-tool.' \
          '  Debian/Ubuntu: sudo apt install libsecret-tools' \
          '  Fedora/RHEL:   sudo dnf install libsecret' \
          'Start/unlock GNOME Keyring, KWallet Secret Service, or another compatible provider.' >&2
        return 1
      fi
      printf 'secret-service\n'
      ;;
    *)
      printf 'claude-oauth: unsupported OS; supported: macOS and Linux\n' >&2
      return 1
      ;;
  esac
}

_claude_oauth_store() {
  local name="$1" token="$2" backend
  backend="$(_claude_oauth_backend)" || return 1
  case "$backend" in
    keychain) security add-generic-password -U -a "$name" -s "${_CLAUDE_OAUTH_SERVICE_PREFIX}${name}" -w "$token" >/dev/null ;;
    secret-service) printf '%s' "$token" | secret-tool store --label="ARTEX Claude OAuth ($name)" service artex-claude-oauth profile "$name" ;;
  esac
}

_claude_oauth_load() {
  local name="$1" backend
  backend="$(_claude_oauth_backend)" || return 1
  case "$backend" in
    keychain) security find-generic-password -a "$name" -s "${_CLAUDE_OAUTH_SERVICE_PREFIX}${name}" -w 2>/dev/null ;;
    secret-service) secret-tool lookup service artex-claude-oauth profile "$name" ;;
  esac
}

_claude_oauth_delete() {
  local name="$1" backend
  backend="$(_claude_oauth_backend)" || return 1
  case "$backend" in
    keychain) security delete-generic-password -a "$name" -s "${_CLAUDE_OAUTH_SERVICE_PREFIX}${name}" >/dev/null ;;
    secret-service) secret-tool clear service artex-claude-oauth profile "$name" ;;
  esac
}

_claude_oauth_label() {
  local name="$1"
  [ -f "$_CLAUDE_OAUTH_META_FILE" ] || return 0
  awk -F '\t' -v wanted="$name" '$1 == wanted { print $2; exit }' "$_CLAUDE_OAUTH_META_FILE"
}

_claude_oauth_save_meta() {
  local name="$1" label="$2" tmp
  mkdir -p "$_CLAUDE_OAUTH_STATE_DIR" || return 1
  chmod 700 "$_CLAUDE_OAUTH_STATE_DIR" || return 1
  tmp="$(mktemp "$_CLAUDE_OAUTH_STATE_DIR/.claude-oauth.XXXXXX")" || return 1
  chmod 600 "$tmp"
  if [ -f "$_CLAUDE_OAUTH_META_FILE" ]; then
    awk -F '\t' -v wanted="$name" '$1 != wanted' "$_CLAUDE_OAUTH_META_FILE" > "$tmp"
  fi
  printf '%s\t%s\n' "$name" "$label" >> "$tmp"
  mv -f "$tmp" "$_CLAUDE_OAUTH_META_FILE"
  chmod 600 "$_CLAUDE_OAUTH_META_FILE"
}

_claude_oauth_remove_meta() {
  local name="$1" tmp
  [ -f "$_CLAUDE_OAUTH_META_FILE" ] || return 0
  tmp="$(mktemp "$_CLAUDE_OAUTH_STATE_DIR/.claude-oauth.XXXXXX")" || return 1
  awk -F '\t' -v wanted="$name" '$1 != wanted' "$_CLAUDE_OAUTH_META_FILE" > "$tmp"
  mv -f "$tmp" "$_CLAUDE_OAUTH_META_FILE"
  chmod 600 "$_CLAUDE_OAUTH_META_FILE"
}

# Feed curl configuration over stdin so the token is absent from process
# arguments and shell history.
_claude_oauth_api() {
  local endpoint="$1" token="$2"
  printf '%s\n' \
    'silent' \
    'show-error' \
    "header = \"Authorization: Bearer $token\"" \
    'header = "anthropic-beta: oauth-2025-04-20"' \
    'header = "user-agent: claude-code/artex-token-switcher"' \
    | curl --config - "https://api.anthropic.com/api/oauth/$endpoint"
}

_claude_oauth_status() {
  _claude_oauth_need claude || return 1
  _claude_oauth_need jq || return 1
  _claude_oauth_need curl || return 1
  local name="${ARTEX_CLAUDE_PROFILE:-saved-login}" label auth token profile usage message rows
  label="$(_claude_oauth_label "$name")"
  auth="$(claude auth status 2>/dev/null)" || auth='{}'

  printf 'Claude terminal profile\n  profile: %s\n' "$name"
  [ -n "$label" ] && printf '  label:   %s\n' "$label"
  printf '%s' "$auth" | jq -r '
    "  logged in: " + ((.loggedIn // false)|tostring),
    "  auth:      " + (.authMethod // "unknown"),
    "  provider:  " + (.apiProvider // "unknown"),
    (if .email then "  account:   " + .email else empty end),
    (if .orgName then "  org:       " + .orgName else empty end),
    (if .subscriptionType then "  plan:      " + .subscriptionType else empty end),
    (if .loginExpiresAt then "  expires:   " + .loginExpiresAt else empty end)'

  token="${CLAUDE_CODE_OAUTH_TOKEN:-}"
  if [ -z "$token" ]; then
    printf '  usage:     unavailable from saved-login mode (open https://claude.ai/settings/usage)\n'
    return 0
  fi

  profile="$(_claude_oauth_api profile "$token" 2>/dev/null)" || profile='{}'
  if printf '%s' "$profile" | jq -e '.error == null' >/dev/null 2>&1; then
    printf '%s' "$profile" | jq -r '
      (if .email_address then "  account:   " + .email_address else empty end),
      (if .display_name then "  name:      " + .display_name else empty end),
      (if .organization_name then "  org:       " + .organization_name else empty end)'
  else
    message="$(printf '%s' "$profile" | jq -r '.error.message // empty')"
    [ -n "$message" ] && printf '  account API: unavailable (%s)\n' "$message"
  fi

  usage="$(_claude_oauth_api usage "$token" 2>/dev/null)" || usage='{}'
  if printf '%s' "$usage" | jq -e '.error == null' >/dev/null 2>&1; then
    rows="$(printf '%s' "$usage" | jq -r '
      to_entries
      | map(select(.value|type == "object" and (.utilization|type == "number")))
      | .[]
      | "  usage " + .key + ": used " + (.value.utilization|tostring) +
        "% · remaining " + ((100 - .value.utilization)|if . < 0 then 0 else . end|tostring) +
        "%" + (if .value.resets_at then " · resets " + .value.resets_at else "" end)')"
    [ -n "$rows" ] && printf '%s\n' "$rows" || printf '  usage:     API returned no percentage windows\n'
  else
    message="$(printf '%s' "$usage" | jq -r '.error.message // empty')"
    case "$message" in
      *'scope requirement'*) printf '  usage:     unavailable — this token lacks user:profile scope\n' ;;
      '') printf '  usage:     unavailable\n' ;;
      *) printf '  usage:     unavailable (%s)\n' "$message" ;;
    esac
  fi
}

_claude_oauth_set_global() {
  local token="$1"
  case "$(uname -s 2>/dev/null)" in
    Darwin) _claude_oauth_need launchctl && launchctl setenv CLAUDE_CODE_OAUTH_TOKEN "$token" ;;
    Linux) _claude_oauth_need systemctl && systemctl --user set-environment "CLAUDE_CODE_OAUTH_TOKEN=$token" ;;
    *) return 1 ;;
  esac
}

_claude_oauth_unset_global() {
  case "$(uname -s 2>/dev/null)" in
    Darwin) launchctl unsetenv CLAUDE_CODE_OAUTH_TOKEN ;;
    Linux) systemctl --user unset-environment CLAUDE_CODE_OAUTH_TOKEN ;;
    *) return 1 ;;
  esac
}

claude-oauth() {
  local action="${1:-status}"
  shift 2>/dev/null || true
  case "$action" in
    add)
      local name="${1:-}" label="${2:-}" token
      _claude_oauth_valid_name "$name" || { printf 'usage: claude-oauth add NAME [ACCOUNT_LABEL_OR_EMAIL]\n' >&2; return 2; }
      printf 'Claude OAuth token for %s: ' "$name" >&2
      IFS= read -r -s token
      printf '\n' >&2
      case "$token" in sk-ant-oat01-*) ;; *) unset token; printf 'invalid Claude OAuth token\n' >&2; return 2 ;; esac
      _claude_oauth_store "$name" "$token" || { unset token; return 1; }
      unset token
      _claude_oauth_save_meta "$name" "$label" || return 1
      printf "Saved '%s' in the OS credential store.\n" "$name"
      ;;
    import-file)
      local name="${1:-}" file="${2:-}" label="${3:-}" token
      _claude_oauth_valid_name "$name" && [ -f "$file" ] || { printf 'usage: claude-oauth import-file NAME TOKEN_FILE [ACCOUNT_LABEL_OR_EMAIL]\n' >&2; return 2; }
      token="$(tr -d '\r\n' < "$file")"
      case "$token" in sk-ant-oat01-*) ;; *) unset token; printf 'invalid Claude OAuth token file\n' >&2; return 2 ;; esac
      _claude_oauth_store "$name" "$token" || { unset token; return 1; }
      unset token
      _claude_oauth_save_meta "$name" "$label" || return 1
      printf "Imported '%s' into the OS credential store.\n" "$name"
      ;;
    use)
      local name="${1:-}" token
      _claude_oauth_valid_name "$name" || { printf 'usage: claude-oauth use NAME\n' >&2; return 2; }
      token="$(_claude_oauth_load "$name")" || { printf 'profile not found: %s\n' "$name" >&2; return 1; }
      CLAUDE_CODE_OAUTH_TOKEN="$token"
      unset token
      export CLAUDE_CODE_OAUTH_TOKEN
      export ARTEX_CLAUDE_PROFILE="$name"
      unset CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
      _claude_oauth_status
      ;;
    global)
      local name="${1:-}" token
      _claude_oauth_valid_name "$name" || { printf 'usage: claude-oauth global NAME\n' >&2; return 2; }
      token="$(_claude_oauth_load "$name")" || { printf 'profile not found: %s\n' "$name" >&2; return 1; }
      _claude_oauth_set_global "$token" || { unset token; return 1; }
      CLAUDE_CODE_OAUTH_TOKEN="$token"
      unset token
      export CLAUDE_CODE_OAUTH_TOKEN
      export ARTEX_CLAUDE_PROFILE="$name"
      unset CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
      printf "Global user default set to '%s' for processes launched after this command.\n" "$name"
      printf 'Already-running Claude sessions cannot change identity; exit and resume them.\n'
      printf 'Security note: the user service-manager environment can reveal this value; per-terminal use is safer.\n'
      _claude_oauth_status
      ;;
    global-unset)
      _claude_oauth_unset_global || return 1
      unset CLAUDE_CODE_OAUTH_TOKEN ARTEX_CLAUDE_PROFILE CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
      printf 'Removed the global token for newly launched user processes. Existing processes are unchanged.\n'
      ;;
    status) _claude_oauth_status ;;
    list)
      if [ ! -s "$_CLAUDE_OAUTH_META_FILE" ]; then printf 'No credential profiles recorded.\n'; return 0; fi
      awk -F '\t' '{ printf "%-24s %s\n", $1, $2 }' "$_CLAUDE_OAUTH_META_FILE"
      ;;
    unset|off)
      unset CLAUDE_CODE_OAUTH_TOKEN ARTEX_CLAUDE_PROFILE CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
      printf "This terminal now uses Claude's saved login.\n"
      _claude_oauth_status
      ;;
    remove)
      local name="${1:-}"
      _claude_oauth_valid_name "$name" || { printf 'usage: claude-oauth remove NAME\n' >&2; return 2; }
      _claude_oauth_delete "$name" || return 1
      _claude_oauth_remove_meta "$name" || return 1
      [ "${ARTEX_CLAUDE_PROFILE:-}" = "$name" ] && unset CLAUDE_CODE_OAUTH_TOKEN ARTEX_CLAUDE_PROFILE
      printf "Removed '%s' from the OS credential store.\n" "$name"
      ;;
    help|-h|--help)
      cat <<'EOF'
Source once per terminal (Bash or Zsh):
  source /path/to/claude-oauth.sh

Commands:
  claude-oauth add NAME [LABEL]              prompt securely and store token
  claude-oauth import-file NAME FILE [LABEL] import a chmod-600 token file
  claude-oauth use NAME                      switch this terminal and show status
  claude-oauth global NAME                   default for newly launched user processes
  claude-oauth global-unset                  remove that user-process default
  claude-oauth status                        show account/auth/quota information
  claude-oauth list                          list aliases (never tokens)
  claude-oauth unset                         return this terminal to saved login
  claude-oauth remove NAME                   delete one credential profile

Backends: macOS Keychain; Linux Secret Service via secret-tool. Usage requires
the token's user:profile scope. user:inference-only tokens report unavailable.
Existing Claude processes cannot switch identity; exit and resume them.
EOF
      ;;
    *) printf 'claude-oauth: unknown command: %s (try: claude-oauth help)\n' "$action" >&2; return 2 ;;
  esac
}
