#!/usr/bin/env bash
# ============================================================================
# Cloud Foundry Application Metadata Extractor (CF v3 API)
# Extracts org, space, app, and process metadata to CSV for migration analysis
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Script Metadata
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

# API Configuration
readonly CONFIG_API_MAX_RETRIES=3
readonly CONFIG_API_MAX_RETRIES_OPTIONAL=2
readonly CONFIG_API_INITIAL_BACKOFF=2

# CSV Output Configuration
readonly CONFIG_CSV_DELIMITER=","
readonly CONFIG_CSV_MULTIVALUE_SEP=";"
readonly CONFIG_CSV_TIMESTAMP_FORMAT="%Y%m%d%H%M%S"
readonly CONFIG_OUTPUT_PREFIX="pcfusage"

# Security/Sanitization Configuration - patterns for sensitive data detection
readonly CONFIG_SENSITIVE_PATTERNS=(
  "PASSWORD" "PASSWD" "PWD" "SECRET" "PRIVATE" "KEY"
  "APIKEY" "TOKEN" "AUTH" "CREDENTIAL" "CERT"
  "CERTIFICATE" "DATABASE_URL" "DB_URL" "JDBC_URL" "URI"
)
readonly CONFIG_REDACTION_PLACEHOLDER="<REDACTED>"

# CSV Column Definitions (order matters for output)
readonly CONFIG_CSV_COLUMNS=(
  "Org" "Space" "App" "Process Type" "Instances"
  "Memory(MB)" "Disk(MB)" "Memory Usage(MB)" "Disk Usage(MB)" "Total Disk Usage(MB)" "State" "Buildpacks"
  "Buildpack Details" "Runtime Version" "Routes"
  "Domains" "Service Instances" "Service Bindings"
  "Volume Services" "Volume Size(GB)"
  "Env Vars" "Security Groups"
)

# ============================================================================
# UTILITY FUNCTIONS (util_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Outputs debug messages to stderr when debug mode is enabled
#
# Parameters:
#   $@ - Debug message to output
#
# Returns:
#   Outputs to stderr if DEBUG mode is enabled
# ----------------------------------------------------------------------------
function util_debug() {
  if [[ "${DEBUG}" == "--debug" ]]; then
    echo "DEBUG: $*" >&2
  fi
}

# ----------------------------------------------------------------------------
# Detects platform and uses correct base64 decode flag
#
# Returns:
#   Decoded base64 output from stdin
# ----------------------------------------------------------------------------
function util_base64_decode() {
  if [[ "${OSTYPE}" == "darwin"* ]]; then
    base64 -D
  else
    base64 -d
  fi
}

# ----------------------------------------------------------------------------
# Extracts value from JSON using jq with null coalescing
# Converts jq's "null" string output to empty string
#
# Parameters:
#   $1 - JSON string to query
#   $2 - jq expression to evaluate
#
# Returns:
#   Extracted value, or empty string if result is "null"
#
# Examples:
#   name=$(util_jq_extract "${json}" '.name // empty')
#   items=$(util_jq_extract "${json}" '[.items[]?.name] | join(";")')
# ----------------------------------------------------------------------------
function util_jq_extract() {
  local json="$1"
  local jq_expr="$2"
  local result

  result=$(echo "${json}" | jq -r "${jq_expr}")
  if [[ "${result}" == "null" ]]; then
    echo ""
  else
    echo "${result}"
  fi
}

# ----------------------------------------------------------------------------
# Joins multiple non-empty items with a separator
# Commonly used for building semicolon-separated lists
#
# Parameters:
#   $1 - Separator string
#   $@ - Items to join (empty items are skipped)
#
# Returns:
#   Joined string with separator between items
#
# Examples:
#   result=$(util_join_with_separator ";" "item1" "" "item3")
#   # Returns: "item1;item3"
# ----------------------------------------------------------------------------
function util_join_with_separator() {
  local separator="$1"
  shift
  local result=""

  for item in "$@"; do
    [[ -z "${item}" ]] && continue
    if [[ -n "${result}" ]]; then
      result="${result}${separator}${item}"
    else
      result="${item}"
    fi
  done

  echo "${result}"
}

# ----------------------------------------------------------------------------
# Appends an item to an existing delimited list
# Handles both empty and non-empty existing lists correctly
#
# Parameters:
#   $1 - Existing list (may be empty)
#   $2 - New item to append
#   $3 - Separator (optional, defaults to CONFIG_CSV_MULTIVALUE_SEP)
#
# Returns:
#   Updated list with new item appended
#
# Examples:
#   list=$(util_append_to_list "${list}" "new_item")
#   list=$(util_append_to_list "${list}" "item" ",")
# ----------------------------------------------------------------------------
function util_append_to_list() {
  local existing_list="$1"
  local new_item="$2"
  local separator="${3:-${CONFIG_CSV_MULTIVALUE_SEP}}"

  if [[ -n "${existing_list}" ]]; then
    echo "${existing_list}${separator}${new_item}"
  else
    echo "${new_item}"
  fi
}

# ============================================================================
# CSV LAYER (csv_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Escapes CSV field per RFC 4180 standards
# Encloses field in quotes if it contains: comma, quote, newline, or CR
# Escapes internal quotes by doubling them
#
# Parameters:
#   $1 - Field value to escape
#
# Returns:
#   Properly escaped CSV field value
#
# Examples:
#   escaped=$(csv_escape_field "value with, comma")
# ----------------------------------------------------------------------------
function csv_escape_field() {
  local field="$1"

  # Check if field contains special characters requiring quoting
  if [[ "${field}" =~ [,\"$'\n'$'\r'] ]]; then
    # Escape quotes by doubling them
    field="${field//\"/\"\"}"
    # Enclose in quotes
    echo "\"${field}\""
  else
    # No special characters, return as-is
    echo "${field}"
  fi
}

# ----------------------------------------------------------------------------
# Writes CSV header row to output file using configured columns
#
# Returns:
#   Creates/overwrites OUTFILE with CSV header
# ----------------------------------------------------------------------------
function csv_write_header() {
  local header=""
  local first=true

  for column in "${CONFIG_CSV_COLUMNS[@]}"; do
    if [[ "${first}" == true ]]; then
      header="${column}"
      first=false
    else
      header="${header}${CONFIG_CSV_DELIMITER}${column}"
    fi
  done

  echo "${header}" > "${OUTFILE}"
}

# ============================================================================
# VALIDATION LAYER (validate_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Validates JSON response is not empty or malformed
# Detects empty API responses ({}) vs valid data
#
# Parameters:
#   $1 - JSON string to validate
#   $2 - Context description for warnings (optional)
#
# Returns:
#   0 if JSON is valid and non-empty
#   1 if JSON is empty ({}) or invalid
# ----------------------------------------------------------------------------
function validate_json_response() {
  local json="$1"
  local context="${2:-API response}"

  # Check if response is literally "{}" (empty object from error handling)
  if [[ "${json}" == "{}" ]]; then
    util_debug "⚠️  WARNING: Empty API response for ${context}"
    WARNING_COUNT=$((WARNING_COUNT + 1))
    return 1
  fi

  # Check if response is valid JSON with content
  if ! echo "${json}" | jq -e 'type' >/dev/null 2>&1; then
    util_debug "⚠️  WARNING: Invalid JSON response for ${context}"
    WARNING_COUNT=$((WARNING_COUNT + 1))
    return 1
  fi

  return 0
}

# ============================================================================
# SANITIZATION LAYER (sanitize_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Determines if a key name matches sensitive data patterns
# Used for environment variable and JSON field redaction
#
# Parameters:
#   $1 - Key name to check
#
# Returns:
#   0 (true) if key is sensitive
#   1 (false) if key is safe
# ----------------------------------------------------------------------------
function sanitize_is_sensitive() {
  local key="$1"
  local key_upper
  key_upper=$(echo "${key}" | tr '[:lower:]' '[:upper:]')

  # Check against configured sensitive patterns
  for pattern in "${CONFIG_SENSITIVE_PATTERNS[@]}"; do
    if [[ "${key_upper}" == *"${pattern}"* ]]; then
      return 0  # Sensitive
    fi
  done

  return 1  # Safe
}

# ----------------------------------------------------------------------------
# Recursively sanitizes JSON structure by redacting sensitive fields
# Uses jq walk() to traverse all nodes and replace sensitive values
#
# Parameters:
#   $1 - JSON string to sanitize
#
# Returns:
#   Sanitized JSON with sensitive fields replaced with <REDACTED>
# ----------------------------------------------------------------------------
function sanitize_json_recursive() {
  local json="$1"

  # Build jq pattern from CONFIG_SENSITIVE_PATTERNS
  local pattern_regex
  pattern_regex=$(IFS="|"; echo "${CONFIG_SENSITIVE_PATTERNS[*]}")

  # Use jq walk to recursively process all object fields
  echo "${json}" | jq -c --arg placeholder "${CONFIG_REDACTION_PLACEHOLDER}" \
    --arg patterns "${pattern_regex}" 'walk(
    if type == "object" then
      to_entries | map(
        if (.key | ascii_upcase | test($patterns)) then
          .value = $placeholder
        else
          .
        end
      ) | from_entries
    else
      .
    end
  )'
}

# ----------------------------------------------------------------------------
# Sanitizes individual environment variable value
# Handles both plain strings and JSON values
#
# Parameters:
#   $1 - Variable key name
#   $2 - Variable value (may be JSON or plain text)
#
# Returns:
#   Sanitized value: <REDACTED> for sensitive keys, recursively sanitized
#   JSON for JSON values, or original value for safe plain text
# ----------------------------------------------------------------------------
function sanitize_env_var() {
  local key="$1"
  local value="$2"

  # First check if the key itself is sensitive
  if sanitize_is_sensitive "${key}"; then
    echo "${CONFIG_REDACTION_PLACEHOLDER}"
    return 0
  fi

  # Try to parse value as JSON
  if echo "${value}" | jq -e '.' >/dev/null 2>&1; then
    # Valid JSON - sanitize recursively
    sanitize_json_recursive "${value}"
  else
    # Not JSON - return original value (key already checked above)
    echo "${value}"
  fi
}

# ----------------------------------------------------------------------------
# Extracts and sanitizes all environment variables from API response
# Processes environment_variables object and returns semicolon-separated
# key=value pairs with sensitive data redacted
#
# Parameters:
#   $1 - JSON response from /v3/apps/{guid}/env endpoint
#
# Returns:
#   Semicolon-separated key=value pairs with sanitized values
# ----------------------------------------------------------------------------
function sanitize_env_vars() {
  local env_vars_json="$1"

  # Validate input
  if ! validate_json_response "${env_vars_json}" "Environment variables"; then
    echo ""
    return 0
  fi

  # Extract environment_variables object
  local env_object
  env_object=$(echo "${env_vars_json}" | jq -r '.environment_variables // {}')

  # If no environment variables, return empty
  if [[ "${env_object}" == "{}" ]] || [[ "${env_object}" == "null" ]]; then
    echo ""
    return 0
  fi

  # Process each key-value pair
  local sanitized_vars=""
  while IFS='=' read -r key value; do
    [[ -z "${key}" ]] && continue

    # Sanitize the value
    local sanitized_value
    sanitized_value=$(sanitize_env_var "${key}" "${value}")

    # Debug log if value was redacted
    if [[ "${sanitized_value}" == "${CONFIG_REDACTION_PLACEHOLDER}" ]]; then
      util_debug "Redacted sensitive environment variable: ${key}"
    fi

    # Build result string
    sanitized_vars=$(util_append_to_list "${sanitized_vars}" "${key}=${sanitized_value}")
  done < <(echo "${env_object}" | jq -r \
    'to_entries | map("\(.key)=\(.value | tostring)") | .[]')

  echo "${sanitized_vars}"
}

# ============================================================================
# API LAYER (api_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Classifies API error as permanent (don't retry) or transient (retry)
# Analyzes CF API error codes and HTTP status patterns
#
# Parameters:
#   $1 - API response JSON
#   $2 - Error message from stderr
#   $3 - Command exit code
#
# Returns:
#   "auth_error" - Authentication/authorization failure (permanent)
#   "not_found" - Resource not found (permanent)
#   "client_error" - Bad request/validation (permanent)
#   "network_error" - Connection/timeout (transient)
#   "server_error" - Server/API error (transient)
# ----------------------------------------------------------------------------
function api_classify_error() {
  local response="$1"
  local error_msg="$2"
  local exit_code="$3"

  # Check JSON for CF API error codes
  if echo "${response}" | jq -e '.errors' >/dev/null 2>&1; then
    local error_code
    error_code=$(echo "${response}" | jq -r '.errors[0].code // empty')
    case "${error_code}" in
      10002|10003) echo "auth_error" ;;      # Unauthorized/Forbidden
      10004|10010) echo "not_found" ;;       # Not found
      1000|10008)  echo "client_error" ;;    # Bad request/Validation
      *) echo "server_error" ;;              # Other API errors, retry-eligible
    esac
    return
  fi

  # Check stderr for network/connection errors
  if echo "${error_msg}" | grep -qi "connection refused\|timeout\|network\|DNS"; then
    echo "network_error"
  elif echo "${error_msg}" | grep -qi "unauthorized\|401\|403"; then
    echo "auth_error"
  elif echo "${error_msg}" | grep -qi "not found\|404"; then
    echo "not_found"
  elif echo "${error_msg}" | grep -qi "50[0-9]\|bad gateway\|service unavailable"; then
    echo "server_error"
  else
    echo "server_error"  # Default to retry-eligible for safety
  fi
}

# ----------------------------------------------------------------------------
# Core API retry function with exponential backoff
# Wraps cf curl with intelligent retry logic and error classification
#
# Parameters:
#   $1 - API endpoint path (e.g., /v3/apps)
#   $2 - Maximum retry attempts (optional, default: 3)
#
# Returns:
#   JSON response on success
#   __ERROR_PERMANENT__ on non-retryable error (exit 2)
#   __ERROR_TRANSIENT__ on retry exhaustion (exit 1)
# ----------------------------------------------------------------------------
function api_fetch_with_retry() {
  local endpoint="$1"
  local max_retries="${2:-${CONFIG_API_MAX_RETRIES}}"
  local attempt=0
  local backoff="${CONFIG_API_INITIAL_BACKOFF}"

  while [[ "${attempt}" -le "${max_retries}" ]]; do
    local tmpfile_out
    tmpfile_out=$(mktemp)
    local tmpfile_err
    tmpfile_err=$(mktemp)
    local exit_code=0

    util_debug "API call attempt $((attempt+1))/$((max_retries+1)): cf curl ${endpoint}"
    cf curl "${endpoint}" > "${tmpfile_out}" 2> "${tmpfile_err}" || exit_code=$?

    local response
    response=$(cat "${tmpfile_out}")
    local error_msg
    error_msg=$(cat "${tmpfile_err}")
    rm -f "${tmpfile_out}" "${tmpfile_err}"

    # Success: valid JSON without errors field
    if [[ "${exit_code}" -eq 0 ]] && \
       echo "${response}" | jq -e 'has("errors") | not' >/dev/null 2>&1; then
      echo "${response}"
      return 0
    fi

    # Classify error type
    local error_type
    error_type=$(api_classify_error "${response}" "${error_msg}" "${exit_code}")

    case "${error_type}" in
      "auth_error"|"not_found"|"client_error")
        # Permanent errors - don't retry
        echo "ERROR: Permanent error calling ${endpoint}: ${error_msg}" >&2
        if [[ -n "${response}" ]] && \
           echo "${response}" | jq -e '.errors' >/dev/null 2>&1; then
          echo "${response}" | \
            jq -r '.errors[]? | "  \(.title // .detail // .code)"' >&2
        fi
        echo "__ERROR_PERMANENT__"
        return 2
        ;;
      "network_error"|"server_error")
        # Transient errors - retry with backoff
        if [[ "${attempt}" -lt "${max_retries}" ]]; then
          echo "WARNING: Transient error (attempt $((attempt+1))/" \
               "$((max_retries+1))): ${error_msg}" >&2
          sleep "${backoff}"
          backoff=$((backoff * 2))
        else
          echo "ERROR: Max retries exceeded for ${endpoint}" >&2
          echo "__ERROR_TRANSIENT__"
          return 1
        fi
        ;;
      *)
        # Unexpected error type - treat as transient for safety
        echo "WARNING: Unexpected error type '${error_type}' - treating as " \
             "transient" >&2
        if [[ "${attempt}" -lt "${max_retries}" ]]; then
          sleep "${backoff}"
          backoff=$((backoff * 2))
        else
          echo "__ERROR_TRANSIENT__"
          return 1
        fi
        ;;
    esac
    attempt=$((attempt + 1))
  done

  echo "__ERROR_TRANSIENT__"
  return 1
}

# ----------------------------------------------------------------------------
# Critical API call wrapper - exits script on any error
# Use for essential data that must be retrieved
#
# Parameters:
#   $1 - API endpoint path
#   $2 - Context description for error messages (optional)
#
# Returns:
#   JSON response on success, exits script with code 1 on failure
# ----------------------------------------------------------------------------
function api_fetch_critical() {
  local endpoint="$1"
  local context="${2:-API call}"
  local result
  result=$(api_fetch_with_retry "${endpoint}" "${CONFIG_API_MAX_RETRIES}")

  if [[ "${result}" == "__ERROR_"* ]]; then
    echo "❌ Critical error: ${context} failed" >&2
    echo "   Endpoint: ${endpoint}" >&2
    exit 1
  fi
  echo "${result}"
}

# ----------------------------------------------------------------------------
# Optional API call wrapper - logs warning and returns {} on error
# Use for non-essential data where failure should not stop execution
#
# Parameters:
#   $1 - API endpoint path
#   $2 - Context description for warning messages (optional)
#
# Returns:
#   JSON response on success, {} on any error (with warning logged)
# ----------------------------------------------------------------------------
function api_fetch_optional() {
  local endpoint="$1"
  local context="${2:-Optional data}"
  local result
  result=$(api_fetch_with_retry "${endpoint}" "${CONFIG_API_MAX_RETRIES_OPTIONAL}")

  if [[ "${result}" == "__ERROR_"* ]]; then
    echo "⚠️  Warning: ${context} unavailable (${endpoint})" >&2
    echo "{}"
    return 0
  fi
  echo "${result}"
}

# ----------------------------------------------------------------------------
# Safe API call wrapper - backward compatible, returns {} on any error
# Silently handles failures without warnings (for legacy compatibility)
#
# Parameters:
#   $1 - API endpoint path
#
# Returns:
#   JSON response on success, {} on any error (no warnings)
# ----------------------------------------------------------------------------
function api_fetch_safe() {
  local endpoint="$1"
  local result
  result=$(api_fetch_with_retry "${endpoint}" "${CONFIG_API_MAX_RETRIES}")

  if [[ "${result}" == "__ERROR_"* ]]; then
    echo "{}"
    return 0
  fi
  echo "${result}"
}

# ----------------------------------------------------------------------------
# Fetches all pages from a CF v3 API paginated list endpoint
# Automatically follows pagination.next links and combines results
#
# Parameters:
#   $1 - Initial API endpoint URL
#   $2 - Description for logging/debugging
#   $3 - API fetch function to use (optional, default: api_fetch_critical)
#
# Returns:
#   Combined JSON with all resources from all pages and updated pagination
#   metadata (total_results, total_pages, fetched_results)
# ----------------------------------------------------------------------------
function api_fetch_all_pages() {
  local initial_url="$1"
  local description="$2"
  local fetch_function="${3:-api_fetch_critical}"

  util_debug "Fetching all pages for: ${initial_url}"

  # Fetch first page
  local page_result
  page_result=$(${fetch_function} "${initial_url}" "${description}")

  # Extract resources and pagination info
  local all_resources
  all_resources=$(echo "${page_result}" | jq -c '.resources // []')
  local next_url
  next_url=$(echo "${page_result}" | jq -r '.pagination.next.href // empty')
  local total_results
  total_results=$(echo "${page_result}" | jq -r '.pagination.total_results // 0')
  local page_num=1

  # Follow pagination links
  while [[ -n "${next_url}" ]]; do
    page_num=$((page_num + 1))
    util_debug "Fetching page ${page_num}: ${next_url}"

    page_result=$(${fetch_function} "${next_url}" \
                  "${description} (page ${page_num})")

    # Append resources to accumulated array
    local page_resources
    page_resources=$(echo "${page_result}" | jq -c '.resources // []')
    all_resources=$(echo "${all_resources} ${page_resources}" | jq -s 'add')

    # Get next page URL
    next_url=$(echo "${page_result}" | jq -r '.pagination.next.href // empty')
  done

  local fetched_count
  fetched_count=$(echo "${all_resources}" | jq 'length')
  if [[ "${fetched_count}" != "${total_results}" ]]; then
    util_debug "WARNING: Fetched ${fetched_count} items but API reported " \
               "${total_results} total"
  fi

  # Return combined result with updated pagination
  jq -n \
    --argjson resources "${all_resources}" \
    --argjson total "${total_results}" \
    --argjson fetched "${fetched_count}" \
    '{
      pagination: {
        total_results: $total,
        total_pages: 1,
        fetched_results: $fetched
      },
      resources: $resources
    }'
}

# ============================================================================
# EXTRACTION FUNCTIONS (extract_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Aggregates security groups from space, org, and global levels
# Combines multiple security group lists into single semicolon-separated list
#
# Parameters:
#   $1 - Space-level security groups (semicolon-separated)
#   $2 - Org-level security groups (semicolon-separated)
#   $3 - Global security groups (semicolon-separated)
#
# Returns:
#   Combined semicolon-separated list of all security groups
#
# Examples:
#   all_groups=$(aggregate_security_groups "${space_sg}" "${org_sg}" "${global_sg}")
# ----------------------------------------------------------------------------
function aggregate_security_groups() {
  local space_groups="$1"
  local org_groups="$2"
  local global_groups="$3"

  util_join_with_separator "${CONFIG_CSV_MULTIVALUE_SEP}" \
    "${space_groups}" "${org_groups}" "${global_groups}"
}

# ----------------------------------------------------------------------------
# Extracts organization GUID for given organization name
# Validates organization exists and returns its GUID
#
# Parameters:
#   $1 - Organization name
#
# Returns:
#   Organization GUID on success
#   Exits script with code 1 if organization not found
# ----------------------------------------------------------------------------
function extract_org_guid() {
  local org_name="$1"

  util_debug "Fetching org GUID for ${org_name}"
  local org_guid
  org_guid=$(api_fetch_critical "/v3/organizations?names=${org_name}" \
             "Organization '${org_name}' lookup" | \
             jq -r '.resources[0].guid // empty')

  if [[ -z "${org_guid}" ]]; then
    echo "❌ Organization '${org_name}' not found." >&2
    echo "Available orgs:" >&2
    cf curl /v3/organizations | jq -r '.resources[].name' >&2
    exit 1
  fi

  echo "✅ Organization: ${org_name} (${org_guid})" >&2
  echo "${org_guid}"
}

# ----------------------------------------------------------------------------
# Extracts organization-level security groups
# Returns semicolon-separated list with "org:" prefix
#
# Parameters:
#   $1 - Organization GUID
#
# Returns:
#   Semicolon-separated security group names with "org:" prefix
# ----------------------------------------------------------------------------
function extract_org_security_groups() {
  local org_guid="$1"

  util_debug "Skipping org-level security groups (CF v3 API limitation)"
  # NOTE: CF v3 API does not support filtering security groups by organization_guids
  # Org-level security groups are not commonly used in most CF deployments
  # Global security groups (extracted separately) cover most use cases
  echo ""
}

# ----------------------------------------------------------------------------
# Extracts global security groups (running and staging)
# Returns semicolon-separated list with "global-running:" or "global-staging:"
# prefix
#
# Returns:
#   Semicolon-separated security group names with appropriate prefixes
# ----------------------------------------------------------------------------
function extract_global_security_groups() {
  util_debug "Fetching global security groups"

  local global_running
  global_running=$(api_fetch_all_pages \
    "/v3/security_groups?globally_enabled_running=true" \
    "Global running security groups" \
    api_fetch_safe | \
    jq -r '[(.resources // [])[]?.name // empty] | map("global-running:" + .) |
           map(select(length>16)) | join(";")')

  local global_staging
  global_staging=$(api_fetch_all_pages \
    "/v3/security_groups?globally_enabled_staging=true" \
    "Global staging security groups" \
    api_fetch_safe | \
    jq -r '[(.resources // [])[]?.name // empty] | map("global-staging:" + .) |
           map(select(length>16)) | join(";")')

  # Combine global groups
  local global_groups=""
  if [[ -n "${global_running}" ]] && [[ "${global_running}" != "null" ]]; then
    global_groups="${global_running}"
  fi
  if [[ -n "${global_staging}" ]] && [[ "${global_staging}" != "null" ]]; then
    global_groups=$(util_append_to_list "${global_groups}" "${global_staging}")
  fi

  util_debug "Global security groups: ${global_groups}"
  echo "${global_groups}"
}

# ----------------------------------------------------------------------------
# Extracts all spaces and their nested apps, processes, and metadata
# Main orchestrator function that processes org → spaces → apps → processes
#
# Parameters:
#   $1 - Organization GUID
#   $2 - Org-level security groups (semicolon-separated)
#   $3 - Global security groups (semicolon-separated)
#
# Returns:
#   Writes CSV rows to OUTFILE for all discovered resources
# ----------------------------------------------------------------------------
function extract_spaces() {
  local org_guid="$1"
  local org_security_groups="$2"
  local global_security_groups="$3"

  local spaces_json
  spaces_json=$(api_fetch_all_pages \
    "/v3/spaces?organization_guids=${org_guid}" \
    "Spaces listing for org '${ORG_NAME}'" \
    api_fetch_critical)

  local space_count
  space_count=$(echo "${spaces_json}" | jq -r '.pagination.total_results // 0')
  echo "📦 Found ${space_count} space(s) in org '${ORG_NAME}'" >&2

  if [[ "${space_count}" -eq 0 ]]; then
    echo "⚠️ No spaces found in org '${ORG_NAME}'" >&2
    return 0
  fi

  for space_guid in $(echo "${spaces_json}" | jq -r '.resources[].guid'); do
    local space_name
    space_name=$(echo "${spaces_json}" | jq -r \
      --arg guid "${space_guid}" '.resources[] | select(.guid==$guid) | .name')

    echo "➡️  Processing space: ${space_name} (${space_guid})"

    # Extract space-level security groups
    # NOTE: CF v3 API does not support filtering security groups by space_guids
    # Space-level security groups are not commonly used in most CF deployments
    # Global security groups (extracted separately) cover most use cases
    local space_security_groups=""
    util_debug "Skipping space-level security groups for '${space_name}' (CF v3 API limitation)"

    # Extract apps in this space
    extract_apps_in_space "${space_guid}" "${space_name}" \
      "${space_security_groups}" "${org_security_groups}" "${global_security_groups}"
  done
}

# ----------------------------------------------------------------------------
# Extracts all apps within a space and their metadata
#
# Parameters:
#   $1 - Space GUID
#   $2 - Space name
#   $3 - Space-level security groups
#   $4 - Org-level security groups
#   $5 - Global security groups
#
# Returns:
#   Writes CSV rows to OUTFILE for all apps and processes in space
# ----------------------------------------------------------------------------
function extract_apps_in_space() {
  local space_guid="$1"
  local space_name="$2"
  local space_security_groups="$3"
  local org_security_groups="$4"
  local global_security_groups="$5"

  local apps_json
  apps_json=$(api_fetch_all_pages \
    "/v3/apps?space_guids=${space_guid}" \
    "Apps listing for space '${space_name}'" \
    api_fetch_critical)

  local app_count
  app_count=$(echo "${apps_json}" | jq -r '.pagination.total_results // 0')

  if [[ "${app_count}" -eq 0 ]]; then
    echo "   ⚠️  No apps found in space '${space_name}'"
    return 0
  fi
  echo "   📱 Found ${app_count} app(s) in space '${space_name}'"

  for app_guid in $(echo "${apps_json}" | jq -r '.resources[]?.guid'); do
    extract_app_metadata "${app_guid}" "${apps_json}" "${space_name}" \
      "${space_security_groups}" "${org_security_groups}" "${global_security_groups}"
  done
}

# ----------------------------------------------------------------------------
# Extracts complete metadata for a single application
# Fetches buildpacks, routes, services, env vars, and processes
#
# Parameters:
#   $1 - App GUID
#   $2 - Apps JSON (containing basic app info)
#   $3 - Space name
#   $4 - Space-level security groups
#   $5 - Org-level security groups
#   $6 - Global security groups
#
# Returns:
#   Writes CSV rows to OUTFILE for all app processes
# ----------------------------------------------------------------------------
function extract_app_metadata() {
  local app_guid="$1"
  local apps_json="$2"
  local space_name="$3"
  local space_security_groups="$4"
  local org_security_groups="$5"
  local global_security_groups="$6"

  local app_name
  app_name=$(echo "${apps_json}" | jq -r \
    --arg guid "${app_guid}" '.resources[] | select(.guid==$guid) | .name')
  local app_state
  app_state=$(echo "${apps_json}" | jq -r \
    --arg guid "${app_guid}" '.resources[] | select(.guid==$guid) | .state')

  # Extract buildpack/lifecycle information
  local app_details
  app_details=$(api_fetch_safe "/v3/apps/${app_guid}")

  if ! validate_json_response "${app_details}" "App details for ${app_name}"; then
    echo "   ⚠️  WARNING: Failed to retrieve app details for '${app_name}' - " \
         "buildpack metadata may be incomplete" >&2
  fi

  local lifecycle_type buildpacks buildpack_details runtime_version
  lifecycle_type=$(echo "${app_details}" | jq -r '.lifecycle.type // empty')
  buildpacks=""
  buildpack_details=""
  runtime_version=""

  # Get droplet GUID
  local current_droplet_guid
  current_droplet_guid=$(api_fetch_safe \
    "/v3/apps/${app_guid}/relationships/current_droplet" | \
    jq -r '.data.guid // empty')

  if [[ "${lifecycle_type}" == "buildpack" ]]; then
    extract_buildpack_metadata "${current_droplet_guid}" "${app_name}"
    buildpacks="${EXTRACTED_BUILDPACKS}"
    buildpack_details="${EXTRACTED_BUILDPACK_DETAILS}"
    runtime_version="${EXTRACTED_RUNTIME_VERSION}"
  elif [[ "${lifecycle_type}" == "docker" ]]; then
    extract_docker_metadata "${current_droplet_guid}" "${app_name}"
    buildpacks="${EXTRACTED_BUILDPACKS}"
    buildpack_details="${EXTRACTED_BUILDPACK_DETAILS}"
  else
    if [[ -n "${lifecycle_type}" ]]; then
      util_debug "Unknown lifecycle type '${lifecycle_type}' for app '${app_name}'"
    fi
  fi

  # Fallback to app details if no droplet data
  if [[ -z "${buildpacks}" ]] || [[ "${buildpacks}" == "null" ]]; then
    buildpacks=$(util_jq_extract "${app_details}" \
      '.lifecycle.data.buildpacks // [] | map(select(length>0)) | join(";")')
  fi
  # Normalize null values to empty strings
  [[ "${buildpack_details}" == "null" ]] && buildpack_details=""
  [[ "${runtime_version}" == "null" ]] && runtime_version=""

  # Extract routes and domains
  local routes domains
  extract_routes_and_domains "${app_guid}" "${app_name}"
  routes="${EXTRACTED_ROUTES}"
  domains="${EXTRACTED_DOMAINS}"

  # Extract services (including volume services)
  local service_instances service_bindings volume_services volume_size
  extract_services "${app_guid}" "${app_name}"
  service_instances="${EXTRACTED_SERVICE_INSTANCES}"
  service_bindings="${EXTRACTED_SERVICE_BINDINGS}"
  volume_services="${EXTRACTED_VOLUME_SERVICES}"
  volume_size="${EXTRACTED_VOLUME_SIZE}"

  # Extract environment variables (with sanitization)
  local env_vars=""
  if [[ "${SKIP_ENV_VARS}" != "true" ]]; then
    local env_vars_json
    env_vars_json=$(api_fetch_optional "/v3/apps/${app_guid}/env" \
                    "Environment variables for ${app_name}")
    env_vars=$(sanitize_env_vars "${env_vars_json}")
    # Normalize null to empty string
    [[ "${env_vars}" == "null" ]] && env_vars=""
  fi

  # Extract processes and write CSV rows
  extract_processes "${app_guid}" "${app_name}" "${app_state}" \
    "${buildpacks}" "${buildpack_details}" "${runtime_version}" \
    "${routes}" "${domains}" "${service_instances}" "${service_bindings}" \
    "${volume_services}" "${volume_size}" \
    "${env_vars}" "${space_name}" "${space_security_groups}" \
    "${org_security_groups}" "${global_security_groups}"
}

# ----------------------------------------------------------------------------
# Extracts buildpack metadata from droplet for buildpack-based apps
# Sets EXTRACTED_BUILDPACKS, EXTRACTED_BUILDPACK_DETAILS, EXTRACTED_RUNTIME_VERSION
#
# Parameters:
#   $1 - Droplet GUID
#   $2 - App name (for error messages)
#
# Returns:
#   Sets global variables: EXTRACTED_BUILDPACKS, EXTRACTED_BUILDPACK_DETAILS,
#   EXTRACTED_RUNTIME_VERSION
# ----------------------------------------------------------------------------
function extract_buildpack_metadata() {
  local droplet_guid="$1"
  local app_name="$2"

  EXTRACTED_BUILDPACKS=""
  EXTRACTED_BUILDPACK_DETAILS=""
  EXTRACTED_RUNTIME_VERSION=""

  if [[ -z "${droplet_guid}" ]]; then
    util_debug "No current droplet GUID found for app '${app_name}'"
    return 0
  fi

  local droplet_json
  droplet_json=$(api_fetch_safe "/v3/droplets/${droplet_guid}")

  if ! validate_json_response "${droplet_json}" \
       "Droplet ${droplet_guid} for ${app_name}"; then
    echo "   ⚠️  WARNING: Failed to retrieve droplet details for '${app_name}' - " \
         "buildpack versions may be missing" >&2
    return 0
  fi

  EXTRACTED_BUILDPACKS=$(echo "${droplet_json}" | jq -r \
    '[.buildpacks[]?.name] // [] | map(select(length>0)) | join(";")')

  EXTRACTED_BUILDPACK_DETAILS=$(echo "${droplet_json}" | jq -r '
    [.buildpacks[]? | [.name, (.version // ""), (.detect_output // "")]
     | map(select(length>0)) | join(" ")] | map(select(length>0)) | join(";")')

  EXTRACTED_RUNTIME_VERSION=$(echo "${droplet_json}" | jq -r '
    (.environment_variables // {}) as $env |
    $env.BP_JVM_VERSION // $env.BP_JAVA_VERSION // $env.JAVA_VERSION // empty')
}

# ----------------------------------------------------------------------------
# Extracts Docker image metadata from droplet for Docker-based apps
# Sets EXTRACTED_BUILDPACKS (image), EXTRACTED_BUILDPACK_DETAILS (registry)
#
# Parameters:
#   $1 - Droplet GUID
#   $2 - App name (for error messages)
#
# Returns:
#   Sets global variables: EXTRACTED_BUILDPACKS, EXTRACTED_BUILDPACK_DETAILS
# ----------------------------------------------------------------------------
function extract_docker_metadata() {
  local droplet_guid="$1"
  local app_name="$2"

  EXTRACTED_BUILDPACKS=""
  EXTRACTED_BUILDPACK_DETAILS=""

  if [[ -z "${droplet_guid}" ]]; then
    util_debug "No current droplet GUID found for Docker app '${app_name}'"
    return 0
  fi

  local droplet_json
  droplet_json=$(api_fetch_safe "/v3/droplets/${droplet_guid}")

  if ! validate_json_response "${droplet_json}" \
       "Droplet ${droplet_guid} for ${app_name}"; then
    echo "   ⚠️  WARNING: Failed to retrieve Docker droplet details for " \
         "'${app_name}'" >&2
    return 0
  fi

  local docker_image
  docker_image=$(echo "${droplet_json}" | jq -r '.image // empty')

  if [[ -z "${docker_image}" ]]; then
    util_debug "No Docker image found in droplet for '${app_name}'"
    return 0
  fi

  # Parse registry from image string
  local docker_registry
  if [[ "${docker_image}" == *"/"* ]]; then
    docker_registry=$(echo "${docker_image}" | cut -d'/' -f1)
  else
    docker_registry="docker.io"
  fi

  EXTRACTED_BUILDPACKS="${docker_image}"
  EXTRACTED_BUILDPACK_DETAILS="registry:${docker_registry}"

  util_debug "Docker app detected: image=${docker_image}, registry=${docker_registry}"
}

# ----------------------------------------------------------------------------
# Extracts domains from routes JSON response
# Fetches domain names for all unique domain GUIDs
#
# Parameters:
#   $1 - Routes JSON response from API
#
# Returns:
#   Semicolon-separated list of domain names via echo
# ----------------------------------------------------------------------------
function extract_domains_from_routes() {
  local routes_json="$1"

  local domain_guids
  domain_guids=$(echo "${routes_json}" | jq -r \
    '(.resources // [])[]?.relationships.domain.data.guid | select(length>0)')

  local domains=""
  if [[ -n "${domain_guids}" ]]; then
    while read -r domain_guid; do
      [[ -z "${domain_guid}" ]] && continue
      local domain_name
      domain_name=$(api_fetch_optional "/v3/domains/${domain_guid}" \
                    "Domain ${domain_guid}" | jq -r '.name // empty')
      if [[ -n "${domain_name}" ]]; then
        domains=$(util_append_to_list "${domains}" "${domain_name}")
      fi
    done < <(printf "%s\n" "${domain_guids}" | sort -u)
  fi

  echo "${domains}"
}

# ----------------------------------------------------------------------------
# Extracts routes and domains for an application
# Sets EXTRACTED_ROUTES and EXTRACTED_DOMAINS
#
# Parameters:
#   $1 - App GUID
#   $2 - App name (for error messages)
#
# Returns:
#   Sets global variables: EXTRACTED_ROUTES, EXTRACTED_DOMAINS
# ----------------------------------------------------------------------------
function extract_routes_and_domains() {
  local app_guid="$1"
  local app_name="$2"

  EXTRACTED_ROUTES=""
  EXTRACTED_DOMAINS=""

  local routes_json
  routes_json=$(api_fetch_all_pages \
    "/v3/routes?app_guids=${app_guid}" \
    "Routes for app '${app_name}'" \
    api_fetch_safe)

  if ! validate_json_response "${routes_json}" "Routes for ${app_name}"; then
    echo "   ⚠️  WARNING: Failed to retrieve routes for '${app_name}' - " \
         "route information may be incomplete" >&2
    return 0
  fi

  EXTRACTED_ROUTES=$(util_jq_extract "${routes_json}" \
    '[(.resources // [])[]?.url // empty] | map(select(length>0)) | join(";")')

  # Debug: distinguish between "no routes" and "routes API failed"
  local route_count
  route_count=$(echo "${routes_json}" | jq -r '.resources | length')
  if [[ "${route_count}" == "0" ]] && [[ -n "${routes_json}" ]] && \
     [[ "${routes_json}" != "{}" ]]; then
    util_debug "App '${app_name}' has no routes (valid empty)"
  fi

  # Extract domains from routes
  EXTRACTED_DOMAINS=$(extract_domains_from_routes "${routes_json}")
}

# ----------------------------------------------------------------------------
# Formats a service instance entry for CSV output
# Builds display string with optional details in brackets
#
# Parameters:
#   $1 - Service instance name
#   $2 - Service instance GUID (fallback if name is empty)
#   $3 - Service offering name (optional)
#   $4 - Service plan name (optional)
#   $5 - Service instance type (optional)
#
# Returns:
#   Formatted entry string (e.g., "my-db [postgres/small (managed)]")
#
# Examples:
#   entry=$(format_service_instance_entry "my-db" "guid-123" "postgres" "small" "managed")
# ----------------------------------------------------------------------------
function format_service_instance_entry() {
  local instance_name="$1"
  local instance_guid="$2"
  local offering_name="$3"
  local plan_name="$4"
  local instance_type="$5"

  # Use name if available, otherwise GUID
  local entry="${instance_name}"
  if [[ -z "${entry}" ]]; then
    entry="${instance_guid}"
  fi

  # Build details string: offering/plan (type)
  local details=""
  if [[ -n "${offering_name}" ]]; then
    details="${offering_name}"
  fi
  if [[ -n "${plan_name}" ]]; then
    details=$(util_append_to_list "${details}" "${plan_name}" "/")
  fi
  if [[ -n "${instance_type}" ]]; then
    if [[ -n "${details}" ]]; then
      details="${details} (${instance_type})"
    else
      details="${instance_type}"
    fi
  fi

  # Add details in brackets if present
  if [[ -n "${details}" ]]; then
    entry="${entry} [${details}]"
  fi

  echo "${entry}"
}

# ----------------------------------------------------------------------------
# Extracts details for a single service instance
# Fetches instance, plan, and offering metadata and formats for display
#
# Parameters:
#   $1 - Service instance GUID
#
# Returns:
#   Formatted service instance entry string via echo
#   Returns empty string if instance cannot be retrieved
# ----------------------------------------------------------------------------
function extract_service_instance_details() {
  local service_instance_guid="$1"

  # Fetch service instance
  local service_instance_json
  service_instance_json=$(api_fetch_optional \
    "/v3/service_instances/${service_instance_guid}" \
    "Service instance ${service_instance_guid}")

  if ! validate_json_response "${service_instance_json}" \
       "Service instance ${service_instance_guid}"; then
    util_debug "Failed to retrieve service instance details for ${service_instance_guid}"
    return 0
  fi

  # Extract instance metadata
  local service_instance_name service_instance_type
  service_instance_name=$(echo "${service_instance_json}" | jq -r '.name // empty')
  service_instance_type=$(echo "${service_instance_json}" | jq -r '.type // empty')

  local service_plan_guid
  service_plan_guid=$(echo "${service_instance_json}" | jq -r \
    '.relationships.service_plan.data.guid // empty')

  # Fetch plan and offering details if plan exists
  local service_plan_name="" service_offering_name=""
  if [[ -n "${service_plan_guid}" ]]; then
    local service_plan_json
    service_plan_json=$(api_fetch_optional \
      "/v3/service_plans/${service_plan_guid}" \
      "Service plan ${service_plan_guid}")
    service_plan_name=$(echo "${service_plan_json}" | jq -r '.name // empty')

    local service_offering_guid
    service_offering_guid=$(echo "${service_plan_json}" | jq -r \
      '.relationships.service_offering.data.guid // empty')

    if [[ -n "${service_offering_guid}" ]]; then
      service_offering_name=$(api_fetch_optional \
        "/v3/service_offerings/${service_offering_guid}" \
        "Service offering" | jq -r '.name // empty')
    fi
  fi

  # Format and return entry
  format_service_instance_entry "${service_instance_name}" \
    "${service_instance_guid}" "${service_offering_name}" \
    "${service_plan_name}" "${service_instance_type}"
}

# ----------------------------------------------------------------------------
# Extracts service instances and bindings for an application
# Identifies volume services for persistent storage requirements
# Sets EXTRACTED_SERVICE_INSTANCES, EXTRACTED_SERVICE_BINDINGS,
#     EXTRACTED_VOLUME_SERVICES, EXTRACTED_VOLUME_SIZE
#
# Parameters:
#   $1 - App GUID
#   $2 - App name (for error messages)
#
# Returns:
#   Sets global variables: EXTRACTED_SERVICE_INSTANCES, EXTRACTED_SERVICE_BINDINGS,
#                          EXTRACTED_VOLUME_SERVICES, EXTRACTED_VOLUME_SIZE
# ----------------------------------------------------------------------------
function extract_services() {
  local app_guid="$1"
  local app_name="$2"

  EXTRACTED_SERVICE_INSTANCES=""
  EXTRACTED_SERVICE_BINDINGS=""
  EXTRACTED_VOLUME_SERVICES=""
  EXTRACTED_VOLUME_SIZE=""

  local service_bindings_json
  service_bindings_json=$(api_fetch_all_pages \
    "/v3/service_credential_bindings?app_guids=${app_guid}" \
    "Service bindings for app '${app_name}'" \
    api_fetch_safe)

  if ! validate_json_response "${service_bindings_json}" \
       "Service bindings for ${app_name}"; then
    echo "   ⚠️  WARNING: Failed to retrieve service bindings for '${app_name}' - " \
         "service information may be incomplete" >&2
    return 0
  fi

  EXTRACTED_SERVICE_BINDINGS=$(util_jq_extract "${service_bindings_json}" \
    '[(.resources // [])[]?.name // empty] | map(select(length>0)) | join(";")')

  # Extract service instance details
  local service_instance_guids
  service_instance_guids=$(echo "${service_bindings_json}" | jq -r \
    '(.resources // [])[]?.relationships.service_instance.data.guid |
     select(length>0)')

  if [[ -n "${service_instance_guids}" ]]; then
    while read -r service_instance_guid; do
      [[ -z "${service_instance_guid}" ]] && continue

      # Fetch service instance to check type
      local service_instance_json
      service_instance_json=$(api_fetch_optional \
        "/v3/service_instances/${service_instance_guid}" \
        "Service instance ${service_instance_guid}")

      if ! validate_json_response "${service_instance_json}" \
           "Service instance ${service_instance_guid}"; then
        util_debug "Failed to retrieve service instance details for ${service_instance_guid}"
        continue
      fi

      # Check if this is a volume service
      local instance_type instance_name
      instance_type=$(echo "${service_instance_json}" | jq -r '.type // empty')
      instance_name=$(echo "${service_instance_json}" | jq -r '.name // empty')

      # Extract and format service instance details
      local entry
      entry=$(extract_service_instance_details "${service_instance_guid}")

      # Append to list if entry was successfully retrieved
      if [[ -n "${entry}" ]]; then
        EXTRACTED_SERVICE_INSTANCES=$(util_append_to_list \
          "${EXTRACTED_SERVICE_INSTANCES}" "${entry}")
      fi

      # If it's a volume service, extract volume-specific data
      if [[ "${instance_type}" == "user-provided" ]]; then
        # Check if it's a volume by looking at credentials or tags
        local tags
        tags=$(echo "${service_instance_json}" | jq -r '.tags // [] | join(",")')
        if [[ "${tags}" == *"volume"* ]] || [[ "${tags}" == *"storage"* ]]; then
          # Extract volume size from parameters if available
          local volume_size
          volume_size=$(echo "${service_instance_json}" | jq -r \
            '.parameters.size // .parameters.capacity // empty')

          if [[ -n "${volume_size}" ]]; then
            # Convert to GB if needed (handle units like "10GB", "5000MB", "5G")
            volume_size=$(echo "${volume_size}" | sed -E 's/([0-9.]+).*/\1/')
            EXTRACTED_VOLUME_SERVICES=$(util_append_to_list \
              "${EXTRACTED_VOLUME_SERVICES}" "${instance_name}")
            EXTRACTED_VOLUME_SIZE=$(util_append_to_list \
              "${EXTRACTED_VOLUME_SIZE}" "${volume_size}")
            util_debug "Volume service detected: ${instance_name} (${volume_size}GB)"
          fi
        fi
      fi
    done < <(printf "%s\n" "${service_instance_guids}" | sort -u)
  fi
}

# ----------------------------------------------------------------------------
# Extracts actual resource usage statistics for a process
# Fetches real-time disk and memory usage from running instances
#
# Parameters:
#   $1 - Process GUID
#   $2 - App name (for error messages)
#   $3 - Process type (for error messages)
#
# Returns:
#   Sets global variables: EXTRACTED_MEMORY_USAGE, EXTRACTED_DISK_USAGE
#   Returns empty strings if stats unavailable (stopped apps, errors)
# ----------------------------------------------------------------------------
function extract_process_stats() {
  local process_guid="$1"
  local app_name="$2"
  local process_type="$3"

  EXTRACTED_MEMORY_USAGE=""
  EXTRACTED_DISK_USAGE=""

  # Stats API only works for running instances
  local stats_json
  stats_json=$(api_fetch_optional "/v3/processes/${process_guid}/stats" \
               "Stats for ${app_name}:${process_type}")

  if ! validate_json_response "${stats_json}" \
       "Process stats for ${app_name}:${process_type}"; then
    util_debug "Stats unavailable for ${app_name}:${process_type} (app may be stopped)"
    return 0
  fi

  # Extract stats from first available instance (index 0)
  # For scaled apps, this gives representative usage per instance
  local instance_stats
  instance_stats=$(echo "${stats_json}" | jq -r '.resources[0] // empty')

  if [[ -z "${instance_stats}" ]]; then
    util_debug "No instance stats available for ${app_name}:${process_type}"
    return 0
  fi

  # Extract usage in bytes and convert to MB
  local mem_bytes disk_bytes
  mem_bytes=$(echo "${instance_stats}" | jq -r '.usage.mem // 0')
  disk_bytes=$(echo "${instance_stats}" | jq -r '.usage.disk // 0')

  # Convert bytes to MB (round up)
  if [[ "${mem_bytes}" -gt 0 ]]; then
    EXTRACTED_MEMORY_USAGE=$(( (mem_bytes + 1048575) / 1048576 ))
  fi
  if [[ "${disk_bytes}" -gt 0 ]]; then
    EXTRACTED_DISK_USAGE=$(( (disk_bytes + 1048575) / 1048576 ))
  fi

  util_debug "Stats for ${app_name}:${process_type}: mem=${EXTRACTED_MEMORY_USAGE}MB, disk=${EXTRACTED_DISK_USAGE}MB"
}

# ----------------------------------------------------------------------------
# Extracts processes for an application and writes CSV rows
# Each process type (web, worker, etc.) gets its own CSV row
#
# Parameters:
#   $1  - App GUID
#   $2  - App name
#   $3  - App state
#   $4  - Buildpacks
#   $5  - Buildpack details
#   $6  - Runtime version
#   $7  - Routes
#   $8  - Domains
#   $9  - Service instances
#   $10 - Service bindings
#   $11 - Volume services
#   $12 - Volume size
#   $13 - Environment variables
#   $14 - Space name
#   $15 - Space security groups
#   $16 - Org security groups
#   $17 - Global security groups
#
# Returns:
#   Writes CSV rows to OUTFILE for each process
# ----------------------------------------------------------------------------
function extract_processes() {
  local app_guid="$1"
  local app_name="$2"
  local app_state="$3"
  local buildpacks="$4"
  local buildpack_details="$5"
  local runtime_version="$6"
  local routes="$7"
  local domains="$8"
  local service_instances="$9"
  local service_bindings="${10}"
  local volume_services="${11}"
  local volume_size="${12}"
  local env_vars="${13}"
  local space_name="${14}"
  local space_security_groups="${15}"
  local org_security_groups="${16}"
  local global_security_groups="${17}"

  local processes_json
  processes_json=$(api_fetch_all_pages \
    "/v3/processes?app_guids=${app_guid}" \
    "Processes for app '${app_name}'" \
    api_fetch_critical)

  local proc_count
  proc_count=$(echo "${processes_json}" | jq -r '.pagination.total_results // 0')

  if [[ "${proc_count}" -eq 0 ]]; then
    echo "      ⚠️  No processes for app '${app_name}'" >&2
    return 0
  fi

  for row in $(echo "${processes_json}" | jq -r '.resources[]? | @base64'); do
    _jq() { echo "${row}" | util_base64_decode | jq -r "$1"; }

    local proc_guid proc_type instances mem disk
    proc_guid=$(_jq '.guid')
    proc_type=$(_jq '.type')
    instances=$(_jq '.instances')
    mem=$(_jq '.memory_in_mb')
    disk=$(_jq '.disk_in_mb')

    # Extract actual resource usage statistics (for running instances)
    extract_process_stats "${proc_guid}" "${app_name}" "${proc_type}"
    local mem_usage="${EXTRACTED_MEMORY_USAGE}"
    local disk_usage="${EXTRACTED_DISK_USAGE}"

    # Calculate total disk usage across all instances
    # Critical for OpenShift ephemeral storage capacity planning
    local total_disk_usage=""
    if [[ -n "${disk_usage}" ]]; then
      total_disk_usage=$((disk_usage * instances))
    fi

    # Aggregate all security groups (space + org + global)
    local all_security_groups
    all_security_groups=$(aggregate_security_groups \
      "${space_security_groups}" "${org_security_groups}" "${global_security_groups}")

    # Write CSV row with new columns: Memory Usage(MB), Disk Usage(MB), Total Disk Usage(MB), Volume Services, Volume Size(GB)
    echo "$(csv_escape_field "${ORG_NAME}"),$(csv_escape_field "${space_name}")," \
         "$(csv_escape_field "${app_name}"),$(csv_escape_field "${proc_type}")," \
         "${instances},${mem},${disk},${mem_usage},${disk_usage},${total_disk_usage}," \
         "$(csv_escape_field "${app_state}")," \
         "$(csv_escape_field "${buildpacks}")," \
         "$(csv_escape_field "${buildpack_details}")," \
         "$(csv_escape_field "${runtime_version}"),$(csv_escape_field "${routes}")," \
         "$(csv_escape_field "${domains}")," \
         "$(csv_escape_field "${service_instances}")," \
         "$(csv_escape_field "${service_bindings}")," \
         "$(csv_escape_field "${volume_services}")," \
         "$(csv_escape_field "${volume_size}")," \
         "$(csv_escape_field "${env_vars}")," \
         "$(csv_escape_field "${all_security_groups}")" >> "${OUTFILE}"
  done
}

# ============================================================================
# COMMAND-LINE INTERFACE (cli_*)
# ============================================================================

# ----------------------------------------------------------------------------
# Displays comprehensive help message
# Called when user provides -h or --help flag
#
# Returns:
#   Outputs help text and exits with code 0
# ----------------------------------------------------------------------------
function cli_show_help() {
  cat << EOF
Cloud Foundry Application Metadata Extractor (v3 API)

USAGE:
  ${SCRIPT_NAME} <org_name> [options]
  ${SCRIPT_NAME} -h|--help

ARGUMENTS:
  <org_name>    Cloud Foundry organization name to extract metadata from

OPTIONS:
  -o, --output FILE    Output CSV file path
                       (default: pcfusage_<org>_YYYYMMDDHHMMSS.csv)
  -d, --debug          Enable verbose diagnostic output
  --no-env-vars        Skip extracting environment variables (Env Vars column will be empty)
  -h, --help           Display this help message

DESCRIPTION:
  Collects comprehensive Cloud Foundry org, space, app, and process metadata
  using the CF v3 API. Produces a detailed CSV report for auditing, reporting,
  and migration analysis (e.g., CF → OpenShift/Kubernetes).

FEATURES:
  • v3 API support (works with v2 API disabled)
  • Comprehensive metadata extraction (org, space, app, processes, buildpacks,
    routes, domains, services, security groups)
  • Actual resource usage extraction (memory and disk usage from running instances)
  • Volume service detection (persistent storage requirements for OpenShift PVCs)
  • Docker support (extracts image and registry info)
  • Security (sanitizes sensitive environment variables)
  • Robust error handling (retry logic with exponential backoff)
  • Automatic pagination (handles large datasets >50 items/page)
  • RFC 4180 CSV formatting (proper escaping)
  • Data quality tracking (reports warnings for incomplete data)

OUTPUT:
  Generates a timestamped CSV file:
    pcfusage_<org_name>_YYYYMMDDHHMMSS.csv

  CSV columns (22 total):
    Org, Space, App, Process Type, Instances, Memory(MB), Disk(MB),
    Memory Usage(MB), Disk Usage(MB), Total Disk Usage(MB), State, Buildpacks,
    Buildpack Details, Runtime Version, Routes, Domains, Service Instances,
    Service Bindings, Volume Services, Volume Size(GB), Env Vars, Security Groups

REQUIREMENTS:
  • Cloud Foundry CLI (cf) installed
  • jq installed
  • Logged into Cloud Foundry (cf login)

EXAMPLES:
  # Extract metadata for abc-company org
  ./${SCRIPT_NAME} abc-company

  # Extract with custom output file
  ./${SCRIPT_NAME} abc-company -o /tmp/report.csv

  # Extract with debug output
  ./${SCRIPT_NAME} abc-company --debug

  # Show this help message
  ./${SCRIPT_NAME} --help

COMMON USES:
  • Migration planning (CF → OpenShift/Kubernetes)
    - Actual ephemeral disk usage for ephemeral-storage limits
    - Volume service mapping to PersistentVolumeClaims (PVCs)
    - Memory/disk quota vs actual usage for right-sizing
  • Resource auditing (memory, disk, instance usage)
  • Buildpack analysis (identify versions and upgrade candidates)
  • Security review (audit security groups and environment variables)
  • Service mapping (document dependencies and bindings)
  • Docker adoption tracking
  • Compliance reporting

For more information, see README.md
EOF
  exit 0
}

# ----------------------------------------------------------------------------
# Validates required command-line tools are available
# Checks for cf, jq, and CF authentication
#
# Returns:
#   Exits with code 1 if validation fails
# ----------------------------------------------------------------------------
function cli_validate_environment() {
  for cmd in cf jq; do
    command -v "${cmd}" >/dev/null 2>&1 || \
      { echo "❌ ${cmd} not found in PATH"; exit 1; }
  done

  if ! cf target >/dev/null 2>&1; then
    echo "❌ Not logged in to Cloud Foundry. Run 'cf login' first."
    exit 1
  fi
}

# ----------------------------------------------------------------------------
# Validates required command-line arguments
# Ensures organization name was provided
#
# Returns:
#   Exits with code 1 and usage message if ORG_NAME is empty
# ----------------------------------------------------------------------------
function cli_validate_required_args() {
  if [[ -z "${ORG_NAME}" ]]; then
    echo "Usage: ${SCRIPT_NAME} <org_name> [options]"
    echo "Try '${SCRIPT_NAME} --help' for more information."
    exit 1
  fi
}

# ----------------------------------------------------------------------------
# Sets default values for optional command-line arguments
# Generates default output filename if not specified
#
# Returns:
#   Sets OUTFILE if not already set
# ----------------------------------------------------------------------------
function cli_set_defaults() {
  if [[ -z "${OUTFILE}" ]]; then
    OUTFILE="${CONFIG_OUTPUT_PREFIX}_${ORG_NAME}_"
    OUTFILE="${OUTFILE}$(date +${CONFIG_CSV_TIMESTAMP_FORMAT}).csv"
  fi
}

# ----------------------------------------------------------------------------
# Parses command-line arguments and sets global variables
# Supports both short and long option forms
#
# Parameters:
#   $@ - Command-line arguments
#
# Returns:
#   Sets global variables: ORG_NAME, OUTFILE, DEBUG
#   Exits with code 1 if validation fails
# ----------------------------------------------------------------------------
function cli_parse_args() {
  # Check for help flag FIRST
  if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    cli_show_help
  fi

  # Initialize defaults
  ORG_NAME=""
  DEBUG=""
  OUTFILE=""
  SKIP_ENV_VARS=""

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--debug)
        DEBUG="--debug"
        echo "🔍 Debug mode enabled" >&2
        shift
        ;;
      --no-env-vars)
        SKIP_ENV_VARS="true"
        echo "⚠️  Environment variable extraction disabled" >&2
        shift
        ;;
      -o|--output)
        if [[ -z "${2:-}" ]]; then
          echo "Error: --output requires a file path argument"
          echo "Try '${SCRIPT_NAME} --help' for more information."
          exit 1
        fi
        OUTFILE="$2"
        shift 2
        ;;
      -h|--help)
        cli_show_help
        ;;
      -*)
        echo "Unknown option: $1"
        echo "Try '${SCRIPT_NAME} --help' for more information."
        exit 1
        ;;
      *)
        if [[ -z "${ORG_NAME}" ]]; then
          ORG_NAME="$1"
        else
          echo "Error: Unexpected argument: $1"
          echo "Try '${SCRIPT_NAME} --help' for more information."
          exit 1
        fi
        shift
        ;;
    esac
  done

  # Validate and set defaults
  cli_validate_required_args
  cli_set_defaults
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Parse command-line arguments
cli_parse_args "$@"

# Validate environment (cf, jq, authentication)
cli_validate_environment

# Initialize output file with CSV header
csv_write_header

# Data quality tracking
WARNING_COUNT=0

# Extract organization GUID
ORG_GUID=$(extract_org_guid "${ORG_NAME}")

# Extract security groups (org and global levels)
ORG_SECURITY_GROUPS=$(extract_org_security_groups "${ORG_GUID}")
GLOBAL_SECURITY_GROUPS=$(extract_global_security_groups)

# Extract spaces and nested data (apps, processes, etc.)
extract_spaces "${ORG_GUID}" "${ORG_SECURITY_GROUPS}" "${GLOBAL_SECURITY_GROUPS}"

# Report completion
echo >&2
echo "✅ Report generated: ${OUTFILE}" >&2
if [[ "${WARNING_COUNT}" -gt 0 ]]; then
  echo "⚠️  Data Quality: ${WARNING_COUNT} warnings encountered " \
       "(see stderr output)" >&2
  echo "   Some data may be incomplete due to API failures" >&2
  echo "   Run with --debug flag for detailed warnings" >&2
else
  echo "✓  Data Quality: No warnings - extraction completed successfully" >&2
fi

if [[ "${DEBUG}" == "--debug" ]]; then
  echo "🔍 CSV preview:" >&2
  head -n 10 "${OUTFILE}" >&2

  # Debug: validate_json_response function test
  util_debug "Testing validate_json_response..."
  if validate_json_response '{}' "test"; then
    util_debug "FAIL: {} should be invalid"
  else
    util_debug "PASS: {} detected as invalid"
  fi
  if validate_json_response '{"data":"value"}' "test"; then
    util_debug "PASS: valid JSON accepted"
  else
    util_debug "FAIL: valid JSON rejected"
  fi
fi
