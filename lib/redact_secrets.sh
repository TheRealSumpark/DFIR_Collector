#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Replace configured secrets as literal strings; never pass them in awk arguments.
_redact_secrets()
{
  printf '%s\n' "${1:-}" | \
    __UAC_REDACT_PASSWORD="${__UAC_OUTPUT_PASSWORD:-}" \
    __UAC_REDACT_ACCESS="${__UAC_S3_ACCESS_KEY:-}" \
    __UAC_REDACT_SECRET="${__UAC_S3_SECRET_KEY:-}" \
    __UAC_REDACT_TOKEN="${__UAC_S3_TOKEN:-}" \
    __UAC_REDACT_PRESIGNED="${__UAC_AWS_S3_PRESIGNED_URL:-}" \
    __UAC_REDACT_PRESIGNED_LOG="${__UAC_AWS_S3_PRESIGNED_URL_LOG_FILE:-}" \
    __UAC_REDACT_AZURE="${__UAC_AZURE_STORAGE_SAS_URL:-}" \
    __UAC_REDACT_AZURE_TEMP="${__UAC_AZURE_STORAGE_SAS_URL_TEMP:-}" \
    awk '
      BEGIN {
        n = 0
        for (name in ENVIRON) {
          if (index(name, "__UAC_REDACT_") == 1 && ENVIRON[name] != "") {
            values[++n] = ENVIRON[name]
          }
        }
        for (i = 1; i <= n; i++) {
          for (j = i + 1; j <= n; j++) {
            if (length(values[j]) > length(values[i])) {
              tmp = values[i]; values[i] = values[j]; values[j] = tmp
            }
          }
        }
      }
      function redact(text, value, result, position) {
        result = ""
        while ((position = index(text, value)) > 0) {
          result = result substr(text, 1, position - 1) "[REDACTED]"
          text = substr(text, position + length(value))
        }
        return result text
      }
      { message = message (NR > 1 ? "\n" : "") $0 }
      END {
        text = message
        for (i = 1; i <= n; i++) text = redact(text, values[i])
        print text
      }'
}

# Format the invocation without ever retaining values of secret-bearing options.
_redact_command_line()
{
  __rl_secret=false
  for __rl_argument in "${@}"; do
    if ${__rl_secret}; then
      printf ' %s' '[REDACTED]'
      __rl_secret=false
      continue
    fi
    printf ' %s' "${__rl_argument}"
    case "${__rl_argument}" in
      -P|--output-password|--s3-access-key|--s3-secret-key|--s3-token|\
      --aws-s3-presigned-url|--aws-s3-presigned-url-log-file|--azure-storage-sas-url)
        __rl_secret=true ;;
    esac
  done
  printf '\n'
}

_has_secrets()
{
  [ -n "${__UAC_OUTPUT_PASSWORD:-}${__UAC_S3_ACCESS_KEY:-}${__UAC_S3_SECRET_KEY:-}${__UAC_S3_TOKEN:-}${__UAC_AWS_S3_PRESIGNED_URL:-}${__UAC_AWS_S3_PRESIGNED_URL_LOG_FILE:-}${__UAC_AZURE_STORAGE_SAS_URL:-}" ]
}

# Read a private key=value input or an explicitly supplied descriptor such as /dev/fd/3.
# Values are data: no eval, variable expansion or command substitution is performed.
_load_secrets()
{
  if [ ! -r "${1:-}" ]; then
    _error_msg "Cannot read the secret input file."
    return 1
  fi
  while IFS= read -r __ls_line || [ -n "${__ls_line}" ]; do
    case "${__ls_line}" in
      ''|\#*) continue ;;
      *=*) __ls_name="${__ls_line%%=*}"; __ls_value="${__ls_line#*=}" ;;
      *) _error_msg "Secret input must contain key=value lines."; return 1 ;;
    esac
    case "${__ls_name}" in
      output_password) __UAC_OUTPUT_PASSWORD="${__ls_value}" ;;
      s3_access_key) __UAC_S3_ACCESS_KEY="${__ls_value}" ;;
      s3_secret_key) __UAC_S3_SECRET_KEY="${__ls_value}" ;;
      s3_token) __UAC_S3_TOKEN="${__ls_value}" ;;
      aws_s3_presigned_url) __UAC_AWS_S3_PRESIGNED_URL="${__ls_value}" ;;
      aws_s3_presigned_url_log_file) __UAC_AWS_S3_PRESIGNED_URL_LOG_FILE="${__ls_value}" ;;
      azure_storage_sas_url) __UAC_AZURE_STORAGE_SAS_URL="${__ls_value}" ;;
      *) _error_msg "Unknown key in secret input (value omitted)."; return 1 ;;
    esac
  done <"${1}"
  unset __ls_line __ls_value
}
