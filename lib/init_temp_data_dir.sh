#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2006

# Create temporary files and directories used during execution.
# Arguments:
#   none
# Returns:
#   none
_init_temp_data_dir()
{
  umask 077
  __it_base="${__UAC_TEMP_DATA_DIR}"
  __it_attempt=0
  __UAC_OWNED_TEMP_DATA_DIR=""
  # mkdir is the atomic reservation; existing runs and symlinks are never reused.
  while [ "${__it_attempt}" -lt 100 ]; do
    __it_candidate="${__it_base}.${$}.${__it_attempt}"
    if mkdir -m 700 "${__it_candidate}" 2>/dev/null; then
      __UAC_TEMP_DATA_DIR="${__it_candidate}"
      __UAC_OWNED_TEMP_DATA_DIR="${__it_candidate}"
      break
    fi
    __it_attempt=`expr "${__it_attempt}" + 1`
  done
  if [ -z "${__UAC_OWNED_TEMP_DATA_DIR}" ]; then
    _error_msg "Cannot reserve a private temporary directory under '${__it_base}'."
    return 1
  fi
  __UAC_ARTIFACTS_OUTPUT_DIR="${__UAC_TEMP_DATA_DIR}/collected"
  # directory where collected data that goes to the output file will be temporarily stored
  mkdir "${__UAC_ARTIFACTS_OUTPUT_DIR}" || return 1
  # directory where collected data using %temp_directory% will be temporarily stored
  mkdir "${__UAC_TEMP_DATA_DIR}/tmp" || return 1

  touch "${__UAC_TEMP_DATA_DIR}/file_collector.tmp"
  touch "${__UAC_TEMP_DATA_DIR}/${__UAC_LOG_FILE}"
  
}
