#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Copy files and directories.
# Arguments:
#   string from_file: file containing the list of files to be copied
#   string destination_file: destination directory
# Returns:
#   integer: zero on success, nonzero if any copy failed
_copy_data()
{
  __cd_from_file="${1:-}"
  __cd_destination_directory="${2:-}"
  
  if [ ! -f "${__cd_from_file}" ]; then
    _error_msg "_copy_data: no such file or directory: '${__cd_from_file}'"
    return 1
  fi

  __cd_status=0
  while IFS= read -r __cd_line || [ -n "${__cd_line}" ]; do
    [ -n "${__cd_line}" ] || continue
    case "${__cd_line}" in
      /*) ;;
      *) __cd_line="./${__cd_line}" ;;
    esac
    __cd_relative="${__cd_line}"
    case "${__cd_line}" in
      "${__UAC_ARTIFACTS_OUTPUT_DIR}"/*)
        __cd_relative="${__cd_line#"${__UAC_ARTIFACTS_OUTPUT_DIR}"/}" ;;
      "${__UAC_MOUNT_POINT%/}"/*)
        __cd_relative="${__cd_line#"${__UAC_MOUNT_POINT%/}"/}" ;;
    esac
    __cd_relative="${__cd_relative#/}"
    case "/${__cd_relative}/" in
      */../*)
        _error_msg "Refusing parent traversal in file list."
        __cd_status=1
        continue ;;
    esac
    # Parameter expansion preserves literal backslashes and trailing whitespace.
    case "${__cd_relative}" in
      */*) __cd_dirname="${__cd_relative%/*}" ;;
      *) __cd_dirname="." ;;
    esac
    if mkdir -p "${__cd_destination_directory}/${__cd_dirname}"; then
      cp -r "${__cd_line}" "${__cd_destination_directory}/${__cd_dirname}" || __cd_status=1
    else
      __cd_status=1
    fi
  done <"${__cd_from_file}"
  return "${__cd_status}"
}
