#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Execute tar with positional arguments, without evaluating paths as shell code.
# The fallback archives the already staged directory, including its dotfiles.
_tar_archive()
{
  case "${__UAC_OPERATING_SYSTEM}" in
    "aix") tar -L "${1}" -cf "${2}" ;;
    "freebsd"|"netbsd"|"netscaler"|"openbsd") tar -I "${1}" -cf "${2}" ;;
    "esxi"|"linux")
      if ${__UAC_TOOL_TAR_NO_FROM_FILE_SUPPORT}; then
        tar -cf "${2}" .
      elif tar --help 2>/dev/null | grep -q -e '--verbatim-files-from'; then
        tar --verbatim-files-from -T "${1}" -cf "${2}"
      else
        tar -T "${1}" -cf "${2}"
      fi
      ;;
    "solaris") tar -cf "${2}" -I "${1}" ;;
    *) tar -T "${1}" -cf "${2}" ;;
  esac
}

# Archive files and directories.
# Arguments:
#   string from_file: file containing the list of files to be archived
#   string destination_file: output file
# Returns:
#   none
_tar_data()
{
  __td_from_file="${1:-}"
  __td_destination_file="${2:-}"

  if [ ! -f "${__td_from_file}" ]; then
    _error_msg "File containing the list of files to be archived '${__td_from_file}' does not exist."
    return 1
  fi

  _verbose_msg "Archiving selected files to '${__td_destination_file}'"
  _tar_archive "${__td_from_file}" "${__td_destination_file}" \
    >>"${__UAC_TEMP_DATA_DIR}/tar_data.stdout.txt" \
    2>>"${__UAC_TEMP_DATA_DIR}/tar_data.stderr.txt"

}
