#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Zip files and directories.
# Arguments:
#   string from_file: file containing the list of files to be zipped
#   string destination_file: output file
#   string password: password (optional)
# Returns:
#   none
_zip_data()
{
  __zd_from_file="${1:-}"
  __zd_destination_file="${2:-}"
  __zd_password="${3:-}"

  if [ ! -f "${__zd_from_file}" ]; then
    _error_msg "File containing the list of files to be archived '${__zd_from_file}' does not exist."
    return 1
  fi

  _verbose_msg "Creating ZIP archive '${__zd_destination_file}' (password omitted)"
  if [ -n "${__zd_password}" ]; then
    zip -6 -r --password "${__zd_password}" "${__zd_destination_file}" -@ \
      <"${__zd_from_file}" >>"${__UAC_TEMP_DATA_DIR}/zip_data.stdout.txt" \
      2>>"${__UAC_TEMP_DATA_DIR}/zip_data.stderr.txt"
  else
    zip -6 -r "${__zd_destination_file}" -@ \
      <"${__zd_from_file}" >>"${__UAC_TEMP_DATA_DIR}/zip_data.stdout.txt" \
      2>>"${__UAC_TEMP_DATA_DIR}/zip_data.stderr.txt"
  fi
}
