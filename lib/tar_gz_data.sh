#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Archive and compress files and directories.
# Arguments:
#   string from_file: file containing the list of files to be archived and compressed
#   string destination_file: output file
# Returns:
#   none
_tar_gz_data()
{
  __tg_from_file="${1:-}"
  __tg_destination_file="${2:-}"

  if [ ! -f "${__tg_from_file}" ]; then
    _error_msg "File containing the list of files to be archived '${__tg_from_file}' does not exist."
    return 1
  fi

  __tg_fifo="${__UAC_TEMP_DATA_DIR}/tar-gzip.${$}.fifo"
  mkfifo "${__tg_fifo}" || return 1
  _verbose_msg "Archiving and compressing selected files to '${__tg_destination_file}'"
  gzip <"${__tg_fifo}" >"${__tg_destination_file}" \
    2>>"${__UAC_TEMP_DATA_DIR}/tar_gz_data.stderr.txt" &
  __tg_gzip_pid=${!}
  # Open the FIFO before executing tar so even early tar failures close the writer.
  _tar_archive "${__tg_from_file}" - >"${__tg_fifo}" \
    2>>"${__UAC_TEMP_DATA_DIR}/tar_gz_data.stderr.txt"
  __tg_tar_status=${?}
  wait "${__tg_gzip_pid}"
  __tg_gzip_status=${?}
  rm -f "${__tg_fifo}"
  [ "${__tg_tar_status}" -eq 0 ] && [ "${__tg_gzip_status}" -eq 0 ]
}
