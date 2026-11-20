#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Clean up and exit.
# Arguments:
#   none
# Returns:
#   integer: exit code 130
_terminate()
{
  printf "\n%s\n" "Caught signal; partial evidence retained in '${__UAC_TEMP_DATA_DIR}'."
  exit 130

}
