#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Print verbose message.
# Arguments:
#   string message: message
# Returns:
#   none
_verbose_msg()
{
  __vm_message="${1:-}"

  if ${__UAC_VERBOSE_MODE}; then
    _redact_secrets "${__vm_message}"
  fi
}
