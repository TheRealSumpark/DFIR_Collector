#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2006

# Transfer file via HTTP PUT method.
# Arguments:
#   string payload: payload (file or string)
#   string url: url
#   string headers: HTTP headers
# Returns:
#   boolean: true on success
#            false on fail
_http_transfer()
{
  __ht_payload="${1:-Testing S3 upload from shell script.}"
  __ht_url="${2:-}"
  __ht_headers="${3:-}"

  if command_exists "curl"; then
    __ht_verbose="--silent --show-error --fail --output /dev/null"
    if [ -f "${__ht_payload}" ]; then
      __ht_command="curl \
${__ht_verbose} \
--insecure \
--request PUT \"${__ht_url}\" \
${__ht_headers} \
--upload-file \"${__ht_payload}\""
    else
      __ht_command="curl \
${__ht_verbose} \
--insecure \
--request PUT \"${__ht_url}\" \
${__ht_headers} \
--data \"${__ht_payload}\""
    fi
  
  else
    __ht_verbose="--quiet"
    if [ -f "${__ht_payload}" ]; then
      __ht_command="wget \
${__ht_verbose} \
--output-document /dev/null \
--no-check-certificate \
--method PUT \"${__ht_url}\" \
${__ht_headers} \
--body-file \"${__ht_payload}\""
    else
      __ht_command="wget \
${__ht_verbose} \
--output-document /dev/null \
--no-check-certificate \
--method PUT \"${__ht_url}\" \
${__ht_headers} \
--body-data \"${__ht_payload}\""
    fi
  fi

  _verbose_msg "Uploading evidence with HTTP PUT (URL and authentication omitted)"
	eval "${__ht_command}"

}
