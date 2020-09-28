#!/bin/sh

URL="https://api.github.com/repos/sifive/testenv-metal/actions/workflows/build_test.yml/dispatches"

if [ $# -ne 4 ]; then
    # Do not print the arguments as they may contain sensitive tokens
    echo "Invalid arguments (count: $#)" >&2
    exit 1
fi

GH_BRANCH="$1"
GH_USER="$2"
GH_TOKEN="$3"
SCL_REF="$4"

CURL_LOG=""

cleanup () {
    if  [ -n "${CURL_LOG}" ]; then
        rm -f "${CURL_LOG}"
    fi
}

set -eu

PAYLOAD="{\"ref\": \"${GH_BRANCH}\", \"inputs\": {\"scl_ref\": \"${SCL_REF}\"}}"

CURL_LOG=$(mktemp)
trap cleanup EXIT

HTTP_CODE=$(curl -XPOST -s -o ${CURL_LOG} -w "%{http_code}" \
            -u "${GH_USER}:${GH_TOKEN}" \
            -H "Accept: application/vnd.github.everest-preview+json" \
            -H "Content-Type: application/json" \
            ${URL} --data "${PAYLOAD}")

if [ ${HTTP_CODE} -ne 204 ]; then
    echo "Remote trigger failed (error: ${HTTP_CODE})" >&2
    cat ${CURL_LOG} >&2
    exit 1
fi