#!/bin/bash

source ./_common.sh

function check_usage {
	DOCKERFILE="$1"
	HELP=$2
	JSON=$3

	if [ ! -e "${DOCKERFILE}" -o ! -r "${DOCKERFILE}" ]
	then
		echo "Error: \"$DOCKERFILE\" doesn't exist or is not readable!"
		echo ""
		HELP=0
	fi

	if [ "${HELP}" -eq 0 ]
	then
		echo "Usage: ${0} [options] [Dockerfile]"
		echo ""
		echo "    Dockerfile: A directory or a Dockerfile to scan (default: ./)"
		echo ""
		echo "The script uses following options:"
		echo "    --help: This screen"
		echo "    --json: JSON output"
		echo ""
		echo "Example: ${0} --json templates/base/Dockerfile"

		exit 1
	fi
}


function main {
	check_utils docker jq tr	
	
	DOCKERFILE="$(echo "$*" | sed -re 's/(--help|--json)*//g' | sed -re 's/^[[:space:]]+|[[:space:]]+$//g')"
	if [ "$DOCKERFILE" = "" ]
	then
		DOCKERFILE="."
	fi
		
	HELP=$(echo "$*" | grep -F -- "--help" >/dev/null; echo $?)
	
	JSON=$(echo "$*" | grep -F -- "--json" >/dev/null; echo $?)

	check_usage "${DOCKERFILE}" $HELP $JSON
	
	SECURITY_DIR=temp-security-$(date "$(date)" "+%Y%m%d%H%M")
	export SECURITY_DIR
	mkdir -p "${SECURITY_DIR}"
	trap "rm -rf ${SECURITY_DIR}" EXIT


	TRIVY_CACHE_DIR=temp-trivy-cache
	export TRIVY_CACHE_DIR
	mkdir -p "${TRIVY_CACHE_DIR}"

	if [ "${DOCKERFILE}" = "." ]
	then
		print_summary $JSON
		
		exit $?
	else	
		print_dockerfile $JSON "${DOCKERFILE}"
		
		exit $?
	fi
}

function print_summary {
	JSON=$1
	
	SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"

	RUN_FILE="${SECURITY_DIR}/run.sh"
	OUTPUT_FILE="${SECURITY_DIR}/output.json"

	if [ "${JSON}" -eq 0 ]
	then
		docker run --rm --volume "${TRIVY_CACHE_DIR}":/root/.cache/ --volume "${SCRIPTPATH}":/src aquasec/trivy conf --quiet --skip-dirs="temp-*" --timeout 15m --format=json /src | jq '.Results[] | {Target:.Target, MisconfSummary:.MisconfSummary}'
	else
		docker run --tty --rm --volume "${TRIVY_CACHE_DIR}":/root/.cache/ --volume "${SCRIPTPATH}":/src aquasec/trivy conf --quiet --skip-dirs="temp-*" --timeout 15m /src | grep -E '(dockerfile)|Tests|Failures|Exceptions|UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL'
		
	fi
}

function print_dockerfile {
	JSON=$1
	DOCKERFILE="$2"
	
	SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"

	if [ "${JSON}" -eq 0 ]
	then
		docker run --rm --volume "${TRIVY_CACHE_DIR}":/root/.cache/ --volume "${SCRIPTPATH}":/src aquasec/trivy conf --quiet --timeout 15m --format=json "/src/$DOCKERFILE" | jq
	else	
		docker run --tty --rm --volume "${TRIVY_CACHE_DIR}":/root/.cache/ --volume "${SCRIPTPATH}":/src aquasec/trivy conf --quiet --skip-dirs="temp-*" --timeout 15m "/src/${DOCKERFILE}"
	fi
}

function test {
	RESULT=$(cat "$OUTPUT_FILE" | jq '.Results[] | select (.MisconfSummary.Failures > 0) | "\(.Target)\n\(.MisconfSummary|@text)\n"' -r)
	
	if [ "$RESULT" != "" ]
	then
		echo "Failures detected! Run with --help or "
		echo ""
		echo "$RESULT"
		exit 1
	fi
}

main $*
