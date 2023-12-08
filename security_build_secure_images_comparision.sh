#!/bin/bash
IMAGE="liferay/portal:7.4.3.103-ga103"

SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"
CVE_DIR=temp-cve-$(date +\%Y-\%m-\%d)

mkdir -p /tmp/trivy-cache "$CVE_DIR"

echo "♾"
echo "♾ Building $IMAGE ..."
echo "♾"
LIFERAY_DOCKER_DEVELOPER_MODE=true ./build_base_image.sh 
LIFERAY_DOCKER_DEVELOPER_MODE=true ./build_jdk11_image.sh 
export LIFERAY_DOCKER_RELEASE_FILE_URL=http://releases-cdn.liferay.com/portal/7.4.3.103-ga103/liferay-ce-portal-tomcat-7.4.3.103-ga103-20231116132758925.7z
LIFERAY_DOCKER_DEVELOPER_MODE=true ./build_bundle_image.sh 


####
#### Default image with updated dependencies
####

echo "♾"
echo "♾ Building $IMAGE-updated with updated dependencies..."
echo "♾"

docker build --tag "$IMAGE-updated" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN yum update -y --disableplugin=subscription-manager && \
	yum upgrade -y --disableplugin=subscription-manager && \
	yum clean all
EOF
)

echo "♾"
echo "♾ Computing vulnerabilities of $IMAGE-updated"
echo "♾"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --scanners vuln --timeout 15m "$IMAGE-updated" --format json > /tmp/trivy-ubuntu-updated.json


####
#### Default image with removed dependencies
####

echo "♾"
echo "♾ Building $IMAGE-manual-remove with removed dependencies..."
echo "♾"

docker build --tag "$IMAGE-manual-remove" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN yum remove -y \
		# breaks yum: bash\
		ca-certificates\
		curl\
		jq\
		less\
		# not installed: not found: libnss3\
		# not installed: not found: telnet\
		# not installed: not found: tini\
		# not installed: not found: tree\
		unzip

RUN yum remove -y \
		bc \
		# not installed:  ffmpeg \
		file \
		# not installed: fonts-dejavu \
		# not installed:  fonts-droid-fallback \
		ghostscript \
		# not installed: google-perftools \
		# not installed: imagemagick \
		# not installed: gifsicle \
		# not installed: libtcnative-1 \

RUN yum update -y --disableplugin=subscription-manager && \
	yum upgrade -y --disableplugin=subscription-manager && \
	yum clean all

EOF
)


echo "♾"
echo "♾ Computing vulnerabilities of $IMAGE-manual-remove"
echo "♾"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --scanners vuln --timeout 15m "$IMAGE-manual-remove" --format json > /tmp/trivy-ubuntu-manual-remove.json



################
# PRINT RESULTS
#
echo ""
echo "Default image with updated dependencies"
echo "========================================"

cat /tmp/trivy-ubuntu-updated.json | \
	jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | "\(.VulnerabilityID) \(.Severity) \(.PkgName) \(.CVSS.nvd.V3Score)"' -r | \
	sort -u | \
	grep -v -E '[0123456]\.[0-9]$'| grep -v -i -E 'low|negligible' > /tmp/trivy-temp.txt

cat /tmp/trivy-temp.txt | sed -re 's/(^[[:space:]]+|[[:space:]]+$)//g' 
echo ""
echo "TOTAL: $(cat /tmp/trivy-temp.txt | wc -l)" && rm /tmp/trivy-temp.txt
echo "---------------------------------------"
echo ""

echo "Default image with removed dependencies"
echo "========================================"
cat /tmp/trivy-ubuntu-manual-remove.json | \
	jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | "\(.VulnerabilityID) \(.Severity) \(.PkgName) \(.CVSS.nvd.V3Score)"' -r | \
	sort -u | \
	grep -v -E '[0123456]\.[0-9]$'| grep -v -i -E 'low|negligible' > /tmp/trivy-temp.txt

cat /tmp/trivy-temp.txt | sed -re 's/(^[[:space:]]+|[[:space:]]+$)//g' 
echo ""
echo "TOTAL: $(cat /tmp/trivy-temp.txt | wc -l)" && rm /tmp/trivy-temp.txt
echo "---------------------------------------"
echo ""