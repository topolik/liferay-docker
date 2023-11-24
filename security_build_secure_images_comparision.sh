#!/bin/bash
UBUNTU_PRO_TOKEN=$(op item get "Ubuntu Pro Token" --fields=password)
IMAGE="liferay/portal:7.4.3.103-ga103-d5.0.54-20231117111559"

SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"
CVE_DIR=temp-cve-$(date +\%Y-\%m-\%d)

mkdir -p /tmp/trivy-cache "$CVE_DIR"

echo "♾"
echo "♾ Pulling $IMAGE ..."
echo "♾"
docker pull "$IMAGE"


####
#### Default image with updated dependencies
####

echo "♾"
echo "♾ Building $IMAGE-updated with updated dependencies..."
echo "♾"

docker build --tag "$IMAGE-updated" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)

echo "♾"
echo "♾ Computing vulnerabilities of $IMAGE-updated"
echo "♾"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --scanners vuln --timeout 15m "$IMAGE-updated" --format json > /tmp/trivy-ubuntu-updated.json


####
#### Ubuntu PRO image with updated dependencies
####
echo "♾"
echo "♾ Building Ubuntu PRO $IMAGE-esm with updated dependencies..."
echo "♾"

docker build --tag "$IMAGE-esm" - < <(cat <<EOF
FROM $IMAGE

USER root

# Insecure, but for simplicity sake, use only for local images!
RUN apt update && apt install ubuntu-advantage-tools -y && pro attach $UBUNTU_PRO_TOKEN

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)

echo "♾"
echo "♾ Computing vulnerabilities of $IMAGE-esm"
echo "♾"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --scanners vuln --timeout 15m "$IMAGE-esm" --format json > /tmp/trivy-ubuntu-esm.json



#
# Remove false positives with Ubuntu Pro's `pro fix CVE` command
#
# That means, fetch each reported CVE and update the state into $CVE_DIR/$CVE.txt

echo "♾"
echo "♾ Downloading vulnerabilities descriptions ..."
echo "♾"


cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID' -r  | sort -u > $CVE_DIR/reported-cves.txt

cat <<"EOF" >"$CVE_DIR/check-reported.sh"
#!/bin/bash
cat "/tmp/cve/reported-cves.txt" | while read CVE; do test -f "/tmp/cve/$CVE.txt" || pro fix "$CVE" > "/tmp/cve/$CVE.txt"; done
EOF

chmod a+x "$CVE_DIR/check-reported.sh"
docker run --rm \
    --entrypoint="/tmp/cve/check-reported.sh" \
    -v "${SCRIPTPATH}/${CVE_DIR}":/tmp/cve \
    "$IMAGE-esm"

####
#### Default image with removed dependencies
####

echo "♾"
echo "♾ Building $IMAGE-manual-remove with removed dependencies..."
echo "♾"

docker build --tag "$IMAGE-manual-remove" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN apt remove --yes bc ffmpeg file fonts-dejavu fonts-droid-fallback ghostscript google-perftools imagemagick gifsicle libtcnative-1

# A good replacement?
# RUN apt update && apt install graphicsmagick -y

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)


echo "♾"
echo "♾ Computing vulnerabilities of $IMAGE-manual-remove"
echo "♾"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --scanners vuln --timeout 15m "$IMAGE-manual-remove" --format json > /tmp/trivy-ubuntu-manual-remove.json


####
#### Ubuntu PRO with removed dependencies
####

echo "♾"
echo "♾ Building Ubuntu PRO $IMAGE-esm-manual-remove with removed dependencies..."
echo "♾"

docker build --tag "$IMAGE-esm-manual-remove" - < <(cat <<EOF
FROM $IMAGE

USER root

# Insecure, but for simplicity sake, use only for local images!
RUN apt update && apt install ubuntu-advantage-tools -y && pro attach $UBUNTU_PRO_TOKEN

RUN apt remove --yes bc ffmpeg file fonts-dejavu fonts-droid-fallback ghostscript google-perftools imagemagick gifsicle libtcnative-1

# A good replacement?
# RUN apt update && apt install graphicsmagick -y

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)

echo "♾"
echo "♾ Computing vulnerabilities of $IMAGE-esm-manual-remove"
echo "♾"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --scanners vuln --timeout 15m "$IMAGE-esm-manual-remove" --format json > /tmp/trivy-ubuntu-esm-manual-remove.json


#
# Remove false positives with Ubuntu Pro's `pro fix CVE` command
#
# That means, fetch each reported CVE and update the state into $CVE_DIR/$CVE.txt

echo "♾"
echo "♾ Downloading vulnerabilities descriptions ..."
echo "♾"

cat /tmp/trivy-ubuntu-esm-manual-remove.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID' -r  | sort -u > "$CVE_DIR/reported-cves.txt"

cat <<"EOF" >"$CVE_DIR/check-reported.sh"
#!/bin/bash
cat /tmp/cve/reported-cves.txt | while read CVE; do test -f "/tmp/cve/$CVE.txt" || pro fix "$CVE" > "/tmp/cve/$CVE.txt"; done
EOF

chmod a+x "$CVE_DIR/check-reported.sh"
docker run --rm \
    --entrypoint="/tmp/cve/check-reported.sh" \
    -v "${SCRIPTPATH}/${CVE_DIR}":/tmp/cve \
    "$IMAGE-esm"


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


echo "Ubuntu PRO with updated dependencies"
echo "========================================"

cat "$CVE_DIR"/CVE-* | grep "CVE-.* is" > "$CVE_DIR/reported-cves-checked.txt"

cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | "\(.VulnerabilityID) \(.Severity) \(.PkgName) \(.CVSS.nvd.V3Score)"' -r | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep "$cve is resolved" "$CVE_DIR/reported-cves-checked.txt" > /dev/null; then
        continue;
    fi
    echo "$line"
done | grep -v -E '[0123456]\.[0-9]$'| grep -v -E -i 'low|negligible' | tee /tmp/trivy-temp.txt | cut -d ' ' -f1 | sort -u | while read CVE; do
    cat "$CVE_DIR/$CVE.txt" | grep 'affected\|not resolved' | grep -v source | sed 's/resolved./resolved.#/' | tr '\n' ' ' | tr '#' '\n' | sed -re 's/(^[[:space:]]+|[[:space:]]+$)//g' 
done

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


echo "Ubuntu PRO with removed dependencies"
echo "========================================"

cat "$CVE_DIR"/CVE-* | grep "CVE-.* is" > "$CVE_DIR/reported-cves-checked.txt"

cat /tmp/trivy-ubuntu-esm-manual-remove.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | "\(.VulnerabilityID) \(.Severity) \(.PkgName) \(.CVSS.nvd.V3Score)"' -r | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep "$cve is resolved" "$CVE_DIR/reported-cves-checked.txt" > /dev/null; then
        continue;
    fi
    echo "$line"
done | grep -v -E '[0123456]\.[0-9]$'| grep -v -E -i 'low|negligible' | tee /tmp/trivy-temp.txt | cut -d ' ' -f1 | sort -u | while read CVE; do
    cat "$CVE_DIR/$CVE.txt" | grep 'affected\|not resolved' | grep -v source | sed 's/resolved./resolved.#/' | tr '\n' ' ' | tr '#' '\n' | sed -re 's/(^[[:space:]]+|[[:space:]]+$)//g' 
done


cat /tmp/trivy-temp.txt | sed -re 's/(^[[:space:]]+|[[:space:]]+$)//g' 
echo ""
echo "TOTAL: $(cat /tmp/trivy-temp.txt | wc -l)" && rm /tmp/trivy-temp.txt
echo "---------------------------------------"
echo ""

