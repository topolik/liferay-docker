IMAGE="alpine:3.18"
Clean

IMAGE="ubuntu:22.04"
14 unfixed

IMAGE="ubuntu:23.04"
11 unfixed

IMAGE="busybox:1.36-glibc"
0 unfixed


mkdir -p /tmp/trivy-cache
mkdir -p /tmp/grype-cache



docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /opt/liferay.git/liferay-docker.git:/src aquasec/trivy conf --quiet --skip-dirs="temp-*" --timeout 15m /src



# !!!!!!!!!!!!!!! GRYPE cannot correctly parse image dependencies when packages are uninstalled!!!!

##########################
# UBUNTU
##########################
# liferay/portal:7.4.3.103-ga103-d5.0.54-20231117111559
#

IMAGE="liferay/portal:7.4.3.103-ga103-d5.0.54-20231117111559"
docker pull "$IMAGE"

docker build --tag "$IMAGE-fixed" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)


docker build --tag "$IMAGE-esm" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN apt update && apt install ubuntu-advantage-tools -y && pro attach ..token...

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE" --format json > /tmp/trivy-ubuntu.json
docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE" -o json > /tmp/grype-ubuntu.json

cat /tmp/trivy-ubuntu.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | select(.Status=="affected")' | jq -c '[.PkgName, .VulnerabilityID, .Severity, .CVSS.nvd.V3Score, .InstalledVersion]' 
cat /tmp/grype-ubuntu.json | jq '.matches[] | select(.artifact.type != "java-archive")' -c |  jq '[ .artifact.name, .vulnerability.id, .vulnerability.severity, .artifact.version, .vulnerability.fix.version, .vulnerability.fix.state, .vulnerability.dataSource]'  -c


cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive")' -c |  jq '[ .artifact.name, .vulnerability.id, .vulnerability.severity, .relatedVulnerabilities[].cvss[].metrics.baseScore, .artifact.version, .vulnerability.dataSource]'  -c



echo "ORIGINAL:"
echo -n "CVES: "
(
cat /tmp/trivy-ubuntu.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f1 | sort -u | wc -l

echo -n "Packages: "
(
cat /tmp/trivy-ubuntu.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f2 | sort -u | wc -l

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-fixed" -o json > /tmp/grype-ubuntu-fixed.json

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-fixed" --format json > /tmp/trivy-ubuntu-fixed.json

echo "FIXED"
echo -n "CVES: "
(
cat /tmp/trivy-ubuntu-fixed.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-fixed.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f1 | sort -u | wc -l

echo -n "Packages: "
(
cat /tmp/trivy-ubuntu-fixed.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-fixed.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f2 | sort -u | wc -l



docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-esm" -o json > /tmp/grype-ubuntu-esm.json

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-esm" --format json > /tmp/trivy-ubuntu-esm.json

echo "Ubuntu PRO:"
echo -n "CVES: "
(
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f1 | sort -u | wc -l

echo -n "Packages: "
(
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f2 | sort -u | wc -l



#### Double check with Ubuntu Pro's `pro fix CVE` command
(
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f1 | sort -u > /tmp/trivy-ubuntu-esm-cves.txt

cat <<"EOF" >/tmp/trivy-ubuntu-esm-cves.sh
#!/bin/bash
cat /tmp/trivy-ubuntu-esm-cves.txt | while read CVE; do pro fix "$CVE" | grep "$CVE is"; done > /tmp/trivy-ubuntu-esm-cves-result.txt
cp /tmp/trivy-ubuntu-esm-cves-result.txt /tmp/trivy-ubuntu-esm-cves.txt
EOF

chmod a+x /tmp/trivy-ubuntu-esm-cves.sh
docker run --rm \
    --entrypoint=/tmp/trivy-ubuntu-esm-cves.sh \
    -v /tmp/trivy-ubuntu-esm-cves.sh:/tmp/trivy-ubuntu-esm-cves.sh \
    -v /tmp/trivy-ubuntu-esm-cves.txt:/tmp/trivy-ubuntu-esm-cves.txt \
    "$IMAGE-esm"
    
echo "Ubuntu PRO - double checked:"
echo -n "CVES: "
(
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep -i "$cve is resolved" /tmp/trivy-ubuntu-esm-cves.txt > /dev/null; then
        continue;
    fi
    echo "$line"
done | cut -d' ' -f1 | sort -u | wc -l
echo -n "Packages: "
(
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep -i "$cve is resolved" /tmp/trivy-ubuntu-esm-cves.txt > /dev/null; then
        continue;
    fi
    echo "$line"
done | cut -d' ' -f2 | sort -u | wc -l








rm -rf /tmp/cve
mkdir /tmp/cve/

(
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " +  .Severity + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .vulnerability.severity + " " + .artifact.name + " " + .artifact.version' -r
) | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep "$cve is resolved" /tmp/trivy-ubuntu-esm-cves.txt > /dev/null; then
        continue;
    fi
    echo "$line"
done | grep -i -v 'low\|negligible' | cut -d ' ' -f1 | sort -u > /tmp/cve/ubuntu-esm-important-cves.txt


cat <<"EOF" >/tmp/cve/check.sh
#!/bin/bash
cat /tmp/cve/ubuntu-esm-important-cves.txt | while read CVE; do test -f "/tmp/cve/$CVE.txt" || pro fix "$CVE" > "/tmp/cve/$CVE.txt"; done
EOF

chmod a+x /tmp/cve/check.sh
docker run --rm \
    --entrypoint=/tmp/cve/check.sh \
    -v /tmp/cve:/tmp/cve \
    "$IMAGE-esm"

cat /tmp/cve/cve-* | grep 'affected\|not resolved' | grep -v source | sed 's/resolved./resolved.#/' | tr '\n' ' ' | tr '#' '\n'

UNRESOLVED_CVES=$(cat /tmp/cve/cve-* | grep 'not resolved' | sed 's/.*\(CVE-[0-9]\+-[0-9]\+\).*/\1/' | tr '\n' '|' | sed 's/|$//')
PACKAGES_TO_REMOVE=$( (
cat /tmp/trivy-ubuntu-esm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " +  .Severity + " " + .PkgName + " " + .InstalledVersion' -r | tr '[:upper:]' '[:lower:]';
cat /tmp/grype-ubuntu-esm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .vulnerability.severity + " " + .artifact.name + " " + .artifact.version' -r | tr '[:upper:]' '[:lower:]'
) | grep -i -E "$UNRESOLVED_CVES" | cut -d ' ' -f 3 | sort -u | tr '\n' ' ')

PACKAGES_TO_REMOVE="imagemagick imagemagick-6-common imagemagick-6.q16 libapparmor1 libc6 libc-bin libheif1 libjbig2dec0 liblzma5 libmagickcore-6.q16-6 libmagickwand-6.q16-6 libnss3 libpixman-1-0 libpython3.10-minimal libpython3.10-stdlib libsndfile1 python3.10 python3.10-minimal"

UNABLE_TO_REMOVE="libc6 libc-bin liblzma5 libpython3.10-minimal libpython3.10-stdlib python3.10 python3.10-minimal"
PACKAGES_TO_REMOVE="imagemagick imagemagick-6-common imagemagick-6.q16 libapparmor1 libheif1 libjbig2dec0 libmagickcore-6.q16-6 libmagickwand-6.q16-6 libnss3 libpixman-1-0  libsndfile1"

PACKAGES_TO_REMOVE="bc ffmpeg file fonts-dejavu fonts-droid-fallback ghostscript google-perftools imagemagick gifsicle libtcnative-1"

docker build --tag "$IMAGE-esm-manual-remove" - < <(cat <<EOF
FROM $IMAGE-esm

USER root

RUN apt remove --yes $PACKAGES_TO_REMOVE

#RUN apt update && apt install graphicsmagick -y

RUN apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y

EOF
)
docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-esm-manual-remove" -o json > /tmp/grype-ubuntu-esm-manual-remove.json

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-esm-manual-remove" --format json > /tmp/trivy-ubuntu-esm-manual-remove.json


#### Double check with Ubuntu Pro's `pro fix CVE` command
(
cat /tmp/trivy-ubuntu-esm-manual-remove.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-ubuntu-esm-manual-remove.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | cut -d' ' -f1 | sort -u > /tmp/cve/reported-cves.txt

cat <<"EOF" >/tmp/cve/check-reported.sh
#!/bin/bash
cat /tmp/cve/reported-cves.txt | while read CVE; do test -f "/tmp/cve/$CVE.txt" || pro fix "$CVE" > "/tmp/cve/$CVE.txt"; done
EOF

chmod a+x /tmp/cve/check-reported.sh
docker run --rm \
    --entrypoint=/tmp/cve/check-reported.sh \
    -v /tmp/cve:/tmp/cve \
    "$IMAGE-esm-manual-remove"

cat /tmp/cve/CVE-* | grep "CVE-.* is" > /tmp/cve/reported-cves-checked.txt


(
cat /tmp/trivy-ubuntu-esm-manual-remove.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " +  .Severity + " " + .PkgName + " " + .InstalledVersion' -r;
) | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep "$cve is resolved" /tmp/cve/reported-cves-checked.txt > /dev/null; then
        continue;
    fi
    echo "$line"
done | grep -v -i 'low\|negligible' | cut -d ' ' -f1 | sort -u | while read CVE; do
    cat /tmp/cve/"$CVE".txt | grep 'affected\|not resolved' | grep -v source | sed 's/resolved./resolved.#/' | tr '\n' ' ' | tr '#' '\n'
done



cat /tmp/trivy-ubuntu-esm-manual-remove.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | "\(.VulnerabilityID) \(.Severity) \(.PkgName) \(.CVSS.nvd.V3Score)"' -r | sort -u | while read line; do
    cve=$(echo "$line" | cut -d ' ' -f 1)
    if grep "$cve is resolved" /tmp/cve/reported-cves-checked.txt > /dev/null; then
        continue;
    fi
    echo "$line"
done | grep -v -E '[0123456]\.[0-9]$'| grep -v -i LOW|  cut -d ' ' -f1 | sort -u | while read CVE; do
    cat /tmp/cve/"$CVE".txt | grep 'affected\|not resolved' | grep -v source | sed 's/resolved./resolved.#/' | tr '\n' ' ' | tr '#' '\n'
done





######
###### LOCAL Debian bookworm 7.4.3.103-ga103-d5.0.54-20231122040755
######
IMAGE="liferay/portal:7.4.3.103-ga103-d5.0.54-20231122040755"

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE" -o json > /tmp/grype-bookworm.json

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE" --format json > /tmp/trivy-bookworm.json


cat /tmp/trivy-bookworm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | select(.Status=="affected")' | jq -c '[.PkgName, .VulnerabilityID, .Severity, .CVSS.nvd.V3Score, .InstalledVersion]' 


cat /tmp/grype-bookworm.json | jq '.matches[] | select(.artifact.type != "java-archive")' -c |  jq '[ .artifact.name, .vulnerability.id, .vulnerability.severity, .artifact.version, .vulnerability.fix.version, .vulnerability.fix.state, .vulnerability.dataSource]'  -c

(
cat /tmp/trivy-bookworm.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-bookworm.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | sort -u | while read cve_ver; do
    cve=$(echo $cve_ver | cut -d' ' -f1);
    name=$(echo $cve_ver | cut -d' ' -f2);
    ver=$(echo $cve_ver | cut -d' ' -f3);
    test -f "$cve.html" || curl -s "https://security-tracker.debian.org/tracker/$cve" > "$cve.html";    
    
    echo -n "$cve $name: ";  
    # vulnerable?
    cat "$cve.html" | grep -oP ">$(echo $ver | sed 's/[][\.|$(){}?+*^]/\\&/g')(</span>)?</td><td>(<span class=\"red\">)?\K[^<]*" | tr -d '\n'
    # fixed?
    echo -n " fixed in sid: "
    fixed_ver=$(cat "$cve.html" | grep -oP "sid.*<td>\K[^>]+(?=</td><td>fixed)")
    if [ "$fixed_ver" != "" ]; then
        echo "$name:$fixed_ver";
    else
        echo "no"
    fi
done > reality-check.txt

packages_to_upgrade=$(cat reality-check.txt | grep -v 'fixed in sid: no' | sed 's/.*fixed in sid: //' | cut -d: -f1 | sort -u | tr '\n' ' ')

docker build --tag "$IMAGE-fixed" - < <(cat <<EOF
FROM $IMAGE

USER root

RUN cat <<debian-sid.sources >/etc/apt/sources.list.d/debian-sid.sources
Types: deb
URIs: http://deb.debian.org/debian
Suites: sid
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
debian-sid.sources

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install --only-upgrade $packages_to_upgrade -y

RUN rm /etc/apt/sources.list.d/debian-sid.sources
RUN apt update && apt autoremove -y && apt autoclean -y

EOF
)

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-fixed" -o json > /tmp/grype-bookworm-fixed.json

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-fixed" --format json > /tmp/trivy-bookworm-fixed.json


cat /tmp/trivy-bookworm-fixed.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | select(.Status=="affected")' | jq -c '[.PkgName, .VulnerabilityID, .Severity, .CVSS.nvd.V3Score, .InstalledVersion]' 


cat /tmp/grype-bookworm-fixed.json | jq '.matches[] | select(.artifact.type != "java-archive") | select (.vulnerability.severity != "Negligible")' -c |  jq '[ .artifact.name, .vulnerability.id, .vulnerability.severity, .artifact.version, .vulnerability.fix.version, .vulnerability.fix.state, .vulnerability.dataSource]'  -c


(
cat /tmp/trivy-bookworm-fixed.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | .VulnerabilityID + " " + .PkgName + " " + .InstalledVersion' -r;
cat /tmp/grype-bookworm-fixed.json | jq '.matches[] | select(.artifact.type != "java-archive") | .vulnerability.id + " " + .artifact.name + " " + .artifact.version' -r
) | sort -u | while read cve_ver; do
    cve=$(echo $cve_ver | cut -d' ' -f1);
    name=$(echo $cve_ver | cut -d' ' -f2);
    ver=$(echo $cve_ver | cut -d' ' -f3);
    test -f "$cve.html" || curl -s "https://security-tracker.debian.org/tracker/$cve" > "$cve.html";    
    
    echo -n "$cve $name: ";  
    # vulnerable?
    cat "$cve.html" | grep -oP ">$(echo $ver | sed 's/[][\.|$(){}?+*^]/\\&/g')(</span>)?</td><td>(<span class=\"red\">)?\K[^<]*" | tr -d '\n'
    # fixed?
    echo -n " fixed in sid: "
    fixed_ver=$(cat "$cve.html" | grep -oP "sid.*<td>\K[^>]+(?=</td><td>fixed)")
    if [ "$fixed_ver" != "" ]; then
        echo "$name:$fixed_ver";
    else
        echo "no"
    fi
done > reality-check-fixed.txt

diff reality-check.txt reality-check-fixed.txt

######
###### LOCAL Debian buster 7.4.3.103-ga103-d5.0.54-20231122081223
######

IMAGE="liferay/portal:7.4.3.103-ga103-d5.0.54-20231122081223"


docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE" -o json > /tmp/grype-buster.json

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE" --format json > /tmp/trivy-buster.json


cat /tmp/trivy-buster.json | jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[] | select(.Status=="affected")' | jq -c '[.PkgName, .VulnerabilityID, .Severity, .CVSS.nvd.V3Score, .InstalledVersion]' 


cat /tmp/grype-buster.json | jq '.matches[] | select(.artifact.type != "java-archive") | select (.vulnerability.severity != "Negligible")' -c |  jq '[ .artifact.name, .vulnerability.id, .vulnerability.severity, .artifact.version, .vulnerability.fix.version, .vulnerability.fix.state, .vulnerability.dataSource]'  -c











##########################
# liferay/dxp:7.3.10-u30-d5.0.47-20231012133816
#

IMAGE="liferay/dxp:7.3.10-u30-d5.0.47-20231012133816"
docker pull "$IMAGE"

docker build --tag "$IMAGE-fixed" - < <(cat <<EOF
FROM $IMAGE

USER root
RUN apt update && apt upgrade -y && apt autoremove -y
USER liferay
EOF
)

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-fixed" --scope all-layers |\
    grep -v -E "won't fix|Negligible" | grep -v 'java-archive' > /tmp/res-1



##########################
# ALPINE
#

IMAGE="alpine:3.18"
docker pull "$IMAGE"

docker build --tag "$IMAGE-fixed" - < <(cat <<EOF
FROM $IMAGE

RUN apk update && apk upgrade

EOF
)


docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-fixed" 

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-fixed"


# ALL all fixable

####
# Ubuntu
#

IMAGE="ubuntu:22.04"
docker pull "$IMAGE"

#docker buildx build --tag "$IMAGE-fixed" --sbom=true --output type=local,dest=out - < <(cat <<EOF
docker build --tag "$IMAGE-fixed" - < <(cat <<EOF
FROM $IMAGE

RUN apt update && apt upgrade -y && apt autoremove -y

EOF
)

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-fixed" 

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-fixed"


###########
# Busybox


IMAGE="busybox:1.36-glibc"

docker pull "$IMAGE"

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE" 

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE"


###########
# Debian

IMAGE="debian:bookworm-slim"

docker pull "$IMAGE"

docker run --rm -it $IMAGE

docker build --tag "$IMAGE-fixed" - < <(cat <<EOF
FROM $IMAGE

RUN apt update && apt upgrade -y && apt autoremove -y

EOF
)

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE" 

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE"


###########
# RHEL

IMAGE="registry.access.redhat.com/ubi8/ubi-minimal"
IMAGE="registry.access.redhat.com/ubi8/ubi"
docker pull "$IMAGE"

docker run --rm -it $IMAGE

docker run --rm -it "registry.access.redhat.com/ubi8/ubi" 
yum update -y --disableplugin=subscription-manager 


docker build --tag "test" - < <(cat <<EOF
FROM registry.access.redhat.com/ubi8/ubi-minimal
#RUN yum update -y --disableplugin=subscription-manager 
#RUN yum install -y --disableplugin=subscription-manager  curl jq less iputils tini tree unzip	
#not foundL: libnss3 telnet
RUN microdnf update && microdnf -y install --nodocs \
  curl jq less iputils tini tree unzip \
  && microdnf clean all


RUN adduser --disabled-password --home /home/liferay liferay --uid 1000 && \
	addgroup liferay liferay && \
	usermod -g 1000 liferay

RUN microdnf -y install --nodocs \
  curl jq less libnss3 telnet tini tree unzip \
  && microdnf clean all
  
EOF
)

docker run --rm --volume /tmp/trivy-cache:/root/.cache/ --volume /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --timeout 15m "$IMAGE-fixed"

docker run --rm -v /tmp/grype-cache:/.cache/ -e GRYPE_DB_CACHE_DIR="/.cache" --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$IMAGE-fixed"



