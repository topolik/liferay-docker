FROM --platform=linux/arm64 liferay/base:latest as liferay-base-arm64

ARG LABEL_ZULU_11_AMD64_VERSION
ARG LABEL_ZULU_11_ARM64_VERSION
ARG LABEL_ZULU_11_VERSION=${LABEL_ZULU_11_ARM64_VERSION}

FROM --platform=linux/amd64 liferay/base:latest as liferay-base-amd64

ARG LABEL_ZULU_11_AMD64_VERSION
ARG LABEL_ZULU_11_ARM64_VERSION
ARG LABEL_ZULU_11_VERSION=${LABEL_ZULU_11_AMD64_VERSION}

FROM liferay-base-${TARGETARCH}

ARG LABEL_BUILD_DATE
ARG LABEL_NAME
ARG LABEL_VCS_REF
ARG LABEL_VCS_URL
ARG LABEL_VERSION
ARG TARGETARCH
ARG TARGETPLATFORM

COPY resources/etc/created-date /etc/created-date
COPY --chown=liferay:liferay resources/home/liferay/.bashrc /home/liferay/
COPY resources/usr/local/bin/* /usr/local/bin/

ENV JAVA_VERSION=zulu11

LABEL org.label-schema.build-date="${LABEL_BUILD_DATE}"
LABEL org.label-schema.name="${LABEL_NAME}"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.vcs-ref="${LABEL_VCS_REF}"
LABEL org.label-schema.vcs-url="${LABEL_VCS_URL}"
LABEL org.label-schema.vendor="Liferay, Inc."
LABEL org.label-schema.version="${LABEL_VERSION}"
LABEL org.label-schema.zulu11_version="${LABEL_ZULU_11_VERSION}"
LABEL org.label-schema.zulu11_arm64_version="${LABEL_ZULU_11_ARM64_VERSION}"
LABEL org.label-schema.zulu11_amd64_version="${LABEL_ZULU_11_AMD64_VERSION}"

# jattach not found in RHEL ubi images
RUN yum install -y https://cdn.azul.com/zulu/bin/zulu-repo-1.0.0-1.noarch.rpm && \
	yum install -y zulu11-jdk && \
	/usr/local/bin/set_java_version.sh