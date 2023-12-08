FROM --platform=${TARGETPLATFORM} registry.access.redhat.com/ubi8/ubi AS ubi8

COPY resources/etc/created-date /etc/created-date

RUN yum update -y && \
	yum upgrade -y && \
	yum install -y --disableplugin=subscription-manager \
		bash\
		ca-certificates\
		curl\
		jq\
		less\
		# not found: libnss3\
		# not found: telnet\
		# not found: tini\
		# not found: tree\
		unzip &&\
	yum clean all


RUN adduser --home-dir /home/liferay liferay --uid 1000

FROM ubi8

ARG LABEL_BUILD_DATE
ARG LABEL_NAME
ARG LABEL_VCS_REF
ARG LABEL_VCS_URL
ARG LABEL_VERSION
ARG TARGETPLATFORM

ENV LANG="C.UTF-8"

LABEL org.label-schema.build-date="${LABEL_BUILD_DATE}"
LABEL org.label-schema.name="${LABEL_NAME}"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.vcs-ref="${LABEL_VCS_REF}"
LABEL org.label-schema.vcs-url="${LABEL_VCS_URL}"
LABEL org.label-schema.vendor="Liferay, Inc."
LABEL org.label-schema.version="${LABEL_VERSION}"