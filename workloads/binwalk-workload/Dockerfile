FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binwalk \
        bzip2 \
        ca-certificates \
        cpio \
        file \
        gzip \
        tar \
        unzip \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /samples

CMD ["sleep", "infinity"]
