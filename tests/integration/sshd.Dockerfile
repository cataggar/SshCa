FROM debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef

ARG DEBIAN_SNAPSHOT=20250812T000000Z
ARG OPENSSH_VERSION=1:9.2p1-2+deb12u6

RUN rm -f /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --yes --no-install-recommends \
        "openssh-client=${OPENSSH_VERSION}" \
        "openssh-server=${OPENSSH_VERSION}" \
        "openssh-sftp-server=${OPENSSH_VERSION}" \
    && test "$(dpkg-query --show --showformat='${Version}' openssh-server)" = "$OPENSSH_VERSION" \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/sh sshca-test \
    && passwd --delete sshca-test \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd \
    && touch /etc/ssh/trusted-user-ca-keys \
    && chmod 0644 /etc/ssh/trusted-user-ca-keys

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config"]
