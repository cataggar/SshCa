#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 1 ]]; then
    mode="local"
    material_command="$1"
elif [[ $# -eq 2 && "$1" == "--azure" ]]; then
    mode="azure"
    material_command="$2"
else
    echo "usage: sshd-login.sh <material-generator>" >&2
    echo "       sshd-login.sh --azure <sshca-cli>" >&2
    exit 2
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
image_id=""
image_tag="sshca-sshd-integration:run-$$-${RANDOM}"
container_id=""

cleanup() {
    local status=$?
    if [[ -n "$container_id" ]]; then
        if [[ $status -ne 0 ]]; then
            docker logs "$container_id" >&2 || true
        fi
        docker rm --force "$container_id" >/dev/null 2>&1 || true
    fi
    if [[ -n "$image_id" ]]; then
        docker image rm "$image_tag" >/dev/null 2>&1 || true
    fi
    rm -rf "$work_dir"
    return "$status"
}
trap cleanup EXIT

ssh-keygen -q -t rsa -b 3072 -N "" -f "$work_dir/rsa"
ssh-keygen -q -t ed25519 -N "" -f "$work_dir/ed25519"

image_id="$(
    docker build \
    --quiet \
    --file "$script_dir/sshd.Dockerfile" \
    --tag "$image_tag" \
    "$script_dir"
)"
container_now="$(docker run --rm --entrypoint /bin/date "$image_id" +%s)"
if [[ "$mode" == "local" ]]; then
    "$material_command" \
        "$work_dir" \
        "$work_dir/rsa.pub" \
        "$work_dir/ed25519.pub" \
        "$container_now"
else
    : "${SSHCA_TEST_VAULT_URL:?SSHCA_TEST_VAULT_URL is required}"
    : "${SSHCA_TEST_KEY_NAME:?SSHCA_TEST_KEY_NAME is required}"
    : "${SSHCA_TEST_KEY_VERSION:?SSHCA_TEST_KEY_VERSION is required}"
    cloud="${SSHCA_TEST_CLOUD:-public}"
    host_now="$(date +%s)"
    clock_drift=$((container_now - host_now))
    if ((clock_drift < 0)); then
        clock_drift=$((-clock_drift))
    fi
    if ((clock_drift > 30)); then
        echo "host and Docker clocks differ by ${clock_drift}s" >&2
        exit 1
    fi

    "$material_command" ca public-key \
        --vault-url "$SSHCA_TEST_VAULT_URL" \
        --name "$SSHCA_TEST_KEY_NAME" \
        --cloud "$cloud" \
        --version "$SSHCA_TEST_KEY_VERSION" \
        > "$work_dir/trusted-user-ca-keys"
    "$material_command" sign \
        --vault-url "$SSHCA_TEST_VAULT_URL" \
        --name "$SSHCA_TEST_KEY_NAME" \
        --cloud "$cloud" \
        --version "$SSHCA_TEST_KEY_VERSION" \
        --subject-key "$work_dir/rsa.pub" \
        --key-id "live-azure-rsa" \
        --principal "sshca-test" \
        --ttl 3600 \
        --output "$work_dir/rsa-valid-cert.pub" \
        --profile none
    "$material_command" sign \
        --vault-url "$SSHCA_TEST_VAULT_URL" \
        --name "$SSHCA_TEST_KEY_NAME" \
        --cloud "$cloud" \
        --version "$SSHCA_TEST_KEY_VERSION" \
        --subject-key "$work_dir/ed25519.pub" \
        --key-id "live-azure-ed25519" \
        --principal "sshca-test" \
        --ttl 3600 \
        --output "$work_dir/ed25519-valid-cert.pub" \
        --profile none
fi

container_id="$(docker create --publish 127.0.0.1::22 "$image_id")"
docker cp \
    "$work_dir/trusted-user-ca-keys" \
    "$container_id:/etc/ssh/trusted-user-ca-keys"
docker start "$container_id" >/dev/null

port=""
for _ in $(seq 1 30); do
    port="$(docker port "$container_id" 22/tcp 2>/dev/null | sed -n 's/.*://p' | head -n 1)"
    if [[ -n "$port" ]] && ssh-keyscan -T 1 -p "$port" 127.0.0.1 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if [[ -z "$port" ]]; then
    echo "sshd did not expose a port" >&2
    exit 1
fi

ssh_options=(
    -p "$port"
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -o PreferredAuthentications=publickey
    -o PasswordAuthentication=no
    -o LogLevel=ERROR
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
)

run_success() {
    local identity="$1"
    local certificate="$2"
    local expected="$3"
    local output
    output="$(
        ssh "${ssh_options[@]}" \
            -i "$identity" \
            -o "CertificateFile=$certificate" \
            sshca-test@127.0.0.1 \
            "printf '$expected'"
    )"
    [[ "$output" == "$expected" ]]
}

run_failure() {
    local identity="$1"
    local certificate="$2"
    local expected_log="$3"
    ssh-keygen -L -f "$certificate" >/dev/null
    if ssh "${ssh_options[@]}" \
        -i "$identity" \
        -o "CertificateFile=$certificate" \
        sshca-test@127.0.0.1 \
        true >/dev/null 2>&1
    then
        echo "unexpected certificate authentication success: $certificate" >&2
        exit 1
    fi
    local server_logs
    server_logs="$(docker logs "$container_id" 2>&1)"
    if [[ "$server_logs" != *"$expected_log"* ]]; then
        echo "sshd did not report the expected rejection: $expected_log" >&2
        exit 1
    fi
}

run_success "$work_dir/rsa" "$work_dir/rsa-valid-cert.pub" "rsa-certificate-ok"
run_success "$work_dir/ed25519" "$work_dir/ed25519-valid-cert.pub" "ed25519-certificate-ok"
if [[ "$mode" == "local" ]]; then
    run_failure \
        "$work_dir/ed25519" \
        "$work_dir/ed25519-wrong-principal-cert.pub" \
        "Certificate invalid: name is not a listed principal"
    run_success "$work_dir/ed25519" "$work_dir/ed25519-valid-cert.pub" "post-principal-check-ok"
    run_failure \
        "$work_dir/ed25519" \
        "$work_dir/ed25519-expired-cert.pub" \
        "Certificate invalid: expired"
    run_success "$work_dir/ed25519" "$work_dir/ed25519-valid-cert.pub" "post-expiry-check-ok"
fi

echo "RSA and Ed25519 certificate logins succeeded; principal and expiry failures were enforced."
