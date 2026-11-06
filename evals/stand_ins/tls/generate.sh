#!/usr/bin/env bash
# Makes the fixture authority and one leaf per HTTPS stand-in host:
#   evals/stand_ins/tls/generate.sh [--out DIR] HOST...
# DIR defaults to this script's directory. The authority's critical name constraints permit each
# host given and exclude its subdomains (an IPv4-literal host: that one address), so it signs for
# nothing else: give every HTTPS stand-in host at once. Each run makes a new authority and every
# leaf from it, and removes the TLS files of a host it was not given. The keys are fixture
# material, trusted only by fixture containers told to trust this authority.
set -euo pipefail

out="$(cd "$(dirname "$0")" && pwd)"
if [ "${1:-}" = "--out" ]; then
  out="$2"
  shift 2
fi
if [ "$#" -eq 0 ]; then
  echo "usage: generate.sh [--out DIR] HOST..." >&2
  exit 2
fi

is_ipv4() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]
}

validity_days=36500
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

{
  printf '[req]\ndistinguished_name = subject\nprompt = no\n'
  printf '[subject]\nCN = mcp-auditor fixture authority\n'
  printf '[authority]\n'
  printf 'basicConstraints = critical,CA:TRUE\n'
  printf 'keyUsage = critical,keyCertSign,cRLSign\n'
  printf 'subjectKeyIdentifier = hash\n'
  printf 'nameConstraints = critical,@constraints\n'
  printf '[constraints]\n'
  index=0
  for host in "$@"; do
    if is_ipv4 "$host"; then
      printf 'permitted;IP.%d = %s/255.255.255.255\n' "$index" "$host"
    else
      printf 'permitted;DNS.%d = %s\nexcluded;DNS.%d = .%s\n' "$index" "$host" "$index" "$host"
    fi
    index=$((index + 1))
  done
} > "$work/authority.cnf"

openssl req -x509 -config "$work/authority.cnf" -extensions authority \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days "$validity_days" \
  -keyout "$work/fixture-authority-key.pem" -out "$work/fixture-authority.pem"

for host in "$@"; do
  # OpenSSL checks the common name of a leaf with no DNS name against the DNS subtrees, so an
  # IP-literal leaf carries no common name, or it fails the authority's constraints.
  if is_ipv4 "$host"; then
    name="IP:$host"
    subject="/O=mcp-auditor fixture stand-in"
  else
    name="DNS:$host"
    subject="/CN=$host"
  fi
  printf '[leaf]\nbasicConstraints = critical,CA:FALSE\nsubjectAltName = %s\n' "$name" \
    > "$work/leaf.cnf"
  printf 'extendedKeyUsage = serverAuth\nauthorityKeyIdentifier = keyid\n' >> "$work/leaf.cnf"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "$subject" \
    -keyout "$work/$host-key.pem" -out "$work/$host.csr"
  openssl x509 -req -in "$work/$host.csr" -CA "$work/fixture-authority.pem" \
    -CAkey "$work/fixture-authority-key.pem" -set_serial "0x$(openssl rand -hex 16)" \
    -days "$validity_days" -extfile "$work/leaf.cnf" -extensions leaf \
    -out "$work/$host.pem"
done

# openssl writes keys 0600, which a container running with no capabilities cannot read from a
# bind mount owned by another uid.
chmod 644 "$work"/*.pem
mkdir -p "$out"
rm -f "$out"/*.pem
mv "$work"/*.pem "$out"/
echo "authority and $# leaves written to $out, valid $validity_days days"
