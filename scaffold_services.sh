#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scaffold_services.sh
#
# WHY this script exists (объяснение по-русски):
# Вручную создавать ~55 пар .hh/.cc с правильными #pragma once, инклюдами
# и наследованием — механическая работа, где легко опечататься один раз
# и потом полдня искать, почему конкретный модуль не собирается. Скрипт
# гарантирует, что КАЖДЫЙ файл создан по одному и тому же шаблону: та же
# структура, тот же родительский класс для своей категории, тот же TODO-
# чеклист. Дальше просто открываешь файл и заполняешь реализацию — форма
# уже готова и корректна.
#
# Run this from the repository root:
#   chmod +x scaffold_services.sh && ./scaffold_services.sh
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="zeus-services/lib"
mkdir -p "${ROOT}/proto" "${ROOT}/net" "${ROOT}/database" "zeus-services/tests"

# name:parent_namespace:parent_class
PROTO_MODULES=(
  "ssh" "sshkey" "telnet" "vnc" "rdp" "smb" "smb2" "cisco" "cisco_enable"
  "afp" "ncp" "pcanywhere" "radmin2" "rexec" "rlogin" "rsh"
)
NET_MODULES=(
  "adam6500" "asterisk" "cobaltstrike" "cvs" "ftp" "http" "http_form"
  "http_proxy" "http_proxy_urlenum" "icq" "imap" "irc" "ldap" "nntp"
  "pcnfs" "pop3" "rpcap" "rtsp" "s7_300" "sip" "smtp" "smtp_enum" "snmp"
  "socks5" "svn" "teamspeak" "vmauthd" "xmpp"
)
DATABASE_MODULES=(
  "firebird" "mongodb" "mssql" "mysql" "oracle" "oracle_listener"
  "oracle_sid" "postgres" "redis" "memcached" "sapr3"
)

# Converts "http_proxy_urlenum" -> "HttpProxyUrlenum" (for the C++ class name)
to_pascal_case() {
    echo "$1" | awk -F'_' '{for(i=1;i<=NF;i++) printf "%s", toupper(substr($i,1,1)) substr($i,2); print ""}'
}

# $1 = module short name, $2 = subdir (proto/net/database),
# $3 = C++ namespace to put the class in, $4 = parent header include,
# $5 = fully-qualified parent class name
generate_pair() {
    local name="$1" subdir="$2" ns="$3" parent_include="$4" parent_class="$5"
    local pascal
    pascal="$(to_pascal_case "$name")"
    local class_name="Zeus${pascal}Module"
    local hh="${ROOT}/${subdir}/zeus_${name}.hh"
    local cc="${ROOT}/${subdir}/zeus_${name}.cc"

    cat > "$hh" <<EOF
#pragma once

// Ported from THC-Hydra's hydra-${name}.c — original C source not reused,
// this is a from-scratch reimplementation against the protocol's public
// specification. See ${parent_include} for the shared connect/handshake/
// authenticate/classify lifecycle this module plugs into.
#include "${parent_include}"

namespace ${ns}
{
    // TODO(zeus): implement against the real protocol spec, then delete this
    // comment block. Minimum overrides usually needed:
    //   - name() / descriptor()            (identity — required by ZeusServices)
    //   - authenticate(...)                (the actual login exchange)
    //   - resolve_target() / default port  (if it isn't the protocol's IANA default)
    class ${class_name} final : public ${parent_class}
    {
        public:
            // TODO(zeus): forward whatever ${parent_class} constructor needs
            // (retry policy, rate limiter, dialect, ...).
    };
}
EOF

    cat > "$cc" <<EOF
#include "zeus_${name}.hh"

namespace ${ns}
{
    // TODO(zeus): implement ${class_name} here.
    // Write the test in zeus-services/tests/test_zeus_${name}.cc FIRST
    // (this project is TDD-first), then make it pass here.
}
EOF
}

for m in "${PROTO_MODULES[@]}"; do
    generate_pair "$m" "proto" "zeus::proto" "../../../zeus-engine/lib/zeus_proto.hh" "zeus::proto::ZeusProtocolService"
done

for m in "${NET_MODULES[@]}"; do
    generate_pair "$m" "net" "zeus::net" "../../../zeus-engine/lib/zeus_proto.hh" "zeus::proto::ZeusProtocolService"
done

for m in "${DATABASE_MODULES[@]}"; do
    generate_pair "$m" "database" "zeus::database" "../../../zeus-engine/lib/zeus_database.hh" "zeus::database::ZeusDatabaseService"
done

total=$(( ${#PROTO_MODULES[@]} + ${#NET_MODULES[@]} + ${#DATABASE_MODULES[@]} ))
echo "Generated ${total} module skeletons ($(( total * 2 )) files) under ${ROOT}/{proto,net,database}/"