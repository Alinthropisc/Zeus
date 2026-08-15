#pragma once

// Ported from THC-Hydra's hydra-asterisk.c — original C source not reused,
// this is a from-scratch reimplementation against the protocol's public
// specification. See ../../../zeus-engine/lib/zeus_proto.hh for the shared connect/handshake/
// authenticate/classify lifecycle this module plugs into.
#include "../../../zeus-engine/lib/zeus_proto.hh"

namespace zeus::net
{
    // TODO(zeus): implement against the real protocol spec, then delete this
    // comment block. Minimum overrides usually needed:
    //   - name() / descriptor()            (identity — required by ZeusServices)
    //   - authenticate(...)                (the actual login exchange)
    //   - resolve_target() / default port  (if it isn't the protocol's IANA default)
    class ZeusAsteriskModule final : public zeus::proto::ZeusProtocolService
    {
        public:
            // TODO(zeus): forward whatever zeus::proto::ZeusProtocolService constructor needs
            // (retry policy, rate limiter, dialect, ...).
    };
}
