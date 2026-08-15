#pragma once

// Ported from THC-Hydra's hydra-firebird.c — original C source not reused,
// this is a from-scratch reimplementation against the protocol's public
// specification. See ../../../zeus-engine/lib/zeus_database.hh for the shared connect/handshake/
// authenticate/classify lifecycle this module plugs into.
#include "../../../zeus-engine/lib/zeus_database.hh"

namespace zeus::database
{
    // TODO(zeus): implement against the real protocol spec, then delete this
    // comment block. Minimum overrides usually needed:
    //   - name() / descriptor()            (identity — required by ZeusServices)
    //   - authenticate(...)                (the actual login exchange)
    //   - resolve_target() / default port  (if it isn't the protocol's IANA default)
    class ZeusFirebirdModule final : public zeus::database::ZeusDatabaseService
    {
        public:
            // TODO(zeus): forward whatever zeus::database::ZeusDatabaseService constructor needs
            // (retry policy, rate limiter, dialect, ...).
    };
}
