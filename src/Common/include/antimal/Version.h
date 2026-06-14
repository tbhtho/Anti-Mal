#pragma once

// Central product/version identity. Bump on releases; surfaced by the CLI
// `version` subcommand and (later) the VERSIONINFO resource / report headers.
namespace antimal {

inline constexpr int kVersionMajor = 0;
inline constexpr int kVersionMinor = 9;
inline constexpr int kVersionPatch = 0;

inline constexpr const char *kProductName = "AntiMal";
inline constexpr const char *kVersionString = "0.9.0";
inline constexpr const char *kBuildDate = __DATE__;
inline constexpr const char *kProductTagline =
    "local interactive malware-analysis sandbox";

} // namespace antimal
