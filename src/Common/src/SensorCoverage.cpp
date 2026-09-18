#include "antimal/SensorCoverage.h"

#include "antimal/FileUtil.h" // UtcNowIso8601, ToLowerAscii

#include <algorithm>

namespace antimal {
namespace {

SensorCoverageState *Find(std::vector<SensorCoverageState> &states,
                          const std::string &sensor) {
  for (auto &s : states) {
    if (s.sensor == sensor) {
      return &s;
    }
  }
  return nullptr;
}

} // namespace

void SensorCoverageTracker::Register(const std::string &sensor,
                                     const std::string &targetUser,
                                     const std::string &scope) {
  if (sensor.empty() || Find(states_, sensor) != nullptr) {
    return;
  }
  SensorCoverageState s;
  s.sensor = sensor;
  s.targetUser = targetUser;
  s.scope = scope;
  states_.push_back(std::move(s));
}

void SensorCoverageTracker::Observe(const std::string &sensor, bool succeeded,
                                    uint64_t emittedRecords,
                                    uint64_t droppedRecords, bool lossKnown,
                                    const std::string &note) {
  SensorCoverageState *s = Find(states_, sensor);
  if (s == nullptr) {
    Register(sensor);
    s = Find(states_, sensor);
    if (s == nullptr) {
      return;
    }
  }
  ++s->attempts;
  const bool firstAttempt = s->attempts == 1;
  if (succeeded) {
    ++s->samples;
    // Sticky: a sensor that failed a collection stays unhealthy for the run, so
    // a later success cannot silently forget the earlier gap.
    if (firstAttempt || s->healthy) {
      s->healthy = true;
    }
  } else {
    s->healthy = false;
  }
  (void)emittedRecords;
  s->dropped += droppedRecords;
  // If any observation could not account for its drops, the aggregate is only a
  // lower bound. Unknown loss is sticky for the same reason as failures.
  s->lossKnown = s->lossKnown && lossKnown;
  if (!note.empty()) {
    s->note = note;
  }
}

void SensorCoverageTracker::MarkUnsupported(const std::string &sensor,
                                            const std::string &note) {
  SensorCoverageState *s = Find(states_, sensor);
  if (s == nullptr) {
    Register(sensor);
    s = Find(states_, sensor);
    if (s == nullptr) {
      return;
    }
  }
  s->supported = false;
  s->healthy = false;
  if (!note.empty()) {
    s->note = note;
  }
}

void SensorCoverageTracker::SetScope(const std::string &sensor,
                                     const std::string &targetUser,
                                     const std::string &scope,
                                     const std::string &note) {
  SensorCoverageState *s = Find(states_, sensor);
  if (s == nullptr) {
    Register(sensor, targetUser, scope);
    return;
  }
  const bool changed = (!s->targetUser.empty() || !s->scope.empty()) &&
                       (s->targetUser != targetUser || s->scope != scope);
  s->targetUser = targetUser;
  s->scope = scope;
  if (changed) {
    // Honest scope transition: the collector observed more than one profile
    // during the run. Keep the fact attached to the coverage record.
    const std::string transition =
        "collector scope changed during the run (earlier observations targeted a "
        "different profile/scope)";
    if (!note.empty()) {
      s->note = s->note.empty() ? note : s->note + "; " + note;
    }
    if (s->note.find("scope changed") == std::string::npos) {
      s->note = s->note.empty() ? transition : s->note + "; " + transition;
    }
  } else if (!note.empty()) {
    s->note = note;
  }
}

std::vector<SensorCoverageState> SensorCoverageTracker::States() const {
  return states_;
}

bool SensorCoverageTracker::Incomplete() const {
  for (const auto &s : states_) {
    if (!s.supported || !s.healthy || s.dropped > 0 || !s.lossKnown) {
      return true;
    }
  }
  return false;
}

std::vector<EventRecord> SensorCoverageTracker::ToEvents(
    uint32_t bootGeneration) const {
  std::vector<EventRecord> out;
  for (const auto &s : states_) {
    EventRecord e;
    e.timestampUtc = UtcNowIso8601();
    e.source = "GuestAgent";
    e.category = "coverage";
    e.action = "agent.coverage";
    e.target = s.sensor;
    e.details["supported"] = s.supported ? "true" : "false";
    e.details["healthy"] = s.healthy ? "true" : "false";
    e.details["samples"] = std::to_string(s.samples);
    e.details["attempts"] = std::to_string(s.attempts);
    e.details["dropped"] = std::to_string(s.dropped);
    e.details["lossKnown"] = s.lossKnown ? "true" : "false";
    if (!s.targetUser.empty()) {
      e.details["targetUser"] = s.targetUser;
    }
    if (!s.scope.empty()) {
      e.details["scope"] = s.scope;
    }
    if (!s.note.empty()) {
      e.details["note"] = s.note;
    }
    if (bootGeneration != 0) {
      e.details["bootGeneration"] = std::to_string(bootGeneration);
    }
    out.push_back(std::move(e));
  }
  return out;
}

void ApplyCoverageEvents(const std::vector<EventRecord> &events,
                         DynamicRunSummary *summary) {
  if (summary == nullptr) {
    return;
  }
  const auto truthy = [](const std::string &v) {
    return v == "true" || v == "1" || v == "yes";
  };
  const auto number = [](const std::string &v) -> uint64_t {
    try {
      return static_cast<uint64_t>(std::stoull(v));
    } catch (...) {
      return 0;
    }
  };
  bool sawAny = false;
  for (const auto &e : events) {
    if (ToLowerAscii(e.action) != "agent.coverage" &&
        ToLowerAscii(e.category) != "coverage") {
      continue;
    }
    sawAny = true;
    const std::string &sensor = e.target;
    auto find = [&]() -> DynamicRunSummary::SensorCoverage * {
      for (auto &s : summary->sensorCoverage) {
        if (s.sensor == sensor) {
          return &s;
        }
      }
      return nullptr;
    };
    DynamicRunSummary::SensorCoverage *s = find();
    const bool first = (s == nullptr);
    if (s == nullptr) {
      summary->sensorCoverage.push_back({});
      s = &summary->sensorCoverage.back();
      s->sensor = sensor;
    }
    const auto get = [&](const char *k) -> std::string {
      const auto it = e.details.find(k);
      return it == e.details.end() ? std::string() : it->second;
    };
    const bool supported = truthy(get("supported"));
    const bool healthy = truthy(get("healthy"));
    const uint64_t samples = number(get("samples"));
    const uint64_t dropped = number(get("dropped"));
    const bool lossKnown = truthy(get("lossKnown"));
    const std::string targetUser = get("targetUser");
    const std::string scope = get("scope");
    const std::string note = get("note");
    if (first) {
      s->supported = supported;
      s->healthy = healthy;
      s->samples = samples;
      s->dropped = dropped;
      s->lossKnown = lossKnown;
    } else {
      // Coverage folding must never FORGET an earlier gap: a later healthy /
      // loss-free status (or a boot-generation reset) cannot retract an earlier
      // unsupported, unhealthy, or unknown-loss observation.
      s->supported = s->supported && supported;
      s->healthy = s->healthy && healthy;
      s->samples = std::max(s->samples, samples);
      s->dropped = std::max(s->dropped, dropped);
      s->lossKnown = s->lossKnown && lossKnown;
    }
    if (!targetUser.empty()) {
      s->targetUser = targetUser;
    }
    if (!scope.empty()) {
      s->scope = scope;
    }
    if (!note.empty()) {
      s->note = note;
    }
  }
  if (sawAny) {
    bool incomplete = false;
    for (const auto &s : summary->sensorCoverage) {
      if (!s.supported || !s.healthy || s.dropped > 0 || !s.lossKnown) {
        incomplete = true;
      }
    }
    summary->coverageIncomplete = incomplete;
  }
}

} // namespace antimal
