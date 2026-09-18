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
                                     const std::string &targetUser) {
  if (sensor.empty() || Find(states_, sensor) != nullptr) {
    return;
  }
  SensorCoverageState s;
  s.sensor = sensor;
  s.targetUser = targetUser;
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
  if (succeeded) {
    ++s->samples;
    s->healthy = true;
  } else {
    s->healthy = false;
  }
  (void)emittedRecords;
  s->dropped += droppedRecords;
  // If any observation could not account for its drops, the aggregate is only a
  // lower bound.
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

std::vector<SensorCoverageState> SensorCoverageTracker::States() const {
  return states_;
}

bool SensorCoverageTracker::Incomplete() const {
  for (const auto &s : states_) {
    if (!s.supported || !s.healthy || s.dropped > 0) {
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
    if (s == nullptr) {
      summary->sensorCoverage.push_back({});
      s = &summary->sensorCoverage.back();
      s->sensor = sensor;
    }
    const auto get = [&](const char *k) -> std::string {
      const auto it = e.details.find(k);
      return it == e.details.end() ? std::string() : it->second;
    };
    s->supported = truthy(get("supported"));
    s->healthy = truthy(get("healthy"));
    s->samples = number(get("samples"));
    s->dropped = number(get("dropped"));
    s->lossKnown = truthy(get("lossKnown"));
    s->targetUser = get("targetUser");
    s->note = get("note");
  }
  if (sawAny) {
    bool incomplete = false;
    for (const auto &s : summary->sensorCoverage) {
      if (!s.supported || !s.healthy || s.dropped > 0) {
        incomplete = true;
      }
    }
    summary->coverageIncomplete = incomplete;
  }
}

} // namespace antimal
