#pragma once

// G4 per-sensor coverage tracking (guest side).
//
// The GuestAgent runs several poll-diff collectors (process, network, registry,
// filesystem, image/module, WER). Each has different cadence, caps, and failure
// modes. A run's "Clean" must never rest on a collector that never ran, was
// unsupported, or silently dropped records. This tracker accumulates, per
// collector, whether it is supported, whether its last collection succeeded, how
// many successful cycles ran, and how many records were dropped at a cap, so the
// agent can periodically emit an `agent.coverage` journal record. The host folds
// those into DynamicRunSummary::sensorCoverage and the scorer gates negatives on
// them.
//
// Pure + host-unit-testable: no I/O, no globals. The GuestAgent owns an instance
// and feeds it observations; the serialization is exercised by tests.

#include <cstdint>
#include <string>
#include <vector>

#include "antimal/Types.h"

namespace antimal {

// One collector's coverage state.
struct SensorCoverageState {
  std::string sensor;      // "process" | "network" | "registry" | "filesystem" |
                           // "image" | "wer_crash"
  bool supported = true;   // the collector exists on this agent build
  bool healthy = false;    // last collection succeeded
  uint64_t samples = 0;    // successful collection cycles
  uint64_t attempts = 0;   // total cycles attempted
  uint64_t dropped = 0;    // records dropped at a cap
  bool lossKnown = true;   // false => dropped is a lower bound / unknown
  std::string targetUser;  // profile the collector resolves from ("" unknown)
  std::string note;        // human-readable limitation, if any
};

// Tracks coverage for a fixed set of collectors.
class SensorCoverageTracker {
public:
  // `sensor` is the stable collector name. Registering the same name twice is a
  // no-op (keeps the first). `targetUser` is the identity the collector's paths
  // resolve from -- "" means unknown.
  void Register(const std::string &sensor, const std::string &targetUser = {});

  // A collection cycle completed without an exception. `emittedRecords` is how
  // many events the collector produced; `droppedRecords` how many it discarded
  // at a cap. `lossKnown=false` records that the drop count cannot be trusted.
  void Observe(const std::string &sensor, bool succeeded,
               uint64_t emittedRecords = 0, uint64_t droppedRecords = 0,
               bool lossKnown = true, const std::string &note = {});

  // Mark a collector unsupported on this agent.
  void MarkUnsupported(const std::string &sensor, const std::string &note);

  // Snapshot of every registered collector, in registration order.
  std::vector<SensorCoverageState> States() const;

  // True when any registered collector is unsupported, unhealthy, or reported
  // dropped records. The host uses this to mark coverageIncomplete.
  bool Incomplete() const;

  // Emits one `agent.coverage` EventRecord per registered collector (so the
  // journal carries a per-sensor record). `bootGeneration` travels with it.
  std::vector<EventRecord> ToEvents(uint32_t bootGeneration) const;

private:
  std::vector<SensorCoverageState> states_;
};

// Host-side fold: merge a batch of `agent.coverage` EventRecords into the
// existing per-sensor list (later events replace earlier ones for the same
// sensor) and recompute DynamicRunSummary::coverageIncomplete. Pure.
void ApplyCoverageEvents(const std::vector<EventRecord> &events,
                         DynamicRunSummary *summary);

} // namespace antimal
