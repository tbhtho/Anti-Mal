#pragma once

// Append-only JSONL journal for streaming telemetry between the guest
// (where events originate) and the host (where the UI consumes them).
//
// Lifecycle:
//   - GuestAgent calls EventJournalWriter::Append(...) for every event as
//     it happens.  The writer flushes after each line so a crash in the
//     guest still leaves a usable partial journal.
//   - Host-side tooling instantiates EventJournalTailer pointed at the
//     same file. Each call to PullNew() returns events written since the
//     previous call, or {} when nothing has been added.
//
// On-disk format is one JSON object per line. The writer uses the same
// fields as antimal::EventRecord plus a wall-clock timestamp written by
// the writer itself (so the host can sort events even when the guest
// clock is skewed).

#include "antimal/Types.h"

#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace antimal {

class EventJournalWriter {
public:
  // Opens (or creates) the journal file for append. Throws std::runtime_error
  // when the file cannot be opened. Existing content is preserved so
  // crashed runs can be resumed.
  explicit EventJournalWriter(const std::filesystem::path &path);
  ~EventJournalWriter();

  EventJournalWriter(const EventJournalWriter &) = delete;
  EventJournalWriter &operator=(const EventJournalWriter &) = delete;

  // Append an event. Thread-safe. Best-effort: failures are silently
  // swallowed (a missing line is better than aborting the guest agent).
  void Append(const EventRecord &event);

  const std::filesystem::path &Path() const noexcept { return path_; }

private:
  std::filesystem::path path_;
  std::FILE *file_ = nullptr;
  std::mutex mu_;
};

class EventJournalTailer {
public:
  explicit EventJournalTailer(const std::filesystem::path &path);

  // Returns events appended to the journal since the last call (or since
  // construction, for the first call). Safe to call when the writer
  // hasn't created the file yet — returns {} until it shows up.
  std::vector<EventRecord> PullNew();

  // Returns every event currently in the journal, ignoring any cursor.
  std::vector<EventRecord> ReadAll();

  const std::filesystem::path &Path() const noexcept { return path_; }

private:
  std::filesystem::path path_;
  std::uintmax_t cursor_ = 0;        // byte offset already consumed
  std::string remainder_;            // partial line carried across reads
};

// Parses a single JSONL line into an EventRecord. On parse failure returns
// a default-constructed record with category="parse-error" and target set
// to the offending line.
EventRecord ParseEventJsonLine(const std::string &line);

// Serializes an EventRecord into a single JSONL line (terminated by '\n').
std::string SerializeEventJsonLine(const EventRecord &event);

} // namespace antimal
