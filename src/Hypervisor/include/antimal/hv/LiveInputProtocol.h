// LiveInputProtocol.h - the host->guest real-time input wire format.
//
// When a human drives the live VM from the UI, keyboard and mouse events are
// appended to a small "_live-input.bin" file that the VM run loop tails. Because
// keyboard and mouse must interleave and a poll can land mid-record, the bytes
// are framed:
//
//   'K' <count:u8> <count scancodes>   -> inject keyboard scancodes (Set-1)
//   'M' <buttons:u8> <dx:i8> <dy:i8>   -> inject one PS/2 mouse packet
//
// Any other leading byte is treated as garbage and skipped one byte at a time to
// resync. A record that is only partially present stays buffered until the rest
// of its bytes arrive on a later poll.
//
// The parser is pulled out of VirtualMachine.cpp's run loop so this framing --
// the tricky split-record / resync behavior that makes the VM feel interactive --
// can be unit-tested without booting a VM. The run loop calls ParseLiveInput then
// replays the decoded events into the PS/2 controller.
#pragma once

#include <cstdint>
#include <vector>

namespace antimal::hv {

struct LiveInputEvent {
  enum class Type { Keyboard, Mouse };
  Type type;
  // Keyboard: the scancodes to inject (non-empty; empty 'K' records carry no
  // event but still consume their 2 header bytes, matching the wire contract).
  std::vector<uint8_t> scancodes;
  // Mouse:
  uint8_t buttons = 0;
  int8_t dx = 0;
  int8_t dy = 0;
};

// Decodes every COMPLETE framed record from the front of `buf`, appending an
// event per record to `out`, then erases the consumed bytes so a trailing
// partial record stays buffered for the next call. Returns the number of bytes
// consumed. `buf` is the caller's persistent remainder buffer.
inline size_t ParseLiveInput(std::vector<uint8_t> &buf,
                             std::vector<LiveInputEvent> &out) {
  size_t off = 0;
  for (;;) {
    if (off >= buf.size()) {
      break;
    }
    const uint8_t tag = buf[off];
    if (tag == 'K') {
      if (off + 2 > buf.size()) {
        break; // need tag + count
      }
      const uint8_t n = buf[off + 1];
      if (off + 2 + static_cast<size_t>(n) > buf.size()) {
        break; // need all scancodes
      }
      if (n > 0) {
        LiveInputEvent ev;
        ev.type = LiveInputEvent::Type::Keyboard;
        ev.scancodes.assign(buf.begin() + off + 2,
                            buf.begin() + off + 2 + static_cast<size_t>(n));
        out.push_back(std::move(ev));
      }
      off += 2 + static_cast<size_t>(n);
    } else if (tag == 'M') {
      if (off + 4 > buf.size()) {
        break; // need tag + buttons + dx + dy
      }
      LiveInputEvent ev;
      ev.type = LiveInputEvent::Type::Mouse;
      ev.buttons = buf[off + 1];
      ev.dx = static_cast<int8_t>(buf[off + 2]);
      ev.dy = static_cast<int8_t>(buf[off + 3]);
      out.push_back(std::move(ev));
      off += 4;
    } else {
      off += 1; // unknown tag: resync by skipping one byte
    }
  }
  if (off > 0) {
    buf.erase(buf.begin(), buf.begin() + off);
  }
  return off;
}

} // namespace antimal::hv
