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

// ---- Encoders (the symmetric inverse of ParseLiveInput) ---------------------
// The host appends these bytes to _live-input.bin; the run loop decodes them with
// ParseLiveInput above. Kept here (not in the UI process) so encode/decode share
// one wire contract and can be round-trip unit-tested without a VM.

// Frame keyboard scancodes as one or more 'K' records. A single record carries at
// most 255 scancodes (the count is a u8), so longer bursts are split across
// records. An empty input yields no bytes.
inline std::vector<uint8_t> EncodeKeyRecords(const std::vector<uint8_t> &scancodes) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i < scancodes.size(); i += 255) {
    const size_t n = (scancodes.size() - i) < 255 ? (scancodes.size() - i) : 255;
    out.push_back('K');
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), scancodes.begin() + i, scancodes.begin() + i + n);
  }
  return out;
}

// Frame one relative PS/2 mouse packet as an 'M' record.
inline std::vector<uint8_t> EncodeMouseRecord(uint8_t buttons, int8_t dx, int8_t dy) {
  return {'M', static_cast<uint8_t>(buttons & 0x07),
          static_cast<uint8_t>(dx), static_cast<uint8_t>(dy)};
}

// Frame a mouse move/button record as one or more 'M' records, splitting a
// displacement that exceeds the signed 8-bit PS/2 packet limit into consecutive
// valid packets. The emitted dx/dy values sum EXACTLY to the requested
// displacement (each record carries clamp(v,-127,127) and the remainder flows
// into the next record), so `vminput --mouse 300,200` moves 300x200 instead of
// the old int8 wrap to 44,-56. An all-zero displacement still emits one record
// so a pure button press/release (dx=dy=0) has a wire representation.
//
// Coordinates here are PS/2-space (Y positive-up) -- EncodeMouseScreenMoveRecords
// below is the screen-space (Y positive-down) front door every host client uses.
inline std::vector<uint8_t> EncodeMouseMoveRecords(uint8_t buttons, int dx,
                                                   int dy) {
  std::vector<uint8_t> out;
  do {
    const int stepX = dx > 127 ? 127 : (dx < -127 ? -127 : dx);
    const int stepY = dy > 127 ? 127 : (dy < -127 ? -127 : dy);
    const auto rec = EncodeMouseRecord(buttons, static_cast<int8_t>(stepX),
                                       static_cast<int8_t>(stepY));
    out.insert(out.end(), rec.begin(), rec.end());
    dx -= stepX;
    dy -= stepY;
  } while (dx != 0 || dy != 0);
  return out;
}

// Screen-space (x right, y down) mouse move -- the ONE convention host clients
// share (webui pointer-lock deltas, LiveVm::Mouse, `vminput --mouse`). The
// screen Y is flipped to the PS/2 positive-up convention exactly once, here at
// the wire boundary, and large displacements are split by EncodeMouseMoveRecords.
inline std::vector<uint8_t> EncodeMouseScreenMoveRecords(uint8_t buttons,
                                                         int screenDx,
                                                         int screenDy) {
  return EncodeMouseMoveRecords(buttons, screenDx, -screenDy);
}

// Map one ASCII character to its Set-1 make scancode (US layout), reporting
// whether Left-Shift must wrap the tap. Returns false for characters with no
// direct US-layout key (the caller skips them). Mirrors the UI's charToScancodes.
inline bool AsciiToSet1Key(char ch, uint8_t &code, bool &shift) {
  shift = false;
  if (ch >= 'a' && ch <= 'z') {
    static const uint8_t kLetters[26] = {
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26,
        0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D,
        0x15, 0x2C};
    code = kLetters[ch - 'a'];
    return true;
  }
  if (ch >= 'A' && ch <= 'Z') {
    static const uint8_t kLetters[26] = {
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26,
        0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D,
        0x15, 0x2C};
    code = kLetters[ch - 'A'];
    shift = true;
    return true;
  }
  switch (ch) {
  // Unshifted digits/symbols.
  case '1': code = 0x02; return true;
  case '2': code = 0x03; return true;
  case '3': code = 0x04; return true;
  case '4': code = 0x05; return true;
  case '5': code = 0x06; return true;
  case '6': code = 0x07; return true;
  case '7': code = 0x08; return true;
  case '8': code = 0x09; return true;
  case '9': code = 0x0A; return true;
  case '0': code = 0x0B; return true;
  case '-': code = 0x0C; return true;
  case '=': code = 0x0D; return true;
  case '[': code = 0x1A; return true;
  case ']': code = 0x1B; return true;
  case ';': code = 0x27; return true;
  case '\'': code = 0x28; return true;
  case '`': code = 0x29; return true;
  case '\\': code = 0x2B; return true;
  case ',': code = 0x33; return true;
  case '.': code = 0x34; return true;
  case '/': code = 0x35; return true;
  case ' ': code = 0x39; return true;
  // Shift-wrapped symbols.
  case '!': code = 0x02; shift = true; return true;
  case '@': code = 0x03; shift = true; return true;
  case '#': code = 0x04; shift = true; return true;
  case '$': code = 0x05; shift = true; return true;
  case '%': code = 0x06; shift = true; return true;
  case '^': code = 0x07; shift = true; return true;
  case '&': code = 0x08; shift = true; return true;
  case '*': code = 0x09; shift = true; return true;
  case '(': code = 0x0A; shift = true; return true;
  case ')': code = 0x0B; shift = true; return true;
  case '_': code = 0x0C; shift = true; return true;
  case '+': code = 0x0D; shift = true; return true;
  case '{': code = 0x1A; shift = true; return true;
  case '}': code = 0x1B; shift = true; return true;
  case ':': code = 0x27; shift = true; return true;
  case '"': code = 0x28; shift = true; return true;
  case '~': code = 0x29; shift = true; return true;
  case '|': code = 0x2B; shift = true; return true;
  case '<': code = 0x33; shift = true; return true;
  case '>': code = 0x34; shift = true; return true;
  case '?': code = 0x35; shift = true; return true;
  default: return false;
  }
}

// Scancodes for a single character tap (Left-Shift wrap + key make/break), or
// empty for an unmappable character. E.g. 'A' -> {0x2A,0x1E,0x9E,0xAA}.
inline std::vector<uint8_t> AsciiToSet1Tap(char ch) {
  uint8_t code = 0;
  bool shift = false;
  if (!AsciiToSet1Key(ch, code, shift)) {
    return {};
  }
  std::vector<uint8_t> out;
  if (shift) {
    out.push_back(0x2A); // Left-Shift make
  }
  out.push_back(code);
  out.push_back(static_cast<uint8_t>(code | 0x80)); // break
  if (shift) {
    out.push_back(0xAA); // Left-Shift break
  }
  return out;
}

} // namespace antimal::hv
