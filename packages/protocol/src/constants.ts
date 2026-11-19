import {
  ACTION,
  CDATA,
  copyRegex,
  E164,
  RESPONSE_TOKEN,
  SDK_NAME,
  SDK_VERSION,
} from './patterns.js';

export const PROTOCOL_VERSION = 1;
export const TOKEN_TTL_SECONDS = 300;
export const TOKEN_MAX_LENGTH = 2048;
/**
 * A challenge expires this many seconds after it is issued. Each challenge (keyed on its id, the
 * PoW salt) is accepted at most once at `/v1/solve`; the spend record is kept until expiry + 60 s.
 */
export const CHALLENGE_TTL_SECONDS = 120;
/** Maximum length of a sealed, opaque challenge string. */
export const CHALLENGE_MAX_LENGTH = 4096;
/** Maximum length of the `signals` string in a solve request (keeps a maximal body under 64 KiB). */
export const SIGNALS_MAX_LENGTH = 49152;
/** A puzzle challenge accepts exactly one answer; a wrong answer closes it (the group goes on, see below). */
export const PUZZLE_MAX_ATTEMPTS = 1;
/** A person passes by answering this many puzzles of a group correctly. */
export const PUZZLE_GROUP_CORRECT = 2;
/** A group that is audio (or became audio by the swap) needs this many correct answers instead. */
export const PUZZLE_GROUP_CORRECT_AUDIO = 3;
/** A group allows this many wrong answers; the next wrong answer ends it with a `retry`. */
export const PUZZLE_GROUP_MAX_WRONG = 1;
/** A puzzle asset capability path stays valid this many seconds. */
export const PUZZLE_ASSET_TTL_SECONDS = 120;
/** The fresh challenge sent after a failed group has this many more PoW difficulty bits. */
export const PUZZLE_POW_BUMP = 2;
/**
 * Each unsolved puzzle group issued in the last `PUZZLE_FAILURE_WINDOW_SECONDS` to a network, at one
 * site, adds `PUZZLE_POW_BUMP` bits to that site's challenges for the network, up to this many bits.
 */
export const PUZZLE_POW_BUMP_CAP = 2;
/**
 * A whole puzzle group must be finished within this many seconds of its first issue. Each puzzle in
 * it lives `CHALLENGE_TTL_SECONDS` from its own issue, never past the group's end (WCAG 2.2.1).
 */
export const PUZZLE_GROUP_MAX_SECONDS = 600;
/** An unsolved group counts against its network for this long (the velocity window of section 10). */
export const PUZZLE_FAILURE_WINDOW_SECONDS = 60;
/** Maximum length of the `telemetry` string in a puzzle answer request. */
export const PUZZLE_TELEMETRY_MAX_LENGTH = 8192;

// Public copies: the schemas validate with private instances (src/patterns.ts), so mutating these
// exports cannot change what is accepted. The whole string must match; no trailing newline.
export const ACTION_RE: RegExp = copyRegex(ACTION);
export const CDATA_RE: RegExp = copyRegex(CDATA);
export const SDK_NAME_RE: RegExp = copyRegex(SDK_NAME);
/** An E.164 number: `+`, then 7 to 15 digits, the first not 0. */
export const E164_RE: RegExp = copyRegex(E164);
export const SDK_VERSION_RE: RegExp = copyRegex(SDK_VERSION);
/** Siteverify `response`: 1 to `TOKEN_MAX_LENGTH` characters of unpadded base64url. */
export const RESPONSE_TOKEN_RE: RegExp = copyRegex(RESPONSE_TOKEN);
