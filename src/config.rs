//BEST
pub const HOST: &str = "0.0.0.0";
pub const RECEIVER_IP: &str = "192.168.1.157";
pub const DATA_PORT: u16 = 5000;

pub const KEY_PORT: u16 = 5001;

pub const CHUNK_SIZE: usize = 1400;

pub const NUM_WORKERS: usize = 4;

pub const UDP_SEND_BUFFER: usize = 16 * 1024 * 1024;

pub const UDP_RECV_BUFFER: usize = 32 * 1024 * 1024;

pub const TCP_BUFFER: usize = 1024 * 1024;

// Receiver sends one ACK after every
// ACK_INTERVAL newly received packets.
pub const ACK_INTERVAL: u32 = 128;

// Retransmit if we haven't heard an ACK
// for this long.
pub const RETRANSMIT_TIMEOUT_MS: u64 = 10;
pub const WINDOW_SIZE: usize = 256;
pub const RETRANSMIT_BATCH_SIZE: usize = 4096;

// ---------------- Adaptive sliding-window transport ----------------
//
// These replace the old "blast everything, then repair once" design.
// The sender keeps at most `cwnd` packets unacknowledged at any time and
// grows/shrinks that window based on what the receiver reports, instead
// of relying on a network-specific pacing sleep. This is deliberately
// conservative to start on unknown networks (office Wi-Fi, VPNs, etc.)
// and ramps up automatically on clean links.

// Starting window size (packets in flight), before any feedback arrives.
pub const INITIAL_WINDOW: usize = 64;

// Window never shrinks below this, so we always make forward progress
// even on very lossy links.
pub const MIN_WINDOW: usize = 32;

// Window never grows past this - just a safety ceiling.
pub const MAX_WINDOW: usize = 4096;

// How much the window grows after each clean (loss-free) ACK round.
pub const WINDOW_GROWTH_STEP: usize = 32;

// How often the receiver reports progress back to the sender.
pub const ACK_INTERVAL_MS: u64 = 15;

// If we haven't heard *anything* about a packet (ack or "missing") after
// this long, assume the ACK carrying that news was itself lost and just
// resend the packet proactively.
pub const RTO_MS: u64 = 200;

// Minimum time that must pass before the same chunk id can be resent
// again in response to the receiver reporting it "missing". The receiver
// reports its missing list on every ACK_INTERVAL_MS tick (15ms) - without
// this gate, a chunk that's still missing gets resent on every single
// tick, turning a handful of stuck chunks into a multi-thousand-packet-
// per-second retransmission storm that never lets up.
pub const MIN_RESEND_INTERVAL_MS: u64 = 60;

// How far past the receiver's cumulative "highest contiguous" point it
// scans for gaps to report each round. Keeps ACK packets small and
// focused on the currently-active window instead of listing every
// not-yet-sent chunk in a multi-GB file.
pub const MISSING_LOOKAHEAD: u32 = 8192;

// Number of independent UDP sockets/threads used to transmit the
// initial burst in parallel. Each pulls encrypted chunks off the same
// queue and sends on its own socket. Try 2-4; more isn't necessarily
// better if the link itself is the bottleneck rather than the sender.
pub const NUM_SENDER_STREAMS: usize = 1;