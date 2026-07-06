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

// Number of independent UDP sockets/threads used to transmit the
// initial burst in parallel. Each pulls encrypted chunks off the same
// queue and sends on its own socket. Try 2-4; more isn't necessarily
// better if the link itself is the bottleneck rather than the sender.
pub const NUM_SENDER_STREAMS: usize = 1;

// ---------------------------------------------------------------------
// Block-pipelined transport (see transport.rs)
// ---------------------------------------------------------------------

// Packets per block. Chosen so a block is small enough to repair cheaply
// (a lossy block costs at most PACKETS_PER_BLOCK ids in one TCP message)
// but large enough to amortize the per-block BlockEnd/BlockAck round trip
// over plenty of data. 256 packets * ~1400 bytes ~= 350 KB per block.
pub const PACKETS_PER_BLOCK: usize = 256;

// Maximum number of blocks the sender keeps "open" (packets sent, not yet
// confirmed complete) at once. This is the only flow-control knob in the
// transport: it bounds memory to a small constant regardless of file size,
// while still letting the receiver repair one block while later blocks
// keep arriving. 3-4 is the sweet spot the design calls for -- enough to
// keep the network saturated across the RTTs seen on Wi-Fi, without
// unbounded cache growth if repairs lag behind.
pub const PIPELINE_DEPTH: usize = 4;

// After a BlockEnd (or, on the receiver side, after a quiet period with no
// new packets for the active block), wait this long before checking for
// gaps -- gives packets already in flight a chance to land so we don't
// request retransmission of something that was just about to arrive.
// This is a short, fixed grace period rather than a pacing delay: it never
// throttles the send rate, it only delays the receiver's *decision* to ask
// for a repair.
pub const BLOCK_GRACE_PERIOD_MS: u64 = 8;

// If no packets at all arrive for the currently-active block for this long,
// the receiver proactively checks it rather than waiting indefinitely for a
// BlockEnd that may have been lost. This is what prevents a lost BlockEnd
// from ever stalling the transfer.
pub const BLOCK_IDLE_TIMEOUT_MS: u64 = 150;

// Safety valve: if a single block still isn't complete after this many
// repair rounds, give up on it (log and move on) rather than retrying
// forever on a truly broken link.
pub const MAX_BLOCK_RETRY_ROUNDS: u32 = 50;