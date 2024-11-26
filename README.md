# MessageFrankingCrypto

This software artifact is associated with the following publication:
Onion Franking: Abuse Reports for Mix-Based Private Messaging
Matthew Gregoire, Margaret Pierce, Saba Eskandarian
NDSS 2025

To run unit tests, run `cargo test`.

To run our benchmarks, run `cargo run --release`. The number of trials each reported result is averaged over is set in the constant `N` in `main.rs`. This value can be tweaked to improve performance.

## Layout of the project

At a high level, `main.rs` can be understood by looking at the `main()` function.

1. We iterate over varying message plaintext sizes, from 0 to 1000 bytes in increments of 100 bytes.
2. For each tested message size, we analyze the performance of all 4 onion franking variants (as well as the performance of plain franking).
3. For each onion franking variant, we analyze the performance while varying the number of servers from 2 to `MAX_N_SERVERS` (which we have set as 10).
4. For each `(msg_size, scheme, n_servers)` selection, we call a `test_<scheme>()` function also defined in `main.rs`. Note that the trap message scheme has an additional parameter that we also vary, so we call `test_trap()` for each combination of `(msg_size, n_servers, n_traps)`.

These `test_<scheme>()` functions each perform N trials of the whole onion franking protocol, from when the sender sends a message to when the moderator receives a report. For each operation in the onion franking syntax, we report the combination `scheme, n_servers, msg_size, ` optionally `n_traps`, and then the average runtime across the N trials for the selected operation. Each such result is one line of the output file.

Each `test_<scheme>()` function is defined almost identically, with the main differences being which scheme is used to implement onion franking. The implementations of each scheme can be found in the files titled `lib_<scheme>.rs`. Functions that are implemented identically across most schemes are implemented in `lib_common.rs`.

Each scheme implementation file explicitly implements the functions that create an onion franking scheme, as defined in the paper.

## Unit tests

Included are unit tests which verify that messages can be successfully sent, read, and moderated in each scheme variant. These are similar in structure to the benchmarks in `main.rs`, but do not time each operation. These can be found in the `tests` directory.