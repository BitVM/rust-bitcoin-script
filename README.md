# Bitvm Bitcoin Script

Utilities used in the official [BitVM](`https://github.com/BitVM/BitVM`) implementation to generate Bitcoin Script. Heavily inspired by [rust-bitcoin-script's inline macro](`https://github.com/mappum/rust-bitcoin-script`).

## Usage

This crate exports a `script!` macro which can be used to build structured Bitcoin scripts and compiled to the [`Script`](https://docs.rs/bitcoin/latest/bitcoin/struct.ScriptBuf.html) type from the [`bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) crate.

**Example:**

```rust
use bitcoin_script::bitcoin_script;

let htlc_script = script! {
    OP_IF
        OP_SHA256 <digest> OP_EQUALVERIFY OP_DUP OP_SHA256 <seller_pubkey_hash>
    OP_ELSE
        100 OP_CSV OP_DROP OP_DUP OP_HASH160 <buyer_pubkey_hash>
    OP_ENDIF
    OP_EQUALVERIFY
    OP_CHECKSIG
};

let script_buf = htlc_script.compile();
```

### Syntax

Scripts are based on the standard syntax made up of opcodes, base-10 integers, or hex string literals. Additionally, Rust expressions can be interpolated in order to support dynamically capturing Rust variables or computing values (delimited by `<angle brackets>` or `{curly brackets}`). The `script!` macro can be nested.

Whitespace is ignored - scripts can be formatted in the author's preferred style.

#### Opcodes

All normal opcodes are available, in the form `OP_X`.

```rust
let script = script!(OP_CHECKSIG OP_VERIFY);
```

#### Integer Literals

Positive and negative 64-bit integer literals can be used, and will resolve to their most efficient encoding.

For example:
- `2` will resolve to `OP_PUSHNUM_2` (`0x52`)
- `255` will resolve to a length-delimited varint: `0x02ff00` (note the extra zero byte, due to the way Bitcoin scripts use the most-significant bit to represent the sign)`

```rust
let script = script!(123 -456 999999);
```

#### Hex Literals

Hex strings can be specified, prefixed with `0x`.

```rust
let script = script!(
    0x0102030405060708090a0b0c0d0e0f OP_HASH160
);
```

#### Escape Sequences

Dynamic Rust expressions are supported inside the script, surrounded by angle brackets or in a code block. In many cases, this will just be a variable identifier, but this can also be a function call or arithmetic.

Rust expressions of the following types are supported:

- `i64`
- `Vec<u8>`
- [`bitcoin::PublicKey`](https://docs.rs/bitcoin/latest/bitcoin/struct.PublicKey.html)
- [`bitcoin::XOnlyPublicKey`](https://docs.rs/bitcoin/latest/bitcoin/struct.XOnlyPublicKey.html)
- [`bitcoin::ScriptBuf`](https://docs.rs/bitcoin/latest/bitcoin/struct.ScriptBuf.html)
- `StructuredScript`

```rust
let bytes = vec![1, 2, 3];

let script = script! {
    <bytes> OP_CHECKSIGVERIFY

    <2016 * 5> OP_CSV

    <script! { OP_FALSE OP_TRUE }>
};
```

#### Conditional Scipt Generation

For-loops and if-else-statements are supported inside the script and will be unrolled when the scripts are generated.

```rust
let loop_count = 10;

let script = script! {
    for i in 0..loop_count {
        if i % 2 == 0 {
            OP_ADD
        } else {
            OP_DUP
            OP_ADD
        }
    }
};

```
