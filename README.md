# Rust Bitcoin Script

Utilities used in the official [BitVM](https://github.com/BitVM/BitVM) implementation to generate Bitcoin Script. Heavily inspired by [rust-bitcoin-script's inline macro](https://github.com/mappum/rust-bitcoin-script).

## Usage

This crate exports a `script!` macro which can be used to build structured Bitcoin scripts and compiled to the [`Script`](https://docs.rs/bitcoin/latest/bitcoin/struct.ScriptBuf.html) type from the [`bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) crate.

**Example:**

```rust
use bitcoin_script::script;

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

### Optimization

Compilation preserves the generated instruction stream by default. Optimizing
is explicit, so callers can inspect or test the script exactly as generated
before choosing to rewrite it.

There are three compilation entry points:

- `compile()` compiles with `CompileOptions::NONE` and performs no optimizer
  rewrites.
- `compile_optimized()` is a convenience method that compiles with
  `CompileOptions::ALL`.
- `compile_with_options(options)` accepts the compilation configuration
  explicitly. This is useful for code that chooses its optimization policy at
  runtime or passes configuration through another API.

`CompileOptions::ALL` is an associated constant containing the configuration
that enables every implemented optimizer pass. It is not an additional mode
beyond `compile_optimized()`; the following two calls are equivalent:

```rust
use bitcoin_script::{script, CompileOptions};

let script = script! {
    OP_DUP
    OP_SHA256
    OP_SWAP
    OP_SHA256
    OP_EQUAL
    OP_VERIFY
};

let optimized = script.clone().compile_optimized();
let same = script.compile_with_options(CompileOptions::ALL);

assert_eq!(optimized, same);
```

The equivalent method definitions are conceptually:

```rust,ignore
fn compile(self) -> ScriptBuf {
    self.compile_with_options(CompileOptions::NONE)
}

fn compile_optimized(self) -> ScriptBuf {
    self.compile_with_options(CompileOptions::ALL)
}
```

At present, `CompileOptions` contains one setting, `optimization`, whose value
is either `OptimizationLevel::None` or `OptimizationLevel::All`. The options
type leaves room for additional compilation settings without adding another
compile method for each combination.

`CompileOptions::ALL` runs the optimizer to a fixpoint and includes:

- direct opcode substitutions such as `1 ADD -> 1ADD` and `2 ROLL -> ROT`;
- symbolic stack rewrites, including multi-item and alt-stack cancellations;
- `VERIFY` and hash fusion;
- dead-result, commutativity, boolean, and comparison simplifications;
- constant folding for arithmetic, comparisons, hashes, `SIZE`, and branches;
- locktime/sequence cleanup, common branch-tail hoisting, and `NOP` removal.

The optimizer targets Tapscript semantics. Rewrites that can alter stack
underflow or numeric parsing are applied only when prefix analysis proves their
preconditions. A script containing any BIP342 `OP_SUCCESSx` opcode is returned
unchanged, and the disabled `CHECKMULTISIG` opcodes are never introduced or
fused.

Optimization changes the serialized script and can remove transient resource
usage. Generate signatures, Tapleaf hashes, and byte-level test vectors from
the final optimized `ScriptBuf`, not from the unoptimized script.

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

#### Conditional Script Generation

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
