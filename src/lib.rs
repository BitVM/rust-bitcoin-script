//! [![Rust](https://github.com/mappum/rust-bitcoin-script/workflows/Rust/badge.svg)](https://github.com/mappum/rust-bitcoin-script/actions?query=workflow%3ARust)
//! [![crates.io](https://img.shields.io/crates/v/bitcoin-script.svg)](https://crates.io/crates/bitcoin-script)
//! [![docs.rs](https://docs.rs/bitcoin-script/badge.svg)](https://docs.rs/bitcoin-script)
//!
//! **Bitcoin scripts inline in Rust.**
//!
//! ---
//!
//! ## Usage
//!
//! This crate exports a `script!` macro which can be used to build
//! Bitcoin scripts. The macro returns the
//! [`Script`](https://docs.rs/bitcoin/0.23.0/bitcoin/blockdata/script/struct.Script.html)
//! type from the [`bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin)
//! crate.
//!
//! **Example:**
//!
//! ```rust
//! # use bitcoin_script::{script, define_pushable};
//!
//! # define_pushable!();
//! # let digest = 0;
//! # let seller_pubkey_hash = 0;
//! # let buyer_pubkey_hash = 0;
//!
//! let htlc_script = script! {
//!     OP_IF
//!         OP_SHA256 <digest> OP_EQUALVERIFY OP_DUP OP_SHA256 <seller_pubkey_hash>
//!     OP_ELSE
//!         100 OP_CSV OP_DROP OP_DUP OP_HASH160 <buyer_pubkey_hash>
//!     OP_ENDIF
//!     OP_EQUALVERIFY
//!     OP_CHECKSIG
//! };
//! ```
//!
//! **NOTE:** As of rustc 1.41, the Rust compiler prevents using procedural
//! macros as expressions. To use this macro you'll need to be on nightly and
//! add `#![feature(proc_macro_hygiene)]` to the root of your crate. This will
//! be stablized in the near future, the PR can be found here:
//! https://github.com/rust-lang/rust/pull/68717
//!
//! ### Syntax
//!
//! Scripts are based on the standard syntax made up of opcodes, base-10
//! integers, or hex string literals. Additionally, Rust expressions can be
//! interpolated in order to support dynamically capturing Rust variables or
//! computing values (delimited by `<angle brackets>`).
//!
//! Whitespace is ignored - scripts can be formatted in the author's preferred
//! style.
//!
//! #### Opcodes
//!
//! All normal opcodes are available, in the form `OP_X`.
//!
//! ```rust
//! # use bitcoin_script::{script, define_pushable};
//! # define_pushable!();
//! let script = script!(OP_CHECKSIG OP_VERIFY);
//! ```
//!
//! #### Integer Literals
//!
//! Positive and negative 64-bit integer literals can be used, and will resolve to their most efficient encoding.
//!
//! For example:
//! -`2` will resolve to `OP_PUSHNUM_2` (`0x52`)
//! -`255` will resolve to a length-delimited varint: `0x02ff00` (note the extra zero byte, due to the way Bitcoin scripts use the most-significant bit to represent the sign)`
//!
//! ```rust
//! # use bitcoin_script::{script, define_pushable};
//! # define_pushable!();
//! let script = script!(123 -456 999999);
//! ```
//!
//! #### Hex Literals
//!
//! Hex strings can be specified, prefixed with `0x`.
//!
//! ```rust
//! # use bitcoin_script::{script, define_pushable};
//! # define_pushable!();
//! let script = script!(
//!     0x0102030405060708090a0b0c0d0e0f OP_HASH160
//! );
//! ```
//!
//! #### Escape Sequences
//!
//! Dynamic Rust expressions are supported inside the script, surrounded by rust delimiters (e.g. "{ }" or "( )"), angle brackets ("< >") or tilde ("~ ~"). In many cases, this will just be a variable identifier, but this can also be a function call, closure or arithmetic.
//!
//! Rust expressions of the following types are supported:
//!
//! - `i64`, `i32`, `u32`,
//! - `Vec<u8>`
//! - [`bitcoin::PublicKey`](https://docs.rs/bitcoin/latest/bitcoin/struct.PublicKey.html)
//! - [`bitcoin::ScriptBuf`](https://docs.rs/bitcoin/latest/bitcoin/blockdata/script/struct.ScriptBuf.html)
//! - And Vec<> variants of all the above types
//!
//!
//! ```rust
//! # use bitcoin_script::{script, define_pushable};
//! # define_pushable!();
//! let bytes = vec![1, 2, 3];
//!
//! let script = script! {
//!     <bytes> OP_CHECKSIGVERIFY
//!
//!     <2016 * 5> OP_CSV
//! };
//! ```

mod generate;
mod parse;

use generate::generate;
use parse::parse;
use proc_macro::TokenStream;
use proc_macro_error::{proc_macro_error, set_dummy};
use quote::quote;

#[proc_macro]
#[proc_macro_error]
pub fn script(tokens: TokenStream) -> TokenStream {
    set_dummy(quote!((::bitcoin::Script::new())));
    generate(parse(tokens.into())).into()
}

#[proc_macro]
pub fn define_pushable(_: TokenStream) -> TokenStream {
    quote!(
        pub mod pushable {

            use bitcoin::blockdata::opcodes::Opcode;
            use bitcoin::blockdata::script::{PushBytes, PushBytesBuf, ScriptBuf};
            use bitcoin::opcodes::{OP_0, OP_TRUE};
            use bitcoin::script::write_scriptint;
            use std::collections::HashMap;
            use std::convert::TryFrom;
            use std::hash::{DefaultHasher, Hash, Hasher};

            #[derive(Clone, Debug, Hash)]
            enum Block {
                Call(u64),
                Script(ScriptBuf),
            }

            impl Block {
                fn new_script() -> Self {
                    let buf = ScriptBuf::new();
                    Block::Script(buf)
                }
            }

            #[derive(Clone, Debug)]
            pub struct Builder {
                size: usize,
                blocks: Vec<Block>,
                // TODO: It may be worth to lazy initialize the script_map
                script_map: HashMap<u64, Builder>,
            }

            impl Hash for Builder {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    self.size.hash(state);
                    self.blocks.hash(state);
                }
            }

            fn calculate_hash<T: Hash>(t: &T) -> u64 {
                let mut hasher = DefaultHasher::new();
                t.hash(&mut hasher);
                hasher.finish()
            }

            impl Builder {
                pub fn new() -> Self {
                    let blocks = Vec::new();
                    Builder {
                        size: 0,
                        blocks,
                        script_map: HashMap::new(),
                    }
                }

                pub fn len(&self) -> usize {
                    self.size
                }

                fn get_script_block(&mut self) -> &mut ScriptBuf {
                    // Check if the last block is a Script block
                    let is_script_block = match self.blocks.last_mut() {
                        Some(Block::Script(_)) => true,
                        _ => false,
                    };

                    // Create a new Script block if necessary
                    if !is_script_block {
                        self.blocks.push(Block::new_script());
                    }

                    if let Some(Block::Script(ref mut script)) = self.blocks.last_mut() {
                        script
                    } else {
                        unreachable!()
                    }
                }

                pub fn push_opcode(mut self, data: Opcode) -> Builder {
                    self.size += 1;
                    let script = self.get_script_block();
                    script.push_opcode(data);
                    self
                }

                pub fn push_env_script(mut self, data: Builder) -> Builder {
                    self.size += data.size;
                    let id = calculate_hash(&data);
                    self.blocks.push(Block::Call(id));
                    // Register script
                    if !self.script_map.contains_key(&id) {
                        self.script_map.insert(id, data);
                    }
                    self
                }

                // Compiles the builder to bytes using a cache that stores all called_script starting
                // positions in script to copy them from script instead of recompiling.
                fn compile_to_bytes(&self, script: &mut Vec<u8>, cache: &mut HashMap<u64, usize>) {
                    for block in self.blocks.as_slice() {
                        match block {
                            Block::Call(id) => {
                                let called_script = self
                                    .script_map
                                    .get(id)
                                    .expect("Missing entry for a called script");
                                // Check if the script with the hash id is in cache
                                match cache.get(id) {
                                    Some(called_start) => {
                                        // Copy the already compiled called_script from the position it was
                                        // inserted in the compiled script.
                                        let start = script.len();
                                        let end = start + called_script.len();
                                        assert!(
                                            end <= script.capacity(),
                                            "Not enough capacity allocated for compilated script"
                                        );
                                        unsafe {
                                            script.set_len(end);

                                            let src_ptr = script.as_ptr().add(*called_start);
                                            let dst_ptr = script.as_mut_ptr().add(start);

                                            std::ptr::copy_nonoverlapping(
                                                src_ptr,
                                                dst_ptr,
                                                called_script.len(),
                                            );
                                        }
                                    }
                                    None => {
                                        // Compile the called_script the first time and add its starting
                                        // position in the compiled script to the cache.
                                        let called_script_start = script.len();
                                        called_script.compile_to_bytes(script, cache);
                                        cache.insert(*id, called_script_start);
                                    }
                                }
                            }
                            Block::Script(block_script) => {
                                let source_script = block_script.as_bytes();
                                let start = script.len();
                                let end = start + source_script.len();
                                assert!(
                                    end <= script.capacity(),
                                    "Not enough capacity allocated for compilated script"
                                );
                                unsafe {
                                    script.set_len(end);

                                    let src_ptr = source_script.as_ptr();
                                    let dst_ptr = script.as_mut_ptr().add(start);

                                    std::ptr::copy_nonoverlapping(
                                        src_ptr,
                                        dst_ptr,
                                        source_script.len(),
                                    );
                                }
                            }
                        }
                    }
                }

                pub fn compile(self) -> ScriptBuf {
                    let mut script = Vec::with_capacity(self.size);
                    let mut cache = HashMap::new();
                    self.compile_to_bytes(&mut script, &mut cache);
                    ScriptBuf::from_bytes(script)
                }
                
                pub fn compile_to_chunks(self) -> Vec<ScriptBuf> {
                    // Go through the builder and see where we could split
                    let tolerance = 20000;
                    let mut script = Vec::with_capacity(self.size);
                    let mut cache = HashMap::new();
                    self.compile_to_bytes(&mut script, &mut cache);
                    ScriptBuf::from_bytes(script)
                }

                pub fn push_int(self, data: i64) -> Builder {
                    // We can special-case -1, 1-16
                    if data == -1 || (1..=16).contains(&data) {
                        let opcode = Opcode::from((data - 1 + OP_TRUE.to_u8() as i64) as u8);
                        self.push_opcode(opcode)
                    }
                    // We can also special-case zero
                    else if data == 0 {
                        self.push_opcode(OP_0)
                    }
                    // Otherwise encode it as data
                    else {
                        self.push_int_non_minimal(data)
                    }
                }
                fn push_int_non_minimal(self, data: i64) -> Builder {
                    let mut buf = [0u8; 8];
                    let len = write_scriptint(&mut buf, data);
                    self.push_slice(&<&PushBytes>::from(&buf)[..len])
                }

                pub fn push_slice<T: AsRef<PushBytes>>(mut self, data: T) -> Builder {
                    let script = self.get_script_block();
                    let old_size = script.len();
                    script.push_slice(data);
                    self.size += script.len() - old_size;
                    self
                }

                pub fn push_key(self, key: &::bitcoin::PublicKey) -> Builder {
                    if key.compressed {
                        self.push_slice(key.inner.serialize())
                    } else {
                        self.push_slice(key.inner.serialize_uncompressed())
                    }
                }

                pub fn push_x_only_key(self, x_only_key: &::bitcoin::XOnlyPublicKey) -> Builder {
                    self.push_slice(x_only_key.serialize())
                }

                pub fn push_expression<T: Pushable>(self, expression: T) -> Builder {
                    let builder = expression.bitcoin_script_push(self);
                    builder
                }
            }

            // We split up the bitcoin_script_push function to allow pushing a single u8 value as
            // an integer (i64), Vec<u8> as raw data and Vec<T> for any T: Pushable object that is
            // not a u8. Otherwise the Vec<u8> and Vec<T: Pushable> definitions conflict.
            trait NotU8Pushable {
                fn bitcoin_script_push(self, builder: Builder) -> Builder;
            }
            impl NotU8Pushable for i64 {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_int(self)
                }
            }
            impl NotU8Pushable for i32 {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_int(self as i64)
                }
            }
            impl NotU8Pushable for u32 {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_int(self as i64)
                }
            }
            impl NotU8Pushable for usize {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_int(
                        i64::try_from(self).unwrap_or_else(|_| panic!("Usize does not fit in i64")),
                    )
                }
            }
            impl NotU8Pushable for Vec<u8> {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_slice(PushBytesBuf::try_from(self).unwrap())
                }
            }
            impl NotU8Pushable for ::bitcoin::PublicKey {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_key(&self)
                }
            }
            impl NotU8Pushable for ::bitcoin::XOnlyPublicKey {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_x_only_key(&self)
                }
            }
            impl NotU8Pushable for Builder {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_env_script(self)
                }
            }
            impl<T: NotU8Pushable> NotU8Pushable for Vec<T> {
                fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
                    for pushable in self {
                        builder = pushable.bitcoin_script_push(builder);
                    }
                    builder
                }
            }
            pub trait Pushable {
                fn bitcoin_script_push(self, builder: Builder) -> Builder;
            }
            impl<T: NotU8Pushable> Pushable for T {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    NotU8Pushable::bitcoin_script_push(self, builder)
                }
            }

            impl Pushable for u8 {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    builder.push_int(self as i64)
                }
            }
        }
    )
    .into()
}
