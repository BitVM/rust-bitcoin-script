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

            use bitcoin::blockdata::opcodes::{all::*, Opcode};
            use bitcoin::blockdata::script::Builder as BitcoinBuilder;
            use bitcoin::blockdata::script::{Instruction, PushBytes, PushBytesBuf, Script};
            use std::convert::TryFrom;

            pub struct Builder(pub BitcoinBuilder);

            impl Builder {
                pub fn new() -> Self {
                    let builder = BitcoinBuilder::new();
                    Builder(builder)
                }

                pub fn as_bytes(&self) -> &[u8] {
                    self.0.as_bytes()
                }

                pub fn as_script(&self) -> &Script {
                    self.0.as_script()
                }

                pub fn push_opcode(mut self, opcode: Opcode) -> Builder {
                    self.0 = self.0.push_opcode(opcode);
                    self
                }

                pub fn push_int(mut self, int: i64) -> Builder {
                    self.0 = self.0.push_int(int);
                    self
                }

                pub fn push_slice<T: AsRef<PushBytes>>(mut self, data: T) -> Builder {
                    self.0 = self.0.push_slice(data);
                    self
                }

                pub fn push_key(mut self, pub_key: &::bitcoin::PublicKey) -> Builder {
                    self.0 = self.0.push_key(pub_key);
                    self
                }

                pub fn push_x_only_key(
                    mut self,
                    x_only_key: &::bitcoin::XOnlyPublicKey,
                ) -> Builder {
                    self.0 = self.0.push_x_only_key(x_only_key);
                    self
                }

                pub fn push_expression<T: Pushable>(self, expression: T) -> Builder {
                    let builder = expression.bitcoin_script_push(self);
                    builder
                }
            }

            impl From<Vec<u8>> for Builder {
                fn from(v: Vec<u8>) -> Builder {
                    let builder = BitcoinBuilder::from(v);
                    Builder(builder)
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
            impl NotU8Pushable for ::bitcoin::ScriptBuf {
                fn bitcoin_script_push(self, builder: Builder) -> Builder {
                    let mut script_vec =
                        Vec::with_capacity(builder.0.as_bytes().len() + self.as_bytes().len());
                    script_vec.extend_from_slice(builder.as_bytes());
                    script_vec.extend_from_slice(self.as_bytes());
                    Builder::from(script_vec)
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
