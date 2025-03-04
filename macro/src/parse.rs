use bitcoin::hex::FromHex;
use bitcoin::{
    blockdata::opcodes::Opcode,
    opcodes::{all::*, OP_0, OP_FALSE, OP_NOP2, OP_NOP3, OP_TRUE},
};
use proc_macro2::{
    Delimiter, Span, TokenStream,
    TokenTree::{self, *},
};
use quote::quote;
use std::iter::Peekable;
use std::str::FromStr;

#[derive(Debug)]
pub enum Syntax {
    Opcode(Opcode),
    Escape(TokenStream),
    Bytes(Vec<u8>),
    Int(i64),
}

macro_rules! emit_error {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::emit_error!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);

        #[allow(unreachable_code)]
        {
            panic!();
        }
    }}
}

macro_rules! abort {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::abort!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);
    }}
}

/// Generates a function that parses a string into an [`Opcode`].
macro_rules! generate_opcode_parser {
    ($($op:ident => $val:expr, $doc:expr);*) => {
        fn parse_opcode(s: &str) -> Result<Opcode, ()> {
            match s {
                // Special cases with aliases
                "OP_0" => Ok(OP_0),
                "OP_TRUE" | "TRUE" => Ok(OP_TRUE),
                "OP_FALSE" | "FALSE" => Ok(OP_FALSE),
                "OP_NOP2" | "NOP2" => Ok(OP_NOP2),
                "OP_NOP3" | "NOP3" => Ok(OP_NOP3),
                "OP_1" => Ok(OP_PUSHNUM_1),
                "OP_2" => Ok(OP_PUSHNUM_2),
                "OP_3" => Ok(OP_PUSHNUM_3),
                "OP_4" => Ok(OP_PUSHNUM_4),
                "OP_5" => Ok(OP_PUSHNUM_5),
                "OP_6" => Ok(OP_PUSHNUM_6),
                "OP_7" => Ok(OP_PUSHNUM_7),
                "OP_8" => Ok(OP_PUSHNUM_8),
                "OP_9" => Ok(OP_PUSHNUM_9),
                "OP_10" => Ok(OP_PUSHNUM_10),
                "OP_11" => Ok(OP_PUSHNUM_11),
                "OP_12" => Ok(OP_PUSHNUM_12),
                "OP_13" => Ok(OP_PUSHNUM_13),
                "OP_14" => Ok(OP_PUSHNUM_14),
                "OP_15" => Ok(OP_PUSHNUM_15),
                "OP_16" => Ok(OP_PUSHNUM_16),
                $(
                    // For all other opcodes, match both with and without OP_ prefix
                    s if s == stringify!($op) || s == &stringify!($op)[3..] => Ok($op),
                )*
                _ => Err(()),
            }
        }
    }
}

generate_opcode_parser! {
    OP_PUSHBYTES_0 => 0x00, "Push an empty array onto the stack.";
    OP_PUSHBYTES_1 => 0x01, "Push the next byte as an array onto the stack.";
    OP_PUSHBYTES_2 => 0x02, "Push the next 2 bytes as an array onto the stack.";
    OP_PUSHBYTES_3 => 0x03, "Push the next 3 bytes as an array onto the stack.";
    OP_PUSHBYTES_4 => 0x04, "Push the next 4 bytes as an array onto the stack.";
    OP_PUSHBYTES_5 => 0x05, "Push the next 5 bytes as an array onto the stack.";
    OP_PUSHBYTES_6 => 0x06, "Push the next 6 bytes as an array onto the stack.";
    OP_PUSHBYTES_7 => 0x07, "Push the next 7 bytes as an array onto the stack.";
    OP_PUSHBYTES_8 => 0x08, "Push the next 8 bytes as an array onto the stack.";
    OP_PUSHBYTES_9 => 0x09, "Push the next 9 bytes as an array onto the stack.";
    OP_PUSHBYTES_10 => 0x0a, "Push the next 10 bytes as an array onto the stack.";
    OP_PUSHBYTES_11 => 0x0b, "Push the next 11 bytes as an array onto the stack.";
    OP_PUSHBYTES_12 => 0x0c, "Push the next 12 bytes as an array onto the stack.";
    OP_PUSHBYTES_13 => 0x0d, "Push the next 13 bytes as an array onto the stack.";
    OP_PUSHBYTES_14 => 0x0e, "Push the next 14 bytes as an array onto the stack.";
    OP_PUSHBYTES_15 => 0x0f, "Push the next 15 bytes as an array onto the stack.";
    OP_PUSHBYTES_16 => 0x10, "Push the next 16 bytes as an array onto the stack.";
    OP_PUSHBYTES_17 => 0x11, "Push the next 17 bytes as an array onto the stack.";
    OP_PUSHBYTES_18 => 0x12, "Push the next 18 bytes as an array onto the stack.";
    OP_PUSHBYTES_19 => 0x13, "Push the next 19 bytes as an array onto the stack.";
    OP_PUSHBYTES_20 => 0x14, "Push the next 20 bytes as an array onto the stack.";
    OP_PUSHBYTES_21 => 0x15, "Push the next 21 bytes as an array onto the stack.";
    OP_PUSHBYTES_22 => 0x16, "Push the next 22 bytes as an array onto the stack.";
    OP_PUSHBYTES_23 => 0x17, "Push the next 23 bytes as an array onto the stack.";
    OP_PUSHBYTES_24 => 0x18, "Push the next 24 bytes as an array onto the stack.";
    OP_PUSHBYTES_25 => 0x19, "Push the next 25 bytes as an array onto the stack.";
    OP_PUSHBYTES_26 => 0x1a, "Push the next 26 bytes as an array onto the stack.";
    OP_PUSHBYTES_27 => 0x1b, "Push the next 27 bytes as an array onto the stack.";
    OP_PUSHBYTES_28 => 0x1c, "Push the next 28 bytes as an array onto the stack.";
    OP_PUSHBYTES_29 => 0x1d, "Push the next 29 bytes as an array onto the stack.";
    OP_PUSHBYTES_30 => 0x1e, "Push the next 30 bytes as an array onto the stack.";
    OP_PUSHBYTES_31 => 0x1f, "Push the next 31 bytes as an array onto the stack.";
    OP_PUSHBYTES_32 => 0x20, "Push the next 32 bytes as an array onto the stack.";
    OP_PUSHBYTES_33 => 0x21, "Push the next 33 bytes as an array onto the stack.";
    OP_PUSHBYTES_34 => 0x22, "Push the next 34 bytes as an array onto the stack.";
    OP_PUSHBYTES_35 => 0x23, "Push the next 35 bytes as an array onto the stack.";
    OP_PUSHBYTES_36 => 0x24, "Push the next 36 bytes as an array onto the stack.";
    OP_PUSHBYTES_37 => 0x25, "Push the next 37 bytes as an array onto the stack.";
    OP_PUSHBYTES_38 => 0x26, "Push the next 38 bytes as an array onto the stack.";
    OP_PUSHBYTES_39 => 0x27, "Push the next 39 bytes as an array onto the stack.";
    OP_PUSHBYTES_40 => 0x28, "Push the next 40 bytes as an array onto the stack.";
    OP_PUSHBYTES_41 => 0x29, "Push the next 41 bytes as an array onto the stack.";
    OP_PUSHBYTES_42 => 0x2a, "Push the next 42 bytes as an array onto the stack.";
    OP_PUSHBYTES_43 => 0x2b, "Push the next 43 bytes as an array onto the stack.";
    OP_PUSHBYTES_44 => 0x2c, "Push the next 44 bytes as an array onto the stack.";
    OP_PUSHBYTES_45 => 0x2d, "Push the next 45 bytes as an array onto the stack.";
    OP_PUSHBYTES_46 => 0x2e, "Push the next 46 bytes as an array onto the stack.";
    OP_PUSHBYTES_47 => 0x2f, "Push the next 47 bytes as an array onto the stack.";
    OP_PUSHBYTES_48 => 0x30, "Push the next 48 bytes as an array onto the stack.";
    OP_PUSHBYTES_49 => 0x31, "Push the next 49 bytes as an array onto the stack.";
    OP_PUSHBYTES_50 => 0x32, "Push the next 50 bytes as an array onto the stack.";
    OP_PUSHBYTES_51 => 0x33, "Push the next 51 bytes as an array onto the stack.";
    OP_PUSHBYTES_52 => 0x34, "Push the next 52 bytes as an array onto the stack.";
    OP_PUSHBYTES_53 => 0x35, "Push the next 53 bytes as an array onto the stack.";
    OP_PUSHBYTES_54 => 0x36, "Push the next 54 bytes as an array onto the stack.";
    OP_PUSHBYTES_55 => 0x37, "Push the next 55 bytes as an array onto the stack.";
    OP_PUSHBYTES_56 => 0x38, "Push the next 56 bytes as an array onto the stack.";
    OP_PUSHBYTES_57 => 0x39, "Push the next 57 bytes as an array onto the stack.";
    OP_PUSHBYTES_58 => 0x3a, "Push the next 58 bytes as an array onto the stack.";
    OP_PUSHBYTES_59 => 0x3b, "Push the next 59 bytes as an array onto the stack.";
    OP_PUSHBYTES_60 => 0x3c, "Push the next 60 bytes as an array onto the stack.";
    OP_PUSHBYTES_61 => 0x3d, "Push the next 61 bytes as an array onto the stack.";
    OP_PUSHBYTES_62 => 0x3e, "Push the next 62 bytes as an array onto the stack.";
    OP_PUSHBYTES_63 => 0x3f, "Push the next 63 bytes as an array onto the stack.";
    OP_PUSHBYTES_64 => 0x40, "Push the next 64 bytes as an array onto the stack.";
    OP_PUSHBYTES_65 => 0x41, "Push the next 65 bytes as an array onto the stack.";
    OP_PUSHBYTES_66 => 0x42, "Push the next 66 bytes as an array onto the stack.";
    OP_PUSHBYTES_67 => 0x43, "Push the next 67 bytes as an array onto the stack.";
    OP_PUSHBYTES_68 => 0x44, "Push the next 68 bytes as an array onto the stack.";
    OP_PUSHBYTES_69 => 0x45, "Push the next 69 bytes as an array onto the stack.";
    OP_PUSHBYTES_70 => 0x46, "Push the next 70 bytes as an array onto the stack.";
    OP_PUSHBYTES_71 => 0x47, "Push the next 71 bytes as an array onto the stack.";
    OP_PUSHBYTES_72 => 0x48, "Push the next 72 bytes as an array onto the stack.";
    OP_PUSHBYTES_73 => 0x49, "Push the next 73 bytes as an array onto the stack.";
    OP_PUSHBYTES_74 => 0x4a, "Push the next 74 bytes as an array onto the stack.";
    OP_PUSHBYTES_75 => 0x4b, "Push the next 75 bytes as an array onto the stack.";
    OP_PUSHDATA1 => 0x4c, "Read the next byte as N; push the next N bytes as an array onto the stack.";
    OP_PUSHDATA2 => 0x4d, "Read the next 2 bytes as N; push the next N bytes as an array onto the stack.";
    OP_PUSHDATA4 => 0x4e, "Read the next 4 bytes as N; push the next N bytes as an array onto the stack.";
    OP_PUSHNUM_NEG1 => 0x4f, "Push the array `0x81` onto the stack.";
    OP_RESERVED => 0x50, "Synonym for OP_RETURN.";
    OP_PUSHNUM_1 => 0x51, "Push the array `0x01` onto the stack.";
    OP_PUSHNUM_2 => 0x52, "Push the array `0x02` onto the stack.";
    OP_PUSHNUM_3 => 0x53, "Push the array `0x03` onto the stack.";
    OP_PUSHNUM_4 => 0x54, "Push the array `0x04` onto the stack.";
    OP_PUSHNUM_5 => 0x55, "Push the array `0x05` onto the stack.";
    OP_PUSHNUM_6 => 0x56, "Push the array `0x06` onto the stack.";
    OP_PUSHNUM_7 => 0x57, "Push the array `0x07` onto the stack.";
    OP_PUSHNUM_8 => 0x58, "Push the array `0x08` onto the stack.";
    OP_PUSHNUM_9 => 0x59, "Push the array `0x09` onto the stack.";
    OP_PUSHNUM_10 => 0x5a, "Push the array `0x0a` onto the stack.";
    OP_PUSHNUM_11 => 0x5b, "Push the array `0x0b` onto the stack.";
    OP_PUSHNUM_12 => 0x5c, "Push the array `0x0c` onto the stack.";
    OP_PUSHNUM_13 => 0x5d, "Push the array `0x0d` onto the stack.";
    OP_PUSHNUM_14 => 0x5e, "Push the array `0x0e` onto the stack.";
    OP_PUSHNUM_15 => 0x5f, "Push the array `0x0f` onto the stack.";
    OP_PUSHNUM_16 => 0x60, "Push the array `0x10` onto the stack.";
    OP_NOP => 0x61, "Does nothing.";
    OP_VER => 0x62, "Synonym for OP_RETURN.";
    OP_IF => 0x63, "Pop and execute the next statements if a nonzero element was popped.";
    OP_NOTIF => 0x64, "Pop and execute the next statements if a zero element was popped.";
    OP_VERIF => 0x65, "Fail the script unconditionally, does not even need to be executed.";
    OP_VERNOTIF => 0x66, "Fail the script unconditionally, does not even need to be executed.";
    OP_ELSE => 0x67, "Execute statements if those after the previous OP_IF were not, and vice-versa. \
             If there is no previous OP_IF, this acts as a RETURN.";
    OP_ENDIF => 0x68, "Pop and execute the next statements if a zero element was popped.";
    OP_VERIFY => 0x69, "If the top value is zero or the stack is empty, fail; otherwise, pop the stack.";
    OP_RETURN => 0x6a, "Fail the script immediately. (Must be executed.).";
    OP_TOALTSTACK => 0x6b, "Pop one element from the main stack onto the alt stack.";
    OP_FROMALTSTACK => 0x6c, "Pop one element from the alt stack onto the main stack.";
    OP_2DROP => 0x6d, "Drops the top two stack items.";
    OP_2DUP => 0x6e, "Duplicates the top two stack items as AB -> ABAB.";
    OP_3DUP => 0x6f, "Duplicates the two three stack items as ABC -> ABCABC.";
    OP_2OVER => 0x70, "Copies the two stack items of items two spaces back to the front, as xxAB -> ABxxAB.";
    OP_2ROT => 0x71, "Moves the two stack items four spaces back to the front, as xxxxAB -> ABxxxx.";
    OP_2SWAP => 0x72, "Swaps the top two pairs, as ABCD -> CDAB.";
    OP_IFDUP => 0x73, "Duplicate the top stack element unless it is zero.";
    OP_DEPTH => 0x74, "Push the current number of stack items onto the stack.";
    OP_DROP => 0x75, "Drops the top stack item.";
    OP_DUP => 0x76, "Duplicates the top stack item.";
    OP_NIP => 0x77, "Drops the second-to-top stack item.";
    OP_OVER => 0x78, "Copies the second-to-top stack item, as xA -> AxA.";
    OP_PICK => 0x79, "Pop the top stack element as N. Copy the Nth stack element to the top.";
    OP_ROLL => 0x7a, "Pop the top stack element as N. Move the Nth stack element to the top.";
    OP_ROT => 0x7b, "Rotate the top three stack items, as [top next1 next2] -> [next2 top next1].";
    OP_SWAP => 0x7c, "Swap the top two stack items.";
    OP_TUCK => 0x7d, "Copy the top stack item to before the second item, as [top next] -> [top next top].";
    OP_CAT => 0x7e, "Fail the script unconditionally, does not even need to be executed.";
    OP_SUBSTR => 0x7f, "Fail the script unconditionally, does not even need to be executed.";
    OP_LEFT => 0x80, "Fail the script unconditionally, does not even need to be executed.";
    OP_RIGHT => 0x81, "Fail the script unconditionally, does not even need to be executed.";
    OP_SIZE => 0x82, "Pushes the length of the top stack item onto the stack.";
    OP_INVERT => 0x83, "Fail the script unconditionally, does not even need to be executed.";
    OP_AND => 0x84, "Fail the script unconditionally, does not even need to be executed.";
    OP_OR => 0x85, "Fail the script unconditionally, does not even need to be executed.";
    OP_XOR => 0x86, "Fail the script unconditionally, does not even need to be executed.";
    OP_EQUAL => 0x87, "Pushes 1 if the inputs are exactly equal, 0 otherwise.";
    OP_EQUALVERIFY => 0x88, "Returns success if the inputs are exactly equal, failure otherwise.";
    OP_RESERVED1 => 0x89, "Synonym for OP_RETURN.";
    OP_RESERVED2 => 0x8a, "Synonym for OP_RETURN.";
    OP_1ADD => 0x8b, "Increment the top stack element in place.";
    OP_1SUB => 0x8c, "Decrement the top stack element in place.";
    OP_2MUL => 0x8d, "Fail the script unconditionally, does not even need to be executed.";
    OP_2DIV => 0x8e, "Fail the script unconditionally, does not even need to be executed.";
    OP_NEGATE => 0x8f, "Multiply the top stack item by -1 in place.";
    OP_ABS => 0x90, "Absolute value the top stack item in place.";
    OP_NOT => 0x91, "Map 0 to 1 and everything else to 0, in place.";
    OP_0NOTEQUAL => 0x92, "Map 0 to 0 and everything else to 1, in place.";
    OP_ADD => 0x93, "Pop two stack items and push their sum.";
    OP_SUB => 0x94, "Pop two stack items and push the second minus the top.";
    OP_MUL => 0x95, "Fail the script unconditionally, does not even need to be executed.";
    OP_DIV => 0x96, "Fail the script unconditionally, does not even need to be executed.";
    OP_MOD => 0x97, "Fail the script unconditionally, does not even need to be executed.";
    OP_LSHIFT => 0x98, "Fail the script unconditionally, does not even need to be executed.";
    OP_RSHIFT => 0x99, "Fail the script unconditionally, does not even need to be executed.";
    OP_BOOLAND => 0x9a, "Pop the top two stack items and push 1 if both are nonzero, else push 0.";
    OP_BOOLOR => 0x9b, "Pop the top two stack items and push 1 if either is nonzero, else push 0.";
    OP_NUMEQUAL => 0x9c, "Pop the top two stack items and push 1 if both are numerically equal, else push 0.";
    OP_NUMEQUALVERIFY => 0x9d, "Pop the top two stack items and return success if both are numerically equal, else return failure.";
    OP_NUMNOTEQUAL => 0x9e, "Pop the top two stack items and push 0 if both are numerically equal, else push 1.";
    OP_LESSTHAN  => 0x9f, "Pop the top two items; push 1 if the second is less than the top, 0 otherwise.";
    OP_GREATERTHAN  => 0xa0, "Pop the top two items; push 1 if the second is greater than the top, 0 otherwise.";
    OP_LESSTHANOREQUAL  => 0xa1, "Pop the top two items; push 1 if the second is <= the top, 0 otherwise.";
    OP_GREATERTHANOREQUAL  => 0xa2, "Pop the top two items; push 1 if the second is >= the top, 0 otherwise.";
    OP_MIN => 0xa3, "Pop the top two items; push the smaller.";
    OP_MAX => 0xa4, "Pop the top two items; push the larger.";
    OP_WITHIN => 0xa5, "Pop the top three items; if the top is >= the second and < the third, push 1, otherwise push 0.";
    OP_RIPEMD160 => 0xa6, "Pop the top stack item and push its RIPEMD160 hash.";
    OP_SHA1 => 0xa7, "Pop the top stack item and push its SHA1 hash.";
    OP_SHA256 => 0xa8, "Pop the top stack item and push its SHA256 hash.";
    OP_HASH160 => 0xa9, "Pop the top stack item and push its RIPEMD(SHA256) hash.";
    OP_HASH256 => 0xaa, "Pop the top stack item and push its SHA256(SHA256) hash.";
    OP_CODESEPARATOR => 0xab, "Ignore this and everything preceding when deciding what to sign when signature-checking.";
    OP_CHECKSIG => 0xac, "<https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for success/failure.";
    OP_CHECKSIGVERIFY => 0xad, "<https://en.bitcoin.it/wiki/OP_CHECKSIG> returning success/failure.";
    OP_CHECKMULTISIG => 0xae, "Pop N, N pubkeys, M, M signatures, a dummy (due to bug in reference code), \
                      and verify that all M signatures are valid. Push 1 for 'all valid', 0 otherwise.";
    OP_CHECKMULTISIGVERIFY => 0xaf, "Like the above but return success/failure.";
    OP_NOP1 => 0xb0, "Does nothing.";
    OP_CLTV => 0xb1, "<https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>";
    OP_CSV => 0xb2, "<https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki>";
    OP_NOP4 => 0xb3, "Does nothing.";
    OP_NOP5 => 0xb4, "Does nothing.";
    OP_NOP6 => 0xb5, "Does nothing.";
    OP_NOP7 => 0xb6, "Does nothing.";
    OP_NOP8 => 0xb7, "Does nothing.";
    OP_NOP9 => 0xb8, "Does nothing.";
    OP_NOP10 => 0xb9, "Does nothing.";
    // Every other opcode acts as OP_RETURN
    OP_CHECKSIGADD => 0xba, "OP_CHECKSIGADD post tapscript.";
    OP_RETURN_187 => 0xbb, "Synonym for OP_RETURN.";
    OP_RETURN_188 => 0xbc, "Synonym for OP_RETURN.";
    OP_RETURN_189 => 0xbd, "Synonym for OP_RETURN.";
    OP_RETURN_190 => 0xbe, "Synonym for OP_RETURN.";
    OP_RETURN_191 => 0xbf, "Synonym for OP_RETURN.";
    OP_RETURN_192 => 0xc0, "Synonym for OP_RETURN.";
    OP_RETURN_193 => 0xc1, "Synonym for OP_RETURN.";
    OP_RETURN_194 => 0xc2, "Synonym for OP_RETURN.";
    OP_RETURN_195 => 0xc3, "Synonym for OP_RETURN.";
    OP_RETURN_196 => 0xc4, "Synonym for OP_RETURN.";
    OP_RETURN_197 => 0xc5, "Synonym for OP_RETURN.";
    OP_RETURN_198 => 0xc6, "Synonym for OP_RETURN.";
    OP_RETURN_199 => 0xc7, "Synonym for OP_RETURN.";
    OP_RETURN_200 => 0xc8, "Synonym for OP_RETURN.";
    OP_RETURN_201 => 0xc9, "Synonym for OP_RETURN.";
    OP_RETURN_202 => 0xca, "Synonym for OP_RETURN.";
    OP_RETURN_203 => 0xcb, "Synonym for OP_RETURN.";
    OP_RETURN_204 => 0xcc, "Synonym for OP_RETURN.";
    OP_RETURN_205 => 0xcd, "Synonym for OP_RETURN.";
    OP_RETURN_206 => 0xce, "Synonym for OP_RETURN.";
    OP_RETURN_207 => 0xcf, "Synonym for OP_RETURN.";
    OP_RETURN_208 => 0xd0, "Synonym for OP_RETURN.";
    OP_RETURN_209 => 0xd1, "Synonym for OP_RETURN.";
    OP_RETURN_210 => 0xd2, "Synonym for OP_RETURN.";
    OP_RETURN_211 => 0xd3, "Synonym for OP_RETURN.";
    OP_RETURN_212 => 0xd4, "Synonym for OP_RETURN.";
    OP_RETURN_213 => 0xd5, "Synonym for OP_RETURN.";
    OP_RETURN_214 => 0xd6, "Synonym for OP_RETURN.";
    OP_RETURN_215 => 0xd7, "Synonym for OP_RETURN.";
    OP_RETURN_216 => 0xd8, "Synonym for OP_RETURN.";
    OP_RETURN_217 => 0xd9, "Synonym for OP_RETURN.";
    OP_RETURN_218 => 0xda, "Synonym for OP_RETURN.";
    OP_RETURN_219 => 0xdb, "Synonym for OP_RETURN.";
    OP_RETURN_220 => 0xdc, "Synonym for OP_RETURN.";
    OP_RETURN_221 => 0xdd, "Synonym for OP_RETURN.";
    OP_RETURN_222 => 0xde, "Synonym for OP_RETURN.";
    OP_RETURN_223 => 0xdf, "Synonym for OP_RETURN.";
    OP_RETURN_224 => 0xe0, "Synonym for OP_RETURN.";
    OP_RETURN_225 => 0xe1, "Synonym for OP_RETURN.";
    OP_RETURN_226 => 0xe2, "Synonym for OP_RETURN.";
    OP_RETURN_227 => 0xe3, "Synonym for OP_RETURN.";
    OP_RETURN_228 => 0xe4, "Synonym for OP_RETURN.";
    OP_RETURN_229 => 0xe5, "Synonym for OP_RETURN.";
    OP_RETURN_230 => 0xe6, "Synonym for OP_RETURN.";
    OP_RETURN_231 => 0xe7, "Synonym for OP_RETURN.";
    OP_RETURN_232 => 0xe8, "Synonym for OP_RETURN.";
    OP_RETURN_233 => 0xe9, "Synonym for OP_RETURN.";
    OP_RETURN_234 => 0xea, "Synonym for OP_RETURN.";
    OP_RETURN_235 => 0xeb, "Synonym for OP_RETURN.";
    OP_RETURN_236 => 0xec, "Synonym for OP_RETURN.";
    OP_RETURN_237 => 0xed, "Synonym for OP_RETURN.";
    OP_RETURN_238 => 0xee, "Synonym for OP_RETURN.";
    OP_RETURN_239 => 0xef, "Synonym for OP_RETURN.";
    OP_RETURN_240 => 0xf0, "Synonym for OP_RETURN.";
    OP_RETURN_241 => 0xf1, "Synonym for OP_RETURN.";
    OP_RETURN_242 => 0xf2, "Synonym for OP_RETURN.";
    OP_RETURN_243 => 0xf3, "Synonym for OP_RETURN.";
    OP_RETURN_244 => 0xf4, "Synonym for OP_RETURN.";
    OP_RETURN_245 => 0xf5, "Synonym for OP_RETURN.";
    OP_RETURN_246 => 0xf6, "Synonym for OP_RETURN.";
    OP_RETURN_247 => 0xf7, "Synonym for OP_RETURN.";
    OP_RETURN_248 => 0xf8, "Synonym for OP_RETURN.";
    OP_RETURN_249 => 0xf9, "Synonym for OP_RETURN.";
    OP_RETURN_250 => 0xfa, "Synonym for OP_RETURN.";
    OP_RETURN_251 => 0xfb, "Synonym for OP_RETURN.";
    OP_RETURN_252 => 0xfc, "Synonym for OP_RETURN.";
    OP_RETURN_253 => 0xfd, "Synonym for OP_RETURN.";
    OP_RETURN_254 => 0xfe, "Synonym for OP_RETURN.";
    OP_INVALIDOPCODE => 0xff, "Synonym for OP_RETURN."
}

pub fn parse(tokens: TokenStream) -> Vec<(Syntax, Span)> {
    let mut tokens = tokens.into_iter().peekable();
    let mut syntax = Vec::with_capacity(2048);

    while let Some(token) = tokens.next() {
        let token_str = token.to_string();
        syntax.push(match (&token, token_str.as_ref()) {
            // Wrap for loops such that they return a Vec<ScriptBuf>
            (Ident(_), "for") => parse_for_loop(token, &mut tokens),
            // Wrap if-else statements such that they return a Vec<ScriptBuf>
            (Ident(_), "if") => parse_if(token, &mut tokens),
            // Replace DEBUG with OP_RESERVED
            (Ident(_), "DEBUG") => (Syntax::Opcode(OP_RESERVED), token.span()),

            // identifier, look up opcode
            (Ident(_), _) => match parse_opcode(&token_str) {
                Ok(opcode) => (Syntax::Opcode(opcode), token.span()),
                Err(_) => {
                    let span = token.span();
                    let mut pseudo_stream = TokenStream::from(token);
                    pseudo_stream.extend(TokenStream::from_str("()"));
                    (Syntax::Escape(pseudo_stream), span)
                }
            },

            (Group(inner), _) => {
                let escape = inner.stream().clone();
                (Syntax::Escape(escape), token.span())
            }

            // '<', start of escape (parse until first '>')
            (Punct(_), "<") => parse_escape(token, &mut tokens),

            // '~' start of escape (parse until the next '~') ignores '<' and '>'
            (Punct(_), "~") => parse_escape_extra(token, &mut tokens),

            // literal, push data (int or bytes)
            (Literal(_), _) => parse_data(token),

            // negative sign, parse negative int
            (Punct(_), "-") => parse_negative_int(token, &mut tokens),

            // anything else is invalid
            _ => abort!(token.span(), "unexpected token"),
        });
    }
    syntax
}

fn parse_if<T>(token: TokenTree, tokens: &mut Peekable<T>) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    // Use a Vec here to get rid of warnings when the variable is overwritten
    let mut escape = quote! {
        let mut script_var = bitcoin_script::Script::new("if");
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(if_token) = tokens.next() {
        match if_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        script_var = script_var.push_env_script(script! {
                            #inner_block
                        });
                    }
                });

                match tokens.peek() {
                    Some(else_token) if else_token.to_string().as_str() == "else" => continue,
                    _ => break,
                }
            }
            _ => {
                escape.extend(std::iter::once(if_token));
                continue;
            }
        };
    }
    escape = quote! {
        {
            #escape;
            script_var
        }
    };
    (Syntax::Escape(escape), token.span())
}

fn parse_for_loop<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = quote! {
        let mut script_var = bitcoin_script::Script::new("for");
    };
    escape.extend(std::iter::once(token.clone()));

    for for_token in tokens.by_ref() {
        match for_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        script_var = script_var.push_env_script(script !{
                            #inner_block
                        });
                    }
                    script_var
                });
                break;
            }
            _ => {
                escape.extend(std::iter::once(for_token));
                continue;
            }
        };
    }

    (Syntax::Escape(quote! { { #escape } }), token.span())
}

fn parse_escape<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), ">") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_escape_extra<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), "~") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_data(token: TokenTree) -> (Syntax, Span) {
    if token.to_string().starts_with("0x") {
        if token
            .to_string()
            .strip_prefix("0x")
            .unwrap_or_else(|| unreachable!())
            .trim_start_matches('0')
            .len()
            <= 8
        {
            parse_hex_int(token)
        } else {
            parse_bytes(token)
        }
    } else {
        parse_int(token, false)
    }
}

fn parse_bytes(token: TokenTree) -> (Syntax, Span) {
    let hex_bytes = &token.to_string()[2..];
    let bytes = Vec::<u8>::from_hex(hex_bytes).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex literal ({})", err);
    });
    (Syntax::Bytes(bytes), token.span())
}

fn parse_hex_int(token: TokenTree) -> (Syntax, Span) {
    let token_str = &token.to_string()[2..];
    let n: u32 = u32::from_str_radix(token_str, 16).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex string ({})", err);
    });
    (Syntax::Int(n as i64), token.span())
}

fn parse_int(token: TokenTree, negative: bool) -> (Syntax, Span) {
    let token_str = token.to_string();
    let n: i64 = token_str.parse().unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid number literal ({})", err);
    });
    let n = if negative { -n } else { n };
    (Syntax::Int(n), token.span())
}

fn parse_negative_int<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let fail = || {
        #[allow(unused_variables)]
        let span = token.span();
        emit_error!(
            span,
            "expected negative sign to be followed by number literal"
        );
    };

    let maybe_token = tokens.next();

    if let Some(token) = maybe_token {
        if let Literal(_) = token {
            parse_int(token, true)
        } else {
            fail()
        }
    } else {
        fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::opcodes::all as opcodes;
    use quote::quote;

    macro_rules! test_opcode {
        ($name:ident, $input:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let syntax = parse(quote!($input));
                if let Syntax::Opcode(opcode) = &syntax[0].0 {
                    assert_eq!(*opcode, $expected);
                } else {
                    panic!("Expected Syntax::Opcode, got {:?}", syntax[0].0);
                }
            }
        };
    }

    macro_rules! test_invalid_opcode {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let syntax = parse(quote!($input));
                assert!(matches!(syntax[0].0, Syntax::Escape(_)));
            }
        };
    }

    #[test]
    fn parse_empty() {
        assert!(parse(quote!()).is_empty());
    }

    #[test]
    #[should_panic(expected = "unexpected token")]
    fn parse_unexpected_token() {
        parse(quote!(OP_CHECKSIG &));
    }

    //#[test]
    //#[should_panic(expected = "unknown opcode \"A\"")]
    //fn parse_invalid_opcode() {
    //    parse(quote!(OP_CHECKSIG A B));
    //}

    // Basic opcode tests
    test_opcode!(parse_op_0, OP_0, OP_0);
    test_opcode!(parse_op_false, FALSE, OP_FALSE);
    test_opcode!(parse_op_true, TRUE, OP_TRUE);
    test_opcode!(parse_op_checksig, OP_CHECKSIG, OP_CHECKSIG);
    test_opcode!(parse_op_hash160, OP_HASH160, OP_HASH160);

    // Test numeric opcodes
    test_opcode!(parse_op_1, OP_1, OP_PUSHNUM_1);
    test_opcode!(parse_op_2, OP_2, OP_PUSHNUM_2);
    test_opcode!(parse_op_3, OP_3, OP_PUSHNUM_3);
    test_opcode!(parse_op_16, OP_16, OP_PUSHNUM_16);

    // Test aliases
    test_opcode!(parse_checksig_no_prefix, CHECKSIG, OP_CHECKSIG);
    test_opcode!(parse_hash160_no_prefix, HASH160, OP_HASH160);

    // Test special cases
    test_opcode!(parse_nop2, OP_NOP2, OP_CLTV);
    test_opcode!(parse_nop3, OP_NOP3, OP_CSV);
    test_opcode!(parse_debug, DEBUG, OP_RESERVED);

    // Test invalid opcodes
    test_invalid_opcode!(parse_invalid_opcode, INVALID_OPCODE);
    test_invalid_opcode!(parse_unknown_identifier, UNKNOWN);

    // Test complex scripts
    #[test]
    fn parse_complex_script() {
        let syntax = parse(quote! {
            OP_DUP OP_HASH160 0x14 0x89abcdef89abcdef89abcdef89abcdef89abcdef OP_EQUALVERIFY OP_CHECKSIG
        });

        assert_eq!(syntax.len(), 6);
        assert!(matches!(syntax[0].0, Syntax::Opcode(OP_DUP)));
        assert!(matches!(syntax[1].0, Syntax::Opcode(OP_HASH160)));
        assert!(matches!(syntax[2].0, Syntax::Int(20))); // 0x14 = 20
        assert!(matches!(syntax[3].0, Syntax::Bytes(_)));
        assert!(matches!(syntax[4].0, Syntax::Opcode(OP_EQUALVERIFY)));
        assert!(matches!(syntax[5].0, Syntax::Opcode(OP_CHECKSIG)));
    }

    #[test]
    fn parse_p2pkh_script() {
        let syntax = parse(quote! {
            OP_DUP
            OP_HASH160
            <pubkey_hash>
            OP_EQUALVERIFY
            OP_CHECKSIG
        });

        assert_eq!(syntax.len(), 5);
        assert!(matches!(syntax[0].0, Syntax::Opcode(OP_DUP)));
        assert!(matches!(syntax[1].0, Syntax::Opcode(OP_HASH160)));
        assert!(matches!(syntax[2].0, Syntax::Escape(_)));
        assert!(matches!(syntax[3].0, Syntax::Opcode(OP_EQUALVERIFY)));
        assert!(matches!(syntax[4].0, Syntax::Opcode(OP_CHECKSIG)));
    }

    #[test]
    fn parse_opcodes() {
        let syntax = parse(quote!(OP_CHECKSIG OP_HASH160));

        if let Syntax::Opcode(opcode) = syntax[0].0 {
            assert_eq!(opcode, opcodes::OP_CHECKSIG);
        } else {
            panic!();
        }

        if let Syntax::Opcode(opcode) = syntax[1].0 {
            assert_eq!(opcode, opcodes::OP_HASH160);
        } else {
            panic!();
        }
    }

    #[test]
    #[should_panic(expected = "unterminated escape")]
    fn parse_unterminated_escape() {
        parse(quote!(OP_CHECKSIG < abc));
    }

    #[test]
    fn parse_escape() {
        let syntax = parse(quote!(OP_CHECKSIG<abc>));

        if let Syntax::Escape(tokens) = &syntax[1].0 {
            let tokens = tokens.clone().into_iter().collect::<Vec<TokenTree>>();

            assert_eq!(tokens.len(), 1);
            if let TokenTree::Ident(_) = tokens[0] {
                assert_eq!(tokens[0].to_string(), "abc");
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "invalid number literal (invalid digit found in string)")]
    fn parse_invalid_int() {
        parse(quote!(OP_CHECKSIG 12g34));
    }

    #[test]
    fn parse_int() {
        let syntax = parse(quote!(OP_CHECKSIG 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, 1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "expected negative sign to be followed by number literal")]
    fn parse_invalid_negative_sign() {
        parse(quote!(OP_CHECKSIG - OP_HASH160));
    }

    #[test]
    fn parse_negative_int() {
        let syntax = parse(quote!(OP_CHECKSIG - 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, -1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    fn parse_hex() {
        let syntax = parse(quote!(OP_CHECKSIG 0x123456789abcde));

        if let Syntax::Bytes(bytes) = &syntax[1].0 {
            assert_eq!(bytes, &vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        } else {
            panic!("Unable to cast Syntax as Syntax::Bytes")
        }
    }
}
