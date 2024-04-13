#![feature(proc_macro_hygiene)]

use bitcoin::{opcodes::all::OP_ADD, ScriptBuf};
use bitcoin_script::{define_pushable, script};

define_pushable!();

#[test]
fn test_generic() {
    let foo = vec![1, 2, 3, 4];
    let script = script! (
        OP_HASH160
        1234
        255
        -1
        -255
        0xabcd
        {1 + 1}
        {foo}
    );

    assert_eq!(
        script.to_bytes(),
        vec![169, 2, 210, 4, 2, 255, 0, 79, 2, 255, 128, 3, 205, 171, 0, 82, 81, 82, 83, 84]
    );
}

#[test]
fn test_pushable_vectors() {
    let byte_vec = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
    let script_vec = vec![
        script! {
            OP_ADD
        },
        script! {
            OP_TRUE
            OP_FALSE
        },
    ];

    let script = script! (
        {byte_vec}
        {script_vec}
    );

    assert_eq!(
        script.to_bytes(),
        vec![81, 82, 83, 84, 85, 86, 87, 88, 147, 81, 0]
    );
}

#[test]
#[should_panic]
fn test_usize_conversion() {
    let usize_value: usize = 0xFFFFFFFFFFFFFFFF;

    let _script = script!({ usize_value });
}

#[test]
fn test_minimal_byte_opcode() {
    let script = script! (
        0x00
        0x0
        0x1
        0x02
        0x3
        0x04
        0x5
        0x06
        0x7
        0x08
        0x9
        0x10
        0x11
        0xd2
        { 0xd2 }
    );

    assert_eq!(
        script.to_bytes(),
        vec![0, 0, 81, 82, 83, 84, 85, 86, 87, 88, 89, 96, 1, 17, 2, 210, 0, 2, 210, 0]
    );
}

fn script_from_func() -> ScriptBuf {
    return script! { OP_ADD };
}

#[test]
fn test_for_loop() {
    let script = script! {
        for i in 0..3 {
            for k in 0..(3 as u32) {
            OP_ADD
            script_from_func
            OP_SWAP
            { i }
            { k }
            }
        }
        OP_ADD
    };

    assert_eq!(
        script.to_bytes(),
        vec![
            147, 147, 124, 0, 0, 147, 147, 124, 0, 81, 147, 147, 124, 0, 82, 147, 147, 124, 81, 0,
            147, 147, 124, 81, 81, 147, 147, 124, 81, 82, 147, 147, 124, 82, 0, 147, 147, 124, 82,
            81, 147, 147, 124, 82, 82, 147
        ]
    );
}

#[test]
fn test_if() {
    let script = script! {
            if true {
                if false {
                    OP_1
                    OP_2
                } else {
                    OP_3
                }
            } else {
                OP_4
            }

            if true {
                OP_5
            } else if false {
                OP_6
            } else {
                OP_7
            }
    };

    assert_eq!(script.to_bytes(), vec![83, 85]);
}

#[test]
fn test_performance_loop() {
    let loop_script = script! {
        OP_ADD
        OP_ADD
        OP_ADD
    };

    let script = script! {
        for _ in 0..5_000_000 {
            { loop_script.clone() }
        }
    };

    assert_eq!(script.as_bytes()[5_000_000 - 1], 147)
}

#[test]
fn test_performance_no_macro() {
    let mut builder = bitcoin::script::Builder::new();
    for _ in 0..40_000_000 {
        builder = builder.push_opcode(OP_ADD);
    }

    let script = builder.as_script();
    assert_eq!(script.as_bytes()[40_000_000 - 1], 147);
}

#[test]
fn test_performance_if() {
    let script = script! {
        for _ in 0..5_000_000 {
            if true {
                OP_ADD
                OP_ADD
            } else {
                OP_ADD
            }
        }
    };

    assert_eq!(script.as_bytes()[5_000_000 - 1], 147)
}

#[test]
fn test_simple() {
    pub mod pushable {

        use bitcoin::blockdata::opcodes::{all::*, Opcode};
        use bitcoin::blockdata::script::Builder as BitcoinBuilder;
        use bitcoin::blockdata::script::{PushBytesBuf, Script};
        use std::convert::TryFrom;

        pub struct Builder(pub BitcoinBuilder);

        pub fn check_optimality(opcode: Opcode, next_opcode: Opcode) {
            if opcode == OP_PUSHBYTES_0 {
                eprintln!("Encountered OP_PUSHBYTES_0 but opcode is {:?}", opcode);
            }
            eprintln!("last opcode: {:?} next_opcode: {:?}", opcode, next_opcode);
            match (opcode, next_opcode) {
                (OP_PUSHNUM_1, OP_ADD) => eprintln!("Script can be optimized: 1 OP_ADD => OP_1ADD"),
                (OP_PUSHNUM_1, OP_SUB) => eprintln!("Script can be optimized: 1 OP_SUB => OP_1SUB"),
                (OP_DROP, OP_DROP) => {
                    eprintln!("Script can be optimized: OP_DROP OP_DROP => OP_2DROP")
                }
                (OP_PUSHBYTES_0, OP_ROLL) => eprintln!("Script can be optimized: Remove 0 OP_ROLL"),
                (OP_PUSHNUM_1, OP_ROLL) => {
                    eprintln!("Script can be optimized: 1 OP_ROLL => OP_SWAP")
                }
                (OP_PUSHNUM_2, OP_ROLL) => {
                    eprintln!("Script can be optimized: 2 OP_ROLL => OP_ROT")
                }
                (OP_PUSHBYTES_0, OP_PICK) => {
                    eprintln!("Script can be optimized: 0 OP_PICK => OP_DUP")
                }
                (OP_PUSHBYTES_1, OP_PICK) => {
                    eprintln!("Script can be optimized: 1 OP_PICK => OP_OVER")
                }
                (OP_IF, OP_ELSE) => eprintln!("Script can be optimized: OP_IF OP_ELSE => OP_NOTIF"),
                (_, _) => (),
            }
        }

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
                match self.as_script().instructions_minimal().last() {
                    Some(instr_result) => match instr_result {
                        Ok(instr) => match instr {
                            bitcoin::script::Instruction::PushBytes(push_bytes) => {
                                if push_bytes.as_bytes() == [] {
                                    check_optimality(::bitcoin::opcodes::all::OP_PUSHBYTES_0, opcode)
                                }
                            },
                            bitcoin::script::Instruction::Op(previous_opcode) => {
                                check_optimality(previous_opcode, opcode)
                            }
                        },
                        Err(_) => eprintln!("Script includes non-minimal pushes."),
                    },
                    None => (),
                };
                self.0 = self.0.push_opcode(opcode);
                self
            }

            pub fn push_int(mut self, int: i64) -> Builder {
                self.0 = self.0.push_int(int);
                self
            }

            pub fn push_slice(mut self, slice: PushBytesBuf) -> Builder {
                self.0 = self.0.push_slice(slice);
                self
            }

            pub fn push_key(mut self, pub_key: &::bitcoin::PublicKey) -> Builder {
                self.0 = self.0.push_key(pub_key);
                self
            }

            pub fn push_expression<T: Pushable>(self, expression: T) -> Builder {
                let last_opcode_index = match self.as_script().instruction_indices_minimal().last()
                {
                    Some(instr_result) => match instr_result {
                        Ok((index, instr)) => match instr {
                            bitcoin::script::Instruction::PushBytes(push_bytes) => {
                                // Seperately handle OP_0 because it is turned into a PushBytes
                                // struct in the Script instruction
                                if push_bytes.as_bytes() == [] {
                                    Some((index, ::bitcoin::opcodes::all::OP_PUSHBYTES_0))
                                } else {
                                    None
                                }
                            },
                            bitcoin::script::Instruction::Op(opcode) => Some((index, opcode)),
                        },
                        Err(_) => {
                            eprintln!("Script includes non-minimal pushes.");
                            None
                        }
                    },
                    None => None,
                };
                let builder = expression.bitcoin_script_push(self);
                if let Some((last_index, previous_opcode)) = last_opcode_index {
                    match builder
                        .as_script()
                        .instructions_minimal()
                        .skip(last_index + 1)
                        .next()
                    {
                        Some(instr_result) => match instr_result {
                            Ok(instr) => match instr {
                                bitcoin::script::Instruction::PushBytes(_) => (),
                                bitcoin::script::Instruction::Op(opcode) => {
                                    check_optimality(previous_opcode, opcode)
                                }
                            },
                            Err(_) => eprintln!("Script includes non-minimal pushes."),
                        },
                        None => eprintln!("Script extends an empty script!"),
                    };
                }
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
        impl NotU8Pushable for ::bitcoin::ScriptBuf {
            fn bitcoin_script_push(self, builder: Builder) -> Builder {
                let previous_opcode = match self.as_script().instructions_minimal().last() {
                    Some(instr_result) => match instr_result {
                        Ok(instr) => match instr {
                            bitcoin::script::Instruction::PushBytes(_) => None,
                            bitcoin::script::Instruction::Op(previous_opcode) => {
                                Some(previous_opcode)
                            }
                        },
                        Err(_) => {
                            eprintln!("Script includes non-minimal pushes.");
                            None
                        }
                    },
                    None => None,
                };

                if let Some(previous_opcode) = previous_opcode {
                    match self.as_script().instructions_minimal().last() {
                        Some(instr_result) => match instr_result {
                            Ok(instr) => match instr {
                                bitcoin::script::Instruction::PushBytes(_) => (),
                                bitcoin::script::Instruction::Op(opcode) => {
                                    check_optimality(previous_opcode, opcode)
                                }
                            },
                            Err(_) => eprintln!("Script includes non-minimal pushes."),
                        },
                        None => (),
                    }
                };
                let mut script_vec = vec![];
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

    let script = script! {
        OP_1
        OP_2
        { 3 }
        { 4 }
    };

    assert_eq!(script.as_bytes(), vec![81, 82, 83, 84]);
}

#[test]
#[should_panic]
fn test_non_optimal_opcodes() {
    let script = script! {
        for i in 0..10 {
            { i }
            OP_ROLL
        }
        //OP_1
        //if true {
        //    OP_ADD
        //} else {
        //    OP_SUB
        //}
        //
        //OP_IF
        //for _ in 0..1 {
        //    OP_ELSE
        //}
        //
        //OP_DROP
        //OP_DROP

    };
    println!("{:?}", script);
}
