use crate::builder::{Block, Builder};
use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::script::{read_scriptint, Instruction};
use bitcoin::opcodes::all::*;
use bitcoin::script::PushBytes;
use std::cmp::min;

#[derive(Debug, Clone)]
enum IfStackEle {
    IfFlow((i32, i32)),
    // if_flow (deepest_stack_accessed, stack_changed), else_flow(deepest_stack_accessed, stack_changed)
    ElseFlow((i32, i32, i32, i32)),
}

#[derive(Debug, Clone)]
pub struct StackAnalyzer {
    deepest_stack_accessed: i32,
    stack_changed: i32,
    // if_stack should be empty after analyzing
    if_stack: Vec<IfStackEle>,
    // last constant? for handling op_roll and op_pick
    last_constant: Option<i64>,
}

impl StackAnalyzer {
    pub fn new() -> Self {
        StackAnalyzer {
            deepest_stack_accessed: 0,
            stack_changed: 0,
            if_stack: vec![],
            last_constant: None,
        }
    }

    pub fn analyze(&mut self, builder: &mut Builder) -> (i32, i32) {
        for block in builder.blocks.iter_mut() {
            match block {
                Block::Call(id) => {
                    let called_script = builder
                        .script_map
                        .get_mut(id)
                        .expect("Missing entry for a called script");
                    self.handle_sub_script(called_script.get_stack());
                }
                Block::Script(block_script) => {
                    for instruct in block_script.instructions().into_iter() {
                        match instruct {
                            Err(err) => {
                                panic!("instruction extract fail from script {}", err);
                            }
                            Ok(x) => match x {
                                Instruction::PushBytes(bytes) => {
                                    self.handle_push_slice(bytes);
                                }
                                Instruction::Op(opcode) => {
                                    self.handle_opcode(opcode);
                                }
                            },
                        }
                    }
                }
            }
        }
        (self.deepest_stack_accessed, self.stack_changed)
    }

    pub fn handle_push_slice(&mut self, bytes: &PushBytes) {
        match read_scriptint(bytes.as_bytes()) {
            Ok(x) => {
                // if i64(data) < 1000, last_constant is true
                if x <= 1000 && x >= 0 {
                    self.last_constant = Some(x);
                } else {
                    self.last_constant = None;
                }
            }
            Err(_) => {}
        }
        self.stack_change((0, 1));
    }

    pub fn handle_opcode(&mut self, opcode: Opcode) {
        // handle if/else flow
        match opcode {
            OP_IF | OP_NOTIF => {
                self.stack_change(Self::opcode_stack_table(&opcode));
                self.if_stack.push(IfStackEle::IfFlow((0, 0)));
            }
            OP_ELSE => match self.if_stack.pop().unwrap() {
                IfStackEle::IfFlow((i, j)) => {
                    self.if_stack.push(IfStackEle::ElseFlow((i, j, 0, 0)));
                }
                IfStackEle::ElseFlow(_) => {
                    panic!("shouldn't happend")
                }
            },
            OP_ENDIF => match self.if_stack.pop().unwrap() {
                IfStackEle::IfFlow((i, j)) => {
                    assert_eq!(j, 0, "only_if_flow shouldn't change stack status");
                    self.stack_change((i, j));
                }
                IfStackEle::ElseFlow((i, j, x, y)) => {
                    assert_eq!(
                        j, y,
                        "if_flow and else_flow should change stack in the same way"
                    );
                    self.stack_change((min(i, x), j));
                }
            },
            OP_PICK => match self.last_constant {
                Some(x) => {
                    self.stack_change((-1 * (x + 1) as i32, 0));
                }
                None => {
                    panic!("need to be handled manually for op_pick")
                }
            },
            OP_ROLL => match self.last_constant {
                Some(x) => {
                    self.stack_change((-1 * (x + 1) as i32, -1));
                }
                None => {
                    panic!("need to be handled manually for op_roll")
                }
            },
            _ => {
                self.stack_change(Self::opcode_stack_table(&opcode));
            }
        }

        // handle last constant, used by op_roll and op_pick
        match opcode {
            OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4 | OP_PUSHNUM_5
            | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9 | OP_PUSHNUM_10
            | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14 | OP_PUSHNUM_15
            | OP_PUSHNUM_16 => self.last_constant = Some((opcode.to_u8() - 0x50) as i64),
            _ => self.last_constant = None,
        }
    }

    pub fn handle_sub_script(&mut self, (access, change): (i32, i32)) {
        self.last_constant = None;
        self.stack_change((access, change));
    }

    pub fn get_status(&self) -> (i32, i32) {
        assert!(self.if_stack.is_empty(), "if stack is not empty");
        (self.deepest_stack_accessed, self.stack_changed)
    }

    fn stack_change(&mut self, (access, change): (i32, i32)) {
        match self.if_stack.last_mut() {
            None => {
                self.deepest_stack_accessed =
                    min(self.deepest_stack_accessed, access + self.stack_changed);
                self.stack_changed = self.stack_changed + change;
            }
            Some(IfStackEle::IfFlow((i, j))) => {
                *i = min(*i, (*j) + access);
                *j = *j + change
            }
            Some(IfStackEle::ElseFlow((_, _, x, y))) => {
                *x = min(*x, (*y) + access);
                *y = *y + change
            }
        }
    }

    /// the first return is deepest access to current stack
    /// the second return is the impact for the stack
    fn opcode_stack_table(data: &Opcode) -> (i32, i32) {
        match data.clone() {
            OP_PUSHBYTES_0 | OP_PUSHBYTES_1 | OP_PUSHBYTES_2 | OP_PUSHBYTES_3 | OP_PUSHBYTES_4
            | OP_PUSHBYTES_5 | OP_PUSHBYTES_6 | OP_PUSHBYTES_7 | OP_PUSHBYTES_8
            | OP_PUSHBYTES_9 | OP_PUSHBYTES_10 | OP_PUSHBYTES_11 | OP_PUSHBYTES_12
            | OP_PUSHBYTES_13 | OP_PUSHBYTES_14 | OP_PUSHBYTES_15 | OP_PUSHBYTES_16
            | OP_PUSHBYTES_17 | OP_PUSHBYTES_18 | OP_PUSHBYTES_19 | OP_PUSHBYTES_20
            | OP_PUSHBYTES_21 | OP_PUSHBYTES_22 | OP_PUSHBYTES_23 | OP_PUSHBYTES_24
            | OP_PUSHBYTES_25 | OP_PUSHBYTES_26 | OP_PUSHBYTES_27 | OP_PUSHBYTES_28
            | OP_PUSHBYTES_29 | OP_PUSHBYTES_30 | OP_PUSHBYTES_31 | OP_PUSHBYTES_32
            | OP_PUSHBYTES_33 | OP_PUSHBYTES_34 | OP_PUSHBYTES_35 | OP_PUSHBYTES_36
            | OP_PUSHBYTES_37 | OP_PUSHBYTES_38 | OP_PUSHBYTES_39 | OP_PUSHBYTES_40
            | OP_PUSHBYTES_41 | OP_PUSHBYTES_42 | OP_PUSHBYTES_43 | OP_PUSHBYTES_44
            | OP_PUSHBYTES_45 | OP_PUSHBYTES_46 | OP_PUSHBYTES_47 | OP_PUSHBYTES_48
            | OP_PUSHBYTES_49 | OP_PUSHBYTES_50 | OP_PUSHBYTES_51 | OP_PUSHBYTES_52
            | OP_PUSHBYTES_53 | OP_PUSHBYTES_54 | OP_PUSHBYTES_55 | OP_PUSHBYTES_56
            | OP_PUSHBYTES_57 | OP_PUSHBYTES_58 | OP_PUSHBYTES_59 | OP_PUSHBYTES_60
            | OP_PUSHBYTES_61 | OP_PUSHBYTES_62 | OP_PUSHBYTES_63 | OP_PUSHBYTES_64
            | OP_PUSHBYTES_65 | OP_PUSHBYTES_66 | OP_PUSHBYTES_67 | OP_PUSHBYTES_68
            | OP_PUSHBYTES_69 | OP_PUSHBYTES_70 | OP_PUSHBYTES_71 | OP_PUSHBYTES_72
            | OP_PUSHBYTES_73 | OP_PUSHBYTES_74 | OP_PUSHBYTES_75 | OP_PUSHDATA1 | OP_PUSHDATA2
            | OP_PUSHDATA4 => (0, 1),
            OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4
            | OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9
            | OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
            | OP_PUSHNUM_15 | OP_PUSHNUM_16 => (0, 1),
            OP_NOP => (0, 0),
            OP_IF => (-1, -1),
            OP_NOTIF => (-1, -1),
            OP_ELSE => {
                panic!("depend on the data on the stack")
            }
            OP_ENDIF => {
                panic!("depend on the data on the stack")
            }
            OP_VERIFY => (-1, -1),
            OP_TOALTSTACK => (-1, -1),
            OP_FROMALTSTACK => (0, 1),
            OP_2DROP => (-2, -2),
            OP_2DUP => (-2, 2),
            OP_3DUP => (-3, 3),
            OP_2OVER => (-4, 2),
            OP_2ROT => (-3, 0),
            OP_2SWAP => (-4, 0),
            OP_IFDUP => {
                panic!("depend on the data on the stack")
            }
            OP_DEPTH => (0, 1),
            OP_DROP => (-1, -1),
            OP_DUP => (-1, 1),
            OP_NIP => (-2, -1),
            OP_OVER => (-2, 1),
            OP_PICK => {
                panic!("depend on the data on the stack")
            }
            OP_ROLL => {
                panic!("depend on the data on the stack")
            }
            OP_ROT => (-3, 0),
            OP_SWAP => (-2, 0),
            OP_TUCK => (-2, 1),
            OP_SIZE => (-1, 1),
            OP_EQUAL => (-2, -1),
            OP_EQUALVERIFY => (-2, -2),
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => (-1, 0),
            OP_ADD | OP_SUB | OP_BOOLAND | OP_BOOLOR | OP_NUMEQUAL => (-2, -1),
            OP_NUMEQUALVERIFY => (-2, -2),
            OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL => (-2, -1),
            OP_MIN | OP_MAX => (-2, -1),
            OP_WITHIN => (-3, -2),
            OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => (-1, 0),
            OP_CHECKSIG => (-2, -1),
            OP_CHECKSIGVERIFY => (-2, -2),
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                (0, 0)
            }
            OP_CLTV | OP_CSV => (1, 1),
            _ => {
                panic!("not implemantation")
            }
        }
    }
}
