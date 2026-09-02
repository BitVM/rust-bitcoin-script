use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::script::{
    read_scriptbool, read_scriptint, Instruction, PushBytesBuf, ScriptBuf,
};
use bitcoin::hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash};
use bitcoin::script::{write_scriptint, Builder};
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::sync::OnceLock;

/// An owned (non-borrowed) representation of one Bitcoin Script instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OwnedInstruction {
    Op(Opcode),
    PushBytes(Vec<u8>),
}

impl OwnedInstruction {
    fn is_op(&self, target: Opcode) -> bool {
        matches!(self, Self::Op(op) if *op == target)
    }

    fn pushed_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::PushBytes(bytes) => Some(bytes.clone()),
            Self::Op(op) => match op.to_u8() {
                0x4f => Some(vec![0x81]),
                0x51..=0x60 => Some(vec![op.to_u8() - 0x50]),
                _ => None,
            },
        }
    }

    /// Return a minimally encoded, four-byte-or-smaller Script integer.
    fn push_num(&self) -> Option<i64> {
        read_scriptint(&self.pushed_bytes()?).ok()
    }

    fn is_push_num(&self, n: i64) -> bool {
        self.push_num() == Some(n)
    }

    fn serialized_len(&self) -> usize {
        match self {
            Self::Op(_) => 1,
            Self::PushBytes(bytes) => match bytes.len() {
                0..=75 => bytes.len() + 1,
                76..=255 => bytes.len() + 2,
                256..=65_535 => bytes.len() + 3,
                n => n + 5,
            },
        }
    }
}

/// Parse a compiled `ScriptBuf` into a flat list of owned instructions.
pub(crate) fn flatten_script(script: &ScriptBuf) -> Vec<OwnedInstruction> {
    script
        .instructions()
        .map(
            |result| match result.expect("script built internally is always valid") {
                Instruction::Op(op) => OwnedInstruction::Op(op),
                Instruction::PushBytes(bytes) => {
                    OwnedInstruction::PushBytes(bytes.as_bytes().to_vec())
                }
            },
        )
        .collect()
}

/// Reconstruct a minimally-pushed `ScriptBuf` from owned instructions.
pub(crate) fn assemble_script(instructions: &[OwnedInstruction]) -> ScriptBuf {
    let mut builder = Builder::new();
    for instruction in instructions {
        builder = match instruction {
            OwnedInstruction::Op(op) => builder.push_opcode(*op),
            OwnedInstruction::PushBytes(bytes) => {
                let bytes = PushBytesBuf::try_from(bytes.clone()).expect("push data <= 520 bytes");
                builder.push_slice(&bytes)
            }
        };
    }
    builder.into_script()
}

/// Run every optimizer pass to a fixpoint.
///
/// The optimizer targets Tapscript. If the script contains an `OP_SUCCESSx`, it
/// is deliberately returned untouched: merely encountering such an opcode has
/// special success semantics under BIP342, including in an unexecuted branch.
/// Scripts with an oversized push are likewise retained because that failure
/// is checked even when the containing branch is not executed.
pub(crate) fn optimize_instructions(
    mut instructions: Vec<OwnedInstruction>,
) -> Vec<OwnedInstruction> {
    if instructions.iter().any(is_tapscript_op_success)
        || instructions.iter().any(
            |instruction| matches!(instruction, OwnedInstruction::PushBytes(bytes) if bytes.len() > 520),
        )
    {
        return instructions;
    }

    let original = instructions.clone();
    let original_len = serialized_instructions_len(&original);
    loop {
        let after_control_flow = optimize_control_flow_once(&instructions);
        let next = apply_local_rules(&after_control_flow);
        if next == instructions {
            return if serialized_instructions_len(&next) < original_len {
                next
            } else {
                original
            };
        }
        instructions = next;
    }
}

fn serialized_instructions_len(instructions: &[OwnedInstruction]) -> usize {
    instructions
        .iter()
        .map(OwnedInstruction::serialized_len)
        .sum()
}

fn is_tapscript_op_success(instruction: &OwnedInstruction) -> bool {
    let OwnedInstruction::Op(op) = instruction else {
        return false;
    };
    matches!(
        op.to_u8(),
        80 | 98 | 126..=129 | 131..=134 | 137..=138 | 141..=142 | 149..=153 | 187..=254
    )
}

fn push_script_num(n: i64) -> OwnedInstruction {
    match n {
        0 => OwnedInstruction::PushBytes(Vec::new()),
        -1 => OwnedInstruction::Op(OP_PUSHNUM_NEG1),
        1..=16 => OwnedInstruction::Op(Opcode::from((0x50 + n) as u8)),
        _ => {
            let mut bytes = [0_u8; 8];
            let len = write_scriptint(&mut bytes, n);
            OwnedInstruction::PushBytes(bytes[..len].to_vec())
        }
    }
}

// ---- Control-flow passes --------------------------------------------------

fn optimize_control_flow_once(instructions: &[OwnedInstruction]) -> Vec<OwnedInstruction> {
    if !control_flow_is_well_formed(instructions) {
        return instructions.to_vec();
    }

    // Fold a canonical constant immediately consumed by IF/NOTIF. MINIMALIF is
    // preserved because only the canonical empty/OP_1 encodings are accepted.
    for condition_index in 0..instructions.len().saturating_sub(1) {
        let Some(condition) = minimal_if_constant(&instructions[condition_index]) else {
            continue;
        };
        let branch_index = condition_index + 1;
        let is_if = instructions[branch_index].is_op(OP_IF);
        let is_notif = instructions[branch_index].is_op(OP_NOTIF);
        if !is_if && !is_notif {
            continue;
        }
        let Some((else_index, endif_index)) = conditional_bounds(instructions, branch_index) else {
            continue;
        };

        // OP_VERIF and OP_VERNOTIF fail even when encountered in a skipped
        // branch, so deleting either would change validation behavior.
        if instructions[branch_index + 1..endif_index]
            .iter()
            .any(|instruction| instruction.is_op(OP_VERIF) || instruction.is_op(OP_VERNOTIF))
        {
            continue;
        }

        let take_then = if is_if { condition } else { !condition };
        let then_end = else_index.unwrap_or(endif_index);
        let selected: &[OwnedInstruction] = if take_then {
            &instructions[branch_index + 1..then_end]
        } else if let Some(else_index) = else_index {
            &instructions[else_index + 1..endif_index]
        } else {
            &[]
        };

        let mut out = Vec::with_capacity(instructions.len());
        out.extend_from_slice(&instructions[..condition_index]);
        out.extend_from_slice(selected);
        out.extend_from_slice(&instructions[endif_index + 1..]);
        return out;
    }

    let facts = analyze_prefixes(instructions);

    // Once a condition is known to be a canonical boolean, MINIMALIF no
    // longer carries extra validation. This lets us turn a one-sided failure
    // into VERIFY and erase conditionals that merely reproduce the boolean.
    for branch_index in 0..instructions.len() {
        let is_if = instructions[branch_index].is_op(OP_IF);
        let is_notif = instructions[branch_index].is_op(OP_NOTIF);
        if (!is_if && !is_notif) || !facts[branch_index].top.is_bool() {
            continue;
        }
        let Some((else_index, endif_index)) = conditional_bounds(instructions, branch_index) else {
            continue;
        };
        let then_end = else_index.unwrap_or(endif_index);
        let then_branch = &instructions[branch_index + 1..then_end];
        let else_branch = else_index.map(|index| &instructions[index + 1..endif_index]);
        let else_is_empty = match else_branch {
            Some(branch) => branch.is_empty(),
            None => true,
        };

        let replacement = if then_branch.is_empty() && else_is_empty {
            Some(vec![OwnedInstruction::Op(OP_DROP)])
        } else if let Some(else_branch) = else_branch {
            let then_bool = single_boolean_constant(then_branch);
            let else_bool = single_boolean_constant(else_branch);
            if let (Some(then_bool), Some(else_bool)) = (then_bool, else_bool) {
                let reproduces_condition =
                    (is_if && then_bool && !else_bool) || (is_notif && !then_bool && else_bool);
                let negates_condition =
                    (is_if && !then_bool && else_bool) || (is_notif && then_bool && !else_bool);
                if reproduces_condition {
                    Some(Vec::new())
                } else if negates_condition {
                    Some(vec![OwnedInstruction::Op(OP_NOT)])
                } else {
                    None
                }
            } else if is_return_only(else_branch) {
                let mut replacement = if is_if {
                    vec![OwnedInstruction::Op(OP_VERIFY)]
                } else {
                    vec![
                        OwnedInstruction::Op(OP_NOT),
                        OwnedInstruction::Op(OP_VERIFY),
                    ]
                };
                replacement.extend_from_slice(then_branch);
                Some(replacement)
            } else if is_return_only(then_branch) {
                let mut replacement = if is_if {
                    vec![
                        OwnedInstruction::Op(OP_NOT),
                        OwnedInstruction::Op(OP_VERIFY),
                    ]
                } else {
                    vec![OwnedInstruction::Op(OP_VERIFY)]
                };
                replacement.extend_from_slice(else_branch);
                Some(replacement)
            } else {
                None
            }
        } else if is_return_only(then_branch) {
            Some(if is_if {
                vec![
                    OwnedInstruction::Op(OP_NOT),
                    OwnedInstruction::Op(OP_VERIFY),
                ]
            } else {
                vec![OwnedInstruction::Op(OP_VERIFY)]
            })
        } else {
            None
        };

        if let Some(replacement) = replacement {
            let mut out = Vec::with_capacity(instructions.len());
            out.extend_from_slice(&instructions[..branch_index]);
            out.extend(replacement);
            out.extend_from_slice(&instructions[endif_index + 1..]);
            return out;
        }
    }

    // Simplify empty branches while retaining IF/NOTIF's stack consumption and
    // MINIMALIF validation.
    for branch_index in 0..instructions.len() {
        let is_if = instructions[branch_index].is_op(OP_IF);
        let is_notif = instructions[branch_index].is_op(OP_NOTIF);
        if !is_if && !is_notif {
            continue;
        }
        let Some((Some(else_index), endif_index)) = conditional_bounds(instructions, branch_index)
        else {
            continue;
        };

        if else_index == branch_index + 1 {
            let mut out = Vec::with_capacity(instructions.len() - 1);
            out.extend_from_slice(&instructions[..branch_index]);
            out.push(OwnedInstruction::Op(if is_if { OP_NOTIF } else { OP_IF }));
            out.extend_from_slice(&instructions[else_index + 1..]);
            return out;
        }
        if endif_index == else_index + 1 {
            let mut out = Vec::with_capacity(instructions.len() - 1);
            out.extend_from_slice(&instructions[..else_index]);
            out.extend_from_slice(&instructions[else_index + 1..]);
            return out;
        }
    }

    // Hoist a common, straight-line suffix from both branches. Control opcodes
    // and CODESEPARATOR form boundaries and are never moved.
    for branch_index in 0..instructions.len() {
        if !instructions[branch_index].is_op(OP_IF) && !instructions[branch_index].is_op(OP_NOTIF) {
            continue;
        }
        let Some((Some(else_index), endif_index)) = conditional_bounds(instructions, branch_index)
        else {
            continue;
        };

        let then_branch = &instructions[branch_index + 1..else_index];
        let else_branch = &instructions[else_index + 1..endif_index];
        let mut common = 0;
        while common < then_branch.len() && common < else_branch.len() {
            let left = &then_branch[then_branch.len() - 1 - common];
            let right = &else_branch[else_branch.len() - 1 - common];
            if left != right || is_control_boundary(left) {
                break;
            }
            common += 1;
        }
        if common == 0 {
            continue;
        }

        let then_tail = then_branch.len() - common;
        let else_tail = else_branch.len() - common;
        let mut out = Vec::with_capacity(instructions.len() - common);
        out.extend_from_slice(&instructions[..branch_index + 1]);
        out.extend_from_slice(&then_branch[..then_tail]);
        out.push(OwnedInstruction::Op(OP_ELSE));
        out.extend_from_slice(&else_branch[..else_tail]);
        out.push(OwnedInstruction::Op(OP_ENDIF));
        out.extend_from_slice(&then_branch[then_tail..]);
        out.extend_from_slice(&instructions[endif_index + 1..]);
        return out;
    }

    instructions.to_vec()
}

fn single_boolean_constant(instructions: &[OwnedInstruction]) -> Option<bool> {
    if instructions.len() == 1 {
        minimal_if_constant(&instructions[0])
    } else {
        None
    }
}

fn is_return_only(instructions: &[OwnedInstruction]) -> bool {
    instructions.len() == 1 && instructions[0].is_op(OP_RETURN)
}

fn control_flow_is_well_formed(instructions: &[OwnedInstruction]) -> bool {
    let mut branches = Vec::new();
    for instruction in instructions {
        if instruction.is_op(OP_IF) || instruction.is_op(OP_NOTIF) {
            branches.push(false);
        } else if instruction.is_op(OP_ELSE) {
            let Some(has_else) = branches.last_mut() else {
                return false;
            };
            if *has_else {
                return false;
            }
            *has_else = true;
        } else if instruction.is_op(OP_ENDIF) && branches.pop().is_none() {
            return false;
        }
    }
    branches.is_empty()
}

fn minimal_if_constant(instruction: &OwnedInstruction) -> Option<bool> {
    if instruction.is_push_num(0) {
        Some(false)
    } else if instruction.is_op(OP_PUSHNUM_1) {
        Some(true)
    } else {
        None
    }
}

fn conditional_bounds(
    instructions: &[OwnedInstruction],
    branch_index: usize,
) -> Option<(Option<usize>, usize)> {
    let mut depth = 0_usize;
    let mut else_index = None;
    for (index, instruction) in instructions.iter().enumerate().skip(branch_index + 1) {
        if instruction.is_op(OP_IF) || instruction.is_op(OP_NOTIF) {
            depth += 1;
        } else if instruction.is_op(OP_ENDIF) {
            if depth == 0 {
                return Some((else_index, index));
            }
            depth -= 1;
        } else if instruction.is_op(OP_ELSE) && depth == 0 {
            if else_index.is_some() {
                return None;
            }
            else_index = Some(index);
        }
    }
    None
}

fn is_control_boundary(instruction: &OwnedInstruction) -> bool {
    instruction.is_op(OP_IF)
        || instruction.is_op(OP_NOTIF)
        || instruction.is_op(OP_ELSE)
        || instruction.is_op(OP_ENDIF)
        || instruction.is_op(OP_CODESEPARATOR)
}

// ---- Abstract prefix analysis --------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueKind {
    Unknown,
    /// A minimally encoded Script number accepted by another numeric opcode.
    Num4,
    /// A canonical empty/`0x01` boolean. This is also a valid four-byte number.
    Bool,
}

impl ValueKind {
    fn is_num4(self) -> bool {
        matches!(self, Self::Num4 | Self::Bool)
    }

    fn is_bool(self) -> bool {
        self == Self::Bool
    }
}

#[derive(Clone, Copy, Debug)]
struct PrefixFacts {
    main_depth: usize,
    alt_depth: usize,
    top: ValueKind,
    second: ValueKind,
}

fn stack_kind(stack: &[ValueKind], depth: usize) -> ValueKind {
    stack
        .len()
        .checked_sub(depth + 1)
        .and_then(|index| stack.get(index))
        .copied()
        .unwrap_or(ValueKind::Unknown)
}

fn pushed_value_kind(bytes: &[u8]) -> ValueKind {
    if bytes.is_empty() || bytes == [1] {
        ValueKind::Bool
    } else if read_scriptint(bytes).is_ok() {
        ValueKind::Num4
    } else {
        ValueKind::Unknown
    }
}

const ABSTRACT_UNKNOWN_INPUTS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct AbstractState {
    main: Vec<ValueKind>,
    alt: Vec<ValueKind>,
    main_depth: usize,
    alt_depth: usize,
}

impl AbstractState {
    fn unknown_inputs() -> Self {
        Self {
            main: vec![ValueKind::Unknown; ABSTRACT_UNKNOWN_INPUTS],
            alt: vec![ValueKind::Unknown; ABSTRACT_UNKNOWN_INPUTS],
            main_depth: 0,
            alt_depth: 0,
        }
    }

    fn facts(&self) -> PrefixFacts {
        PrefixFacts {
            main_depth: self.main_depth,
            alt_depth: self.alt_depth,
            top: stack_kind(&self.main, 0),
            second: stack_kind(&self.main, 1),
        }
    }
}

fn analyze_prefixes(instructions: &[OwnedInstruction]) -> Vec<PrefixFacts> {
    let unknown_facts = PrefixFacts {
        main_depth: 0,
        alt_depth: 0,
        top: ValueKind::Unknown,
        second: ValueKind::Unknown,
    };
    if !control_flow_is_well_formed(instructions) {
        return vec![unknown_facts; instructions.len() + 1];
    }

    let (false_targets, else_targets) = control_flow_targets(instructions);
    let mut states = vec![None; instructions.len() + 1];
    states[0] = Some(AbstractState::unknown_inputs());
    let mut work = VecDeque::from([0_usize]);

    while let Some(index) = work.pop_front() {
        if index == instructions.len() {
            continue;
        }
        let state = states[index].clone().expect("queued state exists");
        let instruction = &instructions[index];

        if instruction.is_op(OP_IF) || instruction.is_op(OP_NOTIF) {
            let mut after_condition = state;
            pop_abstract_main(&mut after_condition, 1);
            after_condition.main_depth = after_condition.main_depth.max(1) - 1;
            propagate_abstract_state(&mut states, &mut work, index + 1, after_condition.clone());
            if let Some(target) = false_targets[index] {
                propagate_abstract_state(&mut states, &mut work, target, after_condition);
            }
            continue;
        }
        if instruction.is_op(OP_ELSE) {
            if let Some(target) = else_targets[index] {
                propagate_abstract_state(&mut states, &mut work, target, state);
            }
            continue;
        }
        if instruction.is_op(OP_RETURN) {
            continue;
        }

        let mut next = state;
        apply_abstract_instruction(&mut next, instruction);
        propagate_abstract_state(&mut states, &mut work, index + 1, next);
    }

    states
        .into_iter()
        .map(|state| state.map_or(unknown_facts, |state| state.facts()))
        .collect()
}

fn control_flow_targets(
    instructions: &[OwnedInstruction],
) -> (Vec<Option<usize>>, Vec<Option<usize>>) {
    let mut false_targets = vec![None; instructions.len()];
    let mut else_targets = vec![None; instructions.len()];
    let mut stack: Vec<(usize, Option<usize>)> = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.is_op(OP_IF) || instruction.is_op(OP_NOTIF) {
            stack.push((index, None));
        } else if instruction.is_op(OP_ELSE) {
            stack.last_mut().expect("well-formed control flow").1 = Some(index);
        } else if instruction.is_op(OP_ENDIF) {
            let (branch, else_index) = stack.pop().expect("well-formed control flow");
            false_targets[branch] = Some(else_index.map_or(index + 1, |else_index| else_index + 1));
            if let Some(else_index) = else_index {
                else_targets[else_index] = Some(index + 1);
            }
        }
    }
    (false_targets, else_targets)
}

fn propagate_abstract_state(
    states: &mut [Option<AbstractState>],
    work: &mut VecDeque<usize>,
    target: usize,
    incoming: AbstractState,
) {
    let changed = match &mut states[target] {
        Some(existing) => merge_abstract_state(existing, &incoming),
        slot @ None => {
            *slot = Some(incoming);
            true
        }
    };
    if changed {
        work.push_back(target);
    }
}

fn merge_abstract_state(existing: &mut AbstractState, incoming: &AbstractState) -> bool {
    let mut merged = existing.clone();
    merged.main_depth = merged.main_depth.min(incoming.main_depth);
    merged.alt_depth = merged.alt_depth.min(incoming.alt_depth);
    merge_abstract_stack(&mut merged.main, &incoming.main);
    merge_abstract_stack(&mut merged.alt, &incoming.alt);
    if *existing == merged {
        false
    } else {
        *existing = merged;
        true
    }
}

fn merge_abstract_stack(existing: &mut Vec<ValueKind>, incoming: &[ValueKind]) {
    if existing.len() != incoming.len() {
        *existing = vec![ValueKind::Unknown; ABSTRACT_UNKNOWN_INPUTS];
        return;
    }
    for (existing, incoming) in existing.iter_mut().zip(incoming) {
        *existing = match (*existing, *incoming) {
            (left, right) if left == right => left,
            (ValueKind::Bool, ValueKind::Num4) | (ValueKind::Num4, ValueKind::Bool) => {
                ValueKind::Num4
            }
            _ => ValueKind::Unknown,
        };
    }
}

fn pop_abstract_main(state: &mut AbstractState, count: usize) {
    for _ in 0..count {
        state.main.pop();
    }
}

fn apply_abstract_instruction(state: &mut AbstractState, instruction: &OwnedInstruction) {
    if let Some(bytes) = instruction.pushed_bytes() {
        state.main.push(pushed_value_kind(&bytes));
        state.main_depth += 1;
        return;
    }

    let OwnedInstruction::Op(op) = instruction else {
        unreachable!();
    };
    if is_fixed_stack_op(*op) {
        if !apply_fixed_stack_op(&mut state.main, &mut state.alt, *op) {
            state.main = vec![ValueKind::Unknown; ABSTRACT_UNKNOWN_INPUTS];
            state.alt = vec![ValueKind::Unknown; ABSTRACT_UNKNOWN_INPUTS];
            let _ = apply_fixed_stack_op(&mut state.main, &mut state.alt, *op);
        }
        apply_depth_effect(&mut state.main_depth, &mut state.alt_depth, *op);
        return;
    }

    if *op == OP_SIZE {
        state.main.push(ValueKind::Num4);
        state.main_depth = state.main_depth.max(1) + 1;
    } else if *op == OP_DEPTH {
        state.main.push(ValueKind::Num4);
        state.main_depth += 1;
    } else if [OP_1ADD, OP_1SUB].contains(op) {
        let input = stack_kind(&state.main, 0);
        pop_abstract_main(state, 1);
        state.main.push(if input.is_bool() {
            ValueKind::Num4
        } else {
            ValueKind::Unknown
        });
        state.main_depth = state.main_depth.max(1);
    } else if [OP_NEGATE, OP_ABS].contains(op) {
        pop_abstract_main(state, 1);
        state.main.push(ValueKind::Num4);
        state.main_depth = state.main_depth.max(1);
    } else if [OP_NOT, OP_0NOTEQUAL].contains(op) {
        pop_abstract_main(state, 1);
        state.main.push(ValueKind::Bool);
        state.main_depth = state.main_depth.max(1);
    } else if [OP_ADD, OP_SUB].contains(op) {
        let bounded = stack_kind(&state.main, 0).is_bool() && stack_kind(&state.main, 1).is_bool();
        pop_abstract_main(state, 2);
        state.main.push(if bounded {
            ValueKind::Num4
        } else {
            ValueKind::Unknown
        });
        state.main_depth = state.main_depth.max(2) - 1;
    } else if [OP_MIN, OP_MAX].contains(op) {
        pop_abstract_main(state, 2);
        state.main.push(ValueKind::Num4);
        state.main_depth = state.main_depth.max(2) - 1;
    } else if *op == OP_EQUAL || is_boolean_binary(*op) {
        pop_abstract_main(state, 2);
        state.main.push(ValueKind::Bool);
        state.main_depth = state.main_depth.max(2) - 1;
    } else if *op == OP_WITHIN {
        pop_abstract_main(state, 3);
        state.main.push(ValueKind::Bool);
        state.main_depth = state.main_depth.max(3) - 2;
    } else if [OP_EQUALVERIFY, OP_NUMEQUALVERIFY].contains(op) {
        pop_abstract_main(state, 2);
        state.main_depth = state.main_depth.max(2) - 2;
    } else if *op == OP_VERIFY {
        pop_abstract_main(state, 1);
        state.main_depth = state.main_depth.max(1) - 1;
    } else if is_hash(*op) {
        pop_abstract_main(state, 1);
        state.main.push(ValueKind::Unknown);
        state.main_depth = state.main_depth.max(1);
    } else if [OP_CLTV, OP_CSV].contains(op) {
        state.main_depth = state.main_depth.max(1);
    } else if *op == OP_CHECKSIG {
        pop_abstract_main(state, 2);
        state.main.push(ValueKind::Num4);
        state.main_depth = state.main_depth.max(2) - 1;
    } else if *op == OP_CHECKSIGVERIFY {
        pop_abstract_main(state, 2);
        state.main_depth = state.main_depth.max(2) - 2;
    } else if *op == OP_CHECKSIGADD {
        pop_abstract_main(state, 3);
        state.main.push(ValueKind::Unknown);
        state.main_depth = state.main_depth.max(3) - 2;
    } else if *op == OP_CODESEPARATOR || *op == OP_NOP || *op == OP_ENDIF {
        // No stack effect.
    } else {
        *state = AbstractState::unknown_inputs();
    }
}

// ---- Local rewrites -------------------------------------------------------

fn apply_local_rules(instructions: &[OwnedInstruction]) -> Vec<OwnedInstruction> {
    let facts = analyze_prefixes(instructions);
    let mut out = Vec::with_capacity(instructions.len());
    let mut index = 0;

    while index < instructions.len() {
        // Re-materialize a repeated literal with DUP. Unlike most rules that
        // remove transient pushes, this has exactly the same stack peak.
        if let Some(bytes) = instructions[index].pushed_bytes() {
            let count = instructions[index..]
                .iter()
                .take_while(|instruction| instruction.pushed_bytes().as_deref() == Some(&bytes))
                .count();
            let original_cost = serialized_instructions_len(&instructions[index..index + count]);
            let representative = instructions[index..index + count]
                .iter()
                .min_by_key(|instruction| instruction.serialized_len())
                .expect("literal run is nonempty");
            let replacement_cost = representative.serialized_len() + count - 1;
            if count >= 2 && replacement_cost < original_cost {
                out.push(representative.clone());
                out.extend((1..count).map(|_| OwnedInstruction::Op(OP_DUP)));
                index += count;
                continue;
            }
        }

        // Larger PICK/ROLL substitutions are checked before their prefixes.
        if matches_num_op_sequence(instructions, index, &[(3, OP_ROLL), (3, OP_ROLL)]) {
            out.push(OwnedInstruction::Op(OP_2SWAP));
            index += 4;
            continue;
        }
        if matches_num_op_sequence(instructions, index, &[(5, OP_ROLL), (5, OP_ROLL)]) {
            out.push(OwnedInstruction::Op(OP_2ROT));
            index += 4;
            continue;
        }
        if matches_num_op_sequence(instructions, index, &[(1, OP_PICK), (1, OP_PICK)]) {
            out.push(OwnedInstruction::Op(OP_2DUP));
            index += 4;
            continue;
        }
        if matches_num_op_sequence(
            instructions,
            index,
            &[(2, OP_PICK), (2, OP_PICK), (2, OP_PICK)],
        ) {
            out.push(OwnedInstruction::Op(OP_3DUP));
            index += 6;
            continue;
        }
        if matches_num_op_sequence(instructions, index, &[(3, OP_PICK), (3, OP_PICK)]) {
            out.push(OwnedInstruction::Op(OP_2OVER));
            index += 4;
            continue;
        }

        // Compute an identical deterministic hash pipeline once, then
        // duplicate its result: DUP P SWAP P -> P DUP.
        if instructions[index].is_op(OP_DUP) {
            let pipeline_start = index + 1;
            let mut swap_index = pipeline_start;
            while matches!(instructions.get(swap_index), Some(OwnedInstruction::Op(op)) if is_hash(*op))
            {
                swap_index += 1;
            }
            let pipeline_len = swap_index - pipeline_start;
            let second_end = swap_index + 1 + pipeline_len;
            if pipeline_len > 0
                && instructions
                    .get(swap_index)
                    .is_some_and(|instruction| instruction.is_op(OP_SWAP))
                && instructions.get(swap_index + 1..second_end)
                    == instructions.get(pipeline_start..swap_index)
            {
                out.extend_from_slice(&instructions[pipeline_start..swap_index]);
                out.push(OwnedInstruction::Op(OP_DUP));
                index = second_end;
                continue;
            }
        }

        // Compute a deterministic unary operation once, then duplicate it:
        // DUP U SWAP U -> U DUP.
        if let (Some(a), Some(b), Some(c), Some(d)) = (
            instructions.get(index),
            instructions.get(index + 1),
            instructions.get(index + 2),
            instructions.get(index + 3),
        ) {
            if a.is_op(OP_DUP)
                && c.is_op(OP_SWAP)
                && matches!((b, d), (OwnedInstruction::Op(left), OwnedInstruction::Op(right)) if left == right && is_pure_unary(*left))
            {
                out.push(b.clone());
                out.push(OwnedInstruction::Op(OP_DUP));
                index += 4;
                continue;
            }
        }

        // Locktime/sequence sequences that retain the inspected value.
        if let (Some(a), Some(b), Some(c)) = (
            instructions.get(index),
            instructions.get(index + 1),
            instructions.get(index + 2),
        ) {
            if a.is_op(OP_DUP)
                && (b.is_op(OP_CLTV) || b.is_op(OP_CSV))
                && (c.is_op(OP_DROP) || c.is_op(OP_NIP))
            {
                out.push(b.clone());
                index += 3;
                continue;
            }
        }

        // Cancel arbitrarily long inverse alt-stack transfers when the prefix
        // proves that every transfer has an input. The symbolic window pass
        // below covers shorter mixed stack sequences.
        if instructions[index].is_op(OP_TOALTSTACK) || instructions[index].is_op(OP_FROMALTSTACK) {
            let first = match &instructions[index] {
                OwnedInstruction::Op(op) => *op,
                _ => unreachable!(),
            };
            let inverse = if first == OP_TOALTSTACK {
                OP_FROMALTSTACK
            } else {
                OP_TOALTSTACK
            };
            let count = instructions[index..]
                .iter()
                .take_while(|instruction| instruction.is_op(first))
                .count();
            if count > 0
                && instructions[index + count..]
                    .iter()
                    .take(count)
                    .all(|instruction| instruction.is_op(inverse))
                && instructions.len() >= index + count * 2
                && ((first == OP_TOALTSTACK && facts[index].main_depth >= count)
                    || (first == OP_FROMALTSTACK && facts[index].alt_depth >= count))
            {
                index += count * 2;
                continue;
            }
        }

        // A literal parked on the alt stack can be pushed after an intervening
        // straight-line region that never observes the alt stack. This saves
        // both transfer opcodes and cannot increase peak stack usage.
        if current_literal_followed_by(instructions, index, OP_TOALTSTACK) {
            let mut from_alt = index + 2;
            let mut matching_from_alt = None;
            while let Some(instruction) = instructions.get(from_alt) {
                if instruction.is_op(OP_FROMALTSTACK) {
                    matching_from_alt = Some(from_alt);
                    break;
                }
                if instruction.is_op(OP_TOALTSTACK) || is_control_boundary(instruction) {
                    break;
                }
                from_alt += 1;
            }
            if let Some(from_alt) = matching_from_alt {
                out.extend_from_slice(&instructions[index + 2..from_alt]);
                out.push(instructions[index].clone());
                index = from_alt + 1;
                continue;
            }
        }

        if let Some((consumed, replacement)) =
            smarter_window_replacement(instructions, index, facts[index])
        {
            out.extend(replacement);
            index += consumed;
            continue;
        }

        if let Some((consumed, replacement)) = fold_constants(instructions, index) {
            out.extend(replacement);
            index += consumed;
            continue;
        }

        // Immediate PICK/ROLL specializations.
        if let Some(next) = instructions.get(index + 1) {
            let current = &instructions[index];
            if current.is_push_num(1) && next.is_op(OP_ADD) {
                out.push(OwnedInstruction::Op(OP_1ADD));
                index += 2;
                continue;
            }
            if current.is_push_num(1) && next.is_op(OP_SUB) {
                out.push(OwnedInstruction::Op(OP_1SUB));
                index += 2;
                continue;
            }
            if current.is_push_num(0) && next.is_op(OP_PICK) {
                out.push(OwnedInstruction::Op(OP_DUP));
                index += 2;
                continue;
            }
            if current.is_push_num(1) && next.is_op(OP_PICK) {
                out.push(OwnedInstruction::Op(OP_OVER));
                index += 2;
                continue;
            }
            if current.is_push_num(0) && next.is_op(OP_ROLL) && facts[index].main_depth >= 1 {
                index += 2;
                continue;
            }
            if current.is_push_num(1) && next.is_op(OP_ROLL) {
                out.push(OwnedInstruction::Op(OP_SWAP));
                index += 2;
                continue;
            }
            if current.is_push_num(2) && next.is_op(OP_ROLL) {
                out.push(OwnedInstruction::Op(OP_ROT));
                index += 2;
                continue;
            }

            if let (Some(position), Some(after_pick)) =
                (current.push_num(), instructions.get(index + 2))
            {
                if position >= 0
                    && next.is_op(OP_PICK)
                    && after_pick.is_op(OP_DROP)
                    && usize::try_from(position)
                        .ok()
                        .is_some_and(|position| facts[index].main_depth > position)
                {
                    index += 3;
                    continue;
                }
            }

            if current.is_push_num(0) && next.is_op(OP_NUMEQUAL) {
                out.push(OwnedInstruction::Op(OP_NOT));
                index += 2;
                continue;
            }
            if current.is_push_num(0) && (next.is_op(OP_NUMNOTEQUAL) || next.is_op(OP_BOOLOR)) {
                out.push(OwnedInstruction::Op(OP_0NOTEQUAL));
                index += 2;
                continue;
            }
            if current.push_num().is_some_and(|constant| constant != 0) && next.is_op(OP_BOOLAND) {
                out.push(OwnedInstruction::Op(OP_0NOTEQUAL));
                index += 2;
                continue;
            }

            // Proof-dependent numeric identities. Num4 proves both parsing and
            // byte-for-byte canonical re-encoding are preserved.
            if current.is_push_num(0)
                && (next.is_op(OP_ADD) || next.is_op(OP_SUB))
                && facts[index].top.is_num4()
            {
                index += 2;
                continue;
            }
            if current.is_op(OP_NEGATE) && next.is_op(OP_NEGATE) && facts[index].top.is_num4() {
                index += 2;
                continue;
            }
            if current.is_op(OP_SIZE) && next.is_op(OP_DROP) && facts[index].main_depth >= 1 {
                index += 2;
                continue;
            }
        }

        if let Some((consumed, replacement)) = stack_run_replacement(instructions, index, &facts) {
            out.extend(replacement.into_iter().map(OwnedInstruction::Op));
            index += consumed;
            continue;
        }

        if let Some(next) = instructions.get(index + 1) {
            let current = &instructions[index];
            if let Some(replacement) = pair_replacement(current, next) {
                if let Some(op) = replacement {
                    out.push(OwnedInstruction::Op(op));
                }
                index += 2;
                continue;
            }
        }

        // Plain NOP is the only upgrade-insensitive NOP removed in Tapscript.
        if instructions[index].is_op(OP_NOP) {
            index += 1;
            continue;
        }

        out.push(instructions[index].clone());
        index += 1;
    }

    out
}

fn current_literal_followed_by(
    instructions: &[OwnedInstruction],
    index: usize,
    opcode: Opcode,
) -> bool {
    instructions[index].pushed_bytes().is_some()
        && instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(opcode))
}

fn smarter_window_replacement(
    instructions: &[OwnedInstruction],
    index: usize,
    facts: PrefixFacts,
) -> Option<(usize, Vec<OwnedInstruction>)> {
    let current = instructions.get(index)?;

    // De Morgan's laws avoid normalizing both operands separately.
    if let (Some(first_not), Some(swap), Some(second_not), Some(OwnedInstruction::Op(boolean_op))) = (
        instructions.get(index),
        instructions.get(index + 1),
        instructions.get(index + 2),
        instructions.get(index + 3),
    ) {
        if first_not.is_op(OP_NOT) && swap.is_op(OP_SWAP) && second_not.is_op(OP_NOT) {
            let dual = if *boolean_op == OP_BOOLAND {
                Some(OP_BOOLOR)
            } else if *boolean_op == OP_BOOLOR {
                Some(OP_BOOLAND)
            } else {
                None
            };
            if let Some(dual) = dual {
                return Some((
                    4,
                    vec![OwnedInstruction::Op(dual), OwnedInstruction::Op(OP_NOT)],
                ));
            }
        }
    }

    // Arithmetic fusions that retain numeric parsing and intermediate-range
    // behavior exactly.
    if current.is_op(OP_NEGATE) {
        if instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(OP_ADD))
        {
            return Some((2, vec![OwnedInstruction::Op(OP_SUB)]));
        }
        if instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(OP_SUB))
        {
            return Some((2, vec![OwnedInstruction::Op(OP_ADD)]));
        }
    }
    if current.is_push_num(0)
        && instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(OP_SWAP))
        && instructions
            .get(index + 2)
            .is_some_and(|instruction| instruction.is_op(OP_SUB))
    {
        return Some((3, vec![OwnedInstruction::Op(OP_NEGATE)]));
    }

    // Constant-index stack accesses can participate in larger exact windows.
    if current.is_push_num(0)
        && instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(OP_ROLL))
        && instructions
            .get(index + 2)
            .is_some_and(|instruction| instruction.is_op(OP_DROP))
    {
        return Some((3, vec![OwnedInstruction::Op(OP_DROP)]));
    }
    if let Some(position) = current.push_num() {
        if position >= 0
            && instructions
                .get(index + 1)
                .is_some_and(|instruction| instruction.is_op(OP_PICK))
            && instructions
                .get(index + 2)
                .is_some_and(|instruction| instruction.is_op(OP_2DROP))
            && usize::try_from(position)
                .ok()
                .is_some_and(|position| facts.main_depth > position)
        {
            return Some((3, vec![OwnedInstruction::Op(OP_DROP)]));
        }
    }

    // A duplicated truth value need only be checked or discarded once.
    if current.is_op(OP_DUP)
        && instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(OP_VERIFY))
        && instructions
            .get(index + 2)
            .is_some_and(|instruction| instruction.is_op(OP_VERIFY) || instruction.is_op(OP_DROP))
    {
        return Some((3, vec![OwnedInstruction::Op(OP_VERIFY)]));
    }

    // Collapse repeated clamps and comparisons against the same clamp.
    if let (
        Some(first_constant),
        Some(OwnedInstruction::Op(first_op)),
        Some(second_constant),
        Some(OwnedInstruction::Op(second_op)),
    ) = (
        current.push_num(),
        instructions.get(index + 1),
        instructions
            .get(index + 2)
            .and_then(OwnedInstruction::push_num),
        instructions.get(index + 3),
    ) {
        if first_op == second_op && (*first_op == OP_MIN || *first_op == OP_MAX) {
            let combined = if *first_op == OP_MIN {
                first_constant.min(second_constant)
            } else {
                first_constant.max(second_constant)
            };
            return Some((
                4,
                vec![push_script_num(combined), OwnedInstruction::Op(*first_op)],
            ));
        }
        if first_constant == second_constant && (*first_op == OP_MIN || *first_op == OP_MAX) {
            let verifies = *second_op == OP_NUMEQUALVERIFY;
            let equality = *second_op == OP_NUMEQUAL || verifies;
            let comparison = if *first_op == OP_MIN && equality {
                Some(OP_GREATERTHANOREQUAL)
            } else if *first_op == OP_MIN && *second_op == OP_NUMNOTEQUAL {
                Some(OP_LESSTHAN)
            } else if *first_op == OP_MAX && equality {
                Some(OP_LESSTHANOREQUAL)
            } else if *first_op == OP_MAX && *second_op == OP_NUMNOTEQUAL {
                Some(OP_GREATERTHAN)
            } else {
                None
            };
            if let Some(comparison) = comparison {
                let mut replacement = vec![
                    instructions[index].clone(),
                    OwnedInstruction::Op(comparison),
                ];
                if verifies {
                    replacement.push(OwnedInstruction::Op(OP_VERIFY));
                }
                return Some((4, replacement));
            }
        }
    }

    // WITHIN over a singleton interval is simply numeric equality.
    if let (Some(lower), Some(upper), Some(within)) = (
        current.push_num(),
        instructions
            .get(index + 1)
            .and_then(OwnedInstruction::push_num),
        instructions.get(index + 2),
    ) {
        if within.is_op(OP_WITHIN) && lower.checked_add(1) == Some(upper) {
            return Some((
                3,
                vec![
                    instructions[index].clone(),
                    OwnedInstruction::Op(OP_NUMEQUAL),
                ],
            ));
        }
    }

    // Hash output lengths are fixed even when the hashed value is not.
    if let OwnedInstruction::Op(hash_op) = current {
        if let Some(length) = hash_output_len(*hash_op) {
            if instructions
                .get(index + 1)
                .is_some_and(|instruction| instruction.is_op(OP_SIZE))
            {
                if let (Some(expected), Some(comparison)) = (
                    instructions
                        .get(index + 2)
                        .and_then(OwnedInstruction::push_num),
                    instructions.get(index + 3),
                ) {
                    let matches = expected == length;
                    if comparison.is_op(OP_NUMEQUAL) || comparison.is_op(OP_EQUAL) {
                        return Some((
                            4,
                            vec![current.clone(), push_script_num(i64::from(matches))],
                        ));
                    }
                    if matches
                        && (comparison.is_op(OP_NUMEQUALVERIFY) || comparison.is_op(OP_EQUALVERIFY))
                    {
                        return Some((4, vec![current.clone()]));
                    }
                }
            }
        }
    }

    // Threshold expressions over two canonical booleans have much smaller
    // direct forms.
    if current.is_op(OP_ADD) && facts.top.is_bool() && facts.second.is_bool() {
        if instructions
            .get(index + 1)
            .is_some_and(|instruction| instruction.is_op(OP_0NOTEQUAL))
        {
            return Some((2, vec![OwnedInstruction::Op(OP_BOOLOR)]));
        }
        if let (Some(threshold), Some(OwnedInstruction::Op(comparison))) = (
            instructions
                .get(index + 1)
                .and_then(OwnedInstruction::push_num),
            instructions.get(index + 2),
        ) {
            let replacement = boolean_sum_comparison(threshold, *comparison);
            if let Some(replacement) = replacement {
                return Some((
                    3,
                    replacement.into_iter().map(OwnedInstruction::Op).collect(),
                ));
            }
        }
    }

    // A constant hash comparison can be decided without materializing the
    // intermediate digest, even when precomputing the hash alone would grow
    // the script.
    if let (Some(input), Some(OwnedInstruction::Op(hash_op)), Some(expected), Some(comparison)) = (
        current.pushed_bytes(),
        instructions.get(index + 1),
        instructions
            .get(index + 2)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 3),
    ) {
        if is_hash(*hash_op) {
            let matches = hash_bytes(*hash_op, &input) == expected;
            if comparison.is_op(OP_EQUAL) {
                return Some((4, vec![push_script_num(i64::from(matches))]));
            }
            if comparison.is_op(OP_EQUALVERIFY) && matches {
                return Some((4, Vec::new()));
            }
        }
    }

    // Fold a constant duplicated into a binary operation. This catches
    // expressions such as `7 DUP ADD` that adjacent-constant folding cannot.
    if let (Some(duplicate), Some(OwnedInstruction::Op(binary))) =
        (instructions.get(index + 1), instructions.get(index + 2))
    {
        if duplicate.is_op(OP_DUP) {
            if *binary == OP_EQUAL {
                return Some((3, vec![push_script_num(1)]));
            }
            if *binary == OP_EQUALVERIFY {
                return Some((3, Vec::new()));
            }
            if let Some(number) = current.push_num() {
                if *binary == OP_NUMEQUALVERIFY {
                    return Some((3, Vec::new()));
                }
                if let Some(result) = fold_binary_numbers(number, number, *binary) {
                    return Some((3, vec![push_script_num(result)]));
                }
            }
        }
    }

    // Repeated literal locktime/sequence assertions are redundant.
    if let (
        Some(value),
        Some(OwnedInstruction::Op(first_check)),
        Some(first_drop),
        Some(other_value),
        Some(OwnedInstruction::Op(second_check)),
        Some(second_drop),
    ) = (
        current.pushed_bytes(),
        instructions.get(index + 1),
        instructions.get(index + 2),
        instructions
            .get(index + 3)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 4),
        instructions.get(index + 5),
    ) {
        if value == other_value
            && first_check == second_check
            && [OP_CLTV, OP_CSV].contains(first_check)
            && first_drop.is_op(OP_DROP)
            && second_drop.is_op(OP_DROP)
        {
            return Some((
                6,
                vec![
                    instructions[index].clone(),
                    OwnedInstruction::Op(*first_check),
                    OwnedInstruction::Op(OP_DROP),
                ],
            ));
        }
    }

    if let (Some(left), Some(right), Some(after)) = (
        current.pushed_bytes(),
        instructions
            .get(index + 1)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 2),
    ) {
        if after.is_op(OP_2DROP) {
            return Some((3, Vec::new()));
        }
        if after.is_op(OP_NIP) {
            return Some((3, vec![instructions[index + 1].clone()]));
        }
        if after.is_op(OP_SWAP) {
            return Some((
                3,
                vec![instructions[index + 1].clone(), instructions[index].clone()],
            ));
        }
        if after.is_op(OP_NUMEQUALVERIFY) {
            if let (Ok(left), Ok(right)) = (read_scriptint(&left), read_scriptint(&right)) {
                if left == right {
                    return Some((3, Vec::new()));
                }
            }
        }
    }

    if let (Some(bytes), Some(size), Some(nip)) = (
        current.pushed_bytes(),
        instructions.get(index + 1),
        instructions.get(index + 2),
    ) {
        if size.is_op(OP_SIZE) && nip.is_op(OP_NIP) {
            return Some((3, vec![push_script_num(bytes.len() as i64)]));
        }
    }

    if current.pushed_bytes().is_some()
        && instructions
            .get(index + 1)
            .is_some_and(|item| item.is_op(OP_DROP))
    {
        return Some((2, Vec::new()));
    }

    if let (Some(duplicate), Some(OwnedInstruction::Op(binary))) =
        (instructions.get(index), instructions.get(index + 1))
    {
        if duplicate.is_op(OP_DUP) {
            if facts.top.is_bool() && (*binary == OP_BOOLAND || *binary == OP_BOOLOR) {
                return Some((2, Vec::new()));
            }
            if *binary == OP_EQUAL {
                return Some((2, vec![OwnedInstruction::Op(OP_DROP), push_script_num(1)]));
            }
            if facts.top.is_num4() {
                if *binary == OP_MIN || *binary == OP_MAX {
                    return Some((2, Vec::new()));
                }
                if *binary == OP_NUMEQUALVERIFY {
                    return Some((2, vec![OwnedInstruction::Op(OP_DROP)]));
                }
                let constant = if [OP_SUB, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN]
                    .contains(binary)
                {
                    Some(0)
                } else if [OP_NUMEQUAL, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL].contains(binary)
                {
                    Some(1)
                } else {
                    None
                };
                if let Some(constant) = constant {
                    return Some((
                        2,
                        vec![OwnedInstruction::Op(OP_DROP), push_script_num(constant)],
                    ));
                }
            }
        }
    }

    if let (Some(OwnedInstruction::Op(operation)), Some(drop)) =
        (instructions.get(index), instructions.get(index + 1))
    {
        if drop.is_op(OP_DROP) {
            if is_numeric_unary(*operation) && facts.top.is_num4() {
                return Some((2, vec![OwnedInstruction::Op(OP_DROP)]));
            }
            if is_numeric_binary(*operation) && facts.top.is_num4() && facts.second.is_num4() {
                return Some((2, vec![OwnedInstruction::Op(OP_2DROP)]));
            }
        }
    }

    if let (Some(constant), Some(OwnedInstruction::Op(operation))) =
        (current.push_num(), instructions.get(index + 1))
    {
        if facts.top.is_bool() {
            if (constant == 1 && (*operation == OP_NUMEQUAL || *operation == OP_BOOLAND))
                || (constant == 0 && (*operation == OP_NUMNOTEQUAL || *operation == OP_BOOLOR))
            {
                return Some((2, Vec::new()));
            }
            if constant == 1 && *operation == OP_NUMNOTEQUAL {
                return Some((2, vec![OwnedInstruction::Op(OP_NOT)]));
            }
            if constant == 1 && *operation == OP_NUMEQUALVERIFY {
                return Some((2, vec![OwnedInstruction::Op(OP_VERIFY)]));
            }
        }
        if facts.top.is_num4() {
            if constant == 0 && *operation == OP_BOOLAND {
                return Some((2, vec![OwnedInstruction::Op(OP_DROP), push_script_num(0)]));
            }
            if constant == 1 && *operation == OP_BOOLOR {
                return Some((2, vec![OwnedInstruction::Op(OP_DROP), push_script_num(1)]));
            }
        }
    }

    if facts.top.is_bool() {
        if current.is_op(OP_0NOTEQUAL) || current.is_op(OP_ABS) {
            return Some((1, Vec::new()));
        }
        if current.is_op(OP_NOT)
            && instructions
                .get(index + 1)
                .is_some_and(|instruction| instruction.is_op(OP_NOT))
        {
            return Some((2, Vec::new()));
        }
    }

    if let Some(branch) = instructions.get(index + 1) {
        if facts.top.is_bool() && current.is_op(OP_NOT) {
            if branch.is_op(OP_IF) {
                return Some((2, vec![OwnedInstruction::Op(OP_NOTIF)]));
            }
            if branch.is_op(OP_NOTIF) {
                return Some((2, vec![OwnedInstruction::Op(OP_IF)]));
            }
        }
        if facts.top.is_bool()
            && current.is_op(OP_0NOTEQUAL)
            && (branch.is_op(OP_IF) || branch.is_op(OP_NOTIF))
        {
            return Some((2, vec![branch.clone()]));
        }
    }

    None
}

fn is_numeric_unary(op: Opcode) -> bool {
    [OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL].contains(&op)
}

fn is_numeric_binary(op: Opcode) -> bool {
    [
        OP_ADD,
        OP_SUB,
        OP_BOOLAND,
        OP_BOOLOR,
        OP_NUMEQUAL,
        OP_NUMNOTEQUAL,
        OP_LESSTHAN,
        OP_GREATERTHAN,
        OP_LESSTHANOREQUAL,
        OP_GREATERTHANOREQUAL,
        OP_MIN,
        OP_MAX,
    ]
    .contains(&op)
}

fn is_pure_unary(op: Opcode) -> bool {
    is_hash(op) || is_numeric_unary(op)
}

fn hash_output_len(op: Opcode) -> Option<i64> {
    if [OP_RIPEMD160, OP_SHA1, OP_HASH160].contains(&op) {
        Some(20)
    } else if [OP_SHA256, OP_HASH256].contains(&op) {
        Some(32)
    } else {
        None
    }
}

fn boolean_sum_comparison(threshold: i64, comparison: Opcode) -> Option<Vec<Opcode>> {
    if (threshold == 0 && comparison == OP_NUMNOTEQUAL)
        || (threshold == 1 && comparison == OP_GREATERTHANOREQUAL)
        || (threshold == 0 && comparison == OP_GREATERTHAN)
    {
        Some(vec![OP_BOOLOR])
    } else if (threshold == 2 && comparison == OP_NUMEQUAL)
        || (threshold == 2 && comparison == OP_GREATERTHANOREQUAL)
        || (threshold == 1 && comparison == OP_GREATERTHAN)
    {
        Some(vec![OP_BOOLAND])
    } else if threshold == 1 && comparison == OP_NUMEQUAL {
        Some(vec![OP_NUMNOTEQUAL])
    } else if threshold == 1 && comparison == OP_NUMNOTEQUAL {
        Some(vec![OP_NUMEQUAL])
    } else if threshold == 0 && comparison == OP_NUMEQUAL {
        Some(vec![OP_BOOLOR, OP_NOT])
    } else if threshold == 2 && comparison == OP_NUMNOTEQUAL {
        Some(vec![OP_BOOLAND, OP_NOT])
    } else {
        None
    }
}

fn matches_num_op_sequence(
    instructions: &[OwnedInstruction],
    start: usize,
    sequence: &[(i64, Opcode)],
) -> bool {
    sequence.iter().enumerate().all(|(offset, (number, op))| {
        instructions
            .get(start + offset * 2)
            .is_some_and(|instruction| instruction.is_push_num(*number))
            && instructions
                .get(start + offset * 2 + 1)
                .is_some_and(|instruction| instruction.is_op(*op))
    })
}

/// `Some(None)` means remove the pair; `Some(Some(op))` means replace it.
fn pair_replacement(current: &OwnedInstruction, next: &OwnedInstruction) -> Option<Option<Opcode>> {
    let pair = |left: Opcode, right: Opcode| current.is_op(left) && next.is_op(right);

    if pair(OP_EQUAL, OP_VERIFY) {
        return Some(Some(OP_EQUALVERIFY));
    }
    if pair(OP_NUMEQUAL, OP_VERIFY) {
        return Some(Some(OP_NUMEQUALVERIFY));
    }
    if pair(OP_CHECKSIG, OP_VERIFY) {
        return Some(Some(OP_CHECKSIGVERIFY));
    }
    if pair(OP_SHA256, OP_RIPEMD160) {
        return Some(Some(OP_HASH160));
    }
    if pair(OP_SHA256, OP_SHA256) {
        return Some(Some(OP_HASH256));
    }
    if is_hash_drop(current, next) {
        return Some(Some(OP_DROP));
    }
    if pair(OP_EQUAL, OP_DROP) {
        return Some(Some(OP_2DROP));
    }
    if pair(OP_DEPTH, OP_DROP) {
        return Some(None);
    }

    if current.is_op(OP_SWAP) {
        if let OwnedInstruction::Op(op) = next {
            if [
                OP_ADD,
                OP_BOOLAND,
                OP_BOOLOR,
                OP_NUMEQUAL,
                OP_NUMNOTEQUAL,
                OP_MIN,
                OP_MAX,
                OP_EQUAL,
                OP_EQUALVERIFY,
                OP_NUMEQUALVERIFY,
            ]
            .contains(op)
            {
                return Some(Some(*op));
            }
            let replacement = if *op == OP_LESSTHAN {
                Some(OP_GREATERTHAN)
            } else if *op == OP_GREATERTHAN {
                Some(OP_LESSTHAN)
            } else if *op == OP_LESSTHANOREQUAL {
                Some(OP_GREATERTHANOREQUAL)
            } else if *op == OP_GREATERTHANOREQUAL {
                Some(OP_LESSTHANOREQUAL)
            } else {
                None
            };
            if replacement.is_some() {
                return Some(replacement);
            }
        }
    }

    let boolean_replacement = if pair(OP_NOT, OP_NOT) || pair(OP_0NOTEQUAL, OP_0NOTEQUAL) {
        Some(OP_0NOTEQUAL)
    } else if pair(OP_NOT, OP_0NOTEQUAL) || pair(OP_0NOTEQUAL, OP_NOT) {
        Some(OP_NOT)
    } else if (current.is_op(OP_ABS) || current.is_op(OP_NEGATE)) && next.is_op(OP_0NOTEQUAL) {
        Some(OP_0NOTEQUAL)
    } else if (current.is_op(OP_ABS) || current.is_op(OP_NEGATE)) && next.is_op(OP_NOT) {
        Some(OP_NOT)
    } else if pair(OP_ABS, OP_ABS) || pair(OP_NEGATE, OP_ABS) {
        Some(OP_ABS)
    } else if pair(OP_NUMEQUAL, OP_NOT) {
        Some(OP_NUMNOTEQUAL)
    } else if pair(OP_NUMNOTEQUAL, OP_NOT) {
        Some(OP_NUMEQUAL)
    } else if pair(OP_LESSTHAN, OP_NOT) {
        Some(OP_GREATERTHANOREQUAL)
    } else if pair(OP_GREATERTHAN, OP_NOT) {
        Some(OP_LESSTHANOREQUAL)
    } else if pair(OP_LESSTHANOREQUAL, OP_NOT) {
        Some(OP_GREATERTHAN)
    } else if pair(OP_GREATERTHANOREQUAL, OP_NOT) {
        Some(OP_LESSTHAN)
    } else {
        None
    };
    if boolean_replacement.is_some() {
        return Some(boolean_replacement);
    }

    if next.is_op(OP_0NOTEQUAL)
        && matches!(current, OwnedInstruction::Op(op) if is_boolean_producer(*op))
    {
        return Some(match current {
            OwnedInstruction::Op(op) => Some(*op),
            _ => unreachable!(),
        });
    }

    if current.is_op(OP_DUP) && (next.is_op(OP_BOOLAND) || next.is_op(OP_BOOLOR)) {
        return Some(Some(OP_0NOTEQUAL));
    }
    if pair(OP_DUP, OP_EQUALVERIFY) {
        return Some(Some(OP_DROP));
    }
    if pair(OP_CLTV, OP_CLTV) {
        return Some(Some(OP_CLTV));
    }
    if pair(OP_CSV, OP_CSV) {
        return Some(Some(OP_CSV));
    }

    None
}

fn is_hash_drop(current: &OwnedInstruction, next: &OwnedInstruction) -> bool {
    next.is_op(OP_DROP) && matches!(current, OwnedInstruction::Op(op) if is_hash(*op))
}

fn is_hash(op: Opcode) -> bool {
    [OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256].contains(&op)
}

fn is_boolean_binary(op: Opcode) -> bool {
    [
        OP_BOOLAND,
        OP_BOOLOR,
        OP_NUMEQUAL,
        OP_NUMNOTEQUAL,
        OP_LESSTHAN,
        OP_GREATERTHAN,
        OP_LESSTHANOREQUAL,
        OP_GREATERTHANOREQUAL,
    ]
    .contains(&op)
}

fn is_boolean_producer(op: Opcode) -> bool {
    is_boolean_binary(op) || [OP_EQUAL, OP_WITHIN, OP_NOT, OP_0NOTEQUAL, OP_CHECKSIG].contains(&op)
}

// ---- Constant folding -----------------------------------------------------

fn fold_constants(
    instructions: &[OwnedInstruction],
    index: usize,
) -> Option<(usize, Vec<OwnedInstruction>)> {
    // SIZE keeps the known byte string on the stack. Fold consumers of its
    // length directly, including lengths whose own push would cost >1 byte.
    if let (Some(bytes), Some(size), Some(min), Some(max), Some(within)) = (
        instructions
            .get(index)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 1),
        instructions
            .get(index + 2)
            .and_then(OwnedInstruction::push_num),
        instructions
            .get(index + 3)
            .and_then(OwnedInstruction::push_num),
        instructions.get(index + 4),
    ) {
        if size.is_op(OP_SIZE) && within.is_op(OP_WITHIN) {
            let length = bytes.len() as i64;
            return Some((
                5,
                vec![
                    instructions[index].clone(),
                    push_script_num(i64::from(length >= min && length < max)),
                ],
            ));
        }
    }

    if let (Some(bytes), Some(size), Some(right), Some(OwnedInstruction::Op(op))) = (
        instructions
            .get(index)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 1),
        instructions
            .get(index + 2)
            .and_then(OwnedInstruction::push_num),
        instructions.get(index + 3),
    ) {
        if size.is_op(OP_SIZE) {
            if let Some(result) = fold_binary_numbers(bytes.len() as i64, right, *op) {
                return Some((
                    4,
                    vec![instructions[index].clone(), push_script_num(result)],
                ));
            }
        }
    }

    if let (Some(bytes), Some(size), Some(OwnedInstruction::Op(op))) = (
        instructions
            .get(index)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 1),
        instructions.get(index + 2),
    ) {
        if size.is_op(OP_SIZE) {
            if let Some(result) = fold_unary_number(bytes.len() as i64, *op) {
                return Some((
                    3,
                    vec![instructions[index].clone(), push_script_num(result)],
                ));
            }
        }
    }

    if let (Some(x), Some(min), Some(max), Some(op)) = (
        instructions.get(index).and_then(OwnedInstruction::push_num),
        instructions
            .get(index + 1)
            .and_then(OwnedInstruction::push_num),
        instructions
            .get(index + 2)
            .and_then(OwnedInstruction::push_num),
        instructions.get(index + 3),
    ) {
        if op.is_op(OP_WITHIN) {
            return Some((4, vec![push_script_num(i64::from(x >= min && x < max))]));
        }
    }

    if let (Some(left), Some(right), Some(OwnedInstruction::Op(op))) = (
        instructions.get(index).and_then(OwnedInstruction::push_num),
        instructions
            .get(index + 1)
            .and_then(OwnedInstruction::push_num),
        instructions.get(index + 2),
    ) {
        if let Some(result) = fold_binary_numbers(left, right, *op) {
            return Some((3, vec![push_script_num(result)]));
        }
    }

    if let (Some(left), Some(right), Some(op)) = (
        instructions
            .get(index)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions
            .get(index + 1)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 2),
    ) {
        if op.is_op(OP_EQUAL) {
            return Some((3, vec![push_script_num(i64::from(left == right))]));
        }
        if op.is_op(OP_EQUALVERIFY) && left == right {
            return Some((3, Vec::new()));
        }
    }

    if let (Some(number), Some(OwnedInstruction::Op(op))) = (
        instructions.get(index).and_then(OwnedInstruction::push_num),
        instructions.get(index + 1),
    ) {
        if let Some(result) = fold_unary_number(number, *op) {
            return Some((2, vec![push_script_num(result)]));
        }
    }

    if let (Some(bytes), Some(OwnedInstruction::Op(op))) = (
        instructions
            .get(index)
            .and_then(OwnedInstruction::pushed_bytes),
        instructions.get(index + 1),
    ) {
        if is_hash(*op) {
            let replacement = OwnedInstruction::PushBytes(hash_bytes(*op, &bytes));
            let original_len = instructions[index].serialized_len() + 1;
            if replacement.serialized_len() < original_len {
                return Some((2, vec![replacement]));
            }
        }
        if *op == OP_SIZE && bytes.len() <= 16 {
            return Some((
                2,
                vec![
                    instructions[index].clone(),
                    push_script_num(bytes.len() as i64),
                ],
            ));
        }
        if *op == OP_VERIFY && read_scriptbool(&bytes) {
            return Some((2, Vec::new()));
        }
    }

    None
}

fn fold_binary_numbers(left: i64, right: i64, op: Opcode) -> Option<i64> {
    if op == OP_ADD {
        Some(left + right)
    } else if op == OP_SUB {
        Some(left - right)
    } else if op == OP_BOOLAND {
        Some(i64::from(left != 0 && right != 0))
    } else if op == OP_BOOLOR {
        Some(i64::from(left != 0 || right != 0))
    } else if op == OP_NUMEQUAL {
        Some(i64::from(left == right))
    } else if op == OP_NUMNOTEQUAL {
        Some(i64::from(left != right))
    } else if op == OP_LESSTHAN {
        Some(i64::from(left < right))
    } else if op == OP_GREATERTHAN {
        Some(i64::from(left > right))
    } else if op == OP_LESSTHANOREQUAL {
        Some(i64::from(left <= right))
    } else if op == OP_GREATERTHANOREQUAL {
        Some(i64::from(left >= right))
    } else if op == OP_MIN {
        Some(left.min(right))
    } else if op == OP_MAX {
        Some(left.max(right))
    } else {
        None
    }
}

fn fold_unary_number(number: i64, op: Opcode) -> Option<i64> {
    if op == OP_1ADD {
        Some(number + 1)
    } else if op == OP_1SUB {
        Some(number - 1)
    } else if op == OP_NEGATE {
        Some(-number)
    } else if op == OP_ABS {
        Some(number.abs())
    } else if op == OP_NOT {
        Some(i64::from(number == 0))
    } else if op == OP_0NOTEQUAL {
        Some(i64::from(number != 0))
    } else {
        None
    }
}

fn hash_bytes(op: Opcode, bytes: &[u8]) -> Vec<u8> {
    if op == OP_RIPEMD160 {
        ripemd160::Hash::hash(bytes).to_byte_array().to_vec()
    } else if op == OP_SHA1 {
        sha1::Hash::hash(bytes).to_byte_array().to_vec()
    } else if op == OP_SHA256 {
        sha256::Hash::hash(bytes).to_byte_array().to_vec()
    } else if op == OP_HASH160 {
        hash160::Hash::hash(bytes).to_byte_array().to_vec()
    } else if op == OP_HASH256 {
        sha256d::Hash::hash(bytes).to_byte_array().to_vec()
    } else {
        unreachable!("caller only passes deterministic hash opcodes")
    }
}

// ---- Symbolic stack superoptimizer ---------------------------------------

const FIXED_STACK_OPS: [Opcode; 15] = [
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_TOALTSTACK,
    OP_FROMALTSTACK,
];

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Symbol {
    Main(u8),
    Alt(u8),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StackTransform {
    main: Vec<Symbol>,
    alt: Vec<Symbol>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StackSignature {
    required_main: usize,
    required_alt: usize,
    transform: StackTransform,
}

struct StackRewriteTables {
    exact: HashMap<StackSignature, Vec<StackProgram>>,
    proven: HashMap<StackTransform, Vec<StackProgram>>,
}

#[derive(Clone)]
struct StackProgram {
    ops: Vec<Opcode>,
    required_main: usize,
    required_alt: usize,
    peak_growth: usize,
}

fn stack_rewrite_tables() -> &'static StackRewriteTables {
    static TABLES: OnceLock<StackRewriteTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exact = HashMap::new();
        let mut proven = HashMap::new();
        let mut sequence = Vec::new();
        enumerate_stack_sequences(0, 4, &mut sequence, &mut |candidate| {
            let Some(signature) = stack_signature(candidate) else {
                return;
            };
            let program = StackProgram {
                ops: candidate.to_vec(),
                required_main: signature.required_main,
                required_alt: signature.required_alt,
                peak_growth: stack_peak_growth(candidate).expect("fixed-stack candidate"),
            };
            insert_pareto_program(&mut exact, signature.clone(), program.clone());
            insert_pareto_program(&mut proven, signature.transform, program);
        });
        StackRewriteTables { exact, proven }
    })
}

fn enumerate_stack_sequences(
    depth: usize,
    max_depth: usize,
    sequence: &mut Vec<Opcode>,
    visit: &mut impl FnMut(&[Opcode]),
) {
    visit(sequence);
    if depth == max_depth {
        return;
    }
    for op in FIXED_STACK_OPS {
        sequence.push(op);
        enumerate_stack_sequences(depth + 1, max_depth, sequence, visit);
        sequence.pop();
    }
}

fn insert_pareto_program<K: Eq + std::hash::Hash>(
    table: &mut HashMap<K, Vec<StackProgram>>,
    key: K,
    candidate: StackProgram,
) {
    let programs = table.entry(key).or_default();
    if programs
        .iter()
        .any(|existing| stack_program_dominates(existing, &candidate))
    {
        return;
    }
    programs.retain(|existing| !stack_program_dominates(&candidate, existing));
    programs.push(candidate);
}

fn stack_program_dominates(left: &StackProgram, right: &StackProgram) -> bool {
    let no_worse = left.ops.len() <= right.ops.len()
        && left.required_main <= right.required_main
        && left.required_alt <= right.required_alt
        && left.peak_growth <= right.peak_growth;
    let strictly_better = left.ops.len() < right.ops.len()
        || left.required_main < right.required_main
        || left.required_alt < right.required_alt
        || left.peak_growth < right.peak_growth
        || (left.ops.len() == right.ops.len()
            && left.required_main == right.required_main
            && left.required_alt == right.required_alt
            && left.peak_growth == right.peak_growth
            && !opcode_sequence_cmp(&left.ops, &right.ops).is_gt());
    no_worse && strictly_better
}

fn opcode_sequence_cmp(left: &[Opcode], right: &[Opcode]) -> std::cmp::Ordering {
    left.iter()
        .map(|opcode| opcode.to_u8())
        .cmp(right.iter().map(|opcode| opcode.to_u8()))
}

fn stack_run_replacement(
    instructions: &[OwnedInstruction],
    start: usize,
    facts: &[PrefixFacts],
) -> Option<(usize, Vec<Opcode>)> {
    const MAX_WINDOW: usize = 12;
    let mut run = Vec::new();
    for instruction in instructions.iter().skip(start) {
        let OwnedInstruction::Op(op) = instruction else {
            break;
        };
        if !is_fixed_stack_op(*op) {
            break;
        }
        run.push(*op);
    }
    if run.len() < 2 {
        return None;
    }

    // Dynamic programming over all bounded rewrite edges avoids committing to
    // the largest immediate saving when two smaller windows compose better.
    struct StackChoice {
        consumed: usize,
        emitted: Vec<Opcode>,
    }

    let mut best_costs = vec![0_usize; run.len() + 1];
    let mut choices: Vec<Option<StackChoice>> =
        std::iter::repeat_with(|| None).take(run.len()).collect();
    for offset in (0..run.len()).rev() {
        best_costs[offset] = 1 + best_costs[offset + 1];
        choices[offset] = Some(StackChoice {
            consumed: 1,
            emitted: vec![run[offset]],
        });

        let max_consumed = MAX_WINDOW.min(run.len() - offset);
        for consumed in 2..=max_consumed {
            let Some(candidate) = stack_sequence_replacement(
                &run[offset..offset + consumed],
                facts[start + offset].main_depth,
                facts[start + offset].alt_depth,
            ) else {
                continue;
            };
            let proposed_cost = candidate.len() + best_costs[offset + consumed];
            if proposed_cost < best_costs[offset] {
                best_costs[offset] = proposed_cost;
                choices[offset] = Some(StackChoice {
                    consumed,
                    emitted: candidate,
                });
            }
        }
    }

    let mut replacement = Vec::with_capacity(best_costs[0]);
    let mut offset = 0;
    while offset < run.len() {
        let choice = choices[offset].take().expect("DP choice exists");
        replacement.extend(choice.emitted);
        offset += choice.consumed;
    }
    (replacement.len() < run.len()).then_some((run.len(), replacement))
}

fn stack_sequence_replacement(
    sequence: &[Opcode],
    known_main: usize,
    known_alt: usize,
) -> Option<Vec<Opcode>> {
    let tables = stack_rewrite_tables();
    let signature = stack_signature(sequence)?;
    let source_peak = stack_peak_growth(sequence)?;
    let mut candidates = Vec::new();
    if let Some(exact) = tables.exact.get(&signature) {
        candidates.extend(exact);
    }
    if known_main >= signature.required_main && known_alt >= signature.required_alt {
        if let Some(proven) = tables.proven.get(&signature.transform) {
            candidates.extend(proven.iter().filter(|candidate| {
                known_main >= candidate.required_main && known_alt >= candidate.required_alt
            }));
        }
    }

    candidates
        .into_iter()
        .filter(|candidate| {
            candidate.ops.len() < sequence.len() && candidate.peak_growth <= source_peak
        })
        .min_by(|left, right| {
            left.ops
                .len()
                .cmp(&right.ops.len())
                .then_with(|| left.peak_growth.cmp(&right.peak_growth))
                .then_with(|| opcode_sequence_cmp(&left.ops, &right.ops))
        })
        .map(|candidate| candidate.ops.clone())
}

fn stack_signature(sequence: &[Opcode]) -> Option<StackSignature> {
    const SYMBOL_DEPTH: usize = 32;
    let (required_main, required_alt) = stack_requirements(sequence)?;
    if required_main > SYMBOL_DEPTH || required_alt > SYMBOL_DEPTH {
        return None;
    }
    let mut main = (0..SYMBOL_DEPTH)
        .map(|index| Symbol::Main(index as u8))
        .collect();
    let mut alt = (0..SYMBOL_DEPTH)
        .map(|index| Symbol::Alt(index as u8))
        .collect();
    for op in sequence {
        if !apply_fixed_stack_op(&mut main, &mut alt, *op) {
            return None;
        }
    }
    Some(StackSignature {
        required_main,
        required_alt,
        transform: StackTransform { main, alt },
    })
}

fn stack_requirements(sequence: &[Opcode]) -> Option<(usize, usize)> {
    let mut main = 0_usize;
    let mut alt = 0_usize;
    let mut required_main = 0_usize;
    let mut required_alt = 0_usize;
    for op in sequence {
        let (main_needed, main_popped, main_pushed, alt_needed, alt_popped, alt_pushed) =
            fixed_stack_effect(*op)?;
        if main < main_needed {
            required_main += main_needed - main;
            main = main_needed;
        }
        if alt < alt_needed {
            required_alt += alt_needed - alt;
            alt = alt_needed;
        }
        main = main - main_popped + main_pushed;
        alt = alt - alt_popped + alt_pushed;
    }
    Some((required_main, required_alt))
}

fn stack_peak_growth(sequence: &[Opcode]) -> Option<usize> {
    let (required_main, required_alt) = stack_requirements(sequence)?;
    let mut main = required_main;
    let mut alt = required_alt;
    let initial_total = main + alt;
    let mut peak_growth = 0;
    for op in sequence {
        let (main_needed, main_popped, main_pushed, alt_needed, alt_popped, alt_pushed) =
            fixed_stack_effect(*op)?;
        if main < main_needed || alt < alt_needed {
            return None;
        }
        main = main - main_popped + main_pushed;
        alt = alt - alt_popped + alt_pushed;
        peak_growth = peak_growth.max((main + alt).saturating_sub(initial_total));
    }
    Some(peak_growth)
}

fn is_fixed_stack_op(op: Opcode) -> bool {
    FIXED_STACK_OPS.contains(&op)
}

fn fixed_stack_effect(op: Opcode) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let effect = if op == OP_DROP {
        (1, 1, 0, 0, 0, 0)
    } else if op == OP_DUP {
        (1, 0, 1, 0, 0, 0)
    } else if op == OP_NIP {
        (2, 1, 0, 0, 0, 0)
    } else if op == OP_OVER {
        (2, 0, 1, 0, 0, 0)
    } else if op == OP_ROT {
        (3, 0, 0, 0, 0, 0)
    } else if op == OP_SWAP {
        (2, 0, 0, 0, 0, 0)
    } else if op == OP_TUCK {
        (2, 0, 1, 0, 0, 0)
    } else if op == OP_2DROP {
        (2, 2, 0, 0, 0, 0)
    } else if op == OP_2DUP {
        (2, 0, 2, 0, 0, 0)
    } else if op == OP_3DUP {
        (3, 0, 3, 0, 0, 0)
    } else if op == OP_2OVER {
        (4, 0, 2, 0, 0, 0)
    } else if op == OP_2ROT {
        (6, 0, 0, 0, 0, 0)
    } else if op == OP_2SWAP {
        (4, 0, 0, 0, 0, 0)
    } else if op == OP_TOALTSTACK {
        (1, 1, 0, 0, 0, 1)
    } else if op == OP_FROMALTSTACK {
        (0, 0, 1, 1, 1, 0)
    } else {
        return None;
    };
    Some(effect)
}

fn apply_depth_effect(main: &mut usize, alt: &mut usize, op: Opcode) {
    let Some((main_needed, main_popped, main_pushed, alt_needed, alt_popped, alt_pushed)) =
        fixed_stack_effect(op)
    else {
        return;
    };
    *main = (*main).max(main_needed) - main_popped + main_pushed;
    *alt = (*alt).max(alt_needed) - alt_popped + alt_pushed;
}

fn apply_fixed_stack_op<T: Clone>(main: &mut Vec<T>, alt: &mut Vec<T>, op: Opcode) -> bool {
    if op == OP_DROP {
        main.pop().is_some()
    } else if op == OP_DUP {
        let Some(value) = main.last().cloned() else {
            return false;
        };
        main.push(value);
        true
    } else if op == OP_NIP {
        if main.len() < 2 {
            return false;
        }
        main.remove(main.len() - 2);
        true
    } else if op == OP_OVER {
        if main.len() < 2 {
            return false;
        }
        main.push(main[main.len() - 2].clone());
        true
    } else if op == OP_ROT {
        if main.len() < 3 {
            return false;
        }
        let value = main.remove(main.len() - 3);
        main.push(value);
        true
    } else if op == OP_SWAP {
        if main.len() < 2 {
            return false;
        }
        let len = main.len();
        main.swap(len - 1, len - 2);
        true
    } else if op == OP_TUCK {
        if main.len() < 2 {
            return false;
        }
        let value = main.last().expect("length checked").clone();
        let index = main.len() - 2;
        main.insert(index, value);
        true
    } else if op == OP_2DROP {
        if main.len() < 2 {
            return false;
        }
        main.truncate(main.len() - 2);
        true
    } else if op == OP_2DUP {
        if main.len() < 2 {
            return false;
        }
        let len = main.len();
        main.extend_from_within(len - 2..);
        true
    } else if op == OP_3DUP {
        if main.len() < 3 {
            return false;
        }
        let len = main.len();
        main.extend_from_within(len - 3..);
        true
    } else if op == OP_2OVER {
        if main.len() < 4 {
            return false;
        }
        let len = main.len();
        main.extend_from_within(len - 4..len - 2);
        true
    } else if op == OP_2ROT {
        if main.len() < 6 {
            return false;
        }
        let index = main.len() - 6;
        let moved: Vec<_> = main.drain(index..index + 2).collect();
        main.extend(moved);
        true
    } else if op == OP_2SWAP {
        if main.len() < 4 {
            return false;
        }
        let index = main.len() - 4;
        let values = main[index..].to_vec();
        main[index..].clone_from_slice(&[
            values[2].clone(),
            values[3].clone(),
            values[0].clone(),
            values[1].clone(),
        ]);
        true
    } else if op == OP_TOALTSTACK {
        let Some(value) = main.pop() else {
            return false;
        };
        alt.push(value);
        true
    } else if op == OP_FROMALTSTACK {
        let Some(value) = alt.pop() else {
            return false;
        };
        main.push(value);
        true
    } else {
        false
    }
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn op(op: Opcode) -> OwnedInstruction {
        OwnedInstruction::Op(op)
    }

    fn num(number: i64) -> OwnedInstruction {
        push_script_num(number)
    }

    fn bytes(bytes: &[u8]) -> OwnedInstruction {
        OwnedInstruction::PushBytes(bytes.to_vec())
    }

    fn assert_rule(before: Vec<OwnedInstruction>, after: Vec<OwnedInstruction>) {
        let optimized = optimize_instructions(before.clone());
        assert_eq!(optimized, after);
        assert!(assemble_script(&optimized).len() < assemble_script(&before).len());
    }

    fn two_unknown_boole() -> Vec<OwnedInstruction> {
        vec![
            op(OP_EQUAL),
            op(OP_TOALTSTACK),
            op(OP_EQUAL),
            op(OP_FROMALTSTACK),
        ]
    }

    #[test]
    fn direct_opcode_substitutions() {
        assert_rule(vec![num(1), op(OP_ADD)], vec![op(OP_1ADD)]);
        assert_rule(vec![num(1), op(OP_SUB)], vec![op(OP_1SUB)]);
        assert_rule(vec![num(0), op(OP_PICK)], vec![op(OP_DUP)]);
        assert_rule(vec![num(1), op(OP_PICK)], vec![op(OP_OVER)]);
        assert_rule(vec![num(1), op(OP_ROLL)], vec![op(OP_SWAP)]);
        assert_rule(vec![num(2), op(OP_ROLL)], vec![op(OP_ROT)]);
        assert_rule(
            vec![num(3), op(OP_ROLL), num(3), op(OP_ROLL)],
            vec![op(OP_2SWAP)],
        );
        assert_rule(
            vec![num(5), op(OP_ROLL), num(5), op(OP_ROLL)],
            vec![op(OP_2ROT)],
        );
        assert_rule(
            vec![num(1), op(OP_PICK), num(1), op(OP_PICK)],
            vec![op(OP_2DUP)],
        );
        assert_rule(
            vec![
                num(2),
                op(OP_PICK),
                num(2),
                op(OP_PICK),
                num(2),
                op(OP_PICK),
            ],
            vec![op(OP_3DUP)],
        );
        assert_rule(
            vec![num(3), op(OP_PICK), num(3), op(OP_PICK)],
            vec![op(OP_2OVER)],
        );
    }

    #[test]
    fn proof_dependent_stack_identities_only_run_with_a_proven_stack() {
        let unsafe_roll = vec![num(0), op(OP_ROLL)];
        assert_eq!(optimize_instructions(unsafe_roll.clone()), unsafe_roll);

        assert_rule(vec![num(7), num(0), op(OP_ROLL)], vec![num(7)]);
        assert_rule(
            vec![num(1), num(2), op(OP_SWAP), op(OP_SWAP)],
            vec![num(1), num(2)],
        );
        assert_rule(
            vec![num(1), op(OP_TOALTSTACK), op(OP_FROMALTSTACK)],
            vec![num(1)],
        );
        assert_rule(
            vec![
                num(1),
                num(2),
                num(3),
                num(4),
                op(OP_TOALTSTACK),
                op(OP_TOALTSTACK),
                op(OP_TOALTSTACK),
                op(OP_TOALTSTACK),
                op(OP_FROMALTSTACK),
                op(OP_FROMALTSTACK),
                op(OP_FROMALTSTACK),
                op(OP_FROMALTSTACK),
            ],
            vec![num(1), num(2), num(3), num(4)],
        );
        assert_rule(vec![num(1), num(0), op(OP_PICK), op(OP_DROP)], vec![num(1)]);
    }

    #[test]
    fn symbolic_stack_peepholes() {
        let cases = [
            (vec![OP_DROP, OP_DROP], vec![OP_2DROP]),
            (vec![OP_NIP, OP_DROP], vec![OP_2DROP]),
            (vec![OP_DUP, OP_2DROP], vec![OP_DROP]),
            (vec![OP_SWAP, OP_DROP], vec![OP_NIP]),
            (vec![OP_TUCK, OP_DROP], vec![OP_SWAP]),
            (vec![OP_TUCK, OP_2DROP], vec![OP_NIP]),
            (vec![OP_2DUP, OP_DROP], vec![OP_OVER]),
            (vec![OP_OVER, OP_OVER], vec![OP_2DUP]),
            (vec![OP_SWAP, OP_OVER], vec![OP_TUCK]),
            (vec![OP_SWAP, OP_TUCK], vec![OP_OVER]),
            (vec![OP_SWAP, OP_2DROP], vec![OP_2DROP]),
        ];
        for (before, after) in cases {
            assert_rule(
                before.into_iter().map(op).collect(),
                after.into_iter().map(op).collect(),
            );
        }

        assert_rule(
            vec![
                op(OP_ROT),
                op(OP_2DROP),
                op(OP_2OVER),
                op(OP_NIP),
                op(OP_NIP),
            ],
            vec![op(OP_2DROP), op(OP_2OVER), op(OP_NIP), op(OP_NIP)],
        );
        assert_rule(
            vec![
                op(OP_TOALTSTACK),
                op(OP_TOALTSTACK),
                op(OP_TOALTSTACK),
                op(OP_TOALTSTACK),
                op(OP_FROMALTSTACK),
                op(OP_FROMALTSTACK),
                op(OP_FROMALTSTACK),
                op(OP_FROMALTSTACK),
            ],
            vec![op(OP_2SWAP), op(OP_2SWAP)],
        );
        assert!(
            stack_peak_growth(&[OP_2SWAP, OP_2SWAP])
                <= stack_peak_growth(&[
                    OP_TOALTSTACK,
                    OP_TOALTSTACK,
                    OP_TOALTSTACK,
                    OP_TOALTSTACK,
                    OP_FROMALTSTACK,
                    OP_FROMALTSTACK,
                    OP_FROMALTSTACK,
                    OP_FROMALTSTACK,
                ])
        );

        // The shortest exact representative needs more temporary stack than
        // this source, so retain and select a one-byte-saving Pareto option.
        let peak_sensitive = vec![
            op(OP_TOALTSTACK),
            op(OP_OVER),
            op(OP_FROMALTSTACK),
            op(OP_ROT),
            op(OP_ROT),
        ];
        let optimized = optimize_instructions(peak_sensitive.clone());
        assert_eq!(optimized.len(), 4);
        let to_ops = |instructions: &[OwnedInstruction]| {
            instructions
                .iter()
                .map(|instruction| match instruction {
                    OwnedInstruction::Op(op) => *op,
                    OwnedInstruction::PushBytes(_) => panic!("stack rewrite emitted a literal"),
                })
                .collect::<Vec<_>>()
        };
        let original_ops = to_ops(&peak_sensitive);
        let optimized_ops = to_ops(&optimized);
        assert_eq!(
            stack_signature(&optimized_ops),
            stack_signature(&original_ops)
        );
        assert!(stack_peak_growth(&optimized_ops) <= stack_peak_growth(&original_ops));

        assert_rule(
            vec![
                op(OP_SWAP),
                op(OP_2DUP),
                op(OP_TOALTSTACK),
                op(OP_NIP),
                op(OP_2DUP),
                op(OP_3DUP),
                op(OP_2SWAP),
            ],
            vec![
                op(OP_SWAP),
                op(OP_TOALTSTACK),
                op(OP_DUP),
                op(OP_2DUP),
                op(OP_3DUP),
            ],
        );
    }

    #[test]
    fn literals_and_constant_stack_accesses_are_rematerialized() {
        let literal = bytes(&[0x2a; 8]);
        assert_rule(
            vec![literal.clone(), literal.clone()],
            vec![literal.clone(), op(OP_DUP)],
        );
        assert_rule(
            vec![literal.clone(), literal.clone(), literal.clone()],
            vec![literal.clone(), op(OP_DUP), op(OP_DUP)],
        );
        assert_rule(vec![bytes(&[1]), num(1)], vec![num(1), op(OP_DUP)]);
        assert_rule(
            vec![
                literal.clone(),
                op(OP_TOALTSTACK),
                num(7),
                op(OP_FROMALTSTACK),
            ],
            vec![num(7), literal],
        );

        assert_rule(vec![num(0), op(OP_ROLL), op(OP_DROP)], vec![op(OP_DROP)]);
        assert_rule(
            vec![num(1), num(2), num(3), num(2), op(OP_PICK), op(OP_2DROP)],
            vec![num(1), num(2)],
        );
        let unproven_pick = vec![num(2), op(OP_PICK), op(OP_2DROP)];
        assert_eq!(optimize_instructions(unproven_pick.clone()), unproven_pick);
    }

    #[test]
    fn verify_hash_and_dead_result_rules() {
        let cases = [
            (vec![OP_EQUAL, OP_VERIFY], vec![OP_EQUALVERIFY]),
            (vec![OP_NUMEQUAL, OP_VERIFY], vec![OP_NUMEQUALVERIFY]),
            (vec![OP_CHECKSIG, OP_VERIFY], vec![OP_CHECKSIGVERIFY]),
            (vec![OP_SHA256, OP_RIPEMD160], vec![OP_HASH160]),
            (vec![OP_SHA256, OP_SHA256], vec![OP_HASH256]),
            (vec![OP_SHA256, OP_DROP], vec![OP_DROP]),
            (vec![OP_EQUAL, OP_DROP], vec![OP_2DROP]),
            (vec![OP_DEPTH, OP_DROP], vec![]),
        ];
        for (before, after) in cases {
            assert_rule(
                before.into_iter().map(op).collect(),
                after.into_iter().map(op).collect(),
            );
        }

        assert_rule(
            vec![op(OP_DUP), op(OP_SHA256), op(OP_SWAP), op(OP_SHA256)],
            vec![op(OP_SHA256), op(OP_DUP)],
        );
        assert_rule(
            vec![
                op(OP_DUP),
                op(OP_SHA256),
                op(OP_HASH160),
                op(OP_SWAP),
                op(OP_SHA256),
                op(OP_HASH160),
            ],
            vec![op(OP_SHA256), op(OP_HASH160), op(OP_DUP)],
        );
        assert_rule(
            vec![op(OP_DUP), op(OP_NEGATE), op(OP_SWAP), op(OP_NEGATE)],
            vec![op(OP_NEGATE), op(OP_DUP)],
        );
        assert_rule(
            vec![op(OP_DUP), op(OP_VERIFY), op(OP_VERIFY)],
            vec![op(OP_VERIFY)],
        );
        assert_rule(
            vec![op(OP_DUP), op(OP_VERIFY), op(OP_DROP)],
            vec![op(OP_VERIFY)],
        );
    }

    #[test]
    fn arithmetic_and_range_algebra() {
        assert_rule(vec![op(OP_NEGATE), op(OP_ADD)], vec![op(OP_SUB)]);
        assert_rule(vec![op(OP_NEGATE), op(OP_SUB)], vec![op(OP_ADD)]);
        assert_rule(vec![num(0), op(OP_SWAP), op(OP_SUB)], vec![op(OP_NEGATE)]);
        assert_rule(vec![num(17), op(OP_BOOLAND)], vec![op(OP_0NOTEQUAL)]);
        assert_rule(
            vec![op(OP_NOT), op(OP_SWAP), op(OP_NOT), op(OP_BOOLAND)],
            vec![op(OP_BOOLOR), op(OP_NOT)],
        );
        assert_rule(
            vec![op(OP_NOT), op(OP_SWAP), op(OP_NOT), op(OP_BOOLOR)],
            vec![op(OP_BOOLAND), op(OP_NOT)],
        );

        assert_rule(
            vec![num(1000), op(OP_MIN), num(20), op(OP_MIN)],
            vec![num(20), op(OP_MIN)],
        );
        assert_rule(
            vec![num(-1000), op(OP_MAX), num(20), op(OP_MAX)],
            vec![num(20), op(OP_MAX)],
        );
        for (clamp, comparison) in [
            (OP_MIN, OP_NUMEQUAL),
            (OP_MIN, OP_NUMNOTEQUAL),
            (OP_MAX, OP_NUMEQUAL),
            (OP_MAX, OP_NUMNOTEQUAL),
        ] {
            let replacement = if clamp == OP_MIN && comparison == OP_NUMEQUAL {
                OP_GREATERTHANOREQUAL
            } else if clamp == OP_MIN {
                OP_LESSTHAN
            } else if comparison == OP_NUMEQUAL {
                OP_LESSTHANOREQUAL
            } else {
                OP_GREATERTHAN
            };
            assert_rule(
                vec![num(21), op(clamp), num(21), op(comparison)],
                vec![num(21), op(replacement)],
            );
        }
        assert_rule(
            vec![num(21), op(OP_MIN), num(21), op(OP_NUMEQUALVERIFY)],
            vec![num(21), op(OP_GREATERTHANOREQUAL), op(OP_VERIFY)],
        );
        assert_rule(
            vec![num(41), num(42), op(OP_WITHIN)],
            vec![num(41), op(OP_NUMEQUAL)],
        );
    }

    #[test]
    fn commutative_and_comparison_rules() {
        for symmetric in [
            OP_ADD,
            OP_BOOLAND,
            OP_BOOLOR,
            OP_NUMEQUAL,
            OP_NUMNOTEQUAL,
            OP_MIN,
            OP_MAX,
            OP_EQUAL,
            OP_EQUALVERIFY,
            OP_NUMEQUALVERIFY,
        ] {
            assert_rule(vec![op(OP_SWAP), op(symmetric)], vec![op(symmetric)]);
        }
        for (before, after) in [
            (OP_LESSTHAN, OP_GREATERTHAN),
            (OP_GREATERTHAN, OP_LESSTHAN),
            (OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL),
            (OP_GREATERTHANOREQUAL, OP_LESSTHANOREQUAL),
        ] {
            assert_rule(vec![op(OP_SWAP), op(before)], vec![op(after)]);
        }
    }

    #[test]
    fn boolean_and_complement_rules() {
        let cases = [
            (vec![OP_NOT, OP_NOT], OP_0NOTEQUAL),
            (vec![OP_0NOTEQUAL, OP_0NOTEQUAL], OP_0NOTEQUAL),
            (vec![OP_NOT, OP_0NOTEQUAL], OP_NOT),
            (vec![OP_0NOTEQUAL, OP_NOT], OP_NOT),
            (vec![OP_ABS, OP_0NOTEQUAL], OP_0NOTEQUAL),
            (vec![OP_NEGATE, OP_NOT], OP_NOT),
            (vec![OP_ABS, OP_ABS], OP_ABS),
            (vec![OP_NEGATE, OP_ABS], OP_ABS),
            (vec![OP_NUMEQUAL, OP_NOT], OP_NUMNOTEQUAL),
            (vec![OP_NUMNOTEQUAL, OP_NOT], OP_NUMEQUAL),
            (vec![OP_LESSTHAN, OP_NOT], OP_GREATERTHANOREQUAL),
            (vec![OP_GREATERTHAN, OP_NOT], OP_LESSTHANOREQUAL),
            (vec![OP_LESSTHANOREQUAL, OP_NOT], OP_GREATERTHAN),
            (vec![OP_GREATERTHANOREQUAL, OP_NOT], OP_LESSTHAN),
            (vec![OP_DUP, OP_BOOLAND], OP_0NOTEQUAL),
            (vec![OP_DUP, OP_BOOLOR], OP_0NOTEQUAL),
            (vec![OP_DUP, OP_EQUALVERIFY], OP_DROP),
        ];
        for (before, after) in cases {
            assert_rule(before.into_iter().map(op).collect(), vec![op(after)]);
        }

        for producer in [
            OP_EQUAL,
            OP_NUMEQUAL,
            OP_NUMNOTEQUAL,
            OP_LESSTHAN,
            OP_GREATERTHAN,
            OP_LESSTHANOREQUAL,
            OP_GREATERTHANOREQUAL,
            OP_BOOLAND,
            OP_BOOLOR,
            OP_WITHIN,
            OP_NOT,
            OP_0NOTEQUAL,
            OP_CHECKSIG,
        ] {
            assert_rule(vec![op(producer), op(OP_0NOTEQUAL)], vec![op(producer)]);
        }

        assert_rule(vec![op(OP_EQUAL), op(OP_ABS)], vec![op(OP_EQUAL)]);
        assert_rule(
            vec![op(OP_EQUAL), op(OP_NOT), op(OP_NOT)],
            vec![op(OP_EQUAL)],
        );
        assert_rule(
            vec![op(OP_EQUAL), op(OP_DUP), op(OP_BOOLAND)],
            vec![op(OP_EQUAL)],
        );
        assert_rule(
            vec![op(OP_EQUAL), num(1), op(OP_NUMEQUAL)],
            vec![op(OP_EQUAL)],
        );

        let equal_cost = vec![op(OP_DUP), op(OP_EQUAL)];
        assert_eq!(optimize_instructions(equal_cost.clone()), equal_cost);
    }

    #[test]
    fn boolean_thresholds_collapse_after_dataflow_analysis() {
        let cases = [
            (vec![OP_ADD, OP_0NOTEQUAL], vec![OP_BOOLOR]),
            (
                vec![OP_ADD, OP_PUSHNUM_1, OP_NUMEQUAL],
                vec![OP_NUMNOTEQUAL],
            ),
            (vec![OP_ADD, OP_PUSHNUM_2, OP_NUMEQUAL], vec![OP_BOOLAND]),
            (
                vec![OP_ADD, OP_PUSHNUM_1, OP_GREATERTHANOREQUAL],
                vec![OP_BOOLOR],
            ),
            (
                vec![OP_ADD, OP_PUSHNUM_2, OP_GREATERTHANOREQUAL],
                vec![OP_BOOLAND],
            ),
        ];
        for (suffix, replacement) in cases {
            let mut before = two_unknown_boole();
            before.extend(suffix.into_iter().map(op));
            let mut after = two_unknown_boole();
            after.extend(replacement.into_iter().map(op));
            assert_rule(before, after);
        }
    }

    #[test]
    fn special_constants_and_constant_folding() {
        assert_rule(vec![num(0), op(OP_NUMEQUAL)], vec![op(OP_NOT)]);
        assert_rule(vec![num(0), op(OP_NUMNOTEQUAL)], vec![op(OP_0NOTEQUAL)]);
        assert_rule(vec![num(0), op(OP_BOOLOR)], vec![op(OP_0NOTEQUAL)]);
        assert_rule(vec![num(1), op(OP_BOOLAND)], vec![op(OP_0NOTEQUAL)]);

        assert_rule(vec![num(7), num(9), op(OP_ADD)], vec![num(16)]);
        assert_rule(vec![num(9), num(7), op(OP_SUB)], vec![num(2)]);
        assert_rule(vec![num(5), num(0), num(10), op(OP_WITHIN)], vec![num(1)]);
        assert_rule(
            vec![bytes(b"same"), bytes(b"same"), op(OP_EQUALVERIFY)],
            vec![],
        );
        assert_rule(vec![num(1), op(OP_VERIFY)], vec![]);

        let twenty_bytes = bytes(&[42; 20]);
        assert_rule(
            vec![twenty_bytes.clone(), op(OP_SIZE), num(20), op(OP_NUMEQUAL)],
            vec![twenty_bytes, num(1)],
        );
    }

    #[test]
    fn constant_hashes_fold_only_when_smaller() {
        let data = vec![42_u8; 100];
        let expected = sha256::Hash::hash(&data).to_byte_array().to_vec();
        assert_rule(
            vec![OwnedInstruction::PushBytes(data), op(OP_SHA256)],
            vec![OwnedInstruction::PushBytes(expected)],
        );

        let short = vec![bytes(b"x"), op(OP_SHA256)];
        assert_eq!(optimize_instructions(short.clone()), short);

        let short_data = b"constant hash comparison";
        let digest = sha256::Hash::hash(short_data).to_byte_array();
        assert_rule(
            vec![
                bytes(short_data),
                op(OP_SHA256),
                bytes(&digest),
                op(OP_EQUAL),
            ],
            vec![num(1)],
        );

        assert_rule(
            vec![op(OP_SHA256), op(OP_SIZE), num(32), op(OP_NUMEQUALVERIFY)],
            vec![op(OP_SHA256)],
        );
    }

    #[test]
    fn locktime_and_nop_rules() {
        assert_rule(vec![op(OP_CLTV), op(OP_CLTV)], vec![op(OP_CLTV)]);
        assert_rule(vec![op(OP_CSV), op(OP_CSV)], vec![op(OP_CSV)]);
        assert_rule(
            vec![op(OP_DUP), op(OP_CLTV), op(OP_DROP)],
            vec![op(OP_CLTV)],
        );
        assert_rule(vec![op(OP_NOP)], vec![]);
    }

    #[test]
    fn control_flow_rules() {
        assert_rule(
            vec![num(1), op(OP_IF), num(2), op(OP_ELSE), num(3), op(OP_ENDIF)],
            vec![num(2)],
        );
        assert_rule(
            vec![
                num(0),
                op(OP_NOTIF),
                num(2),
                op(OP_ELSE),
                num(3),
                op(OP_ENDIF),
            ],
            vec![num(2)],
        );
        assert_rule(
            vec![op(OP_IF), op(OP_ELSE), num(2), op(OP_ENDIF)],
            vec![op(OP_NOTIF), num(2), op(OP_ENDIF)],
        );
        assert_rule(
            vec![op(OP_IF), num(2), op(OP_ELSE), op(OP_ENDIF)],
            vec![op(OP_IF), num(2), op(OP_ENDIF)],
        );
        assert_rule(
            vec![
                op(OP_IF),
                num(2),
                op(OP_DUP),
                op(OP_ELSE),
                num(3),
                op(OP_DUP),
                op(OP_ENDIF),
            ],
            vec![
                op(OP_IF),
                num(2),
                op(OP_ELSE),
                num(3),
                op(OP_ENDIF),
                op(OP_DUP),
            ],
        );

        assert_rule(
            vec![
                op(OP_EQUAL),
                op(OP_IF),
                num(1),
                op(OP_ELSE),
                num(0),
                op(OP_ENDIF),
            ],
            vec![op(OP_EQUAL)],
        );
        assert_rule(
            vec![
                op(OP_EQUAL),
                op(OP_IF),
                num(0),
                op(OP_ELSE),
                num(1),
                op(OP_ENDIF),
            ],
            vec![op(OP_EQUAL), op(OP_NOT)],
        );
        assert_rule(
            vec![
                op(OP_EQUAL),
                op(OP_IF),
                num(2),
                op(OP_ELSE),
                op(OP_RETURN),
                op(OP_ENDIF),
            ],
            vec![op(OP_EQUALVERIFY), num(2)],
        );
        assert_rule(
            vec![op(OP_EQUAL), op(OP_IF), op(OP_ENDIF)],
            vec![op(OP_2DROP)],
        );
        assert_rule(
            vec![
                op(OP_EQUAL),
                op(OP_IF),
                num(2),
                op(OP_ELSE),
                num(3),
                op(OP_ENDIF),
                num(0),
                op(OP_ADD),
            ],
            vec![
                op(OP_EQUAL),
                op(OP_IF),
                num(2),
                op(OP_ELSE),
                num(3),
                op(OP_ENDIF),
            ],
        );
    }

    #[test]
    fn op_success_disables_the_optimizer() {
        let script = vec![op(OP_NOP), op(Opcode::from(0xbb))];
        assert_eq!(optimize_instructions(script.clone()), script);
    }

    #[test]
    fn oversized_pushes_disable_the_optimizer_even_in_branches() {
        let oversized = bytes(&vec![0_u8; 521]);
        let script = vec![
            num(0),
            op(OP_IF),
            oversized,
            op(OP_DROP),
            op(OP_ENDIF),
            op(OP_NOP),
        ];
        assert_eq!(optimize_instructions(script.clone()), script);
    }

    #[test]
    fn malformed_or_eagerly_failing_control_flow_is_not_folded() {
        let malformed = vec![num(1), op(OP_IF), op(OP_ELSE), op(OP_ELSE), op(OP_ENDIF)];
        assert_eq!(optimize_control_flow_once(&malformed), malformed);

        let verif = vec![
            num(1),
            op(OP_IF),
            num(2),
            op(OP_ELSE),
            op(OP_VERIF),
            op(OP_ENDIF),
        ];
        assert_eq!(optimize_control_flow_once(&verif), verif);
    }

    #[test]
    fn proof_dependent_numeric_rules() {
        assert_rule(vec![num(7), num(0), op(OP_ADD)], vec![num(7)]);
        assert_rule(vec![num(7), op(OP_NEGATE), op(OP_NEGATE)], vec![num(7)]);

        let unproven = vec![num(0), op(OP_ADD)];
        assert_eq!(optimize_instructions(unproven.clone()), unproven);
    }

    #[test]
    fn assemble_roundtrip() {
        let original = vec![
            num(0),
            num(1),
            op(OP_ADD),
            bytes(&[0xde, 0xad]),
            op(OP_DROP),
        ];
        assert_eq!(flatten_script(&assemble_script(&original)), original);
    }
}
