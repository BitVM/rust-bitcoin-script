use bitcoin::{hashes::Hash, ScriptBuf, TapLeafHash, Transaction};
use bitcoin_script::{script, CompileOptions};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

fn execute(script: ScriptBuf, witness: Vec<Vec<u8>>) -> (bool, Vec<Vec<u8>>) {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script,
        witness,
    )
    .unwrap();
    while exec.exec_next().is_ok() {}
    let stack = (0..exec.stack().len())
        .map(|i| exec.stack().get(i))
        .collect();
    (exec.result().unwrap().success, stack)
}

#[test]
fn nonconstant_duplicate_comparisons_preserve_execution() {
    for (source, witness, expected) in [
        (
            script! { OP_ADD OP_DUP OP_EQUAL },
            vec![vec![11], vec![22]],
            vec![vec![1]],
        ),
        (
            script! { OP_SWAP OP_DUP OP_EQUALVERIFY },
            vec![vec![17], vec![34]],
            vec![vec![34]],
        ),
        // Numeric comparison is the existing guarded control.
        (
            script! { OP_SWAP OP_DUP OP_NUMEQUALVERIFY },
            vec![vec![17], vec![34]],
            vec![vec![34]],
        ),
    ] {
        let raw = source.clone().compile();
        let optimized = source.compile_with_options(CompileOptions::ALL);
        assert_eq!(
            execute(raw.clone(), witness.clone()),
            (true, expected.clone())
        );
        assert_eq!(execute(optimized.clone(), witness), (true, expected));
        // Optimizing must not turn stack underflow into success.
        for short in [vec![], vec![vec![1]]] {
            assert!(!execute(raw.clone(), short.clone()).0);
            assert!(!execute(optimized.clone(), short).0);
        }
    }
}

#[test]
fn literal_duplicate_byte_comparisons_still_fold() {
    for literal in [vec![], vec![7], vec![0x80], vec![42; 20]] {
        let push = if literal == [7] {
            script! { 7 }.compile()
        } else {
            bitcoin::script::Builder::new()
                .push_slice(bitcoin::script::PushBytesBuf::try_from(literal).unwrap())
                .into_script()
        };
        let equal = script! { { push.clone() } OP_DUP OP_EQUAL };
        assert_eq!(
            equal.compile_with_options(CompileOptions::ALL),
            script! { OP_TRUE }.compile()
        );
        let verify = script! { { push } OP_DUP OP_EQUALVERIFY };
        assert!(verify.compile_with_options(CompileOptions::ALL).is_empty());
    }
}
