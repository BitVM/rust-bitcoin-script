use bitcoin_script::script;
use bitcoin_script::Script;

#[test]
fn test_plain() {
    let mut script = script! (
        OP_ADD
        OP_ADD
        OP_ADD
    );
    let (x, y) = script.analyze_stack();
    assert_eq!(x, -4);
    assert_eq!(y, -3);
}

fn inner_fn1() -> Script {
    script!(
        {10}
        OP_ROLL
        {2}
        OP_ROLL
        OP_ADD
    )
}

fn inner_fn2() -> Script {
    script!(
        {1}
        OP_DUP
        OP_TOALTSTACK
        {2}
        OP_DUP
        OP_TOALTSTACK
        OP_GREATERTHAN
        OP_IF
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_ADD
        OP_ELSE
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_SUB
        OP_ENDIF
    )
}

#[test]
fn test_deepthest() {
    let mut script = script! (
        {inner_fn1()}
        {inner_fn1()}
        OP_ADD
    );
    let (x, y) = script.analyze_stack();
    assert_eq!([x, y], [-11, -3]);

    let mut script = script! (
     {inner_fn2()}
     {inner_fn2()}
     OP_ADD
    );
    let (x, y) = script.analyze_stack();
    assert_eq!([x, y], [0, 1]);
}

#[test]
fn test_deepthest2() {
    let mut script = script! (
        {1}
        OP_IF
            { 120 }
            OP_ADD
        OP_ENDIF
    );
    let (x, y) = script.analyze_stack();
    assert_eq!([x, y], [-1, 0]);
}
