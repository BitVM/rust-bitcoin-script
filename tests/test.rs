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
            147, 147, 124, 0, 0, 147, 147, 124, 0, 139, 147, 124, 0, 82, 147, 147, 124, 81, 0, 147,
            147, 124, 81, 139, 147, 124, 81, 82, 147, 147, 124, 82, 0, 147, 147, 124, 82, 139, 147,
            124, 82, 82, 147
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
            {loop_script.clone()}
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
    let script = script! {
        for i in 0..6 {
            { 6 }
            OP_ROLL
            { 10 + i + 1 }
            OP_ROLL
        }
    };

    assert_eq!(
        script.as_bytes(),
        vec![
            86, 122, 91, 122, 86, 122, 92, 122, 86, 122, 93, 122, 86, 122, 94, 122, 86, 122, 95,
            122, 86, 122, 96, 122
        ]
    );
}

#[test]
fn test_non_optimal_opcodes() {
    let script = script! {
        OP_0
        OP_ROLL
        0
        OP_ROLL
        OP_1
        OP_ROLL

        OP_DROP
        OP_DROP

        for i in 0..4 {
            OP_ROLL
            { i }
        }

        for i in 0..4 {
            { i }
            OP_ROLL
        }

    };

    println!("{:?}", script);
    assert_eq!(
        script.as_bytes(),
        vec![124, 109, 122, 124, 123, 83, 124, 123, 83, 122]
    );
}
