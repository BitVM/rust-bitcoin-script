#![feature(proc_macro_hygiene)]

use bitcoin_script::{bitcoin_script, define_pushable};

#[test]
fn test_generic() {
    define_pushable!();
    let foo = vec![1, 2, 3, 4];
    let script = bitcoin_script! (
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
    define_pushable!();
    let byte_vec = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
    let script_vec = vec![
        bitcoin_script! {
            OP_ADD
        },
        bitcoin_script! {
            OP_TRUE
            OP_FALSE
        },
    ];

    let script = bitcoin_script! (
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
    define_pushable!();
    let usize_value : usize = 0xFFFFFFFFFFFFFFFF;

    let script = bitcoin_script! (
        {usize_value}
    );
}

#[test]
fn test_minimal_byte_opcode() {
    define_pushable!();
    let script = bitcoin_script! (
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
