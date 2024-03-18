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
        vec![169, 2, 210, 4, 2, 255, 0, 79, 2, 255, 128, 2, 171, 205, 82, 81, 82, 83, 84]
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
    );

    assert_eq!(
        script.to_bytes(),
        vec![0, 0, 81, 82, 83, 84, 85, 86, 87, 88, 89, 96, 1, 17]
    );

}
