use bitcoin_script::{script, Chunker};

#[test]
fn test_chunker_simple() {
    let sub_script = script! {
        OP_ADD
        OP_ADD
    };

    let script = script! {
        { sub_script.clone() }
        { sub_script.clone() }
        { sub_script.clone() }
        { sub_script.clone() }
    };

    println!("{:?}", sub_script);

    let mut chunker = Chunker::new(script, 2, 0);
    let chunk_borders = chunker.find_chunks();

    assert_eq!(chunk_borders, vec![2, 2, 2, 2]);
}
#[test]
fn test_chunker_ifs_1() {
    let sub_script = script! {
        OP_ADD
        OP_ADD
    };

    let script = script! {
        { sub_script.clone() }
        OP_IF
        { sub_script.clone() }
        OP_ENDIF
    };

    println!("{:?}", sub_script);

    let mut chunker = Chunker::new(script, 5, 4);
    let chunk_borders = chunker.find_chunks();
    println!("Chunker: {:?}", chunker);

    assert_eq!(chunk_borders, vec![2, 4]);
}

#[test]
fn test_chunker_ifs_2() {
    let sub_script = script! {
        OP_ADD
        OP_ADD
        OP_ADD
        OP_ADD
        OP_ADD
    };

    let script = script! {
        OP_IF
        { sub_script.clone() }
        OP_ENDIF
        { sub_script.clone() }
        OP_IF
        { sub_script.clone() }
        OP_ENDIF
        { sub_script.clone() }
    };

    println!("{:?}", sub_script);

    let mut chunker = Chunker::new(script, 10, 5);
    let chunk_borders = chunker.find_chunks();

    assert_eq!(chunk_borders, vec![7, 5, 7, 5]);
}

//#[test]
//fn test_compile_to_chunks() {
//    let sub_script = script! {
//        OP_ADD
//        OP_ADD
//    };
//
//    let script = script! {
//        { sub_script.clone() }
//        { sub_script.clone() }
//        { sub_script.clone() }
//        { sub_script.clone() }
//        OP_ADD
//    };
//
//    println!("{:?}", script);
//    let (chunks, compiled_script) = script.compile_to_chunks(2, 0);
//    println!(
//        "[RESULT] compiled_script: {:?}, chunks: {:?}",
//        compiled_script, chunks
//    );
//    assert_eq!(chunks, vec![2, 4, 6, 8]);
//    assert_eq!(
//        compiled_script.as_bytes(),
//        vec![147, 147, 147, 147, 147, 147, 147, 147, 147]
//    );
//}
