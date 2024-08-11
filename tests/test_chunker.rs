use bitcoin::ScriptBuf;
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

#[test]
fn test_compile_to_chunks() {
    let sub_script = script! {
        OP_ADD
        OP_ADD
    };

    let script = script! {
        { sub_script.clone() }
        OP_IF
        OP_ROLL
        { sub_script.clone() }
        OP_ENDIF
    };
    let (chunk_borders, chunks) = script.clone().compile_to_chunks(5, 4);
    println!("Chunk borders: {:?}", chunk_borders);
    let compiled_total_script = script.compile();
    let mut compiled_chunk_script = vec![];
    for chunk in chunks {
        compiled_chunk_script.extend(chunk.as_bytes());
    }
    let compiled_chunk_script = ScriptBuf::from_bytes(compiled_chunk_script);

    assert_eq!(compiled_chunk_script, compiled_total_script);
}
