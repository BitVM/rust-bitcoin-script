use bitcoin::opcodes::all::OP_ADD;
use bitcoin_script::{define_pushable, script};

//define_pushable!();

pub mod pushable {

    use bitcoin::blockdata::opcodes::Opcode;
    use bitcoin::blockdata::script::{PushBytes, PushBytesBuf, ScriptBuf};
    use bitcoin::opcodes::{OP_0, OP_TRUE};
    use bitcoin::script::write_scriptint;
    use core::fmt;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::hash::{DefaultHasher, Hash, Hasher};

    #[derive(Clone, Debug, Hash)]
    enum Block {
        Call(u64),
        Script(ScriptBuf),
    }

    impl Block {
        fn new_script() -> Self {
            let buf = ScriptBuf::new();
            Block::Script(buf)
        }
    }

    #[derive(Clone, Debug)]
    pub struct Builder {
        size: usize,
        blocks: Vec<Block>,
        // TODO: It may be worth to lazy initialize the script_map
        script_map: HashMap<u64, Builder>,
    }

    #[derive(Debug, Clone)]
    pub struct ChunkerError;

    impl fmt::Display for ChunkerError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Unable to chunk with set parameters")
        }
    }

    pub struct Chunker<'a> {
        // Each chunk has to be in the interval [target_chunk_size - tolerance, target_chunk_size]
        target_chunk_size: usize,
        tolerance: usize,

        // Original Builder (Maybe remove this and instead push it as first entry to call_stack
        // with 0)
        builder: &'a Builder,

        chunks: Vec<usize>,

        // Builder Callstack (current builder and where we chunked it; always pos the call that
        // will be chunked + 1)
        call_stack: Vec<(&'a Builder, usize)>,
    }

    impl<'a> Chunker<'a> {
        fn highest_chunkable_builder(&mut self) -> Result<(&'a Builder, usize), ChunkerError> {
            let mut chunk_size = 0;
            let result_builder = Err(ChunkerError);
            while chunk_size < self.target_chunk_size {
                let result_builder = self.call_stack.pop();
                if let Some((builder, chunk_pos)) = result_builder {
                    chunk_size += builder.size - chunk_pos;
                }
            }
            result_builder
        }

        // Tries to chunk the provided builder starting from start_pos (so every block before
        // start_pos is considered as part of a previous chunk and ignored).
        // Returns ChunkerError if there is no Call block that chunks or overlaps this chunk.
        // Returns None and appends self.chunks if the builder was chunked.
        // Otherwise, returns the id of the overlapping Call.
        // starting_size is the starting size of the chunk (the previous builder could have been
        // too small)
        fn try_chunk(
            &mut self,
            builder: &Builder,
            starting_size: usize,
            start_pos: usize, // If we chunked the same builder before we have to start
                                         // after that block and not at the beginning of it
        ) -> Result<Option<u64>, ChunkerError> {
            let mut chunk_size = starting_size;
            let mut current_pos = 0;
            let mut overlapping_call = None;
            for block in builder.blocks.iter() {
                let block_len = match block {
                    Block::Call(id) => {
                        let called_script = builder
                            .script_map
                            .get(id)
                            .expect("Missing entry for a called script");
                        overlapping_call = Some(*id);
                        called_script.len()
                    }
                    Block::Script(script) => script.len(),
                };
                current_pos += block_len;
                // The block is already in the previous chunk
                if current_pos < start_pos {
                    continue;
                }
                let block_end = block_len + chunk_size;
                if (block_end < self.target_chunk_size)
                    && (block_end > self.target_chunk_size - self.tolerance)
                {
                    overlapping_call = None;
                    chunk_size += block_len;
                }
            }
            if chunk_size == starting_size {
                Err(ChunkerError)
            } else if overlapping_call.is_none() {
                self.chunks
                    .push(self.chunks.last().unwrap_or(&0_usize) + chunk_size);
                Ok(overlapping_call)
            } else {
                Ok(overlapping_call)
            }
        }

        // TODO: Handle the last chunk because it is allowed to be smaller (probably in find_chunks
        // method)
        // TODO: Push to the call_stack (Finding out the chunk_pos seems to be an issue)
        pub fn find_next_chunk(&mut self) -> Result<(), ChunkerError> {
            //// Find the highest still chunkable builder (call_stack.pop_back())
            // pop call_stack builders until we are over the target_chunk_size
            let (mut builder, start_pos) = self.highest_chunkable_builder()?;
            // Try to chunk the builder
            let mut chunk_result = self.try_chunk(builder, *self.chunks.last().unwrap_or(&0_usize), start_pos);
            while match chunk_result {
                Ok(overlapping_call) => match overlapping_call {
                    Some(_) => {
                        true
                    }
                    None => return Ok(()),
                },
                Err(e) => return Err(e),
            } {
                // Chunk the overlapping call
                let overlapping_call = chunk_result.unwrap_or_else(|_| unreachable!()).unwrap_or_else(|| unreachable!());
                builder = builder
                    .script_map
                    .get(&overlapping_call)
                    .expect("Missing entry for a called script");
                chunk_result = self.try_chunk(builder, *self.chunks.last().unwrap_or(&0_usize), 0);
            }
            Ok(())
        }

        //pub fn find_chunks(self, tolerance: usize, target_chunk_size: usize) -> Vec<usize> {
        //    let i = 0;
        //    let mut chunks = vec![];
        //    let mut target_chunk_size = target_chunk_size;
        //    while i < self.len() {
        //        chunks.push(self.find_chunk(tolerance as i64, target_chunk_size as i64).try_into().unwrap());
        //    }
        //    chunks
        //}
    }

    impl Hash for Builder {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.size.hash(state);
            self.blocks.hash(state);
        }
    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        t.hash(&mut hasher);
        hasher.finish()
    }

    impl Builder {
        pub fn new() -> Self {
            let blocks = Vec::new();
            Builder {
                size: 0,
                blocks,
                script_map: HashMap::new(),
            }
        }

        pub fn len(&self) -> usize {
            self.size
        }

        fn get_script_block(&mut self) -> &mut ScriptBuf {
            // Check if the last block is a Script block
            let is_script_block = match self.blocks.last_mut() {
                Some(Block::Script(_)) => true,
                _ => false,
            };

            // Create a new Script block if necessary
            if !is_script_block {
                self.blocks.push(Block::new_script());
            }

            if let Some(Block::Script(ref mut script)) = self.blocks.last_mut() {
                script
            } else {
                unreachable!()
            }
        }

        pub fn push_opcode(mut self, data: Opcode) -> Builder {
            self.size += 1;
            let script = self.get_script_block();
            script.push_opcode(data);
            self
        }

        pub fn push_env_script(mut self, data: Builder) -> Builder {
            self.size += data.size;
            let id = calculate_hash(&data);
            self.blocks.push(Block::Call(id));
            // Register script
            if !self.script_map.contains_key(&id) {
                self.script_map.insert(id, data);
            }
            self
        }

        // Compiles the builder to bytes using a cache that stores all called_script starting
        // positions in script to copy them from script instead of recompiling.
        fn compile_to_bytes(&self, script: &mut Vec<u8>, cache: &mut HashMap<u64, usize>) {
            for block in self.blocks.as_slice() {
                match block {
                    Block::Call(id) => {
                        let called_script = self
                            .script_map
                            .get(id)
                            .expect("Missing entry for a called script");
                        // Check if the script with the hash id is in cache
                        match cache.get(id) {
                            Some(called_start) => {
                                // Copy the already compiled called_script from the position it was
                                // inserted in the compiled script.
                                let start = script.len();
                                let end = start + called_script.len();
                                assert!(
                                    end <= script.capacity(),
                                    "Not enough capacity allocated for compilated script"
                                );
                                unsafe {
                                    script.set_len(end);

                                    let src_ptr = script.as_ptr().add(*called_start);
                                    let dst_ptr = script.as_mut_ptr().add(start);

                                    std::ptr::copy_nonoverlapping(
                                        src_ptr,
                                        dst_ptr,
                                        called_script.len(),
                                    );
                                }
                            }
                            None => {
                                // Compile the called_script the first time and add its starting
                                // position in the compiled script to the cache.
                                let called_script_start = script.len();
                                called_script.compile_to_bytes(script, cache);
                                cache.insert(*id, called_script_start);
                            }
                        }
                    }
                    Block::Script(block_script) => {
                        let source_script = block_script.as_bytes();
                        let start = script.len();
                        let end = start + source_script.len();
                        assert!(
                            end <= script.capacity(),
                            "Not enough capacity allocated for compilated script"
                        );
                        unsafe {
                            script.set_len(end);

                            let src_ptr = source_script.as_ptr();
                            let dst_ptr = script.as_mut_ptr().add(start);

                            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, source_script.len());
                        }
                    }
                }
            }
        }

        pub fn compile(self) -> ScriptBuf {
            let mut script = Vec::with_capacity(self.size);
            let mut cache = HashMap::new();
            self.compile_to_bytes(&mut script, &mut cache);
            ScriptBuf::from_bytes(script)
        }

        pub fn push_int(self, data: i64) -> Builder {
            // We can special-case -1, 1-16
            if data == -1 || (1..=16).contains(&data) {
                let opcode = Opcode::from((data - 1 + OP_TRUE.to_u8() as i64) as u8);
                self.push_opcode(opcode)
            }
            // We can also special-case zero
            else if data == 0 {
                self.push_opcode(OP_0)
            }
            // Otherwise encode it as data
            else {
                self.push_int_non_minimal(data)
            }
        }
        fn push_int_non_minimal(self, data: i64) -> Builder {
            let mut buf = [0u8; 8];
            let len = write_scriptint(&mut buf, data);
            self.push_slice(&<&PushBytes>::from(&buf)[..len])
        }

        pub fn push_slice<T: AsRef<PushBytes>>(mut self, data: T) -> Builder {
            let script = self.get_script_block();
            let old_size = script.len();
            script.push_slice(data);
            self.size += script.len() - old_size;
            self
        }

        pub fn push_key(self, key: &::bitcoin::PublicKey) -> Builder {
            if key.compressed {
                self.push_slice(key.inner.serialize())
            } else {
                self.push_slice(key.inner.serialize_uncompressed())
            }
        }

        pub fn push_x_only_key(self, x_only_key: &::bitcoin::XOnlyPublicKey) -> Builder {
            self.push_slice(x_only_key.serialize())
        }

        pub fn push_expression<T: Pushable>(self, expression: T) -> Builder {
            let builder = expression.bitcoin_script_push(self);
            builder
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
    impl NotU8Pushable for ::bitcoin::XOnlyPublicKey {
        fn bitcoin_script_push(self, builder: Builder) -> Builder {
            builder.push_x_only_key(&self)
        }
    }
    impl NotU8Pushable for Builder {
        fn bitcoin_script_push(self, builder: Builder) -> Builder {
            builder.push_env_script(self)
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
        script.compile().as_bytes(),
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
        script.compile().to_bytes(),
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
        script.compile().to_bytes(),
        vec![0, 0, 81, 82, 83, 84, 85, 86, 87, 88, 89, 96, 1, 17, 2, 210, 0, 2, 210, 0]
    );
}

fn script_from_func() -> pushable::Builder {
    script! { OP_ADD }
}

#[test]
fn test_simple_loop() {
    let script = script! {
        for _ in 0..3 {
            OP_ADD
        }
    };

    assert_eq!(script.compile().to_bytes(), vec![147, 147, 147])
}

#[test]
fn test_for_loop() {
    let script = script! {
        for i in 0..3 {
            for k in 0..3_u32 {
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
        script.compile().to_bytes(),
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

    assert_eq!(script.compile().to_bytes(), vec![83, 85]);
}

#[test]
fn test_performance_loop() {
    let mut nested_script = script! {
        OP_ADD
    };

    for _ in 0..20 {
        nested_script = script! {
            { nested_script.clone() }
            { nested_script.clone() }
        }
    }
    println!("Subscript size: {}", nested_script.len());

    let script = script! {
        for _ in 0..1000 {
            {nested_script.clone()}
        }
    };

    println!("Expected size: {}", script.len());
    let compiled_script = script.compile();
    println!("Compiled size {}", compiled_script.len());

    assert_eq!(compiled_script.as_bytes()[5_000_000 - 1], 147)
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

    assert_eq!(script.compile().as_bytes()[5_000_000 - 1], 147)
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
        script.compile().as_bytes(),
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
        script.compile().as_bytes(),
        vec![124, 109, 122, 124, 123, 83, 124, 123, 83, 122]
    );
}
