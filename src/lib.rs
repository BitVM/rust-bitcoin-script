pub mod treepp {
    pub use crate::pushable::Builder as Script;
    pub use script_macro::script;
}

pub mod pushable {
    use bitcoin::blockdata::opcodes::Opcode;
    use bitcoin::blockdata::script::{PushBytes, PushBytesBuf, ScriptBuf};
    use bitcoin::opcodes::{OP_0, OP_TRUE};
    use bitcoin::script::write_scriptint;
    use core::fmt;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::ops::Deref;

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

    pub struct Chunker {
        // Each chunk has to be in the interval [target_chunk_size - tolerance, target_chunk_size]
        target_chunk_size: usize,
        tolerance: usize,

        size: usize,
        pub chunks: Vec<usize>,

        // Builder Callstack (current builder and where we chunked it; always pos the call that
        // will be chunked + 1)
        call_stack: Vec<(Box<Builder>, usize)>,
    }

    impl From<Chunker> for Builder {
        fn from(mut chunker: Chunker) -> Self {
            *chunker.call_stack.remove(0).0
        }
    }

    impl Chunker {
        pub fn new(builder: Builder, target_chunk_size: usize, tolerance: usize) -> Self {
            Chunker {
                target_chunk_size,
                tolerance,
                size: builder.size,
                chunks: vec![],
                call_stack: vec![(Box::new(builder), 0)],
            }
        }

        fn highest_chunkable_builder(&mut self) -> Result<(Box<Builder>, usize), ChunkerError> {
            let mut chunk_size = 0;
            let mut result_builder = Err(ChunkerError);
            while chunk_size < self.target_chunk_size {
                let builder_info = self.call_stack.pop();
                if let Some((builder, chunk_pos)) = builder_info {
                    chunk_size += builder.size - chunk_pos;
                    result_builder = Ok((builder, chunk_pos));
                }
            }
            result_builder
        }

        // Tries to chunk the provided builder starting from start_pos (so every block before
        // start_pos is considered as part of a previous chunk and ignored).
        // Returns ChunkerError if there is no Call block that chunks or overlaps this chunk.
        // Returns Ok(None) if the builder was chunked.
        // Otherwise, returns the id of the overlapping Call and the size of the builder until the
        // overlapping_call
        // start_size is the starting size of the chunk (the previous builder could have been
        // too small)
        fn try_chunk(
            &mut self,
            builder: &Builder,
            start_size: usize,
            start_pos: usize, // If we chunked the same builder before we have to start
                              // after that block and not at the beginning of it
        ) -> Result<Option<(u64, usize)>, ChunkerError> {
            let mut chunk_size = start_size;
            let mut current_pos = 0;
            let mut overlapping_call = None;
            for block in builder.blocks.iter() {
                let block_len = match block {
                    Block::Call(id) => {
                        let called_script = builder
                            .script_map
                            .get(id)
                            .expect("Missing entry for a called script");
                        // current_pos is the size of the builder before the overlapping_call
                        overlapping_call = Some((*id, current_pos));
                        called_script.len()
                    }
                    Block::Script(script) => script.len(),
                };
                current_pos += block_len;
                println!(
                    "[INFO] current pos: {:?} - start_pos: {:?}",
                    current_pos, start_pos
                );
                // The block is already in the previous chunk
                // (possibly as an overlapping_call but its remaining size is already accounted for
                // with start_size)
                if current_pos < start_pos {
                    continue;
                }
                let block_end = block_len + chunk_size;
                println!("[INFO] block_end: {:?}", block_end);
                if (block_end <= self.target_chunk_size + start_size)
                    && (block_end >= self.target_chunk_size - self.tolerance + start_size)
                {
                    println!("[INFO] block_end VALID! block_len: {:?}", block_len);
                    overlapping_call = None;
                    chunk_size += block_len;
                    println!("[INFO] chunk_size: {:?}", chunk_size);
                    //TODO we could find a better chunk after the next call if both of them end
                    //in target_chunk_size - tolerance
                    //Watch out for the above overlapping_call = Some(*) then because it overrides
                    //that we found a non-overlapping chunk option
                    break;
                }
            }

            println!("[INFO] overlapping_call: {:?}", overlapping_call);
            if chunk_size == start_size {
                Err(ChunkerError)
            } else if overlapping_call.is_none() {
                self.chunks
                    .push(self.chunks.last().unwrap_or(&0_usize) + chunk_size);
                Ok(overlapping_call)
            } else {
                Ok(overlapping_call)
            }
        }

        pub fn find_next_chunk(&mut self) -> Result<(), ChunkerError> {
            // Find the highest still chunkable builder on the call_stack
            let builder_info = self.highest_chunkable_builder()?;
            println!("[INFO] highest_chunkable builder: {:?}", builder_info);
            let (mut builder, mut start_pos) = (builder_info.0.deref(), builder_info.1);
            let mut chunk_result;
            let mut start_size = start_pos - *self.chunks.last().unwrap_or(&0_usize);
            loop {
                // Try to chunk the current builder
                chunk_result = self.try_chunk(builder, start_size, start_pos);
                println!("[INFO] chunk_result: {:?}", chunk_result);
                // As long as the builder has an overlapping_call set builder to the
                // overlapping_call builder and loop again
                builder = match chunk_result {
                    Ok(option) => match option {
                        Some((call, pos)) => {
                            start_pos = 0;
                            start_size = pos;
                            let next_builder = builder
                                .script_map
                                .get(&call)
                                .expect("Missing entry for a called script");
                            // Push the builder to call_stack because we are now going a builder
                            // deeper to chunk it
                            // Push start_size + next_builder.size as the position where it will be
                            // chunked (we overshoot this because in this builder we will not go into the overlapping call again to chunk it)
                            self.call_stack
                                .push((Box::new(builder.clone()), start_size + next_builder.size));
                            next_builder
                        }
                        None => {
                            // Check if this builder was chunked at the end
                            // This is the result of the try_chunk operation
                            let found_chunk_pos =
                                *self.chunks.last().unwrap_or_else(|| unreachable!());
                            if found_chunk_pos - start_size <= builder.size {
                                self.call_stack
                                    .push((Box::new(builder.clone()), found_chunk_pos));
                            }
                            return Ok(());
                        }
                    },
                    Err(error) => return Err(error),
                };
            }
        }

        pub fn find_chunks(mut self) -> Result<(Vec<usize>, Builder), ChunkerError> {
            while self.size > self.chunks.last().unwrap_or(&0_usize) + self.target_chunk_size {
                self.find_next_chunk()?;
            }
            let builder = *self.call_stack.remove(0).0;
            Ok((self.chunks, builder))
        }
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

        pub fn compile_to_chunks(
            self,
            target_chunk_size: usize,
            tolerance: usize,
        ) -> (Vec<usize>, ScriptBuf) {
            let chunker = Chunker::new(self, target_chunk_size, tolerance);
            let (chunks, builder) = chunker.find_chunks().expect("Unable to chunk script");
            (chunks, builder.compile())
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
