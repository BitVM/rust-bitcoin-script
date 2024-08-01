use crate::{
    analyzer::StackStatus,
    builder::{Block, StructuredScript},
    StackAnalyzer,
};

#[derive(Debug, Clone)]
struct ChunkStats {
    stack_input_size: usize,
    stack_output_size: usize,
    altstack_input_size: usize,
    altstack_output_size: usize,
}


//TODO: Refactor the undoing with this struct
//pub struct UndoInfo {
//    
//
//}

#[derive(Debug, Clone)]
pub struct Chunk {
    scripts: Vec<Box<StructuredScript>>,
    size: usize,
    stats: Option<ChunkStats>,
}

impl Chunk {
    pub fn new(scripts: Vec<Box<StructuredScript>>, size: usize) -> Chunk {
        Chunk {
            scripts,
            size,
            stats: None,
        }
    }

    pub fn scripts(self) -> Vec<Box<StructuredScript>> {
        self.scripts
    }
}

pub struct Chunker {
    // Each chunk has to be in the interval [target_chunk_size - tolerance, target_chunk_size]
    target_chunk_size: usize,
    tolerance: usize,

    size: usize,
    pub chunks: Vec<Chunk>,

    // Builder Callstack (consists of remaining structured scripts)
    pub call_stack: Vec<Box<StructuredScript>>,
}

impl Chunker {
    pub fn new(
        top_level_script: StructuredScript,
        target_chunk_size: usize,
        tolerance: usize,
    ) -> Self {
        Chunker {
            target_chunk_size,
            tolerance,
            size: top_level_script.len(),
            chunks: vec![],
            call_stack: vec![Box::new(top_level_script)],
        }
    }

    pub fn find_chunks_and_analyze_stack(&mut self) -> Vec<Chunk> {
        let mut chunks = vec![];
        while !self.call_stack.is_empty() {
            let chunk = self.find_next_chunk();
            chunks.push(chunk);
        }
        for chunk in chunks.iter_mut() {
            // println!("chunk size: {}", chunk_size);
            let status = self.stack_analyze(&mut chunk.scripts);
            // println!("stack_analyze: {:?}", status);
            // ((-1 * access) as u32, (depth - access) as u32)
            let stack_input_size = status.deepest_stack_accessed.abs() as usize;
            let stack_output_size = (status.stack_changed - status.deepest_stack_accessed) as usize;
            let altstack_input_size = status.deepest_altstack_accessed.abs() as usize;
            let altstack_output_size =
                (status.altstack_changed - status.deepest_altstack_accessed) as usize;
            chunk.stats = Some(ChunkStats {
                stack_input_size,
                stack_output_size,
                altstack_input_size,
                altstack_output_size,
            });
        }
        chunks
    }

    fn stack_analyze(&self, chunk: &mut Vec<Box<StructuredScript>>) -> StackStatus {
        let mut stack_analyzer = StackAnalyzer::new();
        stack_analyzer.analyze_blocks(chunk)
    }

    fn find_next_chunk(&mut self) -> Chunk {
        let mut chunk_scripts = vec![];
        let mut chunk_len = 0;
        let mut num_unclosed_ifs = 0;

        // All not selected StructuredScripts that have to be added to the call_stack again
        let mut call_stack_undo = vec![];
        let mut chunk_len_undo = 0;
        let mut num_unclosed_ifs_undo = 0;

        loop {
            let builder = match self.call_stack.pop() {
                Some(builder) => *builder,
                None => break, // the last block in the call stack
            };

            assert!(
                num_unclosed_ifs + builder.num_unclosed_ifs() >= 0,
                "More OP_ENDIF's than OP_IF's in the script"
            );

            // TODO: Use stack analysis to find best possible chunk border
            let block_len = builder.len();
            if chunk_len + block_len < self.target_chunk_size - self.tolerance {
                // Case 1: Builder is too small. target - tolerance not yet reached with it.
                num_unclosed_ifs += builder.num_unclosed_ifs();
                chunk_scripts.push(Box::new(builder));
                chunk_len += block_len;
            } else if chunk_len + block_len <= self.target_chunk_size {
                // Case 2: Adding the current builder remains a valid solution.
                // TODO: Check with stack analyzer to see if adding the builder is better or not.
                // (If we add it we have to add all intermediary builders that were previously not
                // added - keep another call_stack equivalent for that)
                if num_unclosed_ifs + builder.num_unclosed_ifs() == 0 {
                    // We are going to keep this structured script in the chunk
                    // Reset the undo information
                    call_stack_undo = vec![];
                    chunk_len_undo = 0;
                    num_unclosed_ifs_undo = 0;
                } else {
                    // Update the undo information in case we need to remove this StructuredScript
                    // from the chunk again
                    call_stack_undo.push(Box::new(builder.clone()));
                    chunk_len_undo += block_len;
                    num_unclosed_ifs_undo += builder.num_unclosed_ifs();
                }
                num_unclosed_ifs += builder.num_unclosed_ifs();
                chunk_scripts.push(Box::new(builder));
                chunk_len += block_len;
            } else if chunk_len + block_len > self.target_chunk_size
                && chunk_len < self.target_chunk_size - self.tolerance
            {
                // Case 3: Current builder too large and there is no acceptable solution yet
                // TODO: Could add a depth parameter here to even if we have an acceptable solution
                // check if there is a better one in next depth calls
                // Chunk inside a call of the current builder.
                // Add all its calls to the call_stack.
                let mut contains_call = false;
                for block in builder.blocks.iter().rev() {
                    match block {
                        Block::Call(id) => {
                            let sub_builder = builder.script_map.get(&id).unwrap();
                            self.call_stack.push(Box::new(sub_builder.clone())); //TODO: Avoid cloning here by
                                                                                 //putting Box<Builder> into
                                                                                 //the script_map
                            contains_call = true;
                        }
                        Block::Script(script_buf) => {
                            //TODO: Can we avoid cloning or creating a builder here?
                            self.call_stack.push(Box::new(
                                StructuredScript::new().push_script(script_buf.clone()),
                            ));
                        }
                    }
                }
                assert!(contains_call, "No support for chunking up scriptBufs");
            } else {
                call_stack_undo.push(Box::new(builder));
                break;
            }
        }

        // Undo the lately added scripts if we are not closing all ifs with them.
        if num_unclosed_ifs != 0 {
            num_unclosed_ifs -= num_unclosed_ifs_undo;
            chunk_len -= chunk_len_undo;
        }
        
        assert!(num_unclosed_ifs >= 0, "More OP_ENDIF's than OP_IF's after undo step. (This means there is a bug in the undo logic.)");
        assert_eq!(num_unclosed_ifs, 0, "Unable to make up for the OP_IF's in this chunk. Consider a larger target size or more tolerance. Unclosed OP_IF's: {:?}", num_unclosed_ifs);
        
        // Always have to do this because of the last call_stack element we popped that did not end up in
        // the chunk.
        self.call_stack.extend(call_stack_undo.into_iter().rev());
        Chunk::new(chunk_scripts, chunk_len)
    }

    pub fn find_chunks(&mut self) -> Vec<usize> {
        let mut result = vec![];
        while !self.call_stack.is_empty() {
            let chunk = self.find_next_chunk();
            if chunk.size == 0 {
                panic!("Unable to fit next call_stack entries into a chunk. Borders until this point: {:?}", result);
            }
            result.push(chunk.size);
            self.chunks.push(chunk);
        }
        result
    }
}
