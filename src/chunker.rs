use crate::{
    analyzer::StackStatus,
    builder::{Block, Builder},
    StackAnalyzer,
};


#[derive(Debug, Clone)]
struct ChunkStats {
    stack_input_size: usize,
    stack_output_size: usize,
    altstack_input_size: usize,
    altstack_output_size: usize,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    scripts: Vec<Box<Builder>>,
    size: usize,
    stats: Option<ChunkStats>,
}

impl Chunk {
    pub fn new(scripts: Vec<Box<Builder>>, size: usize) -> Chunk {
        Chunk {
            scripts,
            size,
            stats: None,
        }
    }

    pub fn scripts(self) -> Vec<Box<Builder>>{
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
    pub call_stack: Vec<Box<Builder>>,
}

impl Chunker {
    pub fn new(builder: Builder, target_chunk_size: usize, tolerance: usize) -> Self {
        Chunker {
            target_chunk_size,
            tolerance,
            size: builder.len(),
            chunks: vec![],
            call_stack: vec![Box::new(builder)],
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

    fn stack_analyze(&self, chunk: &mut Vec<Box<Builder>>) -> StackStatus {
        let mut stack_analyzer = StackAnalyzer::new();
        stack_analyzer.analyze_blocks(chunk)
    }

    fn find_next_chunk(&mut self) -> Chunk {
        let mut result = vec![];
        let mut result_len = 0;
        loop {
            let builder = match self.call_stack.pop() {
                Some(builder) => *builder,
                None => break, // the last block in the call stack
            };

            // TODO: Use stack analysis to find best possible chunk border
            // TODO: Consider chunks that are closest to the tolerance first (e.g. if target = 300
            // and tolerance = 20 we can split at 299 and 290 but 299 should be preferred.
            let block_len = builder.len();
            if result_len + block_len < self.target_chunk_size - self.tolerance {
                result.push(Box::new(builder));
                result_len += block_len;
            } else if result_len + block_len > self.target_chunk_size {
                // Chunk inside a call of the current builder
                // Add all its calls to the call_stack
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
                            self.call_stack
                                .push(Box::new(Builder::new().push_script(script_buf.clone())));
                        }
                    }
                }
                assert!(contains_call, "Not able to chunk up scriptBufs");
            } else {
                result.push(Box::new(builder));
                result_len += block_len;
                break;
            }
        }
        Chunk::new(result, result_len)
    }

    pub fn find_chunks(&mut self) -> Vec<usize> {
        let mut result = vec![];
        while !self.call_stack.is_empty() {
            let chunk = self.find_next_chunk();
            result.push(chunk.size);
            self.chunks.push(chunk);
        }
        result
    }
}
