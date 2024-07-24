use core::fmt;

use crate::builder::{Block, Builder};

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
    pub chunks: Vec<Vec<Box<Builder>>>,

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

    fn find_next_chunk(&mut self) -> (Vec<Box<Builder>>, usize) {
        let mut result = vec![];
        let mut result_len = 0;
        loop {
            let builder = match self.call_stack.pop() {
                Some(builder) => *builder,
                None => break, // the last block in the call stack
            };
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
                            self.call_stack
                                .push(Box::new(sub_builder.clone())); //TODO: Avoid cloning here by
                                                                      //putting Box<Builder> into
                                                                      //the script_map
                            contains_call = true;
                        }
                        Block::Script(script_buf) => {
                            //TODO: Can we avoid cloning or creating a builder here?
                            self.call_stack.push(Box::new(Builder::new().push_script(script_buf.clone())));
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
        (result, result_len)
    }

    pub fn find_chunks(&mut self) -> Vec<usize> {
        let mut result = vec![];
        while !self.call_stack.is_empty() {
            let (chunk, size) = self.find_next_chunk();
            self.chunks.push(chunk);
            result.push(size);
        }
        result
    }
}
