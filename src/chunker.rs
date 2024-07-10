use core::fmt;
use std::ops::Deref;

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
    pub chunks: Vec<usize>,

    // Builder Callstack (current builder and where we chunked it; always pos the call that
    // will be chunked + 1)
    pub call_stack: Vec<(Box<Builder>, usize)>,
}

impl Chunker {
    pub fn new(builder: Builder, target_chunk_size: usize, tolerance: usize) -> Self {
        Chunker {
            target_chunk_size,
            tolerance,
            size: builder.len(),
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
                chunk_size += builder.len() - chunk_pos;
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
                            .push((Box::new(builder.clone()), start_size + next_builder.len()));
                        next_builder
                    }
                    None => {
                        // Check if this builder was chunked at the end
                        // This is the result of the try_chunk operation
                        let found_chunk_pos = *self.chunks.last().unwrap_or_else(|| unreachable!());
                        if found_chunk_pos - start_size <= builder.len() {
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
