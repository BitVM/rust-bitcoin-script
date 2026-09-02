pub mod builder;
pub(crate) mod optimizer;

pub use crate::builder::{CompileOptions, OptimizationLevel, StructuredScript as Script};
pub use script_macro::script;
pub use stdext::function_name;
