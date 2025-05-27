use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    ACSSTerm(usize, usize),
}