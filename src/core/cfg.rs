use capstone::Instructions;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeType {
    Unconditional,
    ConditionalTrue,
    ConditionalFalse,
    FallThrough,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub source_id: usize,
    pub target_id: usize,
    pub edge_type: EdgeType,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<(u64, String, String)>, // (address, mnemonic, op_str)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<usize, BasicBlock>,
    pub edges: Vec<Edge>,
    pub entry_block_id: Option<usize>,
}

pub struct CfgBuilder;

impl CfgBuilder {
    pub fn build(insns: &Instructions) -> Result<ControlFlowGraph, String> {
        let mut leaders = HashSet::new();

        // Pass 1: Identify Basic Block Leaders
        // A leader is:
        // 1. The first instruction.
        // 2. The target of any jump.
        // 3. The instruction immediately following any branch or return.
        if let Some(first) = insns.iter().next() {
            let addr: u64 = first.address();
            leaders.insert(addr);
        }

        let mut next_is_leader = false;

        for i in insns.iter() {
            let addr: u64 = i.address();
            let mnemonic = i.mnemonic().unwrap_or("");

            if next_is_leader {
                leaders.insert(addr);
                next_is_leader = false;
            }

            if mnemonic.starts_with('j') || mnemonic == "ret" {
                next_is_leader = true;

                // If it's a jump with a direct target, mark the target as a leader
                if mnemonic != "ret" {
                    if let Some(op_str) = i.op_str() {
                        let op_string: String = op_str.to_string();
                        let dest_str = op_string.replace("0x", "");
                        if let Ok(target_addr) = u64::from_str_radix(&dest_str, 16) {
                            leaders.insert(target_addr);
                        }
                    }
                }
            }
        }

        // Pass 2: Extract Basic Blocks
        let mut leaders_sorted: Vec<u64> = leaders.into_iter().collect();
        leaders_sorted.sort_unstable();

        let mut blocks = HashMap::new();
        let mut addr_to_block_id = HashMap::new();
        
        for (id, &start_addr) in leaders_sorted.iter().enumerate() {
            blocks.insert(
                id,
                BasicBlock {
                    id,
                    start_address: start_addr,
                    end_address: 0,
                    instructions: Vec::new(),
                },
            );
            addr_to_block_id.insert(start_addr, id);
        }

        let mut current_block_id = 0;
        
        if let Some(&start_addr) = leaders_sorted.first() {
            current_block_id = *addr_to_block_id.get(&start_addr).unwrap();
        }

        for i in insns.iter() {
            let addr: u64 = i.address();
            
            if let Some(&new_id) = addr_to_block_id.get(&addr) {
                current_block_id = new_id;
            }

            if let Some(block) = blocks.get_mut(&current_block_id) {
                let mnemonic = i.mnemonic().unwrap_or("").to_string();
                let op_str = i.op_str().unwrap_or("").to_string();
                block.instructions.push((addr, mnemonic, op_str));
                block.end_address = addr; // Will eventually hold the last instruction's addr
            }
        }

        // Pass 3: Edge Generation
        let mut edges = Vec::new();
        
        for block in blocks.values() {
            if let Some(last_insn) = block.instructions.last() {
                let mnemonic = last_insn.1.as_str();
                
                if mnemonic == "jmp" {
                    // Unconditional Jump
                    let dest_str = last_insn.2.replace("0x", "");
                    if let Ok(target_addr) = u64::from_str_radix(&dest_str, 16) {
                        if let Some(&target_id) = addr_to_block_id.get(&target_addr) {
                            edges.push(Edge {
                                source_id: block.id,
                                target_id,
                                edge_type: EdgeType::Unconditional,
                            });
                        }
                    }
                } else if mnemonic.starts_with('j') && mnemonic != "jmp" {
                    // Conditional Jump
                    let dest_str = last_insn.2.replace("0x", "");
                    if let Ok(target_addr) = u64::from_str_radix(&dest_str, 16) {
                        if let Some(&target_id) = addr_to_block_id.get(&target_addr) {
                            edges.push(Edge {
                                source_id: block.id,
                                target_id,
                                edge_type: EdgeType::ConditionalTrue,
                            });
                        }
                    }
                    // Fall-through (False condition)
                    let next_block_id = block.id + 1;
                    if blocks.contains_key(&next_block_id) {
                        edges.push(Edge {
                            source_id: block.id,
                            target_id: next_block_id,
                            edge_type: EdgeType::ConditionalFalse,
                        });
                    }
                } else if mnemonic != "ret" {
                    // Normal instruction falling through to the next block
                    let next_block_id = block.id + 1;
                    if blocks.contains_key(&next_block_id) {
                        edges.push(Edge {
                            source_id: block.id,
                            target_id: next_block_id,
                            edge_type: EdgeType::FallThrough,
                        });
                    }
                }
            }
        }

        let entry_block_id = if !blocks.is_empty() { Some(0) } else { None };

        Ok(ControlFlowGraph {
            blocks,
            edges,
            entry_block_id,
        })
    }

    /// Renders the CFG into Graphviz DOT syntax
    pub fn to_dot(cfg: &ControlFlowGraph) -> String {
        let mut out = String::from("digraph CFG {\n  node [fontname=\"Courier New\", shape=box, style=filled, fillcolor=\"#1E1E1E\", fontcolor=\"#D4D4D4\", color=\"#404040\"];\n  edge [fontname=\"Courier New\", fontsize=10];\n  bgcolor=\"#161616\";\n\n");

        for (_, block) in &cfg.blocks {
            let mut label = format!("Block_{}\\l", block.id);
            for insn in &block.instructions {
                label.push_str(&format!("{:X}: {} {}\\l", insn.0, insn.1, insn.2));
            }
            // Escape quotes inside label string
            let label = label.replace("\"", "\\\"");
            out.push_str(&format!("  b{} [label=\"{}\", URL=\"block_{}\"];\n", block.id, label, block.id));
        }

        out.push('\n');

        for edge in &cfg.edges {
            let (color, xlabel) = match edge.edge_type {
                EdgeType::Unconditional => ("#8A8A8A", "JMP"),
                EdgeType::ConditionalTrue => ("#4CAF50", "TRUE"),
                EdgeType::ConditionalFalse => ("#F44336", "FALSE"),
                EdgeType::FallThrough => ("#8A8A8A", "FALL"),
            };
            out.push_str(&format!("  b{} -> b{} [color=\"{}\", xlabel=\"{}\"];\n", edge.source_id, edge.target_id, color, xlabel));
        }

        out.push_str("}\n");
        out
    }
}
