#![allow(dead_code)]
//! QNX Neutrino-style synchronous rendezvous deadlock cycle detection.
//!
//! Edges are keyed per TRANSACTION (sender -> tx -> target), not per
//! sender: concurrent outstanding calls from one agent must not overwrite
//! each other, otherwise cycles through the older edge go undetected.

use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Default)]
pub struct DeadlockGraph {
    /// sender_pin -> (transaction_id -> target_pin)
    edges: HashMap<u64, HashMap<u64, u64>>,
}

impl DeadlockGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    /// Determines whether adding sender_pin -> target_pin causes a circular dependency.
    pub fn would_deadlock(&self, sender_pin: u64, target_pin: u64) -> bool {
        if sender_pin == target_pin {
            return true;
        }

        let mut visited: HashSet<u64> = HashSet::new();
        visited.insert(sender_pin);
        let mut frontier: VecDeque<u64> = VecDeque::new();
        frontier.push_back(target_pin);

        while let Some(curr) = frontier.pop_front() {
            if let Some(tx_edges) = self.edges.get(&curr) {
                for &next in tx_edges.values() {
                    if !visited.insert(next) {
                        return true;
                    }
                    frontier.push_back(next);
                }
            }
        }
        false
    }

    /// Attempts to add sender_pin ->[tx_id] target_pin dependency.
    /// Returns false if a circular deadlock is detected.
    pub fn add_dependency(&mut self, sender_pin: u64, target_pin: u64, tx_id: u64) -> bool {
        if self.would_deadlock(sender_pin, target_pin) {
            return false;
        }
        self.edges.entry(sender_pin).or_default().insert(tx_id, target_pin);
        true
    }

    /// Removes one transaction's edge (or every edge of the sender when
    /// `tx_id` is None, e.g. agent gone).
    pub fn remove_dependency(&mut self, sender_pin: u64, tx_id: Option<u64>) -> bool {
        match tx_id {
            Some(tx) => {
                let mut removed = false;
                if let Some(tx_edges) = self.edges.get_mut(&sender_pin) {
                    removed = tx_edges.remove(&tx).is_some();
                    if tx_edges.is_empty() {
                        self.edges.remove(&sender_pin);
                    }
                }
                removed
            }
            None => self.edges.remove(&sender_pin).is_some(),
        }
    }

    /// Removes all edges involving an agent that disconnected.
    pub fn remove_agent(&mut self, pin: u64) {
        self.edges.remove(&pin);
        self.edges.retain(|_, tx_edges| {
            tx_edges.retain(|_, &mut target| target != pin);
            !tx_edges.is_empty()
        });
    }

    pub fn is_blocked(&self, pin: u64) -> bool {
        self.edges.get(&pin).map(|m| !m.is_empty()).unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.edges.values().map(|m| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle_detection() {
        let mut graph = DeadlockGraph::new();
        // A -> B -> C
        assert!(graph.add_dependency(1, 2, 10));
        assert!(graph.add_dependency(2, 3, 11));

        // C -> A must be rejected as deadlock
        assert!(graph.would_deadlock(3, 1));
        assert!(!graph.add_dependency(3, 1, 12));

        // Self-dependency must be rejected
        assert!(graph.would_deadlock(1, 1));
        assert!(!graph.add_dependency(1, 1, 13));

        // Removing tx 10 of agent 1 unblocks it waiting on 2
        assert!(graph.remove_dependency(1, Some(10)));
        // Now 2 -> 1 is allowed
        assert!(graph.add_dependency(2, 1, 14));
    }

    #[test]
    fn test_concurrent_edges_do_not_overwrite() {
        let mut graph = DeadlockGraph::new();
        // one agent with two outstanding calls
        assert!(graph.add_dependency(1, 2, 100));
        assert!(graph.add_dependency(1, 3, 101));
        assert_eq!(graph.len(), 2);

        // cycle through the FIRST edge (would be missed if tx 101
        // had overwritten tx 100)
        assert!(graph.would_deadlock(2, 1));
        assert!(!graph.add_dependency(2, 1, 102));

        // replying to tx 100 removes only that edge
        assert!(graph.remove_dependency(1, Some(100)));
        assert!(!graph.would_deadlock(2, 1)); // A->C only now: no cycle
        assert!(graph.add_dependency(2, 1, 102));

        // disconnect cleanup drops both directions
        graph.remove_agent(3);
        assert!(!graph.is_blocked(1)); // both of 1's edges referenced 3
    }
}