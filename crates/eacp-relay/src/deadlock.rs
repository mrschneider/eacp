#![allow(dead_code)]
//! QNX Neutrino-style synchronous rendezvous deadlock cycle detection.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct DeadlockGraph {
    /// Maps sender_pin -> target_pin (sender blocked waiting on target reply)
    edges: HashMap<u64, u64>,
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

        let mut curr = target_pin;
        let mut visited = HashSet::new();
        visited.insert(sender_pin);

        while let Some(&next) = self.edges.get(&curr) {
            if visited.contains(&next) {
                return true;
            }
            visited.insert(next);
            curr = next;
        }

        false
    }

    /// Attempts to add sender_pin -> target_pin dependency.
    /// Returns false if circular deadlock is detected.
    pub fn add_dependency(&mut self, sender_pin: u64, target_pin: u64) -> bool {
        if self.would_deadlock(sender_pin, target_pin) {
            return false;
        }
        self.edges.insert(sender_pin, target_pin);
        true
    }

    /// Removes dependency edge originating from sender_pin.
    pub fn remove_dependency(&mut self, sender_pin: u64) -> bool {
        self.edges.remove(&sender_pin).is_some()
    }

    /// Removes all edges involving an agent that disconnected.
    pub fn remove_agent(&mut self, pin: u64) {
        self.edges.remove(&pin);
        self.edges.retain(|_, &mut target| target != pin);
    }

    pub fn is_blocked(&self, pin: u64) -> bool {
        self.edges.contains_key(&pin)
    }

    pub fn len(&self) -> usize {
        self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle_detection() {
        let mut graph = DeadlockGraph::new();
        // A -> B -> C
        assert!(graph.add_dependency(1, 2));
        assert!(graph.add_dependency(2, 3));

        // C -> A must be rejected as deadlock
        assert!(graph.would_deadlock(3, 1));
        assert!(!graph.add_dependency(3, 1));

        // Self-dependency must be rejected
        assert!(graph.would_deadlock(1, 1));
        assert!(!graph.add_dependency(1, 1));

        // Removing 1 unblocks 1 waiting on 2
        graph.remove_dependency(1);
        // Now 2 -> 1 is allowed
        assert!(graph.add_dependency(2, 1));
    }
}
