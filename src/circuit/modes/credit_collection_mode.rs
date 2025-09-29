use std::num::NonZero;

use crate::{
    Gate as SourceGate, GateType, WireId, circuit::CircuitMode, storage::Credits as SourceCredits,
};

#[derive(Debug)]
pub struct CreditCollectionMode {
    credits: Option<Vec<u16>>, // Original -> Normalized IDs
    next_normalized_id: u64,
}

impl CircuitMode for CreditCollectionMode {
    type WireValue = (); // We don't store values, just translate
    type CiphertextAcc = ();

    fn false_value(&self) -> Self::WireValue {
        ()
    }
    fn true_value(&self) -> Self::WireValue {
        ()
    }

    fn allocate_wire(&mut self, credits: SourceCredits) -> WireId {
        let normalized_id = self.allocate_normalized_id() as usize;

        let creds = self.credits.as_mut().unwrap();
        if normalized_id >= creds.len() {
            creds.resize((normalized_id + 1) as usize, 0);
        }
        let wire_id = WireId(normalized_id as usize);
        creds[normalized_id] = credits;
        wire_id
    }

    fn lookup_wire(&mut self, _wire: WireId) -> Option<Self::WireValue> {
        Some(()) // Always return dummy value
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {
        // No-op for translation
    }

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<SourceCredits>) {
        let creds = self.credits.as_mut().unwrap();
        for wire in wires {
            creds[wire.0] += credits.get();
        }
    }

    fn evaluate_gate(&mut self, gate: &SourceGate) {
        let allocate_id = |s: &mut CreditCollectionMode, num| {
            for _ in 0..num {
                s.allocate_normalized_id();
            }
        };

        // handle additional wires for translation
        match gate.gate_type {
            GateType::And => {}
            GateType::Xor => {}
            GateType::Nand => allocate_id(self, 1),
            GateType::Xnor => allocate_id(self, 1),
            GateType::Not => {}
            GateType::Or => allocate_id(self, 2),
            GateType::Nor => allocate_id(self, 3),
            GateType::Nimp => allocate_id(self, 1),
            GateType::Ncimp => allocate_id(self, 1),
            GateType::Imp => allocate_id(self, 3),
            GateType::Cimp => allocate_id(self, 3),
        };
    }
}

impl CreditCollectionMode {
    pub fn new(num_primary_inputs: usize) -> Self {
        let mut mode = Self {
            credits: Some(Vec::new()),
            next_normalized_id: 0,
        };

        // Reserve normalized IDs for constants
        mode.allocate_normalized_id(); // ID 0 = FALSE
        mode.allocate_normalized_id(); // ID 1 = TRUE (ONE wire)

        // Reserve IDs for primary inputs (2, 3, 4, ...)
        for _ in 0..num_primary_inputs {
            mode.allocate_normalized_id();
        }

        mode
    }

    fn allocate_normalized_id(&mut self) -> u64 {
        let id = self.next_normalized_id;
        self.next_normalized_id += 1;
        id
    }

    pub fn finish(&mut self) -> Vec<u16> {
        let mut creds = self.credits.take().unwrap();
        creds.shrink_to_fit();
        creds
    }
}
