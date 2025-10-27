use std::num::NonZero;

use g16ckt::{
    Gate as SourceGate, GateType, WireId, circuit::CircuitMode, storage::Credits as SourceCredits,
};
use indicatif::ProgressBar;
use sled::Db;

use crate::u24::U24;

#[derive(Debug)]
pub struct CreditCollectionMode {
    credits: Option<Vec<U24>>, // Original -> Normalized IDs
    next_normalized_id: u64,
    primary_inputs: usize,
    biggest_credits_seen: usize,
    spinner: ProgressBar,
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
        self.biggest_credits_seen = self.biggest_credits_seen.max(credits as usize);

        let creds = self.credits.as_mut().unwrap();
        if normalized_id >= creds.len() {
            creds.resize((normalized_id + 1) as usize, 0u32.into());
        }
        let wire_id = WireId(normalized_id as usize);
        creds[normalized_id] = credits.into();
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
            if (0..self.primary_inputs + 2).contains(&wire.0) {
                // don't add credits to primary inputs since they are used too much
                continue;
            }
            match creds[wire.0].checked_add(credits.get().into()) {
                Some(new_credits) => {
                    creds[wire.0] = new_credits;
                    self.biggest_credits_seen = self.biggest_credits_seen.max(new_credits.into());
                }
                None => panic!(
                    "Overflow occurred while adding {} credits to wire {}, prev {}",
                    credits.get(),
                    wire.0,
                    creds[wire.0]
                ),
            }
        }
    }

    fn evaluate_gate(&mut self, gate: &SourceGate) {
        self.spinner.inc(1);
        let allocate_id = |s: &mut CreditCollectionMode, num| {
            for _ in 0..num {
                s.allocate_wire(1);
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
    pub fn new(primary_inputs: usize) -> Self {
        let pb = ProgressBar::no_length();
        let mut mode = Self {
            credits: Some(Vec::new()),
            next_normalized_id: 0,
            primary_inputs,
            biggest_credits_seen: 0,
            spinner: pb,
        };

        // Reserve normalized IDs for constants
        mode.allocate_normalized_id(); // ID 0 = FALSE
        mode.allocate_normalized_id(); // ID 1 = TRUE (ONE wire)

        mode
    }

    fn allocate_normalized_id(&mut self) -> u64 {
        let id = self.next_normalized_id;
        self.next_normalized_id += 1;
        id
    }

    pub fn finish(&mut self) -> (Vec<U24>, usize) {
        let creds = self.credits.take().unwrap();
        (creds, self.biggest_credits_seen)
    }
}
