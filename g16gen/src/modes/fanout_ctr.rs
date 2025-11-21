use std::num::NonZero;

use g16ckt::{
    Gate as SourceGate, GateType, WireId, circuit::CircuitMode, storage::Credits as SourceCredits,
};
use indicatif::ProgressBar;

#[derive(Debug)]
pub struct FanoutCounter {
    fanout: Option<Vec<u16>>, // Original -> Normalized IDs
    next_normalized_id: u64,
    primary_inputs: usize,
    biggest_fanout_seen: usize,
    spinner: ProgressBar,
}

impl CircuitMode for FanoutCounter {
    type WireValue = bool;
    type CiphertextAcc = ();

    fn false_value(&self) -> Self::WireValue {
        false
    }
    fn true_value(&self) -> Self::WireValue {
        true
    }

    fn allocate_wire(&mut self, _credits: SourceCredits) -> WireId {
        let normalized_id = self.allocate_normalized_id() as usize;
        WireId(normalized_id)
    }

    fn lookup_wire(&mut self, _wire: WireId) -> Option<Self::WireValue> {
        Some(false) // Always return dummy value
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {
        // No-op for translation
    }

    fn add_credits(&mut self, _wires: &[WireId], _credits: NonZero<SourceCredits>) {}

    fn evaluate_gate(&mut self, gate: &SourceGate) {
        self.spinner.inc(1);

        let resize = |fanout: &mut Vec<u16>, max_wire_produced: usize| {
            if max_wire_produced >= fanout.len() {
                fanout.resize(max_wire_produced + 1, 0);
            }
        };

        // handle additional wires for translation
        match gate.gate_type {
            // no translation
            GateType::And => {
                resize(self.fanout.as_mut().unwrap(), gate.wire_c.0);
                self.wire_used(gate.wire_a);
                self.wire_used(gate.wire_b);
            }
            // no translation
            GateType::Xor => {
                resize(self.fanout.as_mut().unwrap(), gate.wire_c.0);
                self.wire_used(gate.wire_a);
                self.wire_used(gate.wire_b);
            }
            GateType::Not => {
                self.wire_used(gate.wire_a);
                // ONE is constant, don't count
            }
            // XOR(a, ONE)
            GateType::Nand => {
                let temp = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp as usize);
                self.wire_used(gate.wire_a);
                self.wire_used(gate.wire_b);
                self.wire_used(WireId(temp as usize));
                // ONE is constant, don't count
            }
            //  XOR(XOR(a, b), ONE)
            GateType::Xnor => {
                let temp = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp as usize);
                self.wire_used(gate.wire_a);
                self.wire_used(gate.wire_b);
                self.wire_used(WireId(temp as usize));
                // ONE is constant, don't count
            }
            // XOR(XOR(AND(a, b), a), b)
            GateType::Or => {
                let temp1 = self.allocate_normalized_id();
                let temp2 = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp2 as usize);
                self.wire_used(gate.wire_a);
                self.wire_used(gate.wire_b);
                self.wire_used(WireId(temp1 as usize));
                self.wire_used(gate.wire_a);
                self.wire_used(WireId(temp2 as usize));
                self.wire_used(gate.wire_b);
            }
            // XOR(XOR(XOR(AND(a, b), a), b), ONE)
            GateType::Nor => {
                let temp1 = self.allocate_normalized_id();
                let temp2 = self.allocate_normalized_id();
                let temp3 = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp3 as usize);
                self.wire_used(gate.wire_a);
                self.wire_used(gate.wire_b);
                self.wire_used(WireId(temp1 as usize));
                self.wire_used(gate.wire_a);
                self.wire_used(WireId(temp2 as usize));
                self.wire_used(gate.wire_b);
                self.wire_used(WireId(temp3 as usize));
                // ONE is constant, don't count
            }
            // AND(a, XOR(b, ONE))
            GateType::Nimp => {
                let temp = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp as usize);
                self.wire_used(gate.wire_b);
                // ONE is constant, don't count
                self.wire_used(gate.wire_a);
                self.wire_used(WireId(temp as usize));
            }
            // AND(XOR(a, ONE), b)
            GateType::Ncimp => {
                let temp = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp as usize);
                self.wire_used(gate.wire_a);
                // ONE is constant, don't count
                self.wire_used(WireId(temp as usize));
                self.wire_used(gate.wire_b);
            }
            // XOR(XOR(AND(XOR(a, ONE), b), XOR(a, ONE)), b)
            GateType::Imp => {
                let temp1 = self.allocate_normalized_id();
                let temp2 = self.allocate_normalized_id();
                let temp3 = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp3 as usize);
                self.wire_used(gate.wire_a);
                // ONE is constant, don't count
                self.wire_used(WireId(temp1 as usize));
                self.wire_used(gate.wire_b);
                self.wire_used(WireId(temp2 as usize));
                self.wire_used(WireId(temp1 as usize));
                self.wire_used(WireId(temp3 as usize));
                self.wire_used(gate.wire_b);
            }
            // XOR(XOR(AND(XOR(b, ONE), a), XOR(b, ONE)), a)
            GateType::Cimp => {
                let temp1 = self.allocate_normalized_id();
                let temp2 = self.allocate_normalized_id();
                let temp3 = self.allocate_normalized_id();
                resize(self.fanout.as_mut().unwrap(), temp3 as usize);
                self.wire_used(gate.wire_b);
                // ONE is constant, don't count
                self.wire_used(WireId(temp1 as usize));
                self.wire_used(gate.wire_a);
                self.wire_used(WireId(temp2 as usize));
                self.wire_used(WireId(temp1 as usize));
                self.wire_used(WireId(temp3 as usize));
                self.wire_used(gate.wire_a);
            }
        }
    }
}

impl FanoutCounter {
    pub fn new(primary_inputs: usize) -> Self {
        let pb = ProgressBar::no_length();
        let mut mode = Self {
            fanout: Some(Vec::new()),
            next_normalized_id: 0,
            primary_inputs,
            biggest_fanout_seen: 0,
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

    fn wire_used(&mut self, wire_id: WireId) -> u16 {
        let wire_id = wire_id.0;
        if (0..self.primary_inputs + 2).contains(&wire_id) {
            return 0;
        }
        let fanout = self.fanout.as_mut().unwrap();

        fanout[wire_id] += 1;
        fanout[wire_id]
    }

    pub fn finish(&mut self) -> (Vec<u16>, usize) {
        let fanout = self.fanout.take().unwrap();
        (fanout, self.biggest_fanout_seen)
    }
}
