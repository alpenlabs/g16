use std::{num::NonZero, path::PathBuf, str::FromStr};

use ckt::{
    GateType,
    v5::{
        self,
        a::{GateV5a, writer::CircuitWriterV5a},
    },
};
use cynosure::site_d::ringbuf::{Producer, RingBuf};
use g16ckt::{
    Gate as SourceGate, GateType as SourceGateType, WireId, circuit::CircuitMode,
    storage::Credits as SourceCredits,
};
use indicatif::ProgressBar;
use kanal::{Sender, bounded_async};
use lvl::types::CompactWireId;
use monoio::{FusionDriver, RuntimeBuilder, select};

pub struct TranslationMode {
    creds: Vec<u16>,
    next_normalized_id: u64,

    // Constants
    _false_wire_id: CompactWireId, // Normalized ID for FALSE
    true_wire_id: CompactWireId,   // Normalized ID for TRUE (our ONE wire)
    pb: ProgressBar,
    prod: Producer<GateV5a>,
    stop: Option<Sender<()>>,
}

impl std::fmt::Debug for TranslationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslationMode")
            .field("next_normalized_id", &self.next_normalized_id)
            .finish()
    }
}

impl CircuitMode for TranslationMode {
    type WireValue = bool; // We don't store values, just translate
    type CiphertextAcc = ();

    fn false_value(&self) -> Self::WireValue {
        false
    }
    fn true_value(&self) -> Self::WireValue {
        true
    }

    fn allocate_wire(&mut self, _credits: SourceCredits) -> WireId {
        let normalized_id = self.allocate_normalized_id();
        WireId(normalized_id as usize)
    }

    fn lookup_wire(&mut self, _wire: WireId) -> Option<Self::WireValue> {
        Some(false) // Always return dummy value
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {
        // No-op for translation
    }

    fn add_credits(&mut self, _wires: &[WireId], _credits: NonZero<SourceCredits>) {}

    fn evaluate_gate(&mut self, gate: &SourceGate) {
        // This is where the magic happens - translate instead of execute!
        self.translate_gate(gate);
    }
}

impl TranslationMode {
    pub async fn new(
        creds: Vec<u16>,
        path: &str,
        primary_inputs: u64,
        outputs: Vec<WireId>,
    ) -> Self {
        let (prod, mut cons) = RingBuf::new(2usize.pow(16)).split();
        let (stop_tx, stop_rx) = bounded_async::<()>(1);

        let pb = ProgressBar::new(creds.len() as u64);

        let path = PathBuf::from_str(path).unwrap();
        std::thread::spawn(move || {
            RuntimeBuilder::<FusionDriver>::new()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let mut writer = CircuitWriterV5a::new(
                        path,
                        primary_inputs,
                        outputs.into_iter().map(|w| w.0 as u64).collect(),
                    )
                    .await
                    .unwrap();

                    loop {
                        select! {
                            biased; // EXTREMELY IMPORTANT!!!
                            // we risk losing gates in the buffer if we don't check the buffer before the stop signal
                            gate = cons.pop() => writer.write_gate(gate).await.unwrap(),
                            _ = stop_rx.recv() => break,
                        }
                    }

                    writer.finalize().await.unwrap();
                })
        });

        let mut mode = Self {
            creds,
            pb,
            next_normalized_id: 0,
            _false_wire_id: CompactWireId::from_u64(0),
            true_wire_id: CompactWireId::from_u64(1),
            prod,
            stop: Some(stop_tx.to_sync()),
        };

        // Reserve normalized IDs for constants
        mode.allocate_normalized_id(); // ID 0 = FALSE
        mode.allocate_normalized_id(); // ID 1 = TRUE (ONE wire)

        mode
    }

    pub fn finish(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.pb.finish();
    }

    fn allocate_normalized_id(&mut self) -> u64 {
        let id = self.next_normalized_id;
        self.next_normalized_id += 1;
        id
    }

    fn write_gate(
        &mut self,
        gate_type: GateType,
        in1: CompactWireId,
        in2: CompactWireId,
        out: CompactWireId,
    ) {
        let gate = v5::a::GateV5a {
            in1: in1.to_u64(),
            in2: in2.to_u64(),
            out: out.to_u64(),
            credits: self.creds[out.to_u64() as usize] as u32,
            gate_type,
        };
        loop {
            if self.prod.try_push(gate).is_ok() {
                break;
            }
        }
        self.pb.inc(1);
    }

    fn translate_gate(&mut self, gate: &SourceGate) {
        let in1 = CompactWireId::from_u64(gate.wire_a.0 as u64);
        let in2 = CompactWireId::from_u64(gate.wire_b.0 as u64);
        let out = CompactWireId::from_u64(gate.wire_c.0 as u64);
        let allocate_id =
            |mode: &mut TranslationMode| CompactWireId::from_u64(mode.allocate_normalized_id());
        use SourceGateType::*;
        match gate.gate_type {
            // Direct mappings
            And => self.write_gate(GateType::AND, in1, in2, out),
            Xor => self.write_gate(GateType::XOR, in1, in2, out),

            // Negated versions - XOR result with ONE
            Nand => {
                let temp = allocate_id(self);
                self.write_gate(GateType::AND, in1, in2, temp);
                self.write_gate(GateType::XOR, temp, self.true_wire_id, out);
            }

            Xnor => {
                let temp = allocate_id(self);
                self.write_gate(GateType::XOR, in1, in2, temp);
                self.write_gate(GateType::XOR, temp, self.true_wire_id, out);
            }

            // NOT: XOR with ONE
            Not => self.write_gate(GateType::XOR, in1, self.true_wire_id, out),

            // OR = XOR(XOR(AND(a,b), a), b)
            Or => {
                let temp1 = allocate_id(self);
                let temp2 = allocate_id(self);
                self.write_gate(GateType::AND, in1, in2, temp1);
                self.write_gate(GateType::XOR, temp1, in1, temp2);
                self.write_gate(GateType::XOR, temp2, in2, out);
            }

            // NOR = XOR(OR(a,b), ONE)
            Nor => {
                let temp1 = allocate_id(self);
                let temp2 = allocate_id(self);
                let temp3 = allocate_id(self);
                // First compute OR
                self.write_gate(GateType::AND, in1, in2, temp1);
                self.write_gate(GateType::XOR, temp1, in1, temp2);
                self.write_gate(GateType::XOR, temp2, in2, temp3);
                // Then negate with ONE
                self.write_gate(GateType::XOR, temp3, self.true_wire_id, out);
            }

            // NIMP: a AND NOT b = AND(a, XOR(b, ONE))
            Nimp => {
                let temp = allocate_id(self);
                self.write_gate(GateType::XOR, in2, self.true_wire_id, temp); // NOT b
                self.write_gate(GateType::AND, in1, temp, out); // a AND (NOT b)
            }

            // NCIMP: NOT a AND b = AND(XOR(a, ONE), b)
            Ncimp => {
                let temp = allocate_id(self);
                self.write_gate(GateType::XOR, in1, self.true_wire_id, temp); // NOT a
                self.write_gate(GateType::AND, temp, in2, out); // (NOT a) AND b
            }

            // IMP: a => b = NOT a OR b
            Imp => {
                let temp1 = allocate_id(self);
                let temp2 = allocate_id(self);
                let temp3 = allocate_id(self);

                // NOT a
                self.write_gate(GateType::XOR, in1, self.true_wire_id, temp1);
                // OR(NOT a, b) = XOR(XOR(AND(NOT a, b), NOT a), b)
                self.write_gate(GateType::AND, temp1, in2, temp2);
                self.write_gate(GateType::XOR, temp2, temp1, temp3);
                self.write_gate(GateType::XOR, temp3, in2, out);
            }

            // CIMP: b => a (swap inputs for IMP)
            Cimp => {
                let temp1 = allocate_id(self);
                let temp2 = allocate_id(self);
                let temp3 = allocate_id(self);

                // NOT b
                self.write_gate(GateType::XOR, in2, self.true_wire_id, temp1);
                // OR(NOT b, a)
                self.write_gate(GateType::AND, temp1, in1, temp2);
                self.write_gate(GateType::XOR, temp2, temp1, temp3);
                self.write_gate(GateType::XOR, temp3, in1, out);
            }
        }
    }
}
