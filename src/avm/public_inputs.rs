//! bb's AVM public inputs (`vm2/common/avm_io.hpp` `PublicInputs`): their msgpack, as clients send
//! them with `AvmVerify`, into the verifier's four columns (bb `PublicInputs::to_columns`). Each
//! input sits at its `AVM_PUBLIC_INPUTS_*_ROW_IDX` row, the regen's `public_input_row` table; a
//! structured one spreads across the columns.

use super::tables::layout;
use crate::base::Fr;
use ark_ff::{PrimeField, Zero};
use serde::de::{Deserializer, Error, Visitor};
use serde::Deserialize;

/// One scalar: a field element (32 big-endian bytes), an integer or a bool.
#[derive(Clone, Copy)]
struct S(Fr);

impl<'de> Deserialize<'de> for S {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = S;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a field element, an integer or a bool")
            }
            fn visit_bytes<E: Error>(self, b: &[u8]) -> Result<S, E> {
                if b.len() != 32 {
                    return Err(E::invalid_length(b.len(), &"32 bytes"));
                }
                Ok(S(Fr::from_be_bytes_mod_order(b)))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<S, E> {
                Ok(S(Fr::from(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<S, E> {
                u64::try_from(v).map(|v| S(Fr::from(v))).map_err(|_| E::custom("negative integer"))
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<S, E> {
                Ok(S(Fr::from(v)))
            }
        }
        d.deserialize_any(V)
    }
}

macro_rules! structs {
    ($($name:ident { $($field:ident: $ty:ty),* })*) => {$(
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct $name { $($field: $ty),* }
    )*};
}

structs! {
    GlobalVariables { chain_id: S, version: S, block_number: S, slot_number: S, timestamp: S, coinbase: S, fee_recipient: S, gas_fees: GasFees }
    GasFees { fee_per_da_gas: S, fee_per_l2_gas: S }
    Gas { l2_gas: S, da_gas: S }
    GasSettings { gas_limits: Gas, teardown_gas_limits: Gas, max_fees_per_gas: GasFees, max_priority_fees_per_gas: GasFees }
    Snapshot { root: S, next_available_leaf_index: S }
    TreeSnapshots { l1_to_l2_message_tree: Snapshot, note_hash_tree: Snapshot, nullifier_tree: Snapshot, public_data_tree: Snapshot }
    ProtocolContracts { derived_addresses: Vec<S> }
    CallRequest { msg_sender: S, contract_address: S, is_static_call: S, calldata_hash: S }
    CallRequestLengths { setup_calls: S, app_logic_calls: S, teardown_call: S }
    PrivateLengths { note_hashes: S, nullifiers: S, l2_to_l1_msgs: S }
    PrivateData { note_hashes: Vec<S>, nullifiers: Vec<S>, l2_to_l1_msgs: Vec<ScopedMessage> }
    Message { recipient: S, content: S }
    ScopedMessage { message: Message, contract_address: S }
    AvmLengths { note_hashes: S, nullifiers: S, l2_to_l1_msgs: S, public_data_writes: S }
    PublicLogs { length: u32, payload: Vec<S> }
    DataWrite { leaf_slot: S, value: S }
    AvmData { note_hashes: Vec<S>, nullifiers: Vec<S>, l2_to_l1_msgs: Vec<ScopedMessage>, public_logs: PublicLogs, public_data_writes: Vec<DataWrite> }
    PublicInputs {
        global_variables: GlobalVariables, protocol_contracts: ProtocolContracts, start_tree_snapshots: TreeSnapshots,
        start_gas_used: Gas, gas_settings: GasSettings, effective_gas_fees: GasFees, fee_payer: S, prover_id: S,
        public_call_request_array_lengths: CallRequestLengths, public_setup_call_requests: Vec<CallRequest>,
        public_app_logic_call_requests: Vec<CallRequest>, public_teardown_call_request: CallRequest,
        previous_non_revertible_accumulated_data_array_lengths: PrivateLengths,
        previous_revertible_accumulated_data_array_lengths: PrivateLengths,
        previous_non_revertible_accumulated_data: PrivateData, previous_revertible_accumulated_data: PrivateData,
        end_tree_snapshots: TreeSnapshots, end_gas_used: Gas, accumulated_data_array_lengths: AvmLengths,
        accumulated_data: AvmData, transaction_fee: S, reverted: S
    }
}

/// The columns being filled; a write past a column's end (an array longer than bb's) is an error.
struct Cols(Vec<Vec<Fr>>, Result<(), String>);

impl Cols {
    /// `values` across the columns at `name`'s row plus `offset`.
    fn put(&mut self, name: &str, offset: usize, values: &[S]) {
        let row = layout().public_input_rows[name] + offset;
        for (c, v) in values.iter().enumerate() {
            match self.0[c].get_mut(row) {
                Some(slot) => *slot = v.0,
                None => self.1 = Err(format!("public input {name}[{offset}] is past the columns")),
            }
        }
    }
    fn array<T>(&mut self, name: &str, items: &[T], values: impl Fn(&T) -> Vec<S>) {
        for (i, item) in items.iter().enumerate() {
            self.put(name, i, &values(item));
        }
    }
    fn snapshots(&mut self, prefix: &str, t: &TreeSnapshots) {
        for (tree, s) in [("L1_TO_L2_MESSAGE_TREE", &t.l1_to_l2_message_tree), ("NOTE_HASH_TREE", &t.note_hash_tree), ("NULLIFIER_TREE", &t.nullifier_tree), ("PUBLIC_DATA_TREE", &t.public_data_tree)] {
            self.put(&format!("{prefix}_{tree}"), 0, &[s.root, s.next_available_leaf_index]);
        }
    }
    fn private_data(&mut self, prefix: &str, lengths: &PrivateLengths, data: &PrivateData) {
        self.put(&format!("{prefix}_ARRAY_LENGTHS_NOTE_HASHES"), 0, &[lengths.note_hashes]);
        self.put(&format!("{prefix}_ARRAY_LENGTHS_NULLIFIERS"), 0, &[lengths.nullifiers]);
        self.put(&format!("{prefix}_ARRAY_LENGTHS_L2_TO_L1_MSGS"), 0, &[lengths.l2_to_l1_msgs]);
        self.array(&format!("{prefix}_NOTE_HASHES"), &data.note_hashes, |v| vec![*v]);
        self.array(&format!("{prefix}_NULLIFIERS"), &data.nullifiers, |v| vec![*v]);
        self.array(&format!("{prefix}_L2_TO_L1_MSGS"), &data.l2_to_l1_msgs, message);
    }
}

fn gas(g: &Gas) -> [S; 2] {
    [g.da_gas, g.l2_gas]
}

fn fees(f: &GasFees) -> [S; 2] {
    [f.fee_per_da_gas, f.fee_per_l2_gas]
}

fn call(r: &CallRequest) -> Vec<S> {
    vec![r.msg_sender, r.contract_address, r.is_static_call, r.calldata_hash]
}

fn message(m: &ScopedMessage) -> Vec<S> {
    vec![m.message.recipient, m.message.content, m.contract_address]
}

/// bb `PublicInputs::from(bytes).to_columns()`.
pub fn public_input_columns(bytes: &[u8]) -> Result<Vec<Vec<Fr>>, String> {
    let p: PublicInputs = rmp_serde::from_slice(bytes).map_err(|e| format!("AVM public inputs: {e}"))?;
    let mut c = Cols(layout().public_input_column_lengths.iter().map(|&n| vec![Fr::zero(); n]).collect(), Ok(()));
    let g = &p.global_variables;
    for (name, v) in [("CHAIN_ID", g.chain_id), ("VERSION", g.version), ("BLOCK_NUMBER", g.block_number), ("SLOT_NUMBER", g.slot_number), ("TIMESTAMP", g.timestamp), ("COINBASE", g.coinbase), ("FEE_RECIPIENT", g.fee_recipient)] {
        c.put(&format!("GLOBAL_VARIABLES_{name}"), 0, &[v]);
    }
    c.put("GLOBAL_VARIABLES_GAS_FEES", 0, &fees(&g.gas_fees));
    c.array("PROTOCOL_CONTRACTS", &p.protocol_contracts.derived_addresses, |v| vec![*v]);
    c.snapshots("START_TREE_SNAPSHOTS", &p.start_tree_snapshots);
    c.put("START_GAS_USED", 0, &gas(&p.start_gas_used));
    let s = &p.gas_settings;
    c.put("GAS_SETTINGS_GAS_LIMITS", 0, &gas(&s.gas_limits));
    c.put("GAS_SETTINGS_TEARDOWN_GAS_LIMITS", 0, &gas(&s.teardown_gas_limits));
    c.put("GAS_SETTINGS_MAX_FEES_PER_GAS", 0, &fees(&s.max_fees_per_gas));
    c.put("GAS_SETTINGS_MAX_PRIORITY_FEES_PER_GAS", 0, &fees(&s.max_priority_fees_per_gas));
    c.put("EFFECTIVE_GAS_FEES", 0, &fees(&p.effective_gas_fees));
    c.put("FEE_PAYER", 0, &[p.fee_payer]);
    c.put("PROVER_ID", 0, &[p.prover_id]);
    let l = &p.public_call_request_array_lengths;
    c.put("PUBLIC_CALL_REQUEST_ARRAY_LENGTHS_SETUP_CALLS", 0, &[l.setup_calls]);
    c.put("PUBLIC_CALL_REQUEST_ARRAY_LENGTHS_APP_LOGIC_CALLS", 0, &[l.app_logic_calls]);
    c.put("PUBLIC_CALL_REQUEST_ARRAY_LENGTHS_TEARDOWN_CALL", 0, &[l.teardown_call]);
    c.array("PUBLIC_SETUP_CALL_REQUESTS", &p.public_setup_call_requests, call);
    c.array("PUBLIC_APP_LOGIC_CALL_REQUESTS", &p.public_app_logic_call_requests, call);
    c.put("PUBLIC_TEARDOWN_CALL_REQUEST", 0, &call(&p.public_teardown_call_request));
    c.private_data("PREVIOUS_NON_REVERTIBLE_ACCUMULATED_DATA", &p.previous_non_revertible_accumulated_data_array_lengths, &p.previous_non_revertible_accumulated_data);
    c.private_data("PREVIOUS_REVERTIBLE_ACCUMULATED_DATA", &p.previous_revertible_accumulated_data_array_lengths, &p.previous_revertible_accumulated_data);
    c.snapshots("END_TREE_SNAPSHOTS", &p.end_tree_snapshots);
    c.put("END_GAS_USED", 0, &gas(&p.end_gas_used));
    let l = &p.accumulated_data_array_lengths;
    c.put("AVM_ACCUMULATED_DATA_ARRAY_LENGTHS_NOTE_HASHES", 0, &[l.note_hashes]);
    c.put("AVM_ACCUMULATED_DATA_ARRAY_LENGTHS_NULLIFIERS", 0, &[l.nullifiers]);
    c.put("AVM_ACCUMULATED_DATA_ARRAY_LENGTHS_L2_TO_L1_MSGS", 0, &[l.l2_to_l1_msgs]);
    c.put("AVM_ACCUMULATED_DATA_ARRAY_LENGTHS_PUBLIC_DATA_WRITES", 0, &[l.public_data_writes]);
    let d = &p.accumulated_data;
    c.array("AVM_ACCUMULATED_DATA_NOTE_HASHES", &d.note_hashes, |v| vec![*v]);
    c.array("AVM_ACCUMULATED_DATA_NULLIFIERS", &d.nullifiers, |v| vec![*v]);
    c.array("AVM_ACCUMULATED_DATA_L2_TO_L1_MSGS", &d.l2_to_l1_msgs, message);
    // A header (the length), then that many payload fields.
    let logs = &d.public_logs;
    let payload = logs.payload.get(..logs.length as usize).ok_or("AVM public inputs: public logs length past the payload")?;
    c.put("AVM_ACCUMULATED_DATA_PUBLIC_LOGS", 0, &[S(Fr::from(logs.length))]);
    let header = layout().public_input_rows["PUBLIC_LOGS_HEADER_LENGTH"];
    for (i, v) in payload.iter().enumerate() {
        c.put("AVM_ACCUMULATED_DATA_PUBLIC_LOGS", header + i, &[*v]);
    }
    c.array("AVM_ACCUMULATED_DATA_PUBLIC_DATA_WRITES", &d.public_data_writes, |w| vec![w.leaf_slot, w.value]);
    c.put("TRANSACTION_FEE", 0, &[p.transaction_fee]);
    c.put("REVERTED", 0, &[p.reverted]);
    c.1.map(|()| c.0)
}
