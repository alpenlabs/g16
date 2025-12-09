use ckt_fmtv5_types::v5::a::reader::verify_v5a_checksum;

#[monoio::main]
async fn main() {
    assert!(verify_v5a_checksum("g16.ckt").await.unwrap())
}
