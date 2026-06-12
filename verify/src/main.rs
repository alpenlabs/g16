use ckt_fmtv5_types::v5::a::reader::verify_v5a_checksum;

#[monoio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: verify path_to_file.v5a");
        return;
    }
    assert!(verify_v5a_checksum(args[1].clone()).await.unwrap())
}
