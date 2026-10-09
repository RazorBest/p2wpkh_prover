use std::collections::HashMap;
use std::error::Error;

use bip322::verify_simple_encoded;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::ecdsa::Signature;
use bitcoin::{Address, Network, OutPoint, PublicKey, Transaction, TxOut, Txid, Witness};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "Prove ownership of a P2WPKH->P2PWPKH transaction")]
struct Args {
    /// Spending transaction hex
    raw_tx: String,

    /// Previous transaction hex strings
    #[arg(long = "prev-tx", num_args = 1.., required = true)]
    prev_tx: Vec<String>,

    /// Exact message signed by the wallet
    #[arg(long, required = true)]
    message: String,

    /// BIP322 Simple signature strings
    #[arg(long = "signature", num_args = 1.., required = true)]
    signatures: Vec<String>,
}

/// Checks that the witness follows the BIP-141 spec for P2WPKH witness
/// And the BIP-66 signature is a valid encoding
fn is_witness_p2wpkh(witness: &Witness) -> bool {
    if witness.len() != 2 {
        return false;
    }

    if Signature::from_slice(&witness[0]).is_err() {
        return false;
    }

    if PublicKey::from_slice(&witness[1]).is_err() {
        return false;
    }

    return true;
}

fn check_p2wpkh_witness(tx: &Transaction) {
    for (i, input) in tx.input.iter().enumerate() {
        let witness = &input.witness;
        if !is_witness_p2wpkh(witness) {
            panic!("Input {i} is not P2WPKH");
        }
    }
}

fn find_prevouts(tx: &Transaction, prev_tx: &[Transaction]) -> Result<Vec<TxOut>, Box<dyn Error>> {
    let mut prev_tx_map: HashMap<Txid, &Transaction> = HashMap::new();

    // Parse and index previous transactions by their txid.
    for tx in prev_tx {
        let txid = tx.compute_txid();
        prev_tx_map.insert(txid, tx);
    }

    let mut prevouts = Vec::with_capacity(tx.input.len());

    // Resolve each input in the spending transaction's original order.
    for (i, input) in tx.input.iter().enumerate() {
        let outpoint = &input.previous_output;

        let tx = prev_tx_map.get(&outpoint.txid).ok_or_else(|| {
            format!(
                "Missing previous transaction {} for input {}",
                outpoint.txid, i
            )
        })?;

        let prevout = tx.output.get(outpoint.vout as usize).ok_or_else(|| {
            format!(
                "Output index {} out of range for previous transaction {}",
                outpoint.vout, outpoint.txid
            )
        })?;

        prevouts.push(prevout.clone());
    }

    Ok(prevouts)
}

fn check_prevouts_p2wpkh(prev_tx: &[TxOut]) {
    let ok = prev_tx.iter().all(|tx| tx.script_pubkey.is_p2wpkh());

    if !ok {
        panic!("Not all prev txs are P2WPKH");
    }
}

fn verify_tx(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), Box<dyn Error>> {
    if prevouts.len() != tx.input.len() {
        return Err("Number of prevouts does not match input count".into());
    }

    // Map each input's outpoint to its corresponding previous output.
    let spent: HashMap<OutPoint, TxOut> = tx
        .input
        .iter()
        .zip(prevouts.iter())
        .map(|(input, prevout)| (input.previous_output, prevout.clone()))
        .collect();

    // Verify input scripts and signatures.
    tx.verify(|outpoint| spent.get(outpoint).cloned())?;

    println!("All input scripts and signatures are valid.");
    Ok(())
}

fn check_prev_w2wpkh_valid(tx: &Transaction, prev_tx: &[Transaction]) {
    let prevouts: Vec<TxOut> = find_prevouts(&tx, prev_tx).expect("Not all prevouts found");

    check_prevouts_p2wpkh(&prevouts);

    let spent: HashMap<OutPoint, TxOut> = tx
        .input
        .iter()
        .zip(prevouts.iter())
        .map(|(input, prevout)| (input.previous_output, prevout.clone()))
        .collect();

    tx.verify(|outpoint| spent.get(outpoint).cloned())
        .expect("Verification failed");
}


fn check_spent_output_signatures(
    prevouts: &[bitcoin::TxOut],
    message: &str,
    signatures: &[String],
) {
    if prevouts.len() != signatures.len() {
        panic!("Incorrect amount of signatures. Need {}. Have {}", prevouts.len(), signatures.len());
    }
    let mut signature_matched = vec![false; signatures.len()];

    for (input_index, prevout) in prevouts.iter().enumerate() {
        let address =
            Address::from_script(&prevout.script_pubkey, Network::Bitcoin).unwrap();
        let address_string = address.to_string();

        let mut matched = false;

        for (sig_index, signature) in signatures.iter().enumerate() {
            if verify_simple_encoded(
                &address_string,
                message,
                signature,
            ).is_ok() {
                matched = true;
                signature_matched[sig_index] = true;
            }
        }

        if !matched {
            panic!(
                "Input {input_index}: no supplied BIP322 signature \
                 verifies for address {address_string}"
            );
        }
    }

    for (i, matched) in signature_matched.iter().enumerate() {
        if !matched {
            panic!("Signature {i} does not match any spent output");
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let tx: Transaction = deserialize_hex(&args.raw_tx)?;

    check_p2wpkh_witness(&tx);
    if args.prev_tx.len() > 0 {
        let prev_tx: Vec<Transaction> = args
            .prev_tx
            .into_iter()
            .map(|raw| deserialize_hex(&raw).unwrap())
            .collect();

        check_prev_w2wpkh_valid(&tx, &prev_tx);
        let prevouts: Vec<TxOut> = find_prevouts(&tx, &prev_tx).expect("Not all prevouts found");
        check_spent_output_signatures(&prevouts, &args.message, &args.signatures);
    }

    println!("\n----------------------------------------------------------");
    println!("Verification: SUCCESS");
    println!("----------------------------------------------------------\n");

    println!("txid: {}", tx.compute_txid());
    println!("inputs: {}", tx.input.len());
    println!("outputs: {}", tx.output.len());

    Ok(())
}
