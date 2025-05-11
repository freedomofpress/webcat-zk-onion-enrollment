use clap::{Arg, Command};
use flate2::{write::ZlibEncoder, Compression};
use bellpepper::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use ff::PrimeField;
use nova_eddsa::circuit::SigIter;
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};
use nova_snark::{
    traits::circuit::TrivialCircuit, traits::snark::RelaxedR1CSSNARKTrait, CompressedSNARK,
    PublicParams, RecursiveSNARK,
};
use std::time::Instant;
use hex;

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

fn main() {
    let cmd = Command::new("Onion Signature Proof")
        .bin_name("onion")
        .arg(
            Arg::new("message")
                .short('m')
                .long("msg")
                .required(true)
                .value_name("HEX")
                .help("32-byte message in hex"),
        )
        .arg(
            Arg::new("sk")
                .short('k')
                .long("sk")
                .required(true)
                .value_name("HEX")
                .help("32-byte Ed25519 secret key in hex"),
        );

    let matches = cmd.get_matches();

    let msg_hex = matches.get_one::<String>("message").unwrap();
    let msg_bytes = hex::decode(msg_hex).expect("Invalid hex message");
    assert_eq!(msg_bytes.len(), 32, "Message must be 32 bytes");
    let mut msg = [0u8; 32];
    msg.copy_from_slice(&msg_bytes);

    let sk_hex = matches.get_one::<String>("sk").unwrap();
    let sk_bytes = hex::decode(sk_hex).expect("Invalid hex secret key");
    assert_eq!(sk_bytes.len(), 32, "Secret key must be 32 bytes");
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&sk_bytes);

    type C1 = SigIter<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

    let circuit_primary = SigIter::from_message(msg, Some(sk));
    let circuit_secondary = TrivialCircuit::default();

    println!("Onion Signature Proof");
    println!("=========================================================");
    let param_gen_timer = Instant::now();
    println!("Producing Public Parameters...");
    let pp = PublicParams::<E1, E2, C1, C2>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    );
    let param_gen_time = param_gen_timer.elapsed();

    println!("PublicParams::setup, took {:?}", param_gen_time);
    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );

    let raw_bits: Vec<bool> = bytes_to_bits(&msg);
    type Scalar1 = <E1 as Engine>::Scalar;
    let z0_primary: Vec<Scalar1> = compute_multipacking::<Scalar1>(&raw_bits)
        .into_iter()
        .map(|e| Scalar1::from_repr_vartime(e.to_repr()).unwrap())
        .collect();

    let z0_secondary = [<E2 as Engine>::Scalar::zero()];

    // Prove
    let proof_gen_timer = Instant::now();
    println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
        RecursiveSNARK::new(&pp, &circuit_primary, &circuit_secondary, &z0_primary, &z0_secondary)
            .unwrap();

    let res = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
    assert!(res.is_ok());

    // Verify Recursive
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, 1, &z0_primary[..], &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    // Compress
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let start = Instant::now();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    let proving_time = proof_gen_timer.elapsed();
    println!("Total proving time is {:?}", proving_time);
    assert!(res.is_ok());

    let compressed_snark = res.unwrap();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
    let compressed_snark_encoded = encoder.finish().unwrap();
    println!(
        "CompressedSNARK::len {:?} bytes",
        compressed_snark_encoded.len()
    );

    // Verify compressed
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(&vk, 1, &z0_primary[..], &z0_secondary);
    let verification_time = start.elapsed();
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        verification_time
    );
    assert!(res.is_ok());

    println!("=========================================================");
    println!("Public parameters generation time: {:?}", param_gen_time);
    println!("Total proving time (excl pp generation): {:?}", proving_time);
    println!("Total verification time: {:?}", verification_time);
}
