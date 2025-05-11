// examples/onion-cmd.rs

use clap::{Arg, Command};
use std::{fs::File, error::Error};
use hex::FromHex;
use sha2::{Sha512, Digest};
use ff::PrimeField;
use bellpepper::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use nova_eddsa::ed25519::{keygen, compress};
use nova_eddsa::circuit::SigIter;
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::{Engine, circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait},
    PublicParams, RecursiveSNARK, CompressedSNARK
};
use bincode;

// SNARK / curve types
type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
type C1 = SigIter<<E1 as Engine>::Scalar>;
type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Command::new("onion-cmd")
        .about("Onion‐v3 Ed25519 SNARK CLI (on‐the‐fly params)")
        .subcommand(
            Command::new("prove")
                .about("Prove a message under your secret key")
                .arg(Arg::new("msg").short('m').long("msg")
                    .value_name("HEX").required(true)
                    .help("32‐byte message in hex"))
                .arg(Arg::new("sk").short('k').long("sk")
                    .value_name("HEX").required(true)
                    .help("32‐byte Ed25519 secret key in hex"))
                .arg(Arg::new("out").long("out")
                    .value_name("PATH").default_value("proof.bin")
                    .help("Where to write the proof")),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a proof given message + pubkey‐hash")
                .arg(Arg::new("msg").short('m').long("msg")
                    .value_name("HEX").required(true)
                    .help("32‐byte message in hex"))
                .arg(Arg::new("pk_hash").long("pk-hash")
                    .value_name("HEX").required(true)
                    .help("64‐byte SHA-512(pubkey) in hex"))
                .arg(Arg::new("proof").long("proof")
                    .value_name("PATH").default_value("proof.bin")
                    .help("Proof file from `prove`")),
        )
        .get_matches();

    match cli.subcommand() {
        Some(("prove", sub)) => {
            // 1) parse inputs
            let msg_hex = sub.get_one::<String>("msg").unwrap();
            let sk_hex  = sub.get_one::<String>("sk").unwrap();
            let out     = sub.get_one::<String>("out").unwrap();

            let msg_bytes: [u8;32] = Vec::from_hex(msg_hex)?
                .try_into().expect("msg must be 32 bytes");
            let sk_bytes: [u8;32]  = Vec::from_hex(sk_hex)?
                .try_into().expect("sk must be 32 bytes");

            // 2) derive pubkey and its hash
            let ((_, _hash_prefix), pubkey) = keygen(Some(sk_bytes));
            let compressed_pk = compress(pubkey.clone());
            let mut hasher = Sha512::new();
            hasher.update(&compressed_pk);
            let pk_hash_bytes = hasher.finalize();
            println!("Message     : {}", msg_hex);
            println!("Pubkey-hash : {}", hex::encode(pk_hash_bytes.as_slice()));

            // 3) build the two circuits
            let circuit_primary   = SigIter::from_message(msg_bytes, Some(sk_bytes));
            let circuit_secondary = TrivialCircuit::default();

            // 4) generate PublicParams in memory
            println!("Producing PublicParams...");
            let pp = PublicParams::<E1, E2, C1, C2>::setup(
                &SigIter::get_step(),
                &circuit_secondary,
                &*S1::ck_floor(),
                &*S2::ck_floor(),
            );

            // 5) form public‐inputs = bits(msg)||bits(pk_hash)
            let mut all_bits = Vec::new();
            all_bits.extend(bytes_to_bits(&msg_bytes));
            all_bits.extend(bytes_to_bits(pk_hash_bytes.as_ref()));
            type Scalar1 = <E1 as Engine>::Scalar;
            let z0_primary: Vec<Scalar1> = compute_multipacking::<Scalar1>(&all_bits)
                .into_iter()
                .map(|e| Scalar1::from_repr_vartime(e.to_repr()).unwrap())
                .collect();
            let z0_secondary = [<E2 as Engine>::Scalar::zero()];

            // 6) one‐step recursive SNARK
            println!("Generating RecursiveSNARK...");
            let mut rec_snark =
                RecursiveSNARK::<E1, E2, C1, C2>::new(
                    &pp,
                    &circuit_primary,
                    &circuit_secondary,
                    &z0_primary,
                    &z0_secondary,
                )?;
            rec_snark.prove_step(&pp, &circuit_primary, &circuit_secondary)?;

            // 7) compress to a tiny SNARK
            println!("Generating CompressedSNARK...");
            let (pk_snark, _vk_snark) =
                CompressedSNARK::<E1, E2, C1, C2, S1, S2>::setup(&pp)?;
            let compressed = CompressedSNARK::prove(&pp, &pk_snark, &rec_snark)?;

            // 8) write out the proof
            let mut f = File::create(out)?;
            bincode::serialize_into(&mut f, &compressed)?;
            println!("Wrote proof to `{}`", out);
        }

        Some(("verify", sub)) => {
            // 1) parse inputs
            let msg_hex     = sub.get_one::<String>("msg").unwrap();
            let pk_hash_hex = sub.get_one::<String>("pk_hash").unwrap();
            let proof_path  = sub.get_one::<String>("proof").unwrap();

            let msg_bytes: [u8;32]    = Vec::from_hex(msg_hex)?
                .try_into().expect("msg must be 32 bytes");
            let pk_hash_bytes: Vec<u8> = Vec::from_hex(pk_hash_hex)?;
            assert_eq!(pk_hash_bytes.len(), 64);

            // 2) load the compressed SNARK
            let compressed: CompressedSNARK<E1, E2, C1, C2, S1, S2> = {
                let mut f = File::open(proof_path)?;
                bincode::deserialize_from(&mut f)?
            };

            // 3) rebuild public‐inputs
            let mut all_bits = Vec::new();
            all_bits.extend(bytes_to_bits(&msg_bytes));
            all_bits.extend(bytes_to_bits(&pk_hash_bytes));
            type Scalar1 = <E1 as Engine>::Scalar;
            let z0_primary: Vec<Scalar1> = compute_multipacking::<Scalar1>(&all_bits)
                .into_iter()
                .map(|e| Scalar1::from_repr_vartime(e.to_repr()).unwrap())
                .collect();
            let z0_secondary = [<E2 as Engine>::Scalar::zero()];

            // 4) regenerate PublicParams + vk in memory
            let circuit_secondary = TrivialCircuit::default();
            let pp = PublicParams::<E1, E2, C1, C2>::setup(
                &SigIter::get_step(),
                &circuit_secondary,
                &*S1::ck_floor(),
                &*S2::ck_floor(),
            );
            let (_pk_snark, vk_snark) =
                CompressedSNARK::<E1, E2, C1, C2, S1, S2>::setup(&pp)?;

            // 5) actually verify
            println!("Verifying…");
            let res =
                compressed.verify(&vk_snark, 1, &z0_primary, &z0_secondary);
            println!("Verification result = {:?}", res.is_ok());
        }

        _ => {
            eprintln!("Please invoke either `onion-cmd prove ...` or `onion-cmd verify ...`");
            std::process::exit(1);
        }
    }

    Ok(())
}
