#![allow(non_snake_case)]

use crate::ed25519::{compress, sign, verify};
use bellpepper::gadgets::multipack::bytes_to_bits;
use bellpepper::gadgets::num::AllocatedNum;
use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_ed25519::curve::AffinePoint;
use bellpepper_ed25519::{circuit::AllocatedAffinePoint, curve::Ed25519Curve};
use bellpepper_nonnative::mp::bignat::BigNat;
use bellpepper_nonnative::util::bit::{Bit, Bitvector};
use bellpepper_sha512::sha512::sha512;
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;
use num_bigint::{BigInt, BigUint};
use rand::RngCore;
use std::marker::PhantomData;

pub fn verify_circuit<F, CS>(
    cs: &mut CS,
    G: AffinePoint,
    P: AffinePoint,
    msg: [u8; 32],
    sign: (AffinePoint, BigUint),
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    let q = Ed25519Curve::order();

    let G_al =
        AllocatedAffinePoint::alloc_affine_point(&mut cs.namespace(|| "alloc base point"), &G)?;

    let P_al = AllocatedAffinePoint::alloc_affine_point(&mut cs.namespace(|| "alloc pubkey"), &P)?;

    let R_al = AllocatedAffinePoint::alloc_affine_point(&mut cs.namespace(|| "alloc r"), &sign.0)?;

    // Compute hash_out = SHA512(R || P || msg)
    let mut input = Vec::new();
    input.extend(compress(sign.0.clone()));
    input.extend(compress(P));
    input.extend(msg);
    assert_eq!(input.len(), 96);
    let input_bool: Vec<Boolean> = bytes_to_bits(&input)
        .iter()
        .enumerate()
        .map(|(i, b)| {
            Boolean::from(
                AllocatedBit::alloc(
                    &mut cs.namespace(|| format!("alloc bit {} of hash input", i)),
                    Some(*b),
                )
                .unwrap(),
            )
        })
        .collect();
    let hash_out = sha512(&mut cs.namespace(|| "compute hash of input"), &input_bool).unwrap();

    // compute h = hash_out (mod q)
    let bs: Vec<Bit<F>> = hash_out
        .iter()
        .rev()
        .map(|b| Bit::<F>::from_sapling::<CS>(b.clone()))
        .collect();
    let bit_vector = Bitvector::from_bits(bs);
    let hash_big = BigNat::recompose(&bit_vector, 64);
    let q_big = BigNat::alloc_from_nat(
        &mut cs.namespace(|| "alloc curve order"),
        || Ok(BigInt::from(q.clone())),
        64,
        4,
    )
    .unwrap();
    let h_big = hash_big
        .red_mod(&mut cs.namespace(|| "mod q"), &q_big)
        .unwrap();

    // Allocate h as vector of Boolean
    let mut h_bits = h_big
        .decompose(&mut cs.namespace(|| "decompose to bits"))
        .unwrap()
        .into_bits();
    h_bits.truncate(h_bits.len() - 3);
    assert_eq!(h_bits.len(), 253);
    let h_bool: Vec<Boolean> = h_bits
        .iter()
        .enumerate()
        .map(|(i, b)| {
            Boolean::from(
                AllocatedBit::alloc(
                    &mut cs.namespace(|| format!("alloc bit {} of h", i)),
                    Some(b.value.unwrap_or(false)),
                )
                .unwrap(),
            )
        })
        .collect();

    // Allocate s as vector of Boolean
    let mut s_vec = sign.1.to_radix_le(2);
    s_vec.resize(253, 0u8);
    let s_bits: Vec<bool> = s_vec.into_iter().map(|i| i != 0).collect();
    assert_eq!(s_bits.len(), 253);
    let s_bool: Vec<Boolean> = s_bits
        .iter()
        .enumerate()
        .map(|(i, b)| {
            Boolean::from(
                AllocatedBit::alloc(
                    &mut cs.namespace(|| format!("alloc bit {} of s", i)),
                    Some(*b),
                )
                .unwrap(),
            )
        })
        .collect();

    let p1 = G_al.ed25519_scalar_multiplication(&mut cs.namespace(|| "P1 = s * G"), &s_bool)?;

    let h_mult_pk =
        P_al.ed25519_scalar_multiplication(&mut cs.namespace(|| "h * pubkey"), &h_bool)?;

    let p2 = AllocatedAffinePoint::ed25519_point_addition(
        &mut cs.namespace(|| "R + h * pubkey"),
        &R_al,
        &h_mult_pk,
    )?;

    let _ = AllocatedAffinePoint::assert_equality(&mut cs.namespace(|| "p1 == p2"), &p1, &p2);

    Ok(())
}

#[derive(Clone, Debug)]
pub struct SigIter<F>
where
    F: PrimeField + PrimeFieldBits,
{
    pubkey: AffinePoint,
    msg: [u8; 32],
    sign: (AffinePoint, BigUint),
    _phantom: PhantomData<F>,
}

impl<F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits> SigIter<F> {
    pub fn get_step() -> Self {
        let mut msg: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut msg);

        let ((R, s), P) = sign(msg, None);

        let veri_sig = verify(msg, P.clone(), R.clone(), s.clone());
        assert!(veri_sig);

        Self {
            pubkey: P,
            msg,
            sign: (R, s),
            _phantom: PhantomData,
        }
    }
    pub fn from_message(msg: [u8; 32], secret_opt: Option<[u8; 32]>) -> Self {
        let ((R, s), P) = sign(msg, secret_opt);
        assert!(verify(msg, P.clone(), R.clone(), s.clone()));
        Self {
            pubkey: P,
            msg,
            sign: (R, s),
            _phantom: PhantomData,
        }
    }    
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for SigIter<F> {
    /// We carry both the 32-byte message (256 bits) and the 64-byte pubkey hash (512 bits)
    /// totaling 768 bits, packed into ceil(768 / F::CAPACITY) scalars.
    fn arity(&self) -> usize {
        let total_bits = 32 * 8  /* message */ + 64 * 8  /* pubkey hash */;
        let cap = F::CAPACITY as usize;
        (total_bits + cap - 1) / cap  // e.g. 4
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        _z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // 1) Verify the Ed25519 signature
        let g = Ed25519Curve::basepoint();
        verify_circuit(
            &mut cs.namespace(|| "verify signature"),
            g,
            self.pubkey.clone(),
            self.msg,
            self.sign.clone(),
        )?;

        // 2) Allocate message bits
        let mut msg_bits = Vec::with_capacity(32 * 8);
        for (i, &b) in bytes_to_bits(&self.msg).iter().enumerate() {
            let bit = AllocatedBit::alloc(
                &mut cs.namespace(|| format!("msg bit {}", i)),
                Some(b),
            )?;
            msg_bits.push(Boolean::from(bit));
        }

        // 3) Allocate compressed pubkey bits
        let compressed_pk = compress(self.pubkey.clone());
        let mut pk_bits = Vec::with_capacity(compressed_pk.len() * 8);
        for (i, &byte) in compressed_pk.iter().enumerate() {
            for j in (0..8).rev() {
                let b = ((byte >> j) & 1) == 1;
                let bit = AllocatedBit::alloc(
                    &mut cs.namespace(|| format!("pk bit {}.{}", i, j)),
                    Some(b),
                )?;
                pk_bits.push(Boolean::from(bit));
            }
        }

        // 4) Hash pk_bits via SHA-512 gadget
        let hash_pk = sha512(&mut cs.namespace(|| "sha512(pubkey)"), &pk_bits)?;

        // 5) Build one combined Boolean vector: msg_bits || hash_pk
        let mut all_bits = Vec::with_capacity(msg_bits.len() + hash_pk.len());
        all_bits.extend(msg_bits);
        all_bits.extend(hash_pk);

        // 6) Pack into state scalars
        let mut state = Vec::new();
        let cap = F::CAPACITY as usize;
        for (chunk_i, chunk_bits) in all_bits.chunks(cap).enumerate() {
            let num = bellpepper::gadgets::multipack::pack_bits(
                &mut cs.namespace(|| format!("pack chunk {}", chunk_i)),
                chunk_bits,
            )?;
            state.push(num);
        }

        Ok(state)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use ff::Field;
    use pasta_curves::Fp;

    #[test]
    fn test_step_circuit() {
        let step = SigIter::get_step();
        let mut cs = TestConstraintSystem::<Fp>::new();
        let zero_al =
            AllocatedNum::alloc(&mut cs.namespace(|| "alloc null"), || Ok(Fp::ZERO)).unwrap();

        let _ = step
            .synthesize(&mut cs.namespace(|| "call synth"), &[zero_al])
            .unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 1669649);
        assert_eq!(cs.num_inputs(), 1);
    }
}
