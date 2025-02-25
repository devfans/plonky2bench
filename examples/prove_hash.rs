use std::time::Instant;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Sample;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;


fn build_hashchain_circuit<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, witness: &mut PartialWitness<F>) {
    let num_hashes: i32 = 1 << 10;
    let initial_value = builder.add_virtual_hash_public_input();
    let final_value = builder.add_virtual_hash_public_input();
    let before: HashOut<F> = HashOut::rand();
    let mut after = before.clone();
    let mut current = initial_value;
    for _ in 0..num_hashes {
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(current.elements.to_vec());
        after = PoseidonHash::hash_no_pad(&after.elements);
    }
    builder.connect_hashes(current, final_value);
    witness.set_hash_target(initial_value, before).unwrap();
    witness.set_hash_target(final_value, after).unwrap();
}

fn build_recursive<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>, const D: usize> (
    builder: &mut CircuitBuilder<F, D>, witness: &mut PartialWitness<F>,
    common_data: &CommonCircuitData<F, D>,
    proof_with_pis: &ProofWithPublicInputs<F, C, D>,
    cap_height: usize,
    verifier_data: &plonky2::plonk::circuit_data::VerifierOnlyCircuitData<C, D> 
) where C::Hasher: AlgebraicHasher<F>, {
    let pt = builder.add_virtual_proof_with_pis(common_data);
    witness.set_proof_with_pis_target(&pt, proof_with_pis).unwrap();
    let inner_data = builder.add_virtual_verifier_data(cap_height);
    witness.set_verifier_data_target(&inner_data, verifier_data).unwrap();
    builder.verify_proof::<C>(&pt, &inner_data, common_data);
}

fn main() {
    
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
    let mut witness = PartialWitness::new();
    build_hashchain_circuit(&mut builder, &mut witness);
    // build the circuit
    let start = Instant::now();
    let cd = builder.build::<PoseidonGoldilocksConfig>();
    println!("build {} ms", start.elapsed().as_millis());

    // prove
    let start = Instant::now();
    let proof_with_pis = cd.prove(witness).unwrap();
    println!("prove {} ms", start.elapsed().as_millis());
    {
        let proof_bytes = bincode::serialize(&proof_with_pis.proof).expect("Failed to serialize proof");
        println!("Proof size: {} bytes", proof_bytes.len());
    }

    // verify
    let start = Instant::now();
    cd.verify(proof_with_pis.clone()).expect("Failed to verify");
    println!("verify {} ms", start.elapsed().as_millis());

    // ============== Recursive =====================

    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
    let mut witness = PartialWitness::new();
    build_recursive(&mut builder, &mut witness, &cd.common, &proof_with_pis, cd.common.config.fri_config.cap_height, &cd.verifier_only);
    // build the circuit
    let start = Instant::now();
    let cd = builder.build::<PoseidonGoldilocksConfig>();
    println!("build recursive {} ms", start.elapsed().as_millis());

    // prove
    let start = Instant::now();
    let proof_with_pis = cd.prove(witness).unwrap();
    println!("prove recursive {} ms", start.elapsed().as_millis());
    {
        let proof_bytes = bincode::serialize(&proof_with_pis.proof).expect("Failed to serialize proof");
        println!("Proof recursive size: {} bytes", proof_bytes.len());
    }

    // verify
    let start = Instant::now();
    cd.verify(proof_with_pis.clone()).expect("Failed to verify recursive");
    println!("verify recursive {} ms", start.elapsed().as_millis());

    // ============== Recursive nested =====================


    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
    let mut witness = PartialWitness::new();
    build_recursive(&mut builder, &mut witness, &cd.common, &proof_with_pis, cd.common.config.fri_config.cap_height, &cd.verifier_only);
    // build the circuit
    let start = Instant::now();
    let cd = builder.build::<PoseidonGoldilocksConfig>();
    println!("build nested recursive {} ms", start.elapsed().as_millis());

    // prove
    let start = Instant::now();
    let proof_with_pis = cd.prove(witness).unwrap();
    println!("prove nested recursive {} ms", start.elapsed().as_millis());
    {
        let proof_bytes = bincode::serialize(&proof_with_pis.proof).expect("Failed to serialize proof");
        println!("Proof nested recursive size: {} bytes", proof_bytes.len());
    }

    // verify
    let start = Instant::now();
    cd.verify(proof_with_pis).expect("Failed to verify nested recursive");
    println!("verify nested recursive {} ms", start.elapsed().as_millis());
}

