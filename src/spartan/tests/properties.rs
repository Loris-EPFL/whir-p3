use super::integration::{run_invalid_witness_case, run_spartan_whir_phase1_zry_demo};

#[test]
fn test_property_completeness_phase1_plus_whir_opening() {
    // Happy-path completeness:
    // a valid witness should pass Spartan phase-1 and WHIR Z(r_y)=v opening checks.
    run_spartan_whir_phase1_zry_demo();
}

#[test]
fn test_property_soundness_tamper_paths_are_rejected() {
    // Soundness checks are embedded in the demo routine:
    // - mutate r_y -> Spartan verify fails
    // - mutate WHIR proof payload -> WHIR verify fails
    // - mutate claimed v -> WHIR verify fails
    run_spartan_whir_phase1_zry_demo();
}

#[test]
fn test_property_determinism_fixed_seeds_replay_consistent() {
    // Re-run the full demo multiple times under fixed seeds to ensure stable outcomes.
    for _ in 0..3 {
        run_spartan_whir_phase1_zry_demo();
    }
}

#[test]
#[should_panic(expected = "Witness does not satisfy R1CS constraints")]
fn test_property_unsatisfied_instance_is_rejected() {
    run_invalid_witness_case();
}
