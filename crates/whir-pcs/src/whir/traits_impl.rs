//! Impls tying existing whir-pcs types to the workspace-wide trait
//! interfaces in `whir-traits`. Kept in a separate file so the trait
//! bridge is easy to audit and doesn't clutter the core modules.

use p3_field::Field;
use p3_symmetric::Hash;
use whir_traits::{OodStatement, ParsedCommitmentView};

use crate::whir::committer::reader::ParsedCommitment;
use crate::whir::constraints::statement::EqStatement;

// ──────────────────────────────────────────────────────────────────────────
// OodStatement impl for EqStatement
//
// `EqStatement` already carries a `Vec<MultilinearPoint<F>>` + `Vec<F>` with
// the invariant that every point has `num_variables` coordinates. We expose
// it through the workspace-wide `OodStatement` trait so that fold verifiers
// (which want to carry OOD + shift-query data alongside a Merkle root) can
// consume it generically.
// ──────────────────────────────────────────────────────────────────────────

impl<F: Field> OodStatement<F> for EqStatement<F> {
    fn len(&self) -> usize {
        EqStatement::len(self)
    }

    fn num_variables(&self) -> usize {
        EqStatement::num_variables(self)
    }

    fn iter_constraints<'a>(&'a self) -> impl Iterator<Item = (&'a [F], F)> + 'a
    where
        F: 'a,
    {
        self.iter().map(|(point, &value)| (point.as_slice(), value))
    }
}

// ──────────────────────────────────────────────────────────────────────────
// ParsedCommitmentView impl for ParsedCommitment
//
// `ParsedCommitment<F, D>` bundles a Merkle root `D` and an `EqStatement<F>`
// derived from the commitment transcript. `D` here is concretely always
// `Hash<BaseF, W, DIGEST_ELEMS>` (see `CommitmentReader::parse_commitment`),
// and `[W; DIGEST_ELEMS]` is covered by the blanket impl of
// `CommitmentRoot`. We add a thin wrapper to make the two match.
//
// The `CommitmentRoot` impl for `Hash<F, W, N>` lives in `whir-traits`
// itself — trait + type coherence requires it to be co-located with the
// trait definition, not here.
// ──────────────────────────────────────────────────────────────────────────

impl<F, BaseF, W, const DIGEST_ELEMS: usize> ParsedCommitmentView<F>
    for ParsedCommitment<F, Hash<BaseF, W, DIGEST_ELEMS>>
where
    F: Field,
    BaseF: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
    W: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
{
    type Root = Hash<BaseF, W, DIGEST_ELEMS>;
    type Statement = EqStatement<F>;

    fn root(&self) -> &Self::Root {
        &self.root
    }

    fn ood_statement(&self) -> &Self::Statement {
        &self.ood_statement
    }
}

#[cfg(test)]
mod tests {
    //! Compile-time + runtime coverage for the trait impls above.

    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use whir_core::poly::multilinear::MultilinearPoint;

    type F = KoalaBear;

    /// Compile-time: `EqStatement<F>` must be usable through `OodStatement`.
    #[allow(dead_code)]
    fn _assert_eq_statement_impls_ood<F2: Field>(_: &EqStatement<F2>)
    where
        EqStatement<F2>: OodStatement<F2>,
    {
    }

    /// Compile-time: `ParsedCommitment<F, Hash<…>>` must be usable through
    /// `ParsedCommitmentView<F>`.
    #[allow(dead_code)]
    fn _assert_parsed_impls_view<F2, BaseF, W, const DIGEST: usize>(
        _: &ParsedCommitment<F2, Hash<BaseF, W, DIGEST>>,
    ) where
        F2: Field,
        BaseF: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
        W: Clone + Eq + core::fmt::Debug + Send + Sync + 'static,
        ParsedCommitment<F2, Hash<BaseF, W, DIGEST>>: ParsedCommitmentView<F2>,
    {
    }

    #[test]
    fn eq_statement_iter_constraints_matches_eq_iter() {
        let points = vec![
            MultilinearPoint::new(vec![F::ZERO, F::ONE]),
            MultilinearPoint::new(vec![F::ONE, F::ZERO]),
        ];
        let evals = vec![F::from_u64(7), F::from_u64(11)];
        let eq: EqStatement<F> = EqStatement::new_hypercube(points, evals);

        let via_trait: Vec<_> = <EqStatement<F> as OodStatement<F>>::iter_constraints(&eq)
            .map(|(pt, v)| (pt.to_vec(), v))
            .collect();

        assert_eq!(via_trait.len(), 2);
        assert_eq!(via_trait[0].0, vec![F::ZERO, F::ONE]);
        assert_eq!(via_trait[0].1, F::from_u64(7));
        assert_eq!(via_trait[1].0, vec![F::ONE, F::ZERO]);
        assert_eq!(via_trait[1].1, F::from_u64(11));
    }

    #[test]
    fn eq_statement_len_and_num_variables() {
        let points = vec![MultilinearPoint::new(vec![F::ONE, F::ZERO, F::ONE])];
        let evals = vec![F::from_u64(42)];
        let eq: EqStatement<F> = EqStatement::new_hypercube(points, evals);

        assert_eq!(<EqStatement<F> as OodStatement<F>>::len(&eq), 1);
        assert_eq!(<EqStatement<F> as OodStatement<F>>::num_variables(&eq), 3);
        assert!(!<EqStatement<F> as OodStatement<F>>::is_empty(&eq));
    }
}
