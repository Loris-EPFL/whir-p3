use std::io::{self, Write};

use crate::metrics::Row;

pub fn write_row(w: &mut impl Write, r: &Row) -> io::Result<()> {
    serde_json::to_writer(&mut *w, r)?;
    writeln!(w)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{axes::Axes, metrics::StaticMetrics};

    #[test]
    fn row_roundtrips_through_serde_json() {
        let row = Row {
            scheme: "test".to_string(),
            axes: Axes {
                log_n: 10,
                arity: 2,
                batch: 1,
                ivc_steps: 4,
                step_muls: 100,
                seed: 42,
            },
            run: 0,
            skipped: None,
            phases_ns: BTreeMap::from([("prove_total".to_string(), 12345_u128)]),
            counters: BTreeMap::new(),
            static_: StaticMetrics {
                proof_field_elems: 100,
                circuit_constraints: Some(50),
            },
        };

        let mut buf = Vec::new();
        write_row(&mut buf, &row).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));

        let deser: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(deser["scheme"], "test");
        assert_eq!(deser["axes"]["log_n"], 10);
        assert_eq!(deser["run"], 0);
        assert_eq!(deser["phases_ns"]["prove_total"], 12345);
        assert_eq!(deser["static"]["proof_field_elems"], 100);
    }
}
