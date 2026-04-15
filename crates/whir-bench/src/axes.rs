use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct Axes {
    pub log_n: usize,
    pub arity: usize,
    pub batch: usize,
    pub ivc_steps: usize,
    pub step_muls: usize,
    pub seed: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AxesMatrix {
    pub log_n: Vec<usize>,
    pub arity: Vec<usize>,
    pub batch: Vec<usize>,
    pub ivc_steps: Vec<usize>,
    pub step_muls: Vec<usize>,
    #[serde(default = "default_seed")]
    pub seed: u64,
}

fn default_seed() -> u64 {
    42
}

impl AxesMatrix {
    pub fn iter_cartesian(&self) -> impl Iterator<Item = Axes> + '_ {
        self.log_n.iter().flat_map(move |&log_n| {
            self.arity.iter().flat_map(move |&arity| {
                self.batch.iter().flat_map(move |&batch| {
                    self.ivc_steps.iter().flat_map(move |&ivc_steps| {
                        self.step_muls.iter().map(move |&step_muls| Axes {
                            log_n,
                            arity,
                            batch,
                            ivc_steps,
                            step_muls,
                            seed: self.seed,
                        })
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cartesian_product_count() {
        let m = AxesMatrix {
            log_n: vec![10, 12],
            arity: vec![2],
            batch: vec![1, 8],
            ivc_steps: vec![4],
            step_muls: vec![100],
            seed: 42,
        };
        let axes: Vec<_> = m.iter_cartesian().collect();
        assert_eq!(axes.len(), 2 * 1 * 2 * 1 * 1);
        assert_eq!(axes[0].log_n, 10);
        assert_eq!(axes[0].batch, 1);
        assert_eq!(axes[1].log_n, 10);
        assert_eq!(axes[1].batch, 8);
    }
}
