use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct Axes {
    pub log_n: usize,
    pub arity: usize,
    pub batch: usize,
    pub ivc_steps: usize,
    pub step_muls: usize,
    pub seed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_instances: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_step_circuits: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AxesMatrix {
    pub log_n: Vec<usize>,
    pub arity: Vec<usize>,
    pub batch: Vec<usize>,
    pub ivc_steps: Vec<usize>,
    pub step_muls: Vec<usize>,
    #[serde(default)]
    pub total_instances: Vec<usize>,
    #[serde(default)]
    pub total_step_circuits: Vec<usize>,
    #[serde(default = "default_seed")]
    pub seed: u64,
}

fn default_seed() -> u64 {
    42
}

impl AxesMatrix {
    pub fn iter_cartesian(&self) -> impl Iterator<Item = Axes> {
        let total_instances = optional_axis(&self.total_instances);
        let total_step_circuits = optional_axis(&self.total_step_circuits);
        let mut axes = Vec::new();
        for &log_n in &self.log_n {
            for &arity in &self.arity {
                for &batch in &self.batch {
                    for &ivc_steps in &self.ivc_steps {
                        for &step_muls in &self.step_muls {
                            for &total_instances in &total_instances {
                                for &total_step_circuits in &total_step_circuits {
                                    axes.push(Axes {
                                        log_n,
                                        arity,
                                        batch,
                                        ivc_steps,
                                        step_muls,
                                        seed: self.seed,
                                        total_instances,
                                        total_step_circuits,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        axes.into_iter()
    }
}

fn optional_axis(values: &[usize]) -> Vec<Option<usize>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.iter().copied().map(Some).collect()
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
            total_instances: Vec::new(),
            total_step_circuits: Vec::new(),
            seed: 42,
        };
        let axes: Vec<_> = m.iter_cartesian().collect();
        assert_eq!(axes.len(), 2 * 1 * 2 * 1 * 1);
        assert_eq!(axes[0].log_n, 10);
        assert_eq!(axes[0].batch, 1);
        assert_eq!(axes[0].total_instances, None);
        assert_eq!(axes[1].log_n, 10);
        assert_eq!(axes[1].batch, 8);
    }

    #[test]
    fn optional_work_axes_are_crossed_when_present() {
        let m = AxesMatrix {
            log_n: vec![10],
            arity: vec![2],
            batch: vec![1],
            ivc_steps: vec![4],
            step_muls: vec![100],
            total_instances: vec![16, 32],
            total_step_circuits: vec![8],
            seed: 42,
        };
        let axes: Vec<_> = m.iter_cartesian().collect();
        assert_eq!(axes.len(), 2);
        assert_eq!(axes[0].total_instances, Some(16));
        assert_eq!(axes[0].total_step_circuits, Some(8));
        assert_eq!(axes[1].total_instances, Some(32));
    }
}
