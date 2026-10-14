// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! FTRL (Follow-The-Regularized-Leader) classifier — hashed feature
//! space, logistic loss, model artifact serialize/deserialize for the
//! Storage-backed hot-swap flow (bus event `email8:spam:model:updated`).
//! Per-recipient personalization: the caller trains with (features,
//! label) pairs and can blend a global model with per-recipient bias.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Feature-hashing space size (2^18 — legacy parity).
const DIM: usize = 1 << 18;

/// A hashed feature: `namespace:value` (e.g. `subject:viagra`).
#[derive(Debug, Clone)]
pub struct Features {
    pub pairs: Vec<(String, String)>,
}

impl Features {
    pub fn add(&mut self, ns: &str, v: &str) {
        self.pairs.push((ns.to_string(), v.to_string()));
    }

    fn hashes(&self) -> Vec<(usize, f64)> {
        self.pairs
            .iter()
            .map(|(ns, v)| {
                let mut h = Sha256::new();
                h.update(ns.as_bytes());
                h.update(b"\x1f");
                h.update(v.as_bytes());
                let d = h.finalize();
                let idx = u64::from_be_bytes(d[..8].try_into().unwrap()) as usize % DIM;
                (idx, 1.0)
            })
            .collect()
    }
}

/// The trained model (weights + FTRL z-accumulators + training norms +
/// counters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtrlModel {
    pub weights: Vec<f32>,
    /// FTRL-Proximal z-accumulators (z_i ← z_i + g − σ·w) — the
    /// algorithm's primary state; without them each step would forget
    /// the accumulated gradient history and the L1-zeroed coordinates
    /// could never recover.
    #[serde(default)]
    pub zs: Vec<f32>,
    /// Per-coordinate accumulated gradient squares (training state;
    /// serialized so worker restarts resume exactly).
    #[serde(default)]
    pub norms: Vec<f32>,
    pub alpha: f32,
    pub beta: f32,
    pub l1: f32,
    pub l2: f32,
    pub trained_samples: u64,
}

impl Default for FtrlModel {
    fn default() -> Self {
        Self::new(0.1, 1.0, 0.1, 1.0)
    }
}

impl FtrlModel {
    pub fn new(alpha: f32, beta: f32, l1: f32, l2: f32) -> Self {
        Self {
            weights: vec![0.0; DIM],
            zs: vec![0.0; DIM],
            norms: vec![0.0; DIM],
            alpha,
            beta,
            l1,
            l2,
            trained_samples: 0,
        }
    }

    fn predict_raw(&self, features: &[(usize, f64)]) -> f64 {
        let mut z = 0.0f64;
        for (idx, v) in features {
            z += self.weights[*idx] as f64 * v;
        }
        1.0 / (1.0 + (-z).exp())
    }

    /// Probability the message is spam (0.0-1.0).
    pub fn predict(&self, features: &Features) -> f64 {
        self.predict_raw(&features.hashes())
    }

    /// One FTRL-Proximal step (McMahan et al. 2011, simplified single-λ).
    /// `label` = true for spam.
    pub fn train(&mut self, features: &Features, label: bool) -> TrainOutcome {
        let hashes = features.hashes();
        let p = self.predict_raw(&hashes);
        let y = if label { 1.0 } else { 0.0 };
        let grad = p - y; // d(logloss)/dz
        for (idx, v) in &hashes {
            let w = self.weights[*idx] as f64;
            // Proximal update with combined L1/L2:
            // g = grad*v; σ = (sqrt(n + g²) − sqrt(n)) / α; n += g²
            let g = grad * *v;
            let n_old = self.norms[*idx] as f64;
            let n_new = n_old + g * g;
            self.norms[*idx] = n_new as f32;
            let sigma = (n_new.sqrt() - n_old.sqrt()) / self.alpha as f64;
            // z_i is a PERSISTED accumulator (z ← z + g − σ·w), not
            // derived from w: L1-zeroed coordinates keep their history.
            let z = self.zs[*idx] as f64 + g - sigma * w;
            self.zs[*idx] = z as f32;
            // Sparse-aware solve: w = (sgn(z)·λ1 − z) / (β + λ2 + √n/α).
            // Note the NEGATED z: g = p−y is negative for positive
            // examples, so −z points the weight toward the label.
            let w_new = if z.abs() <= self.l1 as f64 {
                0.0
            } else {
                (z.signum() * self.l1 as f64 - z)
                    / ((self.beta as f64) + self.l2 as f64 + (n_new.sqrt() / self.alpha as f64))
            };
            self.weights[*idx] = w_new as f32;
        }
        self.trained_samples += 1;
        TrainOutcome {
            loss: -(y * p.ln() + (1.0 - y) * (1.0 - p).ln()),
            prediction: p,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TrainOutcome {
    pub loss: f64,
    pub prediction: f64,
}

/// Classify features → spam percentage (0-100), None when the model is
/// cold (`trained_samples < 50` — legacy warm-up guard).
pub fn classify(model: &FtrlModel, features: &Features) -> Option<u8> {
    if model.trained_samples < 50 {
        return None;
    }
    let p = model.predict(features);
    Some((p * 100.0).round().clamp(0.0, 100.0) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn train_kit(model: &mut FtrlModel, label: bool, kw: &[&str]) {
        let mut f = Features { pairs: Vec::new() };
        for k in kw {
            f.add("subject", k);
        }
        model.train(&f, label);
    }

    #[test]
    fn learns_simple_signal() {
        let mut m = FtrlModel::new(0.5, 1.0, 0.001, 1.0);
        for _ in 0..120 {
            train_kit(&mut m, true, &["viagra", "casino"]);
            train_kit(&mut m, false, &["quarterly", "report"]);
        }
        let mut spam = Features { pairs: Vec::new() };
        spam.add("subject", "viagra");
        let mut ham = Features { pairs: Vec::new() };
        ham.add("subject", "report");
        let s = m.predict(&spam);
        let h = m.predict(&ham);
        assert!(s > h, "spam pred {s} should exceed ham {h}");
        let pct = classify(&m, &spam).unwrap();
        assert!(pct > 60, "expected high spam pct, got {pct}");
    }

    #[test]
    fn cold_model_returns_none() {
        let m = FtrlModel::default();
        let mut f = Features { pairs: Vec::new() };
        f.add("x", "y");
        assert!(classify(&m, &f).is_none());
    }

    #[test]
    fn model_serializes() {
        let m = FtrlModel::default();
        let json = serde_json::to_vec(&m).unwrap();
        let back: FtrlModel = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.trained_samples, 0);
    }
}
