//! Minimal self-contained DFT helpers used by the synthetic-input
//! detector and generator. Window lengths used in this codebase are
//! small (128-256 samples), so a direct O(n^2) DFT is fast enough and
//! avoids pulling in an FFT crate for a demo-scale risk engine. If this
//! becomes a hot path in a real deployment, swap in `rustfft`.

use std::f64::consts::PI;

/// Real-input DFT returning (frequencies as fraction of sample rate,
/// power spectrum) for bins 0..=n/2, matching numpy's `rfftfreq`/`rfft`
/// semantics used in the validated Python prototype.
pub fn real_power_spectrum(x: &[f64]) -> (Vec<f64>, Vec<f64>) {
    let n = x.len();
    let n_bins = n / 2 + 1;
    let mut freqs = Vec::with_capacity(n_bins);
    let mut power = Vec::with_capacity(n_bins);

    for k in 0..n_bins {
        let mut re = 0.0;
        let mut im = 0.0;
        for (t, &xt) in x.iter().enumerate() {
            let angle = -2.0 * PI * (k as f64) * (t as f64) / (n as f64);
            re += xt * angle.cos();
            im += xt * angle.sin();
        }
        freqs.push(k as f64 / n as f64);
        power.push(re * re + im * im);
    }
    (freqs, power)
}

/// Full complex DFT (forward, naive O(n^2)) used internally for pink
/// noise shaping.
fn dft(re_in: &[f64], im_in: &[f64]) -> (Vec<f64>, Vec<f64>) {
    let n = re_in.len();
    let mut re_out = vec![0.0; n];
    let mut im_out = vec![0.0; n];
    for k in 0..n {
        let mut sr = 0.0;
        let mut si = 0.0;
        for t in 0..n {
            let angle = -2.0 * PI * (k as f64) * (t as f64) / (n as f64);
            let (c, s) = (angle.cos(), angle.sin());
            sr += re_in[t] * c - im_in[t] * s;
            si += re_in[t] * s + im_in[t] * c;
        }
        re_out[k] = sr;
        im_out[k] = si;
    }
    (re_out, im_out)
}

fn idft(re_in: &[f64], im_in: &[f64]) -> Vec<f64> {
    let n = re_in.len();
    let mut out = vec![0.0; n];
    for t in 0..n {
        let mut sr = 0.0;
        for k in 0..n {
            let angle = 2.0 * PI * (k as f64) * (t as f64) / (n as f64);
            let (c, s) = (angle.cos(), angle.sin());
            sr += re_in[k] * c - im_in[k] * s;
        }
        out[t] = sr / n as f64;
    }
    out
}

/// Approximate 1/f ("pink") noise via spectral shaping of white noise,
/// matching the approach in the validated Python prototype
/// (`_pink_noise` in `research/synthetic_input_detection/synthetic_input_generator.py`):
/// shape the amplitude spectrum of white noise by 1/sqrt(f), inverse
/// transform, and standardize to zero mean / unit variance.
pub fn pink_noise(white: &[f64]) -> Vec<f64> {
    let n = white.len();
    let im_in = vec![0.0; n];
    let (re_f, im_f) = dft(white, &im_in);

    let mut re_shaped = vec![0.0; n];
    let mut im_shaped = vec![0.0; n];
    for k in 0..n {
        // Match numpy rfftfreq behavior: avoid div-by-zero at DC by
        // reusing the first nonzero frequency's scale for k=0, and mirror
        // frequency magnitude for the upper half (standard DFT symmetry).
        let freq_index = if k <= n / 2 { k } else { n - k };
        let f = if freq_index == 0 { 1.0 } else { freq_index as f64 / n as f64 };
        let scale = 1.0 / f.sqrt();
        re_shaped[k] = re_f[k] * scale;
        im_shaped[k] = im_f[k] * scale;
    }

    let mut pink = idft(&re_shaped, &im_shaped);
    let mean = pink.iter().sum::<f64>() / n as f64;
    let var = pink.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    let std = var.sqrt().max(1e-12);
    for v in pink.iter_mut() {
        *v = (*v - mean) / std;
    }
    pink
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_spectrum_of_constant_signal_is_flat_dc_only() {
        let x = vec![1.0; 64];
        let (freqs, power) = real_power_spectrum(&x);
        assert_eq!(freqs.len(), 33);
        // All power should be at DC (k=0) for a constant signal.
        assert!(power[0] > 0.0);
        for &p in &power[1..] {
            assert!(p < 1e-6, "expected ~0 power off DC, got {p}");
        }
    }

    #[test]
    fn pink_noise_is_standardized() {
        let white: Vec<f64> = (0..128).map(|i| ((i * 2654435761u32 as usize) % 1000) as f64 / 1000.0 - 0.5).collect();
        let pink = pink_noise(&white);
        let mean = pink.iter().sum::<f64>() / pink.len() as f64;
        let var = pink.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / pink.len() as f64;
        assert!(mean.abs() < 1e-6);
        assert!((var - 1.0).abs() < 1e-6);
    }
}
