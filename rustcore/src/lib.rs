use pyo3::prelude::*;
use pyo3::types::PyList;

#[pyfunction]
fn detect_exploit(py: Python<'_>, features: &PyList) -> PyResult<bool> {
    let score: f64 = features
        .iter()
        .filter_map(|item| item.extract::<f64>().ok())
        .sum();

    Ok(score > 10.0)  // mock logic
}

#[pymodule]
fn rustcore(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect_exploit, m)?)?;
    Ok(())
}
