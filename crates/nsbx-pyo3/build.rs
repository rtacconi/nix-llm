fn main() {
    // Adds `-undefined dynamic_lookup` on macOS for the extension module.
    pyo3_build_config::add_extension_module_link_args();
}
