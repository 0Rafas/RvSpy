#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod core;
mod gui;
mod python;

fn main() -> eframe::Result<()> {
    // Initialize the C++ Native Engine for Nuitka analysis
    crate::python::nuitka_mod::NuitkaAnalyzer::init();

    // Set up the native GUI options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    // Start the application
    eframe::run_native(
        "RvSpy",
        options,
        Box::new(|cc| {
            let mut app = gui::RvSpyApp::default();
            // Restore from storage if available
            if let Some(storage) = cc.storage {
                if let Some(saved) = eframe::get_value(storage, eframe::APP_KEY) {
                    app = saved;
                }
            }
            Box::new(app)
        }),
    )
}
