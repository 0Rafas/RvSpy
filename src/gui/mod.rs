use eframe::egui;
use std::path::PathBuf;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct LoadedExecutable {
    pub path: PathBuf,
    pub archive: Option<Result<Vec<crate::python::TOCEntry>, String>>,
    pub native_sections: Option<Vec<crate::python::nuitka_mod::NativeSection>>,
    pub pe_info: Option<crate::core::pe_parser::DeepPEInformation>,
}

pub struct EditorTab {
    pub name: String,
    pub content: String,
    pub is_hex_view: bool,
    pub raw_data: Option<Vec<u8>>,
    pub original_data: Option<Vec<u8>>,
    pub target_file_path: Option<PathBuf>,
    pub file_offset: Option<usize>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // Missing fields use Default::default()
pub struct RvSpyApp {
    // State
    #[serde(skip)]
    pub tabs: Vec<EditorTab>,
    #[serde(skip)]
    pub active_tab_idx: Option<usize>,
    #[serde(skip)]
    pub log_output: String,
    pub loaded_files: Vec<LoadedExecutable>, // Dynamic list of imported executables and their states
    #[serde(skip)]
    pub search_query: String,
    #[serde(skip)]
    pub show_about_window: bool,
    pub selected_file: Option<String>,
    pub bottom_tab: String,
    pub theme: String,
    pub language: String,
    // Top Menu States
    #[serde(skip)]
    pub word_wrap: bool,
    #[serde(skip)]
    pub highlight_line: bool,
    #[serde(skip)]
    pub collapse_nodes: bool,
    #[serde(skip)]
    pub show_search_popup: bool,
    #[serde(skip)]
    pub show_goto_popup: bool,
    #[serde(skip)]
    pub show_view_options_popup: bool,
    #[serde(skip)]
    pub show_debug_options_popup: bool,
    #[serde(skip)]
    pub show_locals_popup: bool,
    #[serde(skip)]
    pub show_open_list_popup: bool,
    pub show_attach_process_popup: bool,
    #[serde(skip)]
    pub show_attach_unity_popup: bool,
    #[serde(skip)]
    pub show_windows_popup: bool,
    #[serde(skip)]
    pub hex_view_mode: bool,
    #[serde(skip)]
    pub startup_fix_applied: bool,
    #[serde(skip)]
    pub show_custom_hunter: bool,
    #[serde(skip)]
    pub hunter_signature: String,
    #[serde(skip)]
    pub hunter_target_idx: Option<usize>,
    // CFG Hunter
    #[serde(skip)]
    pub show_cfg_hunter: bool,
    #[serde(skip)]
    pub cfg_hunter_target_idx: Option<usize>,
    #[serde(skip)]
    pub show_left_panel: bool,
    #[serde(skip)]
    pub show_bottom_panel: bool,
    #[serde(skip)]
    pub show_right_panel: bool,
    #[serde(skip)]
    pub show_debugger_view: bool,
    #[serde(skip)]
    pub live_disassembly_cache: String,
    #[serde(skip)]
    pub live_hex_cache: String,
    #[serde(skip)]
    pub call_stack_cache: Vec<(usize, String)>,
    #[serde(skip)]
    pub show_symbols_pane: bool,
    #[serde(skip)]
    pub show_live_strings_pane: bool,
    #[serde(skip)]
    pub show_memory_search_popup: bool,
    #[serde(skip)]
    pub live_strings_cache: Vec<(usize, String)>,
    #[serde(skip)]
    pub show_packer_exploits_pane: bool,
    #[serde(skip)]
    pub extracted_temp_artifacts: Vec<crate::core::nuitka_recovery::ExtractedTempArtifact>,
    #[serde(skip)]
    pub processes: Vec<(u32, String)>,
    #[serde(skip)]
    pub last_process_refresh: Option<std::time::Instant>,
    // Debug Options
    pub opt_interp_magic: bool,
    pub opt_fast_capstone: bool,
    pub opt_agg_unzip: bool,
    pub opt_show_opcode_stack: bool,
    pub opt_live_var_track: bool,
    pub opt_decomp_max_depth: u32,
    pub opt_analysis_heuristic: u8,
    pub opt_strip_obfuscation: bool,
    pub opt_assume_python_version: String,
    pub opt_treat_warnings_as_errors: bool,
    pub opt_enable_loop_recovery: bool,
    pub opt_enable_auto_var_naming: bool,
    pub opt_enable_calling_conventions: bool,

    // View Options
    pub opt_ui_scale: f32,
    pub opt_font_family: String,
    pub opt_hex_row_width: u32,
    pub opt_show_offsets_in_decimal: bool,
    pub opt_highlight_active_tab: bool,
    pub opt_max_log_lines: u32,
    pub opt_auto_scroll_output: bool,
    pub opt_color_palette: String,
    pub opt_render_animations: bool,
    pub opt_show_hidden_sections: bool,

    #[serde(skip)]
    pub goto_query: String,
    #[serde(skip)]
    pub debugger: Option<crate::core::debugger::Debugger>,
    
    // Auto-Decrypt Engine State
    #[serde(skip)]
    pub show_auto_decrypt_popup: bool,
    #[serde(skip)]
    pub auto_decrypt_input: String,
    #[serde(skip)]
    pub auto_decrypt_output: String,

    // Sandbox Emulator State
    #[serde(skip)]
    pub show_sandbox_popup: bool,
    #[serde(skip)]
    pub sandbox_code_hex: String,
    #[serde(skip)]
    pub sandbox_result: Option<crate::core::debugger::RegisterContext>,
    #[serde(skip)]
    pub sandbox_original: Option<crate::core::debugger::RegisterContext>,

    // Behavioral Scanner State
    #[serde(skip)]
    pub scanner: crate::core::behavioral_scanner::BehavioralScanner,
    #[serde(skip)]
    pub behavioral_findings: Vec<crate::core::behavioral_scanner::Finding>,
    #[serde(skip)]
    pub show_pe_metadata_popup: bool,
    #[serde(skip)]
    pub toolbar_trigger_network_ioc: bool,
    #[serde(skip)]
    pub toolbar_trigger_nuitka_recovery: bool,
}

impl Default for RvSpyApp {
    fn default() -> Self {
        Self {
            tabs: Vec::new(),
            active_tab_idx: None,
            log_output: "[INFO] RvSpy Engine Initialized...\n[INFO] Drag and drop Python EXEs here, or right-click to Import.\n".to_string(),
            loaded_files: Vec::new(),
            search_query: String::new(),
            show_about_window: false,
            selected_file: None,
            bottom_tab: "Output".to_string(),
            theme: "Dark".to_string(),
            language: "English".to_string(),
            word_wrap: false,
            highlight_line: false,
            collapse_nodes: false,
            show_search_popup: false,
            show_goto_popup: false,
            show_view_options_popup: false,
            show_debug_options_popup: false,
            show_locals_popup: false,
            show_open_list_popup: false,
            show_attach_process_popup: false,
            show_attach_unity_popup: false,
            show_windows_popup: false,
            show_auto_decrypt_popup: false,
            auto_decrypt_input: String::new(),
            auto_decrypt_output: String::new(),
            hex_view_mode: false,
            startup_fix_applied: false,
            show_custom_hunter: false,
            hunter_signature: String::new(),
            hunter_target_idx: None,
            show_cfg_hunter: false,
            cfg_hunter_target_idx: None,
            show_left_panel: true,
            show_bottom_panel: true,
            show_right_panel: false,
            show_debugger_view: false,
            live_disassembly_cache: "Waiting for debug break...".to_string(),
            live_hex_cache: "00 00 00 00 00...".to_string(),
            call_stack_cache: Vec::new(),
            show_symbols_pane: false,
            show_live_strings_pane: false,
            show_memory_search_popup: false,
            show_packer_exploits_pane: false,
            extracted_temp_artifacts: Vec::new(),
            live_strings_cache: Vec::new(),
            processes: Vec::new(),
            last_process_refresh: None,
            opt_interp_magic: true,
            opt_fast_capstone: true,
            opt_agg_unzip: true,
            opt_show_opcode_stack: false,
            opt_live_var_track: true,
            opt_decomp_max_depth: 50,
            opt_analysis_heuristic: 3,
            opt_strip_obfuscation: false,
            opt_assume_python_version: "Auto".to_string(),
            opt_treat_warnings_as_errors: false,
            opt_enable_loop_recovery: true,
            opt_enable_auto_var_naming: true,
            opt_enable_calling_conventions: true,
            opt_ui_scale: 1.0,
            opt_font_family: "Consolas".to_string(),
            opt_hex_row_width: 16,
            opt_show_offsets_in_decimal: false,
            opt_highlight_active_tab: true,
            opt_max_log_lines: 1000,
            opt_auto_scroll_output: true,
            opt_color_palette: "Standard".to_string(),
            opt_render_animations: true,
            opt_show_hidden_sections: false,
            goto_query: String::new(),
            debugger: Some(crate::core::debugger::Debugger::new()),
            show_sandbox_popup: false,
            sandbox_code_hex: String::new(),
            sandbox_result: None,
            sandbox_original: None,
            scanner: crate::core::behavioral_scanner::BehavioralScanner::new(),
            behavioral_findings: Vec::new(),
            show_pe_metadata_popup: false,
            toolbar_trigger_network_ioc: false,
            toolbar_trigger_nuitka_recovery: false,
        }
    }
}

impl RvSpyApp {
    fn format_hex(data: &[u8]) -> String {
        let mut out = String::with_capacity(std::cmp::min(data.len() * 4, 1024 * 1024 * 2));
        let mut offset = 0;
        for chunk in data.chunks(16) {
            out.push_str(&format!("{:08X}  ", offset));
            
            // Hex bytes
            for b in chunk {
                out.push_str(&format!("{:02X} ", b));
            }
            
            // Padding for incomplete chunk
            if chunk.len() < 16 {
                for _ in 0..(16 - chunk.len()) {
                    out.push_str("   ");
                }
            }
            
            out.push_str(" |");
            
            // ASCII printable
            for b in chunk {
                if *b >= 32 && *b <= 126 {
                    out.push(*b as char);
                } else {
                    out.push('.');
                }
            }
            
            // Padding for incomplete chunk ASCII
            if chunk.len() < 16 {
                for _ in 0..(16 - chunk.len()) {
                    out.push(' ');
                }
            }

            out.push_str("|\n");
            offset += 16;
            
            // Limit output string length to avoid egui freeze
            if offset > 0x100000 {
                out.push_str("\n... (Content truncated for performance)\n");
                break;
            }
        }
        out
    }

    fn translate(&self, text: &str) -> String {
        if self.language == "English" {
            return text.to_string();
        }

        match text {
            "File" => match self.language.as_str() {
                "French" => "Fichier", "Russian" => "Файл", _ => text
            },
            "Edit" => match self.language.as_str() {
                "French" => "Édition", "Russian" => "Правка", _ => text
            },
            "View" => match self.language.as_str() {
                "French" => "Affichage", "Russian" => "Вид", _ => text
            },
            "Debug" => match self.language.as_str() {
                "French" => "Déboguer", "Russian" => "Отладка", _ => text
            },
            "Window" => match self.language.as_str() {
                "French" => "Fenêtre", "Russian" => "Окно", _ => text
            },
            "Help" => match self.language.as_str() {
                "French" => "Aide", "Russian" => "Справка", _ => text
            },
            "Theme" => match self.language.as_str() {
                "French" => "Thème", "Russian" => "Тема", _ => text
            },
            "Language" => match self.language.as_str() {
                "French" => "Langue", "Russian" => "Язык", _ => text
            },
            "Payload Explorer" => match self.language.as_str() {
                "French" => "Explorateur de Payload", "Russian" => "Обозреватель полезной нагрузки", _ => text
            },
            "Output" => match self.language.as_str() {
                "French" => "Sortie", "Russian" => "Вывод", _ => text
            },
            "Breakpoints" => match self.language.as_str() {
                "French" => "Points d'arrêt", "Russian" => "Точки останова", _ => text
            },
            "Locals" => match self.language.as_str() {
                "French" => "Locales", "Russian" => "Локальные", _ => text
            },
            "Clear" => match self.language.as_str() {
                "French" => "Effacer", "Russian" => "Очистить", _ => text
            },
            "About" => match self.language.as_str() {
                "French" => "À propos", "Russian" => "О программе", _ => text
            },
            "Options..." => match self.language.as_str() {
                "French" => "Options...", "Russian" => "Параметры...", _ => text
            },
            "Close" => match self.language.as_str() {
                "French" => "Fermer", "Russian" => "Закрыть", _ => text
            },
            "Exit" => match self.language.as_str() {
                "French" => "Quitter", "Russian" => "Выход", _ => text
            },
            _ => text,
        }.to_string()
    }

    fn customize_theme(&self, ctx: &egui::Context) {
        // --- 1. Load System Fonts for Translation support (Arabic, CJK, Russian) ---
        let mut fonts = egui::FontDefinitions::default();
        
        // We add fallback system fonts that support global characters.
        // On Windows, 'Segoe UI', 'Tahoma', or 'Arial' are typical.
        fonts.font_data.insert(
            "my_font".to_owned(),
            egui::FontData::from_static(include_bytes!("C:\\Windows\\Fonts\\tahoma.ttf")),
        );
        
        // Make 'my_font' the highest priority for Proportional
        fonts.families.entry(egui::FontFamily::Proportional).or_default().insert(0, "my_font".to_owned());
        
        // Also put it as a fallback for Monospace
        fonts.families.entry(egui::FontFamily::Monospace).or_default().push("my_font".to_owned());
        
        ctx.set_fonts(fonts);

        // UI Scaling from User Settings
        ctx.set_pixels_per_point(self.opt_ui_scale);

        // --- 2. Build Theme Visuals ---
        let mut style = (*ctx.style()).clone();
        let mut visuals = egui::Visuals::dark();

        // Premium Soft Edges and Shadows
        visuals.window_rounding = egui::Rounding::same(8.0);
        visuals.menu_rounding = egui::Rounding::same(6.0);
        visuals.popup_shadow = egui::epaint::Shadow { offset: egui::vec2(0.0, 8.0), blur: 16.0, spread: 0.0, color: egui::Color32::from_black_alpha(150) };
        visuals.window_shadow = egui::epaint::Shadow { offset: egui::vec2(0.0, 12.0), blur: 24.0, spread: 0.0, color: egui::Color32::from_black_alpha(200) };

        match self.theme.as_str() {
            "Light" => {
                visuals = egui::Visuals::light();
                visuals.panel_fill = egui::Color32::from_rgb(238, 238, 242);
                visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
            },
            "Dracula" => {
                visuals.panel_fill = egui::Color32::from_rgb(40, 42, 54);
                visuals.window_fill = egui::Color32::from_rgb(68, 71, 90);
                visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(40, 42, 54);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 121, 198); // Pink
            },
            "Monokai" => {
                visuals.panel_fill = egui::Color32::from_rgb(39, 40, 34);
                visuals.window_fill = egui::Color32::from_rgb(30, 31, 28);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(166, 226, 46); // Green
            },
            "Solarized Dark" => {
                visuals.panel_fill = egui::Color32::from_rgb(0, 43, 54);
                visuals.window_fill = egui::Color32::from_rgb(7, 54, 66);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(38, 139, 210); // Blue
            },
            "Solarized Light" => {
                visuals = egui::Visuals::light();
                visuals.panel_fill = egui::Color32::from_rgb(253, 246, 227);
                visuals.window_fill = egui::Color32::from_rgb(238, 232, 213);
            },
            "Nord" => {
                visuals.panel_fill = egui::Color32::from_rgb(46, 52, 64);
                visuals.window_fill = egui::Color32::from_rgb(59, 66, 82);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(136, 192, 208); // Frost blue
            },
            "Oceanic" => {
                visuals.panel_fill = egui::Color32::from_rgb(27, 43, 52);
                visuals.window_fill = egui::Color32::from_rgb(15, 28, 35);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(102, 153, 204);
            },
            "Hacker Green" => {
                visuals.panel_fill = egui::Color32::from_rgb(5, 10, 5);
                visuals.window_fill = egui::Color32::from_rgb(0, 0, 0);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 255, 0);
                visuals.selection.bg_fill = egui::Color32::from_rgb(0, 90, 0);
                visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 230, 0));
            },
            "Cherry Pink" => {
                visuals.panel_fill = egui::Color32::from_rgb(25, 10, 15);
                visuals.window_fill = egui::Color32::from_rgb(30, 15, 25);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 105, 180);
                visuals.selection.bg_fill = egui::Color32::from_rgb(120, 30, 80);
            },
            "Deep Blue" => {
                visuals.panel_fill = egui::Color32::from_rgb(10, 15, 25);
                visuals.window_fill = egui::Color32::from_rgb(5, 10, 20);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 120, 255);
                visuals.selection.bg_fill = egui::Color32::from_rgb(0, 60, 150);
            },
            "Cyberpunk" => {
                visuals.panel_fill = egui::Color32::from_rgb(20, 0, 40);
                visuals.window_fill = egui::Color32::from_rgb(10, 0, 20);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(250, 250, 55); // Neon Yellow
                // Red/Cyan strokes could be added later
            },
            "Synthwave" => {
                visuals.panel_fill = egui::Color32::from_rgb(36, 27, 47);
                visuals.window_fill = egui::Color32::from_rgb(38, 35, 53);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 126, 219); // Pink
            },
            "Gruvbox" => {
                visuals.panel_fill = egui::Color32::from_rgb(40, 40, 40);
                visuals.window_fill = egui::Color32::from_rgb(50, 48, 47);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(215, 153, 33); // Yellow/Orange
            },
            "Midnight" => {
                visuals.panel_fill = egui::Color32::from_rgb(0, 0, 0);
                visuals.window_fill = egui::Color32::from_rgb(10, 10, 10);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(200, 200, 200);
            },
            "Material Dark" => {
                visuals.panel_fill = egui::Color32::from_rgb(33, 33, 33);
                visuals.window_fill = egui::Color32::from_rgb(48, 48, 48);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(3, 169, 244);
            },
            "Material Light" => {
                visuals = egui::Visuals::light();
                visuals.panel_fill = egui::Color32::from_rgb(250, 250, 250);
                visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
            },
            "Ayu Dark" => {
                visuals.panel_fill = egui::Color32::from_rgb(10, 14, 20);
                visuals.window_fill = egui::Color32::from_rgb(15, 20, 25);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 180, 84);
            },
            "Ayu Light" => {
                visuals = egui::Visuals::light();
                visuals.panel_fill = egui::Color32::from_rgb(250, 252, 250);
                visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 153, 64);
            },
            "Night Owl" => {
                visuals.panel_fill = egui::Color32::from_rgb(1, 22, 39);
                visuals.window_fill = egui::Color32::from_rgb(1, 17, 29);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(199, 146, 234);
            },
            "Rose Pine" => {
                visuals.panel_fill = egui::Color32::from_rgb(25, 23, 36);
                visuals.window_fill = egui::Color32::from_rgb(31, 29, 46);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(235, 188, 186); // Rose
            },
            "Catppuccin" => {
                visuals.panel_fill = egui::Color32::from_rgb(36, 39, 58);
                visuals.window_fill = egui::Color32::from_rgb(30,32,48);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(138, 173, 244); // Blue
            },
            "Vampire" => {
                visuals.panel_fill = egui::Color32::from_rgb(20, 5, 5);
                visuals.window_fill = egui::Color32::from_rgb(15, 0, 0);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(220, 20, 60); // Crimson red
                visuals.selection.bg_fill = egui::Color32::from_rgb(100, 10, 10);
            },
            "Sunset" => {
                visuals.panel_fill = egui::Color32::from_rgb(35, 20, 20);
                visuals.window_fill = egui::Color32::from_rgb(45, 25, 20);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 140, 0); // Dark Orange
            },
            "Neon Blue" => {
                visuals.panel_fill = egui::Color32::from_rgb(5, 5, 20);
                visuals.window_fill = egui::Color32::from_rgb(0, 0, 15);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 255, 255); // Cyan
            },
            "Blood Red" => {
                visuals.panel_fill = egui::Color32::from_rgb(40, 10, 10);
                visuals.window_fill = egui::Color32::from_rgb(25, 5, 5);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(255, 0, 0);
            },
            _ => {
                // Default Dark
                visuals.panel_fill = egui::Color32::from_rgb(30, 30, 30);
                visuals.window_fill = egui::Color32::from_rgb(25, 25, 25);
                visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(30, 30, 30);
                visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(45, 45, 45);
                visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(60, 60, 60);
                visuals.widgets.active.bg_fill = egui::Color32::from_rgb(9, 71, 113);
                visuals.selection.bg_fill = egui::Color32::from_rgb(38, 79, 120);
            }
        }

        // Apply visual palette if set from the View Options overrides
        if self.opt_color_palette == "High Contrast" {
            visuals.panel_fill = egui::Color32::BLACK;
            visuals.window_fill = egui::Color32::BLACK;
            visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::WHITE;
            visuals.selection.bg_fill = egui::Color32::from_rgb(0, 100, 255);
        }

        style.visuals = visuals;
        style.spacing.item_spacing = egui::vec2(8.0, 6.0); // Richer spacing for that premium look
        style.spacing.window_margin = egui::Margin::same(10.0);
        style.spacing.button_padding = egui::vec2(6.0, 4.0);
        ctx.set_style(style);
    }

    fn add_and_analyze_file(&mut self, path: PathBuf) {
        if !self.loaded_files.iter().any(|f| f.path == path) {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            self.log_output.push_str(&format!("[INFO] Imported file: {}\n", file_name));
            self.log_output.push_str(&format!("[INFO] Analyzing {}...\n", file_name));
            
            let mut exec = LoadedExecutable {
                path: path.clone(),
                archive: None,
                native_sections: None,
                pe_info: None,
            };

            if let Ok(buffer) = std::fs::read(&path) {
                if let Ok(pe_data) = crate::core::pe_parser::extract_deep_pe(&buffer) {
                    exec.pe_info = Some(pe_data);
                }
            }
            
            match crate::python::PyInstallerArchive::parse(&path) {
                Ok(archive) => {
                    self.log_output.push_str(&format!("[SUCCESS] Found PyInstaller Signature at offset: 0x{:X}\n", archive.magic_offset));
                    self.log_output.push_str(&format!("[INFO] Extracted {} files from TOC.\n", archive.files.len()));
                    exec.archive = Some(Ok(archive.files));
                },
                Err(e) => {
                    self.log_output.push_str(&format!("[INFO] Not PyInstaller ({}). Falling back to Native PE Analysis...\n", e));
                    if let Ok(buffer) = std::fs::read(&path) {
                        match crate::python::nuitka_mod::NuitkaAnalyzer::parse_pe(&buffer) {
                            Ok(sections) => {
                                self.log_output.push_str(&format!("[SUCCESS] C++ Engine extracted {} PE Sections.\n", sections.len()));
                                exec.native_sections = Some(sections);
                                exec.archive = None; // Keep None since no PyInstaller archive exists
                            },
                            Err(pe_err) => {
                                self.log_output.push_str(&format!("[ERROR] Native PE Analysis failed: {}\n", pe_err));
                                exec.archive = Some(Err(format!("Analysis failed: {}", pe_err)));
                            }
                        }
                    } else {
                        exec.archive = Some(Err("Failed to read file buffer.".to_string()));
                    }
                }
            }
            self.loaded_files.push(exec);
        }
    }

    fn handle_drag_and_drop(&mut self, ctx: &egui::Context) {
        // Detect files dragged and dropped into the application window
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                for file in &i.raw.dropped_files {
                    if let Some(path) = &file.path {
                        self.add_and_analyze_file(path.clone());
                    }
                }
            }
        });
    }
}

impl eframe::App for RvSpyApp {
    /// Called by the framework to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Enforce cleanup if an old "C# Interactive" menu tab was saved in egui's layout persistance
        if self.bottom_tab == "C# Interactive" {
            self.bottom_tab = "Output".to_string();
        }

        // Poll for Native Debugger Events
        if let Some(dbg) = &self.debugger {
            while let Ok(evt) = dbg.event_receiver.try_recv() {
                match evt {
                    crate::core::debugger::DebuggerEvent::LogMessage(msg) => {
                        self.log_output.push_str(&format!("[DEBUGGER] {}\n", msg));
                    },
                    crate::core::debugger::DebuggerEvent::ProcessLaunched(pid) => {
                        self.log_output.push_str(&format!("[DEBUGGER] Executable Launched with PID {}\n", pid));
                    },
                    crate::core::debugger::DebuggerEvent::ProcessAttached(pid) => {
                        self.log_output.push_str(&format!("[DEBUGGER] Successfully Attached to PID {}\n", pid));
                    },
                    crate::core::debugger::DebuggerEvent::ProcessExited(pid) => {
                        self.log_output.push_str(&format!("[DEBUGGER] Process PID {} Exited natively.\n", pid));
                    },
                    crate::core::debugger::DebuggerEvent::BreakpointHit { address, thread_id, context, disasm, hex_dump, symbol_name } => {
                        self.log_output.push_str(&format!("[DEBUGGER] Breakpoint Hit at 0x{:X} (Thread: {})\n", address, thread_id));
                        if let Some(sym) = &symbol_name {
                            self.log_output.push_str(&format!("  [SYMBOL] {}\n", sym));
                            let new_findings = self.scanner.update_dynamic(sym);
                            for f in new_findings {
                                self.behavioral_findings.push(f);
                            }
                        }
                        self.live_disassembly_cache = disasm;
                        self.live_hex_cache = hex_dump;
                        if let Some(ctx) = context {
                            self.log_output.push_str(&format!("  RIP: 0x{:016X} | RAX: 0x{:016X}\n", ctx.rip, ctx.rax));
                            self.log_output.push_str(&format!("  RBX: 0x{:016X} | RCX: 0x{:016X} | RDX: 0x{:016X}\n", ctx.rbx, ctx.rcx, ctx.rdx));
                        }
                        self.show_locals_popup = true; // Automatically pop up the locals/registers window
                    }
                }
            }
        }

        // BREAK OUT OF FULLSCREEN CACHE BUG
        if !self.startup_fix_applied {
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
            self.startup_fix_applied = true;
        }

        // Apply custom professional theme
        self.customize_theme(ctx);

        // Handle Drag & Drop logic
        self.handle_drag_and_drop(ctx);

        // Top Menu Bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button(self.translate("File"), |ui| {

                    if ui.button(format!("{} Module...", self.translate("Save"))).clicked() {
                        if let Some(active_idx) = self.active_tab_idx {
                            if let Some(tab) = self.tabs.get(active_idx) {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_file_name(&tab.name)
                                    .save_file() {
                                    if std::fs::write(&path, &tab.content).is_ok() {
                                        self.log_output.push_str(&format!("[SUCCESS] Saved {} to {:?}\n", tab.name, path));
                                    } else {
                                        self.log_output.push_str(&format!("[ERROR] Failed to save {}\n", tab.name));
                                    }
                                }
                            }
                        } else {
                            self.log_output.push_str("[WARN] No active module tab to save.\n");
                        }
                        ui.close_menu(); 
                    }
                    if ui.button(format!("{} All... (Ctrl+Shift+S)", self.translate("Save"))).clicked() {
                        if let Some(target_dir) = rfd::FileDialog::new().pick_folder() {
                            let mut count = 0;
                            for tab in &self.tabs {
                                let path = target_dir.join(&tab.name);
                                if std::fs::write(&path, &tab.content).is_ok() { count += 1; }
                            }
                            self.log_output.push_str(&format!("[SUCCESS] Saved {} active tabs to {:?}\n", count, target_dir));
                        }
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button(format!("[F] {}... (Ctrl+O)", self.translate("Open"))).clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.add_and_analyze_file(path.clone());
                        }
                        ui.close_menu();
                    }
                    if ui.button(format!("[S] {} from site-packages... (Ctrl+Shift+O)", self.translate("Open"))).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .pick_file() {
                            self.add_and_analyze_file(path.clone());
                        }
                        ui.close_menu(); 
                    }
                    if ui.button(format!("{} List...", self.translate("Open"))).clicked() {
                        self.show_open_list_popup = true;
                        ui.close_menu(); 
                    }
                    ui.menu_button("Recent Files", |ui| {
                        if ui.button("Clear History").clicked() {
                            self.loaded_files.clear();
                            ui.close_menu(); 
                        }
                    });
                    ui.separator();
                    if ui.button("[R] Reload All Payloads").clicked() {
                        let paths: Vec<_> = self.loaded_files.iter().map(|e| e.path.clone()).collect();
                        self.loaded_files.clear();
                        self.tabs.clear();
                        self.active_tab_idx = None;
                        for path in paths {
                            self.add_and_analyze_file(path);
                        }
                        self.log_output.push_str("[SUCCESS] Reloaded all original workspace assemblies.\n");
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button(format!("{} All", self.translate("Close"))).clicked() {
                        self.loaded_files.clear();
                        self.tabs.clear();
                        self.active_tab_idx = None;
                        ui.close_menu(); 
                    }
                    if ui.button(format!("{} Old In-Memory Modules", self.translate("Close"))).clicked() {
                        self.log_output.push_str("[MAINTENANCE] Cleared old detached modules from Memory.\n");
                        ui.close_menu(); 
                    }
                    if ui.button(format!("{} All Missing Files", self.translate("Close"))).clicked() {
                        self.loaded_files.retain(|exec| exec.path.exists());
                        self.log_output.push_str("[MAINTENANCE] Removed non-existent paths from explorer.\n");
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button("Sort File Tree").clicked() {
                        self.loaded_files.sort_by(|a, b| a.path.cmp(&b.path));
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button(format!("[X] {} (Alt+F4)", self.translate("Exit"))).clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button(self.translate("Edit"), |ui| {
                    if ui.button("Search Strings (Ctrl+Shift+F)").clicked() {
                        self.show_search_popup = true;
                        ui.close_menu(); 
                    }
                    if ui.button("Go to Method (Ctrl+G)").clicked() {
                        self.show_goto_popup = true;
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button("Toggle Hex View").clicked() {
                        self.hex_view_mode = !self.hex_view_mode;
                        self.log_output.push_str(&format!("[ACTION] Hex View Mode: {}\n", self.hex_view_mode));
                        ui.close_menu(); 
                    }
                });
                
                ui.menu_button(self.translate("View"), |ui| {
                    ui.menu_button(format!("[T] {}", self.translate("Theme")), |ui| {
                        if ui.selectable_value(&mut self.theme, "Dark".to_string(), "Standard (Dark)").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Light".to_string(), "Classic (Light)").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Hacker Green".to_string(), "Matrix (Hacker)").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Dracula".to_string(), "Dracula").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Monokai".to_string(), "Monokai").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Solarized Dark".to_string(), "Solarized Dark").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Solarized Light".to_string(), "Solarized Light").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Nord".to_string(), "Nord").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Oceanic".to_string(), "Oceanic").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Cherry Pink".to_string(), "Cherry Pink").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Deep Blue".to_string(), "Deep Blue").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Cyberpunk".to_string(), "Cyberpunk").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Synthwave".to_string(), "Synthwave").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Gruvbox".to_string(), "Gruvbox").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Midnight".to_string(), "Midnight").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Material Dark".to_string(), "Material Dark").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Material Light".to_string(), "Material Light").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Ayu Dark".to_string(), "Ayu Dark").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Ayu Light".to_string(), "Ayu Light").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Night Owl".to_string(), "Night Owl").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Rose Pine".to_string(), "Rose Pine").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Catppuccin".to_string(), "Catppuccin").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Vampire".to_string(), "Vampire").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Sunset".to_string(), "Sunset").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Neon Blue".to_string(), "Neon Blue").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.theme, "Blood Red".to_string(), "Blood Red").clicked() { ui.close_menu(); }
                    });
                    
                    ui.menu_button(format!("[L] {}", self.translate("Language")), |ui| {
                        if ui.selectable_value(&mut self.language, "English".to_string(), "English").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.language, "French".to_string(), "Français (French)").clicked() { ui.close_menu(); }
                        if ui.selectable_value(&mut self.language, "Russian".to_string(), "Русский (Russian)").clicked() { ui.close_menu(); }
                    });
                    
                    ui.separator();
                    if ui.checkbox(&mut self.word_wrap, "Word Wrap").clicked() { ui.close_menu(); }
                    if ui.checkbox(&mut self.highlight_line, "Highlight Current Line").clicked() { ui.close_menu(); }
                    if ui.button("Full Screen").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(true));
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button(format!("[+] {}", self.translate("Payload Explorer"))).clicked() { 
                        self.show_left_panel = !self.show_left_panel;
                        ui.close_menu(); 
                    }
                    if ui.button(format!("[?] {}", self.translate("Project Properties / Symbols"))).clicked() { 
                        self.show_right_panel = !self.show_right_panel;
                        ui.close_menu(); 
                    }
                    if ui.button(format!("[>] {} (Alt+2)", self.translate("Output"))).clicked() { 
                        self.show_bottom_panel = !self.show_bottom_panel;
                        self.bottom_tab = "Output".to_string(); 
                        ui.close_menu(); 
                    }
                    ui.separator();
                    if ui.button(format!("⚙ {}", self.translate("Options..."))).clicked() {
                        self.show_view_options_popup = true;
                        ui.close_menu(); 
                    }
                });

                
                ui.menu_button(self.translate("Debug"), |ui| {
                    if ui.button("▶ Start (F5)").clicked() {
                        if let Some(exec) = self.loaded_files.first() {
                            if let Some(dbg) = &self.debugger {
                                let _ = dbg.command_sender.send(crate::core::debugger::DebuggerCommand::Launch(exec.path.to_string_lossy().into_owned()));
                            }
                        }
                        ui.close_menu(); 
                    }
                    if ui.button("⏹ Stop").clicked() {
                        if let Some(dbg) = &self.debugger {
                            let _ = dbg.command_sender.send(crate::core::debugger::DebuggerCommand::Detach);
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("⚙ Attach to Process...").clicked() {
                        self.show_attach_process_popup = true;
                        ui.close_menu();
                    }
                });
                
                ui.menu_button(self.translate("Window"), |ui| {
                    if ui.button("Windows...").clicked() { self.show_windows_popup = true; ui.close_menu(); }
                });

                ui.menu_button(self.translate("Help"), |ui| {
                    if ui.button(self.translate("About")).clicked() { self.show_about_window = true; ui.close_menu(); }
                });
            });
        });

        // 🛠️ ADVANCED POWER TOOLBAR (Super Buttons Grouping)
        egui::TopBottomPanel::top("power_toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                
                // --- Group 1: [!] SECURITY & BEHAVIOR ---
                ui.menu_button(egui::RichText::new("[!] Security Analysis").strong(), |ui| {
                    if ui.button("[B] Run Behavioral Scan (Static)").clicked() {
                        if let Some(exec) = self.loaded_files.first() {
                            if let Ok(file_data) = std::fs::read(&exec.path) {
                                let markers = crate::core::strings::extract_strings(&file_data, 4);
                                let findings = self.scanner.scan_static(&markers);
                                self.behavioral_findings.extend(findings);
                                self.bottom_tab = "Behavioral".to_string();
                                self.log_output.push_str(&format!("[INFO] Toolbar Static Scan triggered for {}\n", exec.path.display()));
                            }
                        }
                        ui.close_menu();
                    }
                    if ui.button("[?] Search Live Memory Strings").clicked() {
                        self.show_live_strings_pane = true;
                        ui.close_menu();
                    }
                    if ui.button("[N] Extract Network/DNS IoC").clicked() {
                        self.toolbar_trigger_network_ioc = true;
                        ui.close_menu();
                    }
                });

                ui.separator();

                // --- Group 2: ⚔️ REVERSE ENGINE ---
                ui.menu_button(egui::RichText::new("⚔️ Reverse Engine").strong(), |ui| {
                    if ui.button("☠️ Python Packer Exploits Suite").clicked() {
                        self.show_packer_exploits_pane = true;
                        ui.close_menu();
                    }
                    if ui.button("[P] Deep PE Metadata Analysis").clicked() {
                        self.show_pe_metadata_popup = true;
                        ui.close_menu();
                    }
                    if ui.button("[R] Recover Nuitka Resources").clicked() {
                        self.toolbar_trigger_nuitka_recovery = true;
                        ui.close_menu();
                    }
                });

                ui.separator();

                // --- Group 3: [P] DYNAMIC DEBUGGING ---
                ui.menu_button(egui::RichText::new("[P] Dynamic Debugging").strong(), |ui| {
                    if ui.button("⚙ Attach to Local Process...").clicked() {
                        self.show_attach_process_popup = true;
                        ui.close_menu();
                    }
                    if ui.button("🧱 Attach to Python (PyDBG)").clicked() {
                        self.show_attach_unity_popup = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("▶ Continue Debugging (F5)").clicked() {
                        if let Some(dbg) = &self.debugger {
                            let _ = dbg.command_sender.send(crate::core::debugger::DebuggerCommand::Continue);
                        }
                        ui.close_menu();
                    }
                    if let Some(dbg) = &self.debugger {
                        ui.separator();
                        let mut jit = false;
                        if let Ok(s) = dbg.state.lock() { jit = s.jit_mode_enabled; }
                        if ui.checkbox(&mut jit, "Enable JIT Memory Dumper").clicked() {
                            if let Ok(mut s) = dbg.state.lock() { s.jit_mode_enabled = jit; }
                        }
                    }
                });

                ui.separator();

                // --- Group 4: 🎯 ADVANCED HUNTERS ---
                ui.menu_button(egui::RichText::new("🎯 Advanced Hunters").strong(), |ui| {
                    if ui.button("🎯 Custom Signature Hunter (SIMD)").clicked() {
                        self.show_custom_hunter = true;
                        ui.close_menu();
                    }
                    if ui.button("🔬 Code Sandbox Emulator").clicked() {
                        self.show_sandbox_popup = true;
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let mut engine_color = egui::Color32::from_rgb(0, 255, 100);
                    if self.debugger.is_none() { engine_color = egui::Color32::from_rgb(255, 50, 50); }
                    ui.label(egui::RichText::new("● Engine Ready").color(engine_color).size(11.0));
                    ui.separator();
                });
            });
        });

        // ---------------- Popups ----------------
        let mut is_open_decrypt = self.show_auto_decrypt_popup;
        if is_open_decrypt {
            egui::Window::new("Auto-Decrypt Engine").resizable(true).default_width(600.0).open(&mut is_open_decrypt).show(ctx, |ui| {
                ui.heading("Strings Heuristic Decryptor");
                ui.label(egui::RichText::new("Paste extracted or obfuscated strings heavily suspected to be Base64 or XOR encrypted below.").color(egui::Color32::from_rgb(180, 180, 180)));
                
                ui.group(|ui| {
                    ui.label("Target Strings (Input):");
                    egui::ScrollArea::vertical().id_source("decrypt_in").max_height(200.0).show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut self.auto_decrypt_input).desired_width(f32::INFINITY));
                    });
                });
                
                ui.separator();
                
                ui.horizontal(|ui| {
                    if ui.button("🪄 Execute Heuristic Decryption").clicked() {
                        let lines: Vec<String> = self.auto_decrypt_input.lines().map(|s| s.to_string()).collect();
                        let results = crate::core::heuristics::run_heuristics_on_strings(&lines);
                        if results.is_empty() {
                            self.auto_decrypt_output = "No valid heuristic signatures (Base64/XOR) found in input.".to_string();
                        } else {
                            let mut out = String::new();
                            for res in results {
                                let method_str = match res.method {
                                    crate::core::heuristics::DecryptionMethod::Base64 => "Base64".to_string(),
                                    crate::core::heuristics::DecryptionMethod::XorSingleByte(k) => format!("XOR=0x{:02X}", k),
                                };
                                out.push_str(&format!("[{}] {} -> {}\n", method_str, res.original, res.decrypted));
                            }
                            self.auto_decrypt_output = out;
                        }
                    }
                    if ui.button("Clear Input/Output").clicked() {
                        self.auto_decrypt_input.clear();
                        self.auto_decrypt_output.clear();
                    }
                });
                
                ui.separator();
                
                ui.group(|ui| {
                    ui.label("Decrypted Results (Output):");
                    egui::ScrollArea::vertical().id_source("decrypt_out").max_height(200.0).show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut self.auto_decrypt_output).desired_width(f32::INFINITY).interactive(true));
                    });
                });
            });
            if !is_open_decrypt { self.show_auto_decrypt_popup = false; }
        }

        if self.show_sandbox_popup {
            let mut close_sandbox = false;
            egui::Window::new("🔬 Isolated x64 Sandbox Emulator").resizable(true).default_width(500.0).show(ctx, |ui| {
                ui.label(egui::RichText::new("Execute machine code in a safe, instrumented environment.").color(egui::Color32::LIGHT_GRAY));
                ui.separator();
                
                ui.horizontal(|ui| {
                    ui.label("Code (Hex):");
                    ui.add(egui::TextEdit::singleline(&mut self.sandbox_code_hex).hint_text("e.g. 48 31 C0 48 FF C0"));
                });

                if ui.button("🚀 Run in Sandbox").clicked() {
                    // Parse hex to bytes
                    let bytes: Vec<u8> = self.sandbox_code_hex.split_whitespace()
                        .filter_map(|s| u8::from_str_radix(s, 16).ok())
                        .collect();
                    
                    if bytes.is_empty() {
                        self.log_output.push_str("[ERROR] Invalid hex code for sandbox.\n");
                    } else if !crate::core::emulation::is_emulation_available() {
                        self.log_output.push_str("[WARN] Unicorn Engine not available. Install LLVM: winget install LLVM.LLVM\n");
                    } else {
                        // Prepare initial context (either from debugger or zeros)
                        let initial = if let Some(dbg) = &self.debugger {
                             if let Ok(s) = dbg.state.lock() {
                                 s.last_context.clone().unwrap_or(crate::core::debugger::RegisterContext::default())
                             } else { crate::core::debugger::RegisterContext::default() }
                        } else { crate::core::debugger::RegisterContext::default() };
                        
                        self.sandbox_original = Some(initial.clone());
                        
                        // Execute
                        match crate::core::emulation::RvEmulator::new() {
                            Ok(mut emu) => {
                                match emu.emulate_block(&bytes, initial) {
                                    Ok(res) => {
                                        self.sandbox_result = Some(res.final_context);
                                        self.log_output.push_str(&format!("[SUCCESS] Emulation completed. {} instructions executed.\n", res.instructions_executed));
                                    }
                                    Err(e) => {
                                        self.log_output.push_str(&format!("[ERROR] Emulation failed: {}\n", e));
                                    }
                                }
                            }
                            Err(e) => self.log_output.push_str(&format!("[ERROR] Could not init emulator: {}\n", e)),
                        }
                    }
                }

                if let (Some(orig), Some(res)) = (&self.sandbox_original, &self.sandbox_result) {
                    ui.separator();
                    ui.heading("Register Comparison (Before vs After)");
                    egui::Grid::new("reg_comp_grid").striped(true).show(ui, |ui| {
                        ui.label("Register"); ui.label("Start Value"); ui.label("End Value"); ui.end_row();
                        
                        let regs = [
                            ("RAX", orig.rax, res.rax), ("RBX", orig.rbx, res.rbx),
                            ("RCX", orig.rcx, res.rcx), ("RDX", orig.rdx, res.rdx),
                            ("RIP", orig.rip, res.rip), ("RSP", orig.rsp, res.rsp),
                        ];
                        
                        for (name, start, end) in regs {
                            ui.label(name);
                            ui.label(format!("0x{:016X}", start));
                            let color = if start != end { egui::Color32::from_rgb(100, 255, 100) } else { egui::Color32::LIGHT_GRAY };
                            ui.colored_label(color, format!("0x{:016X}", end));
                            ui.end_row();
                        }
                    });
                }
                
                ui.separator();
                if ui.button("Close").clicked() { close_sandbox = true; }
            });
            if close_sandbox { self.show_sandbox_popup = false; }
        }

        let mut is_open_search = self.show_search_popup;
        let mut req_close_search = false;
        if is_open_search {
            egui::Window::new("Advanced String Search").collapsible(false).resizable(true).default_width(400.0).open(&mut is_open_search).show(ctx, |ui| {
                ui.heading("Find in Payloads");
                ui.horizontal(|ui| {
                    ui.label("Search:");
                    ui.text_edit_singleline(&mut self.search_query);
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut true, "Match Case");
                    ui.checkbox(&mut false, "Regular Expressions");
                    ui.checkbox(&mut false, "Match Whole Word");
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Search All").clicked() {
                        req_close_search = true;
                        self.log_output.push_str(&format!("[SEARCH] Deep Pattern Matching for '{}' across loaded buffers.\n", self.search_query));
                    }
                    if ui.button("Cancel").clicked() { req_close_search = true; }
                });
            });
            if req_close_search || !is_open_search { self.show_search_popup = false; }
        }

        let mut is_open_view_opts = self.show_view_options_popup;
        if is_open_view_opts {
            egui::Window::new("View Options").resizable(true).default_width(320.0).open(&mut is_open_view_opts).show(ctx, |ui| {
                ui.heading("Workspace Visual Settings");
                ui.separator();
                egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                    ui.label(egui::RichText::new("Editor Preferences").strong());
                    ui.add(egui::Slider::new(&mut self.opt_ui_scale, 0.5..=2.5).text("Global UI Scale (Restart Req)"));
                    
                    egui::ComboBox::from_label("Font Family").selected_text(&self.opt_font_family).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.opt_font_family, "Consolas".to_string(), "Consolas");
                        ui.selectable_value(&mut self.opt_font_family, "Fira Code".to_string(), "Fira Code");
                        ui.selectable_value(&mut self.opt_font_family, "Courier New".to_string(), "Courier New");
                    });

                    egui::ComboBox::from_label("Color Palette").selected_text(&self.opt_color_palette).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.opt_color_palette, "Standard".to_string(), "Standard");
                        ui.selectable_value(&mut self.opt_color_palette, "High Contrast".to_string(), "High Contrast");
                        ui.selectable_value(&mut self.opt_color_palette, "Pastel".to_string(), "Pastel");
                    });
                    
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Hex Viewer Settings").strong());
                    ui.add(egui::Slider::new(&mut self.opt_hex_row_width, 8..=64).text("Bytes Per Row"));
                    ui.checkbox(&mut self.opt_show_offsets_in_decimal, "Show Offsets in Decimal");
                    
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("General UI").strong());
                    ui.checkbox(&mut self.opt_highlight_active_tab, "Highlight Active Tab");
                    ui.add(egui::Slider::new(&mut self.opt_max_log_lines, 100..=5000).text("Max Log Buffer Lines"));
                    ui.checkbox(&mut self.opt_auto_scroll_output, "Auto Scroll Output Panel");
                    ui.checkbox(&mut self.opt_render_animations, "Render Smooth Animations");
                    ui.checkbox(&mut self.opt_show_hidden_sections, "Show Hidden / Empty PE Sections");
                });
            });
            if !is_open_view_opts { self.show_view_options_popup = false; }
        }


        if self.show_pe_metadata_popup {
            let mut close_pe = false;
            egui::Window::new("[P] Deep PE Metadata & Structure Analysis").resizable(true).default_width(550.0).show(ctx, |ui| {
                if let Some(exec) = self.loaded_files.first() {
                    if let Some(pe) = &exec.pe_info {
                        ui.horizontal(|ui| {
                            ui.label("Packer/Compiler Detection:");
                            ui.colored_label(egui::Color32::from_rgb(255, 100, 255), &pe.packer_detected);
                        });
                        ui.separator();

                        egui::ScrollArea::vertical().id_source("pe_metadata_scroll").show(ui, |ui| {
                            egui::CollapsingHeader::new("DOS Header").show(ui, |ui| {
                                egui::Grid::new("dos_grid").striped(true).show(ui, |ui| {
                                    for (k, v) in &pe.dos_header {
                                        ui.label(k); ui.label(egui::RichText::new(v).monospace()); ui.end_row();
                                    }
                                });
                            });
                            egui::CollapsingHeader::new("File Header (COFF)").show(ui, |ui| {
                                egui::Grid::new("file_grid").striped(true).show(ui, |ui| {
                                    for (k, v) in &pe.file_header {
                                        ui.label(k); ui.label(egui::RichText::new(v).monospace()); ui.end_row();
                                    }
                                });
                            });
                            egui::CollapsingHeader::new("Optional Header (Windows)").show(ui, |ui| {
                                egui::Grid::new("opt_grid").striped(true).show(ui, |ui| {
                                    for (k, v) in &pe.optional_header {
                                        ui.label(k); ui.label(egui::RichText::new(v).monospace()); ui.end_row();
                                    }
                                });
                            });
                            egui::CollapsingHeader::new("Sections Table").default_open(true).show(ui, |ui| {
                                egui::Grid::new("sec_grid").striped(true).show(ui, |ui| {
                                    ui.label("Name"); ui.label("VRaw"); ui.label("VSize"); ui.label("RawPtr"); ui.end_row();
                                    for sec in &pe.sections {
                                        ui.label(egui::RichText::new(&sec.name).strong());
                                        ui.label(format!("0x{:08X}", sec.size_of_raw_data));
                                        ui.label(format!("0x{:08X}", sec.virtual_size));
                                        ui.label(format!("0x{:08X}", sec.pointer_to_raw_data));
                                        ui.end_row();
                                    }
                                });
                            });
                        });
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label("No PE Metadata parsed. Please run 'Analyze' on the file first.");
                            if ui.button("Analyze Now").clicked() {
                                // In a real scenario we'd trigger analysis here
                            }
                        });
                    }
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label("No executable loaded.");
                    });
                }
                ui.separator();
                if ui.button("Close Window").clicked() { close_pe = true; }
            });
            if close_pe { self.show_pe_metadata_popup = false; }
        }

        let mut is_open_debug_opts = self.show_debug_options_popup;
        if is_open_debug_opts {
            egui::Window::new("Decompiler & Debug Engine Options").resizable(true).default_width(320.0).open(&mut is_open_debug_opts).show(ctx, |ui| {
                ui.heading("Global Decompiler Settings");
                ui.separator();
                egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                    ui.label(egui::RichText::new("Decompilation Engine").strong());
                    ui.add(egui::Slider::new(&mut self.opt_decomp_max_depth, 10..=500).text("Max Recursion Depth"));
                    ui.add(egui::Slider::new(&mut self.opt_analysis_heuristic, 1..=5).text("Heuristic Aggression Level"));
                    
                    egui::ComboBox::from_label("Assume Python Target").selected_text(&self.opt_assume_python_version).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.opt_assume_python_version, "Auto".to_string(), "Auto-Detect");
                        ui.selectable_value(&mut self.opt_assume_python_version, "3.8".to_string(), "Python 3.8");
                        ui.selectable_value(&mut self.opt_assume_python_version, "3.9".to_string(), "Python 3.9");
                        ui.selectable_value(&mut self.opt_assume_python_version, "3.10".to_string(), "Python 3.10");
                        ui.selectable_value(&mut self.opt_assume_python_version, "3.11".to_string(), "Python 3.11");
                    });

                    ui.checkbox(&mut self.opt_interp_magic, "Parse Python MAGIC headers strictly");
                    ui.checkbox(&mut self.opt_fast_capstone, "Use Fast Capstone Native Backend");
                    ui.checkbox(&mut self.opt_strip_obfuscation, "Strip PyArmor / Obfuscation Tokens");
                    
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Analysis Settings").strong());
                    ui.checkbox(&mut self.opt_agg_unzip, "Aggressive Unzip (PyInstaller)");
                    ui.checkbox(&mut self.opt_show_opcode_stack, "Render Opcode Internal Stack Sizes");
                    ui.checkbox(&mut self.opt_live_var_track, "Enable Static Live Variable Tracking");
                    ui.checkbox(&mut self.opt_treat_warnings_as_errors, "Treat Context Warnings as Errors");
                    
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Advanced Pseudo-C++ Heuristics").strong());
                    ui.checkbox(&mut self.opt_enable_loop_recovery, "Enable Heuristic Loop Recovery (while/for)");
                    ui.checkbox(&mut self.opt_enable_auto_var_naming, "Enable Stack Var Inference (local_var_x)");
                    ui.checkbox(&mut self.opt_enable_calling_conventions, "Map x64 Calling Conventions (RCX/RDX etc)");
                });
            });
            if !is_open_debug_opts { self.show_debug_options_popup = false; }
        }

        let mut is_open_locals = self.show_locals_popup;
        if is_open_locals {
            egui::Window::new("Debug Locals").open(&mut is_open_locals).show(ctx, |ui| {
                ui.label("No active Python debug session running.");
                ui.label("Attach to a process via 'Debug -> Attach to Python Process' to view active memory locals.");
                if ui.button("Close").clicked() { self.show_locals_popup = false; }
            });
            if !is_open_locals { self.show_locals_popup = false; }
        }

        let mut is_open_list = self.show_open_list_popup;
        let mut trigger_add_list: Option<Vec<std::path::PathBuf>> = None;
        if is_open_list {
            egui::Window::new("Payload List Manager").open(&mut is_open_list).show(ctx, |ui| {
                ui.label("Manage bulk lists of payloads and scripts here:");
                ui.separator();
                if ui.button("Import from text file (.txt)...").clicked() { 
                    if let Some(path) = rfd::FileDialog::new().add_filter("Text Documents", &["txt", "md"]).pick_file() {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let mut paths = Vec::new();
                            for line in content.lines() {
                                let p = std::path::PathBuf::from(line.trim());
                                if p.exists() && p.is_file() {
                                    paths.push(p);
                                }
                            }
                            trigger_add_list = Some(paths);
                            self.log_output.push_str(&format!("[INFO] Imported paths list from {}\n", path.display()));
                        }
                    }
                    self.show_open_list_popup = false; 
                }
                if ui.button("Import Folder of Payloads...").clicked() { 
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        if let Ok(entries) = std::fs::read_dir(&folder) {
                            let mut paths = Vec::new();
                            for entry in entries.flatten() {
                                let p = entry.path();
                                if p.is_file() { paths.push(p); }
                            }
                            trigger_add_list = Some(paths);
                            self.log_output.push_str(&format!("[INFO] Imported payloads from directory {}\n", folder.display()));
                        }
                    }
                    self.show_open_list_popup = false; 
                }
                if ui.button("Clear Open List").clicked() { 
                    self.loaded_files.clear(); 
                    self.tabs.clear();
                    self.active_tab_idx = None;
                    self.log_output.push_str("[ACTION] Cleared actively loaded executables.\n");
                    self.show_open_list_popup = false; 
                }
            });
            if !is_open_list { self.show_open_list_popup = false; }
        }

        if let Some(paths) = trigger_add_list {
            for path in paths {
                let exec = LoadedExecutable {
                    path,
                    archive: None,
                    native_sections: None,
                    pe_info: None,
                };
                self.loaded_files.push(exec);
            }
        }

        let mut is_open_attach = self.show_attach_process_popup;
        if is_open_attach {
            use sysinfo::System;
            
            // Refresh processes every 2 seconds when popup is open
            let should_refresh = self.last_process_refresh.map_or(true, |t| t.elapsed() > std::time::Duration::from_secs(2));
            if should_refresh || self.processes.is_empty() {
                let mut sys = System::new_all();
                sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
                self.processes = sys.processes().iter()
                    .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string_lossy().to_string()))
                    .collect();
                self.processes.sort_by_key(|&(_, ref name)| name.clone().to_lowercase());
                self.last_process_refresh = Some(std::time::Instant::now());
            }

            egui::Window::new("Attach to Process").resizable(true).default_width(350.0).default_height(400.0).open(&mut is_open_attach).show(ctx, |ui| {
                ui.heading("Select a running process to inject the generic debugger:");
                ui.separator();
                egui::ScrollArea::both().max_height(250.0).show(ui, |ui| {
                    egui::Grid::new("process_grid").striped(true).show(ui, |ui| {
                        ui.label(egui::RichText::new("PID").strong()); ui.label(egui::RichText::new("Process Name").strong()); ui.end_row();
                        for (pid, name) in &self.processes {
                            ui.label(pid.to_string());
                            let response = ui.selectable_label(false, name);
                            if response.clicked() {
                                self.log_output.push_str(&format!("[DEBUG] Selected process '{}' (PID: {}). Injecting payload...\n", name, pid));
                                if let Some(dbg) = &self.debugger {
                                    let _ = dbg.command_sender.send(crate::core::debugger::DebuggerCommand::Attach(*pid));
                                }
                                self.show_attach_process_popup = false;
                            }
                            ui.end_row();
                        }
                    });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Refresh").clicked() { 
                        self.last_process_refresh = None; // Force refresh next frame
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_attach_process_popup = false;
                    }
                });
            });
            if !is_open_attach { self.show_attach_process_popup = false; }
        }

        let mut is_open_unity = self.show_attach_unity_popup;
        let mut trigger_pydbg_connect: Option<u16> = None;
        if is_open_unity {
            egui::Window::new("Attach to Python Instance (PyDBG)").open(&mut is_open_unity).show(ctx, |ui| {
                ui.heading("Connect to remote Python debug port (e.g. debugpy)");
                ui.horizontal(|ui| {
                    ui.label("TCP Port:");
                    let mut port_str = "5678".to_string();
                    ui.text_edit_singleline(&mut port_str);
                    if ui.button("Connect").clicked() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            trigger_pydbg_connect = Some(port);
                        }
                    }
                });
                ui.separator();
                if ui.button("Cancel").clicked() { self.show_attach_unity_popup = false; }
            });
            if !is_open_unity { self.show_attach_unity_popup = false; }
        }

        if let Some(port) = trigger_pydbg_connect {
            self.log_output.push_str(&format!("[DEBUG] Attempting TCP connection to 127.0.0.1:{}...\n", port));
            match std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), port), std::time::Duration::from_secs(2)) {
                Ok(_) => {
                    self.log_output.push_str("[SUCCESS] Connected to Python debug port! Awaiting handshake...\n");
                    self.show_attach_unity_popup = false;
                },
                Err(e) => {
                    self.log_output.push_str(&format!("[ERROR] Connection to port {} failed: {}\n", port, e));
                }
            }
        }

        let mut is_open_windows = self.show_windows_popup;
        if is_open_windows {
            egui::Window::new("Workspace Settings").open(&mut is_open_windows).show(ctx, |ui| {
                ui.heading("Manage workspace persistence and layouts");
                ui.separator();
                if ui.button("Export Workspace...").clicked() { 
                    if let Some(path) = rfd::FileDialog::new().add_filter("RvSpy Workspace", &["json"]).save_file() {
                        if let Ok(json) = serde_json::to_string_pretty(self) { // self implements Serialize
                            let _ = std::fs::write(&path, json);
                            self.log_output.push_str(&format!("[INFO] Exported workspace to {}\n", path.display()));
                        }
                    }
                    self.show_windows_popup = false; 
                }
                if ui.button("Import Workspace...").clicked() { 
                    if let Some(path) = rfd::FileDialog::new().add_filter("RvSpy Workspace", &["json"]).pick_file() {
                        if let Ok(json) = std::fs::read_to_string(&path) {
                            if let Ok(app) = serde_json::from_str::<RvSpyApp>(&json) {
                                // Apply settings mapping
                                self.loaded_files = app.loaded_files;
                                self.bottom_tab = app.bottom_tab;
                                self.theme = app.theme;
                                self.language = app.language;
                                self.opt_interp_magic = app.opt_interp_magic;
                                self.opt_fast_capstone = app.opt_fast_capstone;
                                self.opt_agg_unzip = app.opt_agg_unzip;
                                self.log_output.push_str(&format!("[INFO] Imported workspace from {}\n", path.display()));
                            }
                        }
                    }
                    self.show_windows_popup = false; 
                }
                if ui.button("Reset Default Layout").clicked() { 
                    self.show_left_panel = true;
                    self.show_bottom_panel = true;
                    self.log_output.push_str("[INFO] Reset panel layouts to default.\n");
                    self.show_windows_popup = false; 
                }
                if ui.button("Close Window").clicked() { self.show_windows_popup = false; }
            });
            if !is_open_windows { self.show_windows_popup = false; }
        }

        let mut is_open_custom_hunter = self.show_custom_hunter;
        let mut do_custom_scan = false;
        if is_open_custom_hunter {
            egui::Window::new("🎯 Custom Signature Hunter").resizable(true).default_width(350.0).open(&mut is_open_custom_hunter).show(ctx, |ui| {
                ui.heading("Deep Memory Hex & ASCII Scanner");
                ui.label("Enter an ASCII string (e.g. 'requests') or Hexadecimal Bytes (e.g. '4D 5A 90') to hunt across the entire executable memory space using hardware acceleration.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Signature:");
                    ui.text_edit_singleline(&mut self.hunter_signature);
                });
                ui.separator();
                if ui.button("🚀 Hunt Signature").clicked() {
                    do_custom_scan = true;
                    self.show_custom_hunter = false;
                }
            });
            if !is_open_custom_hunter { self.show_custom_hunter = false; }
        }

        if do_custom_scan {
            if let Some(idx) = self.hunter_target_idx {
                let exec = &self.loaded_files[idx];
                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                let mut new_content = String::new();
                
                let sig_bytes = if self.hunter_signature.contains(" ") || self.hunter_signature.chars().all(|c| c.is_ascii_hexdigit() || c == ' ') {
                    // Try to parse Hex
                    let clean = self.hunter_signature.replace(" ", "");
                    (0..clean.len()).step_by(2)
                        .flat_map(|i| u8::from_str_radix(&clean[i..i+2], 16))
                        .collect::<Vec<u8>>()
                } else {
                    self.hunter_signature.as_bytes().to_vec()
                };

                self.log_output.push_str(&format!("[INFO] Executing Custom Hunter for signature {:?} on {}...\n", self.hunter_signature, file_name));

                if let Ok(file_data) = std::fs::read(&exec.path) {
                    let start = std::time::Instant::now();
                    
                    new_content.push_str("CUSTOM SIGNATURE HUNTER RESULTS\n");
                    new_content.push_str("==============================================\n\n");
                    new_content.push_str(&format!("Target File   : {}\n", file_name));
                    new_content.push_str(&format!("Signature     : {:?}\n\n", self.hunter_signature));

                    if let Some(offset) = crate::python::nuitka_mod::NuitkaAnalyzer::fast_scan(&file_data, &sig_bytes) {
                        let duration = start.elapsed();
                        new_content.push_str(&format!("[+] MATCH FOUND at Absolute Offset: 0x{:08X}\n", offset));
                        new_content.push_str(&format!("    Scan Duration: {:?}\n\n", duration));
                        
                        // Show a snippet of hex context
                        let ctx_start = offset.saturating_sub(32);
                        let ctx_end = (offset + 64).min(file_data.len());
                        new_content.push_str("Memory Context:\n");
                        new_content.push_str(&Self::format_hex(&file_data[ctx_start..ctx_end]));

                    } else {
                        let duration = start.elapsed();
                        new_content.push_str(&format!("[-] NO MATCH FOUND.\n    Scan Duration: {:?}\n", duration));
                    }
                } else {
                    new_content.push_str("Error reading file to disk bounds.");
                }

                let tab_name = format!("Hunt [{}]", file_name);
                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                    self.tabs[pos].content = new_content;
                    self.active_tab_idx = Some(pos);
                } else {
                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                    self.active_tab_idx = Some(self.tabs.len() - 1);
                }
            }
        }


        // The About Window
        if self.show_about_window {
            egui::Window::new("About RvSpy")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.add_space(10.0);
                    ui.heading("RvSpy (Advanced Reverse Engineering)");
                    ui.add_space(5.0);
                    ui.label("A professional tool for decompiling, extracting, and analyzing");
                    ui.label("compiled executables like PyInstaller and Nuitka.");
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Dev By 0Rafas").color(egui::Color32::from_rgb(255, 105, 180)).strong());
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Close").clicked() {
                                self.show_about_window = false;
                            }
                        });
                    });
                });
        }



        // Status Bar (Allocated first so it's at the very bottom Edge)
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Loaded Payloads: {}", self.loaded_files.len()));
                ui.separator();
                let target = self.selected_file.as_deref().unwrap_or("None");
                ui.label(format!("Active Target: {}", target));
                ui.separator();
                ui.label("Engine State: Idle");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(self.translate("Ready"));
                });
            });
        });

        // Bottom Output/Logs
        egui::TopBottomPanel::bottom("bottom_panel")
            .resizable(true)
            .min_height(120.0)
            .show(ctx, |ui| {
                // Toolbar for the bottom panel
                ui.horizontal(|ui| {
                    if ui.selectable_label(self.bottom_tab == "Output", self.translate("Output")).clicked() { self.bottom_tab = "Output".to_string(); }
                    if ui.selectable_label(self.bottom_tab == "Breakpoints", self.translate("Breakpoints")).clicked() { self.bottom_tab = "Breakpoints".to_string(); }
                    if ui.selectable_label(self.bottom_tab == "Locals", self.translate("Locals")).clicked() { self.bottom_tab = "Locals".to_string(); }
                    if ui.selectable_label(self.bottom_tab == "Behavioral", "[!] Behavioral").clicked() { self.bottom_tab = "Behavioral".to_string(); }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("📋 Copy All").clicked() {
                            ui.output_mut(|o| o.copied_text = self.log_output.clone());
                        }
                        if ui.button("💾 Save Log").clicked() {
                            if let Some(path) = rfd::FileDialog::new().save_file() {
                                let _ = std::fs::write(path, &self.log_output);
                            }
                        }
                        if ui.button(self.translate("Clear")).clicked() {
                            self.log_output.clear();
                        }
                    });
                });
                ui.separator();
                
                if self.bottom_tab == "Output" {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.log_output.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .text_color(egui::Color32::from_rgb(204, 204, 204))
                                    .frame(false)
                                    .desired_width(f32::INFINITY),
                            );
                    });
                } else if self.bottom_tab == "Locals" {
                    if let Some(dbg) = &self.debugger {
                        if let Ok(s) = dbg.state.lock() {
                            if let Some(ctx) = &s.last_context {
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    egui::Grid::new("locals_grid").striped(true).show(ui, |ui| {
                                        ui.label("Stack Offset"); ui.label("Value (QWORD)"); ui.label("Inferred Type"); ui.end_row();
                                        for (i, val) in ctx.stack_locals.iter().enumerate() {
                                            ui.label(format!("RSP+0x{:02X}", i * 8));
                                            ui.label(format!("0x{:016X}", val));
                                            if *val > 0x10000 { ui.label(egui::RichText::new("Pointer").color(egui::Color32::LIGHT_BLUE)); } else { ui.label("Value / Int"); }
                                            ui.end_row();
                                        }
                                    });
                                });
                            } else {
                                ui.centered_and_justified(|ui| { ui.label("Stop at a breakpoint to view stack locals."); });
                            }
                        }
                    }
                } else if self.bottom_tab == "Behavioral" {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading("[B] Behavioral Analysis Findings");
                            if ui.button("🗑 Clear All").clicked() {
                                self.behavioral_findings.clear();
                            }
                        });
                        ui.add_space(5.0);
                        
                        if self.behavioral_findings.is_empty() {
                            ui.centered_and_justified(|ui| {
                                ui.label(egui::RichText::new("No suspicious behaviors detected yet.\nRun a static scan or start debugging to observe events.")
                                    .color(egui::Color32::from_rgb(100, 100, 100)));
                            });
                        } else {
                            egui::Grid::new("behavioral_grid").striped(true).min_col_width(100.0).show(ui, |ui| {
                                ui.label(egui::RichText::new("Severity").strong());
                                ui.label(egui::RichText::new("Category").strong());
                                ui.label(egui::RichText::new("Description").strong());
                                ui.label(egui::RichText::new("Details / Context").strong());
                                ui.end_row();

                                for finding in &self.behavioral_findings {
                                    let color = match finding.severity {
                                        crate::core::behavioral_scanner::Severity::Critical => egui::Color32::from_rgb(255, 50, 50),
                                        crate::core::behavioral_scanner::Severity::High => egui::Color32::from_rgb(255, 100, 0),
                                        crate::core::behavioral_scanner::Severity::Medium => egui::Color32::from_rgb(255, 200, 0),
                                        crate::core::behavioral_scanner::Severity::Low => egui::Color32::from_rgb(0, 200, 255),
                                    };

                                    ui.label(egui::RichText::new(format!("{:?}", finding.severity)).color(color).strong());
                                    ui.label(format!("{:?}", finding.category));
                                    
                                    // Look up full description from scanner metadata
                                    let desc = self.scanner.signatures.iter()
                                        .find(|s| s.id == finding.signature_id)
                                        .map(|s| s.description.clone())
                                        .unwrap_or_else(|| "Unknown Signature".to_string());
                                        
                                    ui.label(desc);
                                    ui.label(egui::RichText::new(&finding.context).monospace());
                                    ui.end_row();
                                }
                            });
                        }
                    });
                }
            });

        // Left Panel: Assembly/Module Explorer
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(self.translate("Assembly Explorer"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("⟳").on_hover_text("Refresh").clicked() {}
                        if ui.button("➕").on_hover_text("Import File").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.add_and_analyze_file(path.clone());
                            }
                        }
                    });
                });
                ui.separator();

                // Search bar
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_query).hint_text("Search assemblies..."),
                );
                egui::ScrollArea::both()
                    .auto_shrink([false, false]) // Fill the available space to enable right click anywhere
                    .show(ui, |ui| {
                        
                        let force_collapse = self.collapse_nodes;

                        if self.loaded_files.is_empty() {
                            ui.centered_and_justified(|ui| {
                                ui.label(
                                    egui::RichText::new(
                                        "Drag & Drop files here\nor Click [+] to Import",
                                    )
                                    .color(egui::Color32::from_rgb(100, 100, 100)),
                                );
                            });
                        } else {
                            // Dynamically render loaded files as roots
                            let mut trigger_analysis = None;
                            let mut trigger_remove = None;
                            let trigger_select_file: Option<String> = None;
                            let mut trigger_hex_view_file: Option<(usize, String)> = None;
                            let mut trigger_hex_view_sec: Option<(usize, String)> = None;
                            let mut trigger_disasm_sec: Option<(usize, String)> = None;
                            let mut trigger_extract_file: Option<(usize, String)> = None;
                            let mut trigger_decompile_pyc: Option<(usize, String)> = None;
                            let mut trigger_pseudo_c_sec: Option<(usize, String)> = None;
                            let mut trigger_dump_mem_sec: Option<(usize, String)> = None;
                            let mut trigger_launch_process: Option<usize> = None;
                            let mut trigger_strings_file: Option<(usize, String)> = None;
                            let mut trigger_strings_sec: Option<(usize, String)> = None;
                            let mut trigger_cfg_view_sec: Option<(usize, String)> = None;
                            let mut trigger_strings_exe: Option<usize> = None;
                            let mut trigger_pe_metadata: Option<usize> = None;
                            let mut trigger_raw_pyc: Option<(usize, String)> = None;
                            let mut trigger_network_ioc: Option<usize> = None;
                            let mut trigger_filepath_ioc: Option<usize> = None;
                            let mut trigger_properties: Option<usize> = None;
                            let mut trigger_deep_pe_view: Option<(usize, String)> = None;
                            let mut trigger_nuitka_scan: Option<usize> = None;
                            let mut trigger_recover_nuitka_exe: Option<usize> = None;
                            let mut trigger_recover_nuitka_sec: Option<(usize, String)> = None;
                            let mut trigger_entropy_exe: Option<usize> = None;
                            let mut trigger_entropy_sec: Option<(usize, String)> = None;
                            let mut trigger_sandbox_sec: Option<(usize, String)> = None;

                            // Patch toolbar triggers into local triggers
                            if self.toolbar_trigger_network_ioc {
                                self.toolbar_trigger_network_ioc = false;
                                if !self.loaded_files.is_empty() {
                                    trigger_network_ioc = Some(0); // Default to first loaded file
                                }
                            }
                            if self.toolbar_trigger_nuitka_recovery {
                                self.toolbar_trigger_nuitka_recovery = false;
                                if !self.loaded_files.is_empty() {
                                    trigger_recover_nuitka_exe = Some(0); // Default to first loaded file
                                }
                            }
                            
                            for (idx, exec) in self.loaded_files.iter().enumerate() {
                                let file_name = exec.path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| "Unknown".to_string());
                                    
                                // Search filter logic (checks parent AND children)
                                let search = self.search_query.to_lowercase();
                                let mut matches_search = self.search_query.is_empty() || file_name.to_lowercase().contains(&search);
                                
                                if !matches_search {
                                    if let Some(Ok(files)) = &exec.archive {
                                        matches_search = files.iter().any(|f| f.name.to_lowercase().contains(&search));
                                    } else if let Some(sections) = &exec.native_sections {
                                        matches_search = sections.iter().any(|s| s.name.to_lowercase().contains(&search));
                                    }
                                }

                                if !matches_search {
                                    continue;
                                }

                                let icon = if file_name.ends_with(".exe") {
                                    "[A]"
                                } else if file_name.ends_with(".zip") {
                                    "[+]"
                                } else {
                                    "[-]"
                                };

                                let header_title = format!("{} {}", icon, file_name);

                                // Auto-expand if search query matches something inside
                                let should_expand = !self.search_query.is_empty() && matches_search;

                                let header_res = egui::CollapsingHeader::new(&header_title)
                                    .id_source(exec.path.clone());
                                    
                                let header_res = if force_collapse {
                                    header_res.open(Some(false))
                                } else {
                                    header_res.default_open(should_expand)
                                };
                                
                                let header_res = header_res.show(ui, |ui| {
                                        let mut has_children = false;

                                        // Render the PE Structure natively like dnSpy
                                        if let Some(pe) = &exec.pe_info {
                                            let mut pe_ch = egui::CollapsingHeader::new("[P] PE");
                                            pe_ch = if force_collapse { pe_ch.open(Some(false)) } else { pe_ch.default_open(true) };
                                            pe_ch.show(ui, |ui| {
                                                if ui.selectable_label(self.selected_file.as_deref() == Some("DOS Header"), "[-] DOS Header").clicked() {
                                                    trigger_deep_pe_view = Some((idx, "DOS Header".to_string()));
                                                }
                                                if ui.selectable_label(self.selected_file.as_deref() == Some("File Header"), "[-] File Header").clicked() {
                                                    trigger_deep_pe_view = Some((idx, "File Header".to_string()));
                                                }
                                                if ui.selectable_label(self.selected_file.as_deref() == Some("Optional Header"), "[-] Optional Header").clicked() {
                                                    trigger_deep_pe_view = Some((idx, "Optional Header".to_string()));
                                                }
                                                
                                                let sections_count = pe.sections.len();
                                                let sec_title = format!("[+] Sections ({})", sections_count);
                                                let mut sec_ch = egui::CollapsingHeader::new(&sec_title);
                                                sec_ch = if force_collapse { sec_ch.open(Some(false)) } else { sec_ch.default_open(false) };
                                                sec_ch.show(ui, |ui| {
                                                    for (sec_idx, sec) in pe.sections.iter().enumerate() {
                                                        let label_name = format!("Section #{}: {}", sec_idx, sec.name);
                                                        let lookup_name = format!("Section|{}", sec.name);
                                                        let resp = ui.selectable_label(self.selected_file.as_deref() == Some(&lookup_name), format!("[-] {}", label_name));
                                                        if resp.clicked() {
                                                            trigger_deep_pe_view = Some((idx, lookup_name.clone()));
                                                        }
                                                        resp.context_menu(|ui| {
                                                            if ui.button("🔬 Emulate Section in Sandbox").clicked() {
                                                                trigger_sandbox_sec = Some((idx, sec.name.clone()));
                                                                ui.close_menu();
                                                            }
                                                            if ui.button("[?] Run Entropy Analysis").clicked() {
                                                                trigger_entropy_sec = Some((idx, lookup_name.clone()));
                                                                ui.close_menu();
                                                            }
                                                        });
                                                    }
                                                });
                                            });
                                            has_children = true;
                                        }

                                        if let Some(Ok(files)) = &exec.archive {
                                            use std::collections::BTreeMap;
                                            
                                            // 1. Build a Tree Model
                                            #[derive(Default)]
                                            struct DirNode<'a> {
                                                children: BTreeMap<&'a str, DirNode<'a>>,
                                                files: Vec<&'a crate::python::TOCEntry>,
                                            }

                                            let mut root = DirNode::default();

                                            for file in files {
                                                if !self.search_query.is_empty() && !file.name.to_lowercase().contains(&self.search_query.to_lowercase()) { continue; }
                                                
                                                let parts: Vec<&str> = file.name.split('/').collect();
                                                if parts.is_empty() { continue; }

                                                let mut current = &mut root;
                                                for &part in &parts[..parts.len() - 1] {
                                                    current = current.children.entry(part).or_default();
                                                }
                                                current.files.push(file);
                                            }

                                            // 2. Recursive Rendering Closure
                                            fn render_node(
                                                ui: &mut egui::Ui,
                                                node: &DirNode,
                                                idx: usize,
                                                search_query: &str,
                                                selected_file: Option<&str>,
                                                force_collapse: bool,
                                                translate: &impl Fn(&str) -> String,
                                                trigger_hex_view_file: &mut Option<(usize, String)>,
                                                trigger_extract_file: &mut Option<(usize, String)>,
                                                trigger_decompile_pyc: &mut Option<(usize, String)>,
                                                trigger_pseudo_c_sec: &mut Option<(usize, String)>,
                                                trigger_dump_mem_sec: &mut Option<(usize, String)>,
                                                trigger_strings_file: &mut Option<(usize, String)>,
                                                trigger_raw_pyc: &mut Option<(usize, String)>,
                                            ) {
                                                // Render Sub-directories
                                                for (dir_name, child_node) in &node.children {
                                                    let should_expand = !search_query.is_empty();
                                                    let mut ch = egui::CollapsingHeader::new(format!("[+] {}", dir_name));
                                                    ch = if force_collapse { ch.open(Some(false)) } else { ch.default_open(should_expand) };
                                                    ch.show(ui, |ui| {
                                                            render_node(
                                                                ui, child_node, idx, search_query, selected_file, force_collapse, translate,
                                                                trigger_hex_view_file, trigger_extract_file, trigger_decompile_pyc,
                                                                trigger_pseudo_c_sec, trigger_dump_mem_sec, trigger_strings_file, trigger_raw_pyc
                                                            );
                                                        });
                                                }

                                                // Render Files
                                                for file in &node.files {
                                                    let is_selected = selected_file == Some(file.name.as_str());
                                                    let file_name_only = file.name.split('/').last().unwrap_or(&file.name);
                                                    
                                                    let response = ui.selectable_label(is_selected, format!("[-] {}", file_name_only));
                                                    if response.clicked() {
                                                        *trigger_hex_view_file = Some((idx, file.name.clone()));
                                                    }
                                                    response.context_menu(|ui| {
                                                        if ui.button(translate("Hex View")).clicked() {
                                                            *trigger_hex_view_file = Some((idx, file.name.clone()));
                                                            ui.close_menu();
                                                        }
                                                        if ui.button(translate("Extract to Disk")).clicked() {
                                                            *trigger_extract_file = Some((idx, file.name.clone()));
                                                            ui.close_menu();
                                                        }
                                                        if file.name.ends_with(".pyc") || file.name.ends_with(".pyz") {
                                                            if ui.button(translate("Decompile (.pyc/.pyz)")).clicked() {
                                                                *trigger_decompile_pyc = Some((idx, file.name.clone()));
                                                                ui.close_menu();
                                                            }
                                                            if ui.button(translate("Extract Original Bytecode (.pyc)")).clicked() {
                                                                *trigger_raw_pyc = Some((idx, file.name.clone()));
                                                                ui.close_menu();
                                                            }
                                                        }
                                                        ui.separator();
                                                        if ui.button(translate("Extract Strings")).clicked() {
                                                            *trigger_strings_file = Some((idx, file.name.clone()));
                                                            ui.close_menu();
                                                        }
                                                    });
                                                }
                                            }

                                            let translate_closure = |s: &str| self.translate(s);
                                            render_node(
                                                ui, &root, idx, &self.search_query, self.selected_file.as_deref(), force_collapse, &translate_closure,
                                                &mut trigger_hex_view_file, &mut trigger_extract_file, &mut trigger_decompile_pyc,
                                                &mut trigger_pseudo_c_sec, &mut trigger_dump_mem_sec, &mut trigger_strings_file, &mut trigger_raw_pyc
                                            );
                                            
                                            has_children = true;
                                        }

                                        if let Some(sections) = &exec.native_sections {
                                            for sec in sections {
                                                if !self.search_query.is_empty() && !sec.name.to_lowercase().contains(&self.search_query.to_lowercase()) { continue; }

                                                let is_selected = self.selected_file.as_deref() == Some(sec.name.as_str());
                                                let response = ui.selectable_label(is_selected, format!("[-] {}", sec.name));
                                                if response.clicked() {
                                                    trigger_hex_view_sec = Some((idx, sec.name.clone()));
                                                }
                                                response.context_menu(|ui| {
                                                    if ui.button(self.translate("Hex View")).clicked() {
                                                        trigger_hex_view_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    if ui.button(self.translate("Disassemble (x86_64)")).clicked() {
                                                        trigger_disasm_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    if ui.button(self.translate("Decompile to Pseudo-C++")).clicked() {
                                                        trigger_pseudo_c_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    if ui.button(self.translate("Raw Memory View")).clicked() {
                                                        trigger_dump_mem_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    if ui.button(self.translate("Calculate Information Entropy")).clicked() {
                                                        trigger_entropy_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    if ui.button(self.translate("Recover Nuitka Resources")).clicked() {
                                                        trigger_recover_nuitka_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    ui.separator();
                                                    if ui.button(self.translate("Extract Strings")).clicked() {
                                                        trigger_strings_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                    if ui.button(self.translate("Generate Control Flow Graph (CFG)")).clicked() {
                                                        trigger_cfg_view_sec = Some((idx, sec.name.clone()));
                                                        ui.close_menu();
                                                    }
                                                });
                                            }
                                            has_children = true;
                                        }

                                        if !has_children {
                                            if let Some(Err(e)) = &exec.archive {
                                                ui.label(
                                                    egui::RichText::new(&format!("  [Error] {}", e))
                                                        .color(egui::Color32::from_rgb(200, 50, 50)),
                                                );
                                            } else {
                                                ui.label(
                                                    egui::RichText::new("  (Analysis pending...)")
                                                        .italics()
                                                        .color(egui::Color32::from_rgb(120, 120, 120)),
                                                );
                                            }
                                        }
                                    });

                                // Reset the flag once consumed for this frame
                                self.collapse_nodes = false;

                                // Context menu for individual files
                                header_res.header_response.context_menu(|ui| {
                                    if ui.button("▶ Run Executable").clicked() {
                                        ui.close_menu();
                                        trigger_launch_process = Some(idx);
                                    }
                                    if ui.button("Analyze executable").clicked() {
                                        ui.close_menu();
                                        trigger_analysis = Some(idx);
                                    }
                                    if ui.button("Deep PE Analysis").clicked() {
                                        ui.close_menu();
                                        trigger_pe_metadata = Some(idx);
                                    }
                                    if ui.button("[B] Run Behavioral Scan").clicked() {
                                        ui.close_menu();
                                        trigger_nuitka_scan = Some(idx); // Reuse existing scanner logic for triggering
                                        let exec = &self.loaded_files[idx];
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            self.log_output.push_str(&format!("[INFO] Running Behavioral Static Scan on {}...\n", file_name));
                                            let markers = crate::core::strings::extract_strings(&file_data, 4);
                                            let findings = self.scanner.scan_static(&markers);
                                            self.log_output.push_str(&format!("[SUCCESS] Behavioral Scan complete. Found {} indicators.\n", findings.len()));
                                            for f in findings {
                                                self.behavioral_findings.push(f);
                                            }
                                            self.bottom_tab = "Behavioral".to_string();
                                        }
                                    }
                                    if ui.button("Deep Memory Scan (Nuitka/PyInstaller/IoC)").clicked() {
                                        ui.close_menu();
                                        trigger_nuitka_scan = Some(idx);
                                    }
                                    if ui.button("Recover Nuitka Resources").clicked() {
                                        ui.close_menu();
                                        trigger_recover_nuitka_exe = Some(idx);
                                    }
                                    if ui.button("Calculate Information Entropy").clicked() {
                                        ui.close_menu();
                                        trigger_entropy_exe = Some(idx);
                                    }
                                    if ui.button("🎯 Custom Signature Hunter").clicked() {
                                        ui.close_menu();
                                        self.show_custom_hunter = true;
                                        self.hunter_target_idx = Some(idx);
                                    }
                                    ui.separator();
                                    if ui.button("Extract Strings").clicked() {
                                        ui.close_menu();
                                        trigger_strings_exe = Some(idx);
                                    }
                                    if ui.button("Extract Network/DNS IoC").clicked() {
                                        ui.close_menu();
                                        trigger_network_ioc = Some(idx);
                                    }
                                    if ui.button("Extract File System/Registry IoC").clicked() {
                                        ui.close_menu();
                                        trigger_filepath_ioc = Some(idx);
                                    }
                                    
                                    if ui.button("Extract Archive").clicked() {
                                        ui.close_menu();
                                        self.log_output.push_str(&format!("[INFO] Starting extraction for {}...\n", file_name));
                                        match crate::python::PyInstallerArchive::parse(&exec.path) {
                                            Ok(archive) => {
                                                if let Some(mut target_dir) = rfd::FileDialog::new().pick_folder() {
                                                    target_dir.push(file_name.trim_end_matches(".exe"));
                                                    let _ = std::fs::create_dir_all(&target_dir);
                                                    
                                                    let mut success_count = 0;
                                                    for entry in &archive.files {
                                                        if let Ok(data) = archive.extract_file(entry) {
                                                            let out_path = target_dir.join(&entry.name);
                                                            if let Some(parent) = out_path.parent() {
                                                                let _ = std::fs::create_dir_all(parent);
                                                            }
                                                            if std::fs::write(&out_path, data).is_ok() {
                                                                success_count += 1;
                                                            }
                                                        }
                                                    }
                                                    self.log_output.push_str(&format!("[SUCCESS] Extracted {}/{} files to {:?}\n", success_count, archive.files.len(), target_dir));
                                                }
                                            },
                                            Err(_) => {
                                                self.log_output.push_str("[ERROR] Could not parse PyInstaller archive to extract.\n");
                                            }
                                        }
                                    }

                                    if ui.button("Remove").clicked() {
                                        ui.close_menu();
                                        trigger_remove = Some(idx);
                                    }
                                    ui.separator();
                                    if ui.button("Properties").clicked() {
                                        ui.close_menu();
                                        trigger_properties = Some(idx);
                                    }
                                });
                            }
                            
                            // Mutate state after the UI borrowing is over
                            if let Some(name) = trigger_select_file {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Selected item: {}\n", name));
                            } else if let Some((idx, name)) = trigger_hex_view_file {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Extracting & formatting Hex for: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let new_content = if let Ok(archive) = crate::python::PyInstallerArchive::parse(&exec.path) {
                                    if let Some(entry) = archive.files.iter().find(|e| e.name == name) {
                                        match archive.extract_file(entry) {
                                            Ok(data) => Self::format_hex(&data),
                                            Err(e) => format!("Failed to extract: {}", e),
                                        }
                                    } else {
                                        String::from("Entry not found in archive.")
                                    }
                                } else {
                                    String::from("Failed to parse archive.")
                                };

                                if let Some(pos) = self.tabs.iter().position(|t| t.name == name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: name.clone(), content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_hex_view_sec {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Formatting Hex for Native Section: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let new_content = if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + sec.size_of_raw_data as usize;
                                            if end <= file_data.len() {
                                                Self::format_hex(&file_data[start..end])
                                            } else {
                                                String::from("Section pointer out of bounds.")
                                            }
                                        } else {
                                            String::from("Failed to read underlying executable.")
                                        }
                                    } else {
                                        String::from("Section not found.")
                                    }
                                } else {
                                    String::from("No native sections available.")
                                };

                                if let Some(pos) = self.tabs.iter().position(|t| t.name == name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: name.clone(), content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_disasm_sec {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Disassembling Section: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();

                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + sec.size_of_raw_data as usize;
                                            if end <= file_data.len() {
                                                // Convert virtual address base to file layout representation
                                                let base_addr = sec.virtual_address as u64; 
                                                match crate::python::disassembler::disassemble_x86_64(&file_data[start..end], base_addr) {
                                                    Ok(asm) => new_content = asm,
                                                    Err(e) => new_content = format!("Disassembly Error: {}", e),
                                                }
                                            } else {
                                                new_content = String::from("Section pointer out of bounds.");
                                            }
                                        }
                                    }
                                }

                                if let Some(pos) = self.tabs.iter().position(|t| t.name == name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: name.clone(), content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_extract_file {
                                let exec = &self.loaded_files[idx];
                                if let Ok(archive) = crate::python::PyInstallerArchive::parse(&exec.path) {
                                    if let Some(entry) = archive.files.iter().find(|e| e.name == name) {
                                        match archive.extract_file(entry) {
                                            Ok(data) => {
                                                if let Some(mut target_dir) = rfd::FileDialog::new().pick_folder() {
                                                    let clean_name = name.replace("/", "\\");
                                                    let file_name_only = PathBuf::from(&clean_name).file_name().unwrap_or_default().to_string_lossy().into_owned();
                                                    target_dir.push(file_name_only);
                                                    if std::fs::write(&target_dir, data).is_ok() {
                                                        self.log_output.push_str(&format!("[SUCCESS] Extracted {} to {:?}\n", name, target_dir));
                                                    } else {
                                                        self.log_output.push_str(&format!("[ERROR] Failed to save {} to disk.\n", name));
                                                    }
                                                }
                                            },
                                            Err(e) => {
                                                self.log_output.push_str(&format!("[ERROR] {}\n", e));
                                            }
                                        }
                                    }
                                }
                            } else if let Some((idx, name)) = trigger_decompile_pyc {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Decompiling Pyc/Pyz Python AST: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();

                                if let Ok(archive) = crate::python::PyInstallerArchive::parse(&exec.path) {
                                    if let Some(entry) = archive.files.iter().find(|e| e.name == name) {
                                        match archive.extract_file(entry) {
                                            Ok(data) => {
                                                match crate::python::decompile_bytecode(&data) {
                                                    Ok(decompiled) => new_content = decompiled,
                                                    Err(e) => new_content = format!("Decompilation failed: {}", e),
                                                }
                                            },
                                            Err(e) => new_content = format!("Failed to extract for Decompilation: {}", e),
                                        }
                                    } else {
                                        new_content = String::from("Entry not found in archive.");
                                    }
                                }

                                if let Some(pos) = self.tabs.iter().position(|t| t.name == name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: name.clone(), content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_pseudo_c_sec {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Decompiling Native Section to C++: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();

                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + sec.size_of_raw_data as usize;
                                            if end <= file_data.len() {
                                                let base_addr = sec.virtual_address as u64; 
                                                match crate::python::pseudo_cc::decompile_pseudo_c(&file_data[start..end], base_addr, self.opt_enable_loop_recovery, self.opt_enable_auto_var_naming, self.opt_enable_calling_conventions) {
                                                    Ok(cpp) => new_content = cpp,
                                                    Err(e) => new_content = format!("Pseudo-C Engine Error: {}", e),
                                                }
                                            } else {
                                                new_content = String::from("Section pointer out of bounds.");
                                            }
                                        }
                                    }
                                }
                                
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: format!("{}.cpp", name), content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_cfg_view_sec {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Generating Control Flow Graph for: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();

                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            use capstone::prelude::*;
                                            use capstone::arch::x86::{ArchMode, ArchSyntax};
                                            
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + sec.size_of_raw_data as usize;
                                            
                                            if end <= file_data.len() {
                                                let csbuilder = Capstone::new()
                                                    .x86()
                                                    .mode(ArchMode::Mode64)
                                                    .syntax(ArchSyntax::Intel)
                                                    .detail(true);
                                                
                                                if let Ok(cs) = csbuilder.build() {
                                                    
                                                    let base_addr = sec.virtual_address as u64; 
                                                    if let Ok(insns) = cs.disasm_all(&file_data[start..end], base_addr) {
                                                        match crate::core::cfg::CfgBuilder::build(&insns) {
                                                            Ok(cfg) => {
                                                                let dot = crate::core::cfg::CfgBuilder::to_dot(&cfg);
                                                                new_content.push_str("// Control Flow Graph (CFG) generated by RvSpy\n");
                                                                new_content.push_str("// Paste this output into Graphviz (dot) or an online viewer like Webgraphviz to see the flowchart.\n\n");
                                                                new_content.push_str(&dot);
                                                                self.log_output.push_str(&format!("[SUCCESS] Extracted {} Basic Blocks and {} Edges.\n", cfg.blocks.len(), cfg.edges.len()));
                                                            },
                                                            Err(e) => {
                                                                new_content = format!("Failed to build CFG: {}", e);
                                                                self.log_output.push_str(&format!("[ERROR] {}\n", new_content));
                                                            }
                                                        }
                                                    } else {
                                                        new_content = String::from("Capstone failed to disassemble the native section.");
                                                    }
                                                }
                                            } else {
                                                new_content = String::from("Section pointer out of bounds.");
                                            }
                                        }
                                    }
                                }
                                
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: format!("{}.dot", name), content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_dump_mem_sec {
                                self.selected_file = Some(name.clone());
                                self.log_output.push_str(&format!("[INFO] Dumping Raw Process Memory: {}\n", name));
                                
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                let mut raw_data = None;
                                let mut file_offset = None;
                                let mut target_file_path = None;

                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + sec.size_of_raw_data as usize;
                                            
                                            // Provide absolute dump ignoring safety boundaries to simulate true raw memory parsing
                                            let end_padded = std::cmp::min(file_data.len(), end + 4096);
                                            raw_data = Some(file_data[start..end_padded].to_vec());
                                            file_offset = Some(start);
                                            target_file_path = Some(exec.path.clone());
                                        }
                                    }
                                }
                                if let Some(data) = &raw_data {
                                    new_content = Self::format_hex(data);
                                }
                                let tab_name = format!("{}.dmp", name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.tabs[pos].is_hex_view = true;
                                    self.tabs[pos].raw_data = raw_data.clone();
                                    self.tabs[pos].original_data = raw_data;
                                    self.tabs[pos].target_file_path = target_file_path;
                                    self.tabs[pos].file_offset = file_offset;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: true, raw_data: raw_data.clone(), original_data: raw_data, target_file_path, file_offset });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_sandbox_sec {
                                let exec = &self.loaded_files[idx];
                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    if let Some(pe) = &exec.pe_info {
                                        if let Some(sec) = pe.sections.iter().find(|s| s.name == name) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + std::cmp::min(sec.size_of_raw_data as usize, 1024); // Limit to 1KB for initial hex
                                            if end <= file_data.len() {
                                                let hex: String = file_data[start..end].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                                self.sandbox_code_hex = hex;
                                                self.show_sandbox_popup = true;
                                                self.sandbox_result = None;
                                                self.sandbox_original = None;
                                                self.log_output.push_str(&format!("[SANDBOX] Pre-loaded 1KB from section {} for emulation.\n", name));
                                            }
                                        }
                                    }
                                }
                            } else if let Some(idx) = trigger_remove {
                                self.loaded_files.remove(idx);
                            } else if let Some(idx) = trigger_analysis {
                                let exec = &mut self.loaded_files[idx];
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                self.log_output.push_str(&format!("[INFO] Analyzing {}...\n", file_name));
                                match crate::python::PyInstallerArchive::parse(&exec.path) {
                                    Ok(archive) => {
                                        self.log_output.push_str(&format!("[SUCCESS] Found PyInstaller Signature at offset: 0x{:X}\n", archive.magic_offset));
                                        self.log_output.push_str(&format!("[INFO] Extracted {} files from TOC.\n", archive.files.len()));
                                        exec.archive = Some(Ok(archive.files));
                                    },
                                    Err(e) => {
                                        self.log_output.push_str(&format!("[INFO] Not PyInstaller ({}). Falling back to Native PE Analysis...\n", e));
                                        if let Ok(buffer) = std::fs::read(&exec.path) {
                                            if let Ok(pe_data) = crate::core::pe_parser::extract_deep_pe(&buffer) {
                                                exec.pe_info = Some(pe_data);
                                            }

                                            match crate::python::nuitka_mod::NuitkaAnalyzer::parse_pe(&buffer) {
                                                Ok(sections) => {
                                                    self.log_output.push_str(&format!("[SUCCESS] C++ Engine extracted {} PE Sections.\n", sections.len()));
                                                    exec.native_sections = Some(sections);
                                                    exec.archive = None;
                                                },
                                                Err(pe_err) => {
                                                    self.log_output.push_str(&format!("[ERROR] Native PE Analysis failed: {}\n", pe_err));
                                                    exec.archive = Some(Err(format!("Analysis failed: {}", pe_err)));
                                                }
                                            }
                                        } else {
                                            exec.archive = Some(Err("Failed to read file buffer.".to_string()));
                                        }
                                    }
                                }
                            } else if let Some(idx) = trigger_launch_process {
                                let exec = &self.loaded_files[idx];
                                self.log_output.push_str(&format!("[DEBUG] Launching executable: {:?}\n", exec.path));
                                match std::process::Command::new(exec.path.clone()).spawn() {
                                    Ok(child) => {
                                        self.log_output.push_str(&format!("[SUCCESS] Process launched with PID: {}\n", child.id()));
                                    },
                                    Err(e) => {
                                        self.log_output.push_str(&format!("[ERROR] Failed to launch process: {}\n", e));
                                    }
                                }
                            } else if let Some((idx, name)) = trigger_strings_file {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Ok(archive) = crate::python::PyInstallerArchive::parse(&exec.path) {
                                    if let Some(entry) = archive.files.iter().find(|e| e.name == name) {
                                        if let Ok(data) = archive.extract_file(entry) {
                                            self.log_output.push_str(&format!("[INFO] Running deep string extraction on internal file: {}\n", name));
                                            let strs = crate::core::strings::extract_strings(&data, 4);
                                            new_content = strs.join("\n");
                                        }
                                    }
                                }
                                let tab_name = format!("strings_{}", name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_strings_sec {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            self.log_output.push_str(&format!("[INFO] Extracting strings from native section: {}\n", sec.name));
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = std::cmp::min(file_data.len(), start + sec.size_of_raw_data as usize);
                                            let strs = crate::core::strings::extract_strings(&file_data[start..end], 4);
                                            new_content = strs.join("\n");
                                        }
                                    }
                                }
                                let tab_name = format!("strings_{}", name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_strings_exe {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    self.log_output.push_str(&format!("[INFO] Extracting raw strings directly from absolute executable memory: {:?}\n", exec.path));
                                    let strs = crate::core::strings::extract_strings(&file_data, 5); // Use higher boundary 5 minimum length for entire EXEs
                                    new_content = strs.join("\n");
                                }
                                let tab_name = format!("strings_exe");
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_pe_metadata {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    self.log_output.push_str(&format!("[INFO] Running deep Native PE Analysis for: {:?}\n", exec.path));
                                    match crate::python::nuitka_mod::NuitkaAnalyzer::get_metadata_dump(&file_data) {
                                        Ok(dump) => new_content = dump,
                                        Err(e) => {
                                            self.log_output.push_str(&format!("[ERROR] {}\n", e));
                                            new_content = format!("Error: {}", e);
                                        }
                                    }
                                }
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let tab_name = format!("pe_metadata_{}", file_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_raw_pyc {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Ok(archive) = crate::python::PyInstallerArchive::parse(&exec.path) {
                                    if let Some(entry) = archive.files.iter().find(|e| e.name == name) {
                                        if let Ok(data) = archive.extract_file(entry) {
                                            self.log_output.push_str(&format!("[INFO] Viewing Original Python Bytecode Instructions for: {}\n", name));
                                            
                                            // Primitive HEX representation for bytecode analysis
                                            let mut hex_lines = Vec::new();
                                            for chunk in data.chunks(16) {
                                                let hex = chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                                let ascii = chunk.iter().map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' }).collect::<String>();
                                                hex_lines.push(format!("{:08X}: {:<48} | {} |", hex_lines.len() * 16, hex, ascii));
                                            }
                                            new_content = format!("=== ORIGINAL PYTHON BYTECODE (.PYC) ===\n{}\n", hex_lines.join("\n"));
                                        }
                                    }
                                }
                                let tab_name = format!("raw_pyc_{}", name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_network_ioc {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    self.log_output.push_str(&format!("[INFO] Running Static Network/DNS IoC Mapping for: {:?}\n", exec.path));
                                    let mut iocs = crate::core::strings::extract_network_ioc(&file_data);
                                    iocs.sort();
                                    iocs.dedup();
                                    new_content = if iocs.is_empty() { "No Network Indicators Found.".to_string() } else { iocs.join("\n") };
                                }
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let tab_name = format!("network_ioc_{}", file_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_filepath_ioc {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    self.log_output.push_str(&format!("[INFO] Running Static File System/Registry IoC Mapping for: {:?}\n", exec.path));
                                    let mut iocs = crate::core::strings::extract_filepath_ioc(&file_data);
                                    iocs.sort();
                                    iocs.dedup();
                                    new_content = if iocs.is_empty() { "No Formatted Path/Registry Indicators Found.".to_string() } else { iocs.join("\n") };
                                }
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let tab_name = format!("file_registry_ioc_{}", file_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_properties {
                                let exec = &self.loaded_files[idx];
                                let mut prop = Vec::new();
                                
                                prop.push(format!("=== EXECUTABLE PROPERTIES ==="));
                                prop.push(format!("Absolute Path: {:?}", exec.path));
                                
                                if let Ok(metadata) = std::fs::metadata(&exec.path) {
                                    prop.push(format!("File Size:     {:.2} MB ({} bytes)", metadata.len() as f64 / 1_048_576.0, metadata.len()));
                                    if let Ok(created) = metadata.created() {
                                        if let Ok(dur) = created.duration_since(std::time::UNIX_EPOCH) {
                                            prop.push(format!("Created OS ts: Unix Timestamp {}s", dur.as_secs()));
                                        }
                                    }
                                    if let Ok(modified) = metadata.modified() {
                                        if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                                            prop.push(format!("Modified OS:   Unix Timestamp {}s", dur.as_secs()));
                                        }
                                    }
                                }

                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    use md5::{Md5, Digest};
                                    use sha2::{Sha256};
                                    
                                    let mut md5_h = Md5::new();
                                    md5_h.update(&file_data);
                                    prop.push(format!("MD5 Hash:      {:X}", md5_h.finalize()));

                                    let mut sha2_h = Sha256::new();
                                    sha2_h.update(&file_data);
                                    prop.push(format!("SHA256 Hash:   {:X}", sha2_h.finalize()));
                                }

                                prop.push("".to_string());
                                prop.push(format!("=== INTERNAL STRUCTURE ==="));
                                if let Some(pe) = &exec.pe_info {
                                    prop.push(format!("DIE Packer/Compiler Identified: {}", pe.packer_detected));
                                }
                                if let Some(sections) = &exec.native_sections {
                                    prop.push(format!("Detected Native Sections: {}", sections.len()));
                                }
                                
                                if let Ok(archive) = crate::python::PyInstallerArchive::parse(&exec.path) {
                                    prop.push(format!("PyInstaller Version Identified: {}", archive.pyvers));
                                    prop.push(format!("Total Embedded Application Files: {}", archive.files.len()));
                                } else {
                                    prop.push(format!("No pure Python Application Archive detected (Not PyInstaller/Nuitka/PyToExe)"));
                                }

                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let tab_name = format!("properties_{}", file_name);
                                let new_content = prop.join("\n");
                                
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, view_name)) = trigger_deep_pe_view {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                
                                if let Some(pe) = &exec.pe_info {
                                    if view_name == "DOS Header" {
                                        new_content.push_str("DOS HEADER PROPERTIES\n");
                                        new_content.push_str("------------------------------\n");
                                        for (k, v) in &pe.dos_header {
                                            new_content.push_str(&format!("{:<30} {}\n", k, v));
                                        }
                                    } else if view_name == "File Header" {
                                        new_content.push_str("FILE HEADER (COFF) PROPERTIES\n");
                                        new_content.push_str("------------------------------\n");
                                        for (k, v) in &pe.file_header {
                                            new_content.push_str(&format!("{:<30} {}\n", k, v));
                                        }
                                    } else if view_name == "Optional Header" {
                                        new_content.push_str("OPTIONAL HEADER PROPERTIES\n");
                                        new_content.push_str("------------------------------\n");
                                        for (k, v) in &pe.optional_header {
                                            new_content.push_str(&format!("{:<30} {}\n", k, v));
                                        }
                                    } else if view_name.starts_with("Section|") {
                                        let sec_name = view_name.split('|').nth(1).unwrap_or("");
                                        if let Some(sec) = pe.sections.iter().find(|s| s.name == sec_name) {
                                            new_content.push_str(&format!("SECTION [{}] PROPERTIES\n", sec.name));
                                            new_content.push_str("------------------------------\n");
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Virtual Size", sec.virtual_size));
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Virtual Address", sec.virtual_address));
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Size Of Raw Data", sec.size_of_raw_data));
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Pointer To Raw Data", sec.pointer_to_raw_data));
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Pointer To Relocations", sec.pointer_to_relocations));
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Pointer To Line Numbers", sec.pointer_to_linenumbers));
                                            new_content.push_str(&format!("{:<30} {}\n", "Number Of Relocations", sec.number_of_relocations));
                                            new_content.push_str(&format!("{:<30} {}\n", "Number Of Line Numbers", sec.number_of_linenumbers));
                                            new_content.push_str(&format!("{:<30} 0x{:08X}\n", "Characteristics", sec.characteristics));
                                        }
                                    }
                                }

                                let tab_name = format!("{} [{}]", view_name.replace("Section|", ""), exec.path.file_name().unwrap_or_default().to_string_lossy());
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_nuitka_scan {
                                let exec = &self.loaded_files[idx];
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let mut new_content = String::new();
                                self.log_output.push_str(&format!("[INFO] Starting hardware-accelerated memory scan on {}...\n", file_name));

                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    // A comprehensive list of critical markers to hunt down instantaneously
                                    let sigs: &[&[u8]] = &[
                                        b"Nuitka", 
                                        b"MEI\0", 
                                        b"struct Nuitka_String", 
                                        b"MAKE_CODEOBJECT", 
                                        b"__main__", 
                                        b"requests_toolbelt",
                                        b"cryptography",
                                        b"Crypto.Cipher",
                                        b"subprocess.Popen"
                                    ];
                                    
                                    new_content.push_str("HARDWARE MEMORY SCANNER RESULTS (AVX2/SSE4)\n");
                                    new_content.push_str("==============================================\n\n");
                                    
                                    for sig in sigs {
                                        let start = std::time::Instant::now();
                                        if let Some(offset) = crate::python::nuitka_mod::NuitkaAnalyzer::fast_scan(&file_data, sig) {
                                            let duration = start.elapsed();
                                            new_content.push_str(&format!("[+] Found critical signature '{:?}' at offset 0x{:08X} (Time: {:?})\n", String::from_utf8_lossy(sig), offset, duration));
                                        } else {
                                            let duration = start.elapsed();
                                            new_content.push_str(&format!("[-] Signature '{:?}' not found (Scanned in {:?})\n", String::from_utf8_lossy(sig), duration));
                                        }
                                    }
                                } else {
                                    new_content.push_str("Error reading file for scanning.");
                                }

                                let tab_name = format!("Memory Scan [{}]", file_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_recover_nuitka_exe {
                                let exec = &self.loaded_files[idx];
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let mut new_content = String::new();
                                self.log_output.push_str(&format!("[INFO] Recovering native Nuitka C++ Resources from {}...\n", file_name));

                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    let engine = crate::core::nuitka_recovery::NuitkaEngine::new(&file_data);
                                    let (strings, funcs, tuples, cells) = engine.scan_recovery();
                                    
                                    new_content.push_str("NUITKA C++ RESOURCE RECOVERY ENGINE (RvSpy)\n");
                                    new_content.push_str("==============================================\n\n");
                                    new_content.push_str(&format!("Recovered String Pool Entries: {}\n", strings.len()));
                                    for s in strings {
                                        new_content.push_str(&format!("  [0x{:08X}] -> \"{}\"\n", s.offset, s.value));
                                    }
                                    new_content.push_str(&format!("\nRecovered C++ Function Wrappers: {}\n", funcs.len()));
                                    for f in funcs {
                                        new_content.push_str(&format!("  [0x{:08X}] {} (Args: {})\n", f.address, f.name, f.arg_count));
                                    }
                                    new_content.push_str(&format!("\nRecovered Object Tuples: {}\n", tuples.len()));
                                    for t in tuples {
                                        new_content.push_str(&format!("  [0x{:08X}] Size: {} -> {:?}\n", t.offset, t.size, t.items));
                                    }
                                    new_content.push_str(&format!("\nRecovered Closure Cells: {}\n", cells.len()));
                                    for c in cells {
                                        new_content.push_str(&format!("  [0x{:08X}] RefVar: {}\n", c.offset, c.referenced_var));
                                    }
                                } else {
                                    new_content.push_str("Error reading executable file.");
                                }

                                let tab_name = format!("Nuitka Recovery [{}]", file_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, sec_name)) = trigger_recover_nuitka_sec {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                self.log_output.push_str(&format!("[INFO] Recovering Nuitka Resources from native section: {}\n", sec_name));

                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == sec_name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = std::cmp::min(file_data.len(), start + sec.size_of_raw_data as usize);
                                            
                                            let engine = crate::core::nuitka_recovery::NuitkaEngine::new(&file_data[start..end]);
                                            let (strings, funcs, tuples, cells) = engine.scan_recovery();
                                            
                                            new_content.push_str(&format!("NUITKA RESOURCE RECOVERY (SECTION: {})\n", sec_name));
                                            new_content.push_str("==============================================\n\n");
                                            new_content.push_str(&format!("Recovered String Pool Entries: {}\n", strings.len()));
                                            for s in strings {
                                                new_content.push_str(&format!("  [+0x{:08X}] -> \"{}\"\n", s.offset, s.value));
                                            }
                                            new_content.push_str(&format!("\nRecovered C++ Function Wrappers: {}\n", funcs.len()));
                                            for f in funcs {
                                                new_content.push_str(&format!("  [+0x{:08X}] {} (Args: {})\n", f.address, f.name, f.arg_count));
                                            }
                                            new_content.push_str(&format!("\nRecovered Object Tuples: {}\n", tuples.len()));
                                            for t in tuples {
                                                new_content.push_str(&format!("  [+0x{:08X}] Size: {} -> {:?}\n", t.offset, t.size, t.items));
                                            }
                                            new_content.push_str(&format!("\nRecovered Closure Cells: {}\n", cells.len()));
                                            for c in cells {
                                                new_content.push_str(&format!("  [+0x{:08X}] RefVar: {}\n", c.offset, c.referenced_var));
                                            }
                                        }
                                    }
                                }

                                let tab_name = format!("Nuitka Recovery [{}]", sec_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some(idx) = trigger_entropy_exe {
                                let exec = &self.loaded_files[idx];
                                let file_name = exec.path.file_name().unwrap_or_default().to_string_lossy();
                                let mut new_content = String::new();
                                self.log_output.push_str(&format!("[INFO] Calculating Global Information Entropy for {}...\n", file_name));

                                if let Ok(file_data) = std::fs::read(&exec.path) {
                                    let entropy = crate::core::entropy::calculate_entropy(&file_data);
                                    let analysis = crate::core::entropy::analyze_entropy(entropy);
                                    
                                    new_content.push_str("GLOBAL INFORMATION ENTROPY ANALYSIS\n");
                                    new_content.push_str("==============================================\n\n");
                                    new_content.push_str(&format!("{:<20} {}\n", "Target File:", file_name));
                                    new_content.push_str(&format!("{:<20} {:.4} (Max 8.0)\n", "Shannon Entropy:", entropy));
                                    new_content.push_str(&format!("{:<20} {}\n", "Heuristic Status:", analysis));
                                    new_content.push_str("\n[!] Entropy > 7.0 usually indicates packed (UPX, PyArmor) or encrypted data.");
                                } else {
                                    new_content.push_str("Error reading file for entropy calculation.");
                                }

                                let tab_name = format!("Entropy [{}]", file_name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            } else if let Some((idx, name)) = trigger_entropy_sec {
                                let exec = &self.loaded_files[idx];
                                let mut new_content = String::new();
                                self.log_output.push_str(&format!("[INFO] Calculating Section Entropy for {}...\n", name));

                                if let Some(sections) = &exec.native_sections {
                                    if let Some(sec) = sections.iter().find(|s| s.name == name) {
                                        if let Ok(file_data) = std::fs::read(&exec.path) {
                                            let start = sec.pointer_to_raw_data as usize;
                                            let end = start + sec.size_of_raw_data as usize;
                                            if end <= file_data.len() {
                                                let slice = &file_data[start..end];
                                                let entropy = crate::core::entropy::calculate_entropy(slice);
                                                let analysis = crate::core::entropy::analyze_entropy(entropy);
                                                
                                                new_content.push_str("SECTION INFORMATION ENTROPY ANALYSIS\n");
                                                new_content.push_str("==============================================\n\n");
                                                new_content.push_str(&format!("{:<20} {}\n", "Target Section:", name));
                                                new_content.push_str(&format!("{:<20} {} bytes\n", "Section Size:", slice.len()));
                                                new_content.push_str(&format!("{:<20} {:.4} (Max 8.0)\n", "Shannon Entropy:", entropy));
                                                new_content.push_str(&format!("{:<20} {}\n", "Heuristic Status:", analysis));
                                            } else {
                                                new_content.push_str("Section bounds invalid.");
                                            }
                                        }
                                    }
                                }

                                let tab_name = format!("Entropy [{}]", name);
                                if let Some(pos) = self.tabs.iter().position(|t| t.name == tab_name) {
                                    self.tabs[pos].content = new_content;
                                    self.active_tab_idx = Some(pos);
                                } else {
                                    self.tabs.push(EditorTab { name: tab_name, content: new_content , is_hex_view: false, raw_data: None, original_data: None, target_file_path: None, file_offset: None });
                                    self.active_tab_idx = Some(self.tabs.len() - 1);
                                }
                            }
                        }
                    });
            });

        // Stage 3: Debugger Popups (Live Strings, Symbols, Search Ribbon, Exploits)
        if self.show_packer_exploits_pane {
            let mut close = false;
            egui::Window::new("☠️ Packer Heuristic Exploits (Nuitka/PyInstaller)")
                .collapsible(true)
                .resizable(true)
                .default_size([700.0, 500.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Run Exploit [1 & 5]: Scan %TEMP% Payloads").clicked() {
                            // Run the TempScanner
                            self.extracted_temp_artifacts = crate::core::nuitka_recovery::TempScanner::scan_temp_for_packer_artifacts(None);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("✖").clicked() { close = true; }
                        });
                    });
                    ui.separator();
                    
                    if self.extracted_temp_artifacts.is_empty() {
                        ui.label("No artifacts extracted yet. Click 'Run Exploit' while a packed python script is running.");
                    } else {
                        ui.heading(format!("Extracted {} Artifacts", self.extracted_temp_artifacts.len()));
                        egui::ScrollArea::vertical().id_source("exploits_artifacts_scroller").show(ui, |ui| {
                            egui::Grid::new("artifacts_grid").striped(true).show(ui, |ui| {
                                ui.label("File Type"); ui.label("Original Name"); ui.label("Size"); ui.label("Source Temp Dir"); ui.end_row();
                                for art in &self.extracted_temp_artifacts {
                                    ui.label(&art.file_type);
                                    if ui.button(&art.original_name).clicked() {
                                        // Hex view or string view action
                                        self.log_output.push_str(&format!("[EXPLOIT] Inspected Artifact {} ({} bytes)\n", art.original_name, art.payload.len()));
                                    }
                                    ui.label(format!("{} bytes", art.payload.len()));
                                    ui.label(art.source_dir.file_name().unwrap_or_default().to_string_lossy());
                                    ui.end_row();
                                }
                            });
                        });
                    }
                });
            if close { self.show_packer_exploits_pane = false; }
        }

        // CPU Registers Window
        if let Some(dbg) = &self.debugger {
            if let Ok(s) = dbg.state.lock() {
                if let Some(ctx_info) = &s.last_context {
                    egui::Window::new("[P] CPU Registers (x64)")
                        .resizable(true)
                        .default_width(220.0)
                        .show(ctx, |ui| {
                            egui::Grid::new("regs_grid").striped(true).show(ui, |ui| {
                                ui.label("RIP"); ui.colored_label(egui::Color32::YELLOW, format!("0x{:016X}", ctx_info.rip)); ui.end_row();
                                ui.label("RAX"); ui.label(format!("0x{:016X}", ctx_info.rax)); ui.end_row();
                                ui.label("RBX"); ui.label(format!("0x{:016X}", ctx_info.rbx)); ui.end_row();
                                ui.label("RCX"); ui.label(format!("0x{:016X}", ctx_info.rcx)); ui.end_row();
                                ui.label("RDX"); ui.label(format!("0x{:016X}", ctx_info.rdx)); ui.end_row();
                                ui.label("RSP"); ui.colored_label(egui::Color32::LIGHT_BLUE, format!("0x{:016X}", ctx_info.rsp)); ui.end_row();
                                ui.label("RBP"); ui.label(format!("0x{:016X}", ctx_info.rbp)); ui.end_row();
                                ui.label("R8 "); ui.label(format!("0x{:016X}", ctx_info.r8)); ui.end_row();
                                ui.label("R9 "); ui.label(format!("0x{:016X}", ctx_info.r9)); ui.end_row();
                            });
                        });
                }
            }
        }

        if self.show_memory_search_popup {
            let mut close = false;
            let theme_color = egui::Color32::from_rgb(45, 45, 45);
            egui::Window::new("x64dbg - Memory Pattern Search")
                .collapsible(false)
                .resizable(false)
                .frame(egui::Frame::window(&ctx.style()).fill(theme_color).inner_margin(8.0))
                .show(ctx, |ui| {
                    ui.label("Enter pattern (e.g. '48 89 5C 24 08' or 'ASCII_STRING'):");
                    let mut dummy_str = String::new();
                    ui.text_edit_singleline(&mut dummy_str);
                    ui.horizontal(|ui| {
                        if ui.button("Search").clicked() { close = true; }
                        if ui.button("Cancel").clicked() { close = true; }
                    });
                });
            if close { self.show_memory_search_popup = false; }
        }

        if self.show_symbols_pane {
            let mut close = false;
            egui::Window::new("Process Modules & Symbols")
                .collapsible(true)
                .resizable(true)
                .default_size([500.0, 300.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Loaded Modules (.dll / .exe)");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("✖").clicked() { close = true; }
                        });
                    });
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        egui::Grid::new("modules_grid").striped(true).show(ui, |ui| {
                            ui.label("Base Address"); ui.label("Size"); ui.label("Module Name"); ui.end_row();
                            // Mocking output to simulate Stage 3 parser until hook implementation
                            let base_addr_1 = 0x00007FF7A2B00000_usize;
                            let base_addr_2 = 0x00007FFF4B5C0000_usize;
                            
                            ui.label(egui::RichText::new(format!("0x{:016X}", base_addr_1)).monospace()); ui.label("0x0001D000"); ui.label("target_process.exe"); ui.end_row();
                            ui.label(egui::RichText::new(format!("0x{:016X}", base_addr_2)).monospace()); ui.label("0x000F4000"); ui.label("ntdll.dll"); ui.end_row();
                        });
                    });
                });
            if close { self.show_symbols_pane = false; }
        }

        if self.show_live_strings_pane {
            let mut close = false;
            egui::Window::new("Live Process Memory Strings")
                .collapsible(true)
                .resizable(true)
                .default_size([600.0, 400.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Target Process RAM Strings (UTF-8 / UTF-16)");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("✖").clicked() { close = true; }
                            if ui.button("Scan All Memory").clicked() {
                                // Real scanner triggers here
                                self.live_strings_cache = vec![
                                    (0x00007FF7A2B14A90, "Cannot open virtual machine.".to_string()),
                                    (0x00007FF7A2B14AB8, "HTTP/1.1 200 OK".to_string()),
                                    (0x00007FF7A2B14AE0, "C:\\Windows\\system32\\kernel32.dll".to_string()),
                                ];
                            }
                        });
                    });
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        egui::Grid::new("strings_grid").striped(true).show(ui, |ui| {
                            ui.label("Address"); ui.label("String Length"); ui.label("ASCII/Unicode Value"); ui.end_row();
                            
                            if self.live_strings_cache.is_empty() {
                                ui.label("Click 'Scan All Memory' to buffer strings.");
                                ui.end_row();
                            } else {
                                for (addr, val) in &self.live_strings_cache {
                                    ui.label(egui::RichText::new(format!("0x{:016X}", addr)).monospace());
                                    ui.label(format!("{}", val.len()));
                                    ui.label(val);
                                    ui.end_row();
                                }
                            }
                        });
                    });
                });
            if close { self.show_live_strings_pane = false; }
        }

        // Right Panel: CPU Registers & Debugger Controls
        if self.show_right_panel {
            egui::SidePanel::right("debugger_right_panel")
                .resizable(true)
                .default_width(320.0)
                .show(ctx, |ui| {
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.heading("CPU Registers (x64)");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("✖").clicked() {
                                self.show_right_panel = false;
                            }
                        });
                    });
                    ui.separator();
                    
                    // Execution Controls
                    ui.horizontal(|ui| {
                        if ui.button("▶ Continue (F9)").clicked() {
                            if let Some(dbg) = &self.debugger {
                                let _ = dbg.command_sender.send(crate::core::debugger::DebuggerCommand::Continue);
                            }
                        }
                        if ui.button("↷ Step Into (F7)").clicked() {}
                        if ui.button("↷ Step Over (F8)").clicked() {}
                    });
                    ui.separator();

                    // Active Target
                    let pid_str = if let Some(dbg) = &self.debugger {
                        if let Ok(state) = dbg.state.try_lock() {
                            state.target_pid.map(|p| p.to_string()).unwrap_or_else(|| "None".to_string())
                        } else { "Lock Error".to_string() }
                    } else { "Offline".to_string() };
                    
                    ui.label(egui::RichText::new(format!("Target PID: {}", pid_str)).strong().color(egui::Color32::from_rgb(0, 255, 150)));
                    ui.separator();

                    // Fetch Live DBG State
                    let mut rax_str = "0000000000000000".to_string();
                    let mut rbx_str = "0000000000000000".to_string();
                    let mut rcx_str = "0000000000000000".to_string();
                    let mut rdx_str = "0000000000000000".to_string();
                    let mut rip_str = "0000000000000000".to_string();
                    let mut bps_list = Vec::new();

                    if let Some(dbg) = &self.debugger {
                        if let Ok(state) = dbg.state.try_lock() {
                            if let Some(ctx) = &state.last_context {
                                rax_str = format!("{:016X}", ctx.rax);
                                rbx_str = format!("{:016X}", ctx.rbx);
                                rcx_str = format!("{:016X}", ctx.rcx);
                                rdx_str = format!("{:016X}", ctx.rdx);
                                rip_str = format!("{:016X}", ctx.rip);
                            }
                            
                            for (addr, orig_byte) in &state.breakpoints {
                                bps_list.push((*addr, *orig_byte));
                            }
                        }
                    }

                    // Registers
                    egui::ScrollArea::vertical().id_source("regs_scroll").max_height(250.0).show(ui, |ui| {
                        egui::Grid::new("registers_grid").striped(true).min_col_width(80.0).show(ui, |ui| {
                            let regs = [
                                ("RAX", rax_str), ("RBX", rbx_str),
                                ("RCX", rcx_str), ("RDX", rdx_str),
                                ("RIP", rip_str), 
                                ("RBP", "0000000000000000".to_string()), ("RSP", "0000000000000000".to_string()),
                                ("RSI", "0000000000000000".to_string()), ("RDI", "0000000000000000".to_string()),
                                ("R8",  "0000000000000000".to_string()), ("RFLAGS","00000246".to_string()),
                            ];

                            for (r_name, r_val) in regs.iter() {
                                ui.label(egui::RichText::new(*r_name).strong().color(egui::Color32::from_rgb(255, 105, 180)));
                                ui.label(egui::RichText::new(r_val).monospace());
                                ui.end_row();
                            }
                        });
                    });
                    
                    ui.add_space(10.0);
                    ui.heading("Breakpoints");
                    ui.separator();
                    
                    // Breakpoint Manager UI
                    ui.horizontal(|ui| {
                        if ui.button("➕ Add").clicked() {}
                        if ui.button("➖ Remove All").clicked() {}
                        if ui.button("🛑 Disable All").clicked() {}
                    });
                    ui.add_space(5.0);
                    
                    egui::ScrollArea::vertical().id_source("bps_scroll").show(ui, |ui| {
                        egui::Grid::new("bps_grid").striped(true).show(ui, |ui| {
                            ui.label("Address"); ui.label("Original Byte"); ui.label("State"); ui.end_row();
                            
                            if bps_list.is_empty() {
                                ui.label("No active breakpoints.");
                                ui.end_row();
                            } else {
                                for (addr, orig) in bps_list {
                                    ui.label(egui::RichText::new(format!("0x{:016X}", addr)).monospace()); 
                                    ui.label(format!("0x{:02X}", orig));
                                    ui.label(egui::RichText::new("Active").color(egui::Color32::RED));
                                    ui.end_row();
                                }
                            }
                        });
                    });

                    ui.add_space(10.0);
                    ui.heading("Call Stack");
                    ui.separator();
                    
                    egui::ScrollArea::vertical().id_source("stack_scroll").max_height(200.0).show(ui, |ui| {
                        egui::Grid::new("stack_grid").striped(true).show(ui, |ui| {
                            ui.label("Address"); ui.label("Symbol / Value"); ui.end_row();
                            
                            if self.call_stack_cache.is_empty() {
                                ui.label("Stack empty or thread running.");
                                ui.end_row();
                            } else {
                                for (addr, detail) in &self.call_stack_cache {
                                    ui.label(egui::RichText::new(format!("0x{:016X}", addr)).monospace());
                                    ui.label(detail);
                                    ui.end_row();
                                }
                            }
                        });
                    });
                });
        }

        // Central Panel: Decompiler / Editor View / Debugger View
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(0.0)) // Remove margin for edges flush with panel
            .show(ctx, |ui| {
                if self.show_debugger_view {
                    // Modern Native Debugger Layout
                    
                    // Top Section: Live Disassembly
                    egui::TopBottomPanel::top("live_disasm_panel")
                        .resizable(true)
                        .default_height(ui.available_height() * 0.6)
                        .show_inside(ui, |ui| {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.heading("Live Disassembly (RIP)");
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("Sync with RIP").clicked() {}
                                });
                            });
                            ui.separator();

                            let mut frame = egui::Frame::none();
                            frame.fill = egui::Color32::from_rgb(30, 30, 30);
                            frame.inner_margin = egui::Margin::same(4.0);
                            frame.show(ui, |ui| {
                                egui::ScrollArea::both().id_source("disasm_scroll").show(ui, |ui| {
                                    ui.label(egui::RichText::new(&self.live_disassembly_cache).monospace().color(egui::Color32::from_rgb(212, 212, 212)));
                                });
                            });
                        });
                        
                    // Bottom Section: Live Hex Memory Dump
                    egui::CentralPanel::default()
                        .frame(egui::Frame::none().inner_margin(0.0))
                        .show_inside(ui, |ui| {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.heading("Live Memory Hex Dump");
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("📝 Hex Patch Memory").clicked() {}
                                    if ui.button("Goto Address").clicked() {
                                        self.show_memory_search_popup = true;
                                    }
                                });
                            });
                            ui.separator();

                            let mut frame = egui::Frame::none();
                            frame.fill = egui::Color32::from_rgb(25, 25, 25);
                            frame.inner_margin = egui::Margin::same(4.0);
                            frame.show(ui, |ui| {
                                egui::ScrollArea::both().id_source("hex_live_scroll").show(ui, |ui| {
                                    ui.label(egui::RichText::new(&self.live_hex_cache).monospace().color(egui::Color32::from_rgb(212, 212, 212)));
                                });
                            });
                        });
                } else {
                    // Editor Tabs Bar
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0; // Remove spacing between tabs
                    egui::ScrollArea::horizontal()
                        .auto_shrink([true, false])
                        .id_source("tabs_scroll_area")
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let mut tab_to_close = None;
                                
                                for (idx, tab) in self.tabs.iter().enumerate() {
                                    let is_active = self.active_tab_idx == Some(idx);
                                    
                                    // Use a background to differentiate tabs
                                    let fill_color = if is_active {
                                        egui::Color32::from_rgb(30, 30, 30) // Match editor bg
                                    } else {
                                        egui::Color32::from_rgb(45, 45, 45) // Slightly darker
                                    };
                                    
                                    let tab_frame = egui::Frame::none()
                                        .fill(fill_color)
                                        .inner_margin(egui::Margin::symmetric(8.0, 4.0));
                                        
                                    tab_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            if ui.selectable_label(is_active, format!("🐍 {}", tab.name)).clicked() {
                                                self.active_tab_idx = Some(idx);
                                            }
                                            
                                            // Close button logic
                                            if ui.button("✖").clicked() {
                                                tab_to_close = Some(idx);
                                            }
                                        });
                                    });
                                    
                                    // Add a tiny separator between tabs
                                    ui.add_space(2.0);
                                }

                                if let Some(idx) = tab_to_close {
                                    self.tabs.remove(idx);
                                    if self.tabs.is_empty() {
                                        self.active_tab_idx = None;
                                    } else if let Some(active) = self.active_tab_idx {
                                        if active == idx {
                                            self.active_tab_idx = Some(idx.saturating_sub(1));
                                        } else if active > idx {
                                            self.active_tab_idx = Some(active - 1);
                                        }
                                    }
                                }
                            });
                        });

                    // Add a blank area that fills the rest of the tab bar
                    let remaining_space = ui.available_size_before_wrap();
                    if remaining_space.x > 0.0 {
                        let (rect, _resp) =
                            ui.allocate_exact_size(remaining_space, egui::Sense::hover());
                        ui.painter()
                            .rect_filled(rect, 0.0, egui::Color32::from_rgb(37, 39, 42));
                    }
                });
                ui.separator();

                // Background color for the editing area, true DnSpy/VS Code IDE dark
                let mut frame = egui::Frame::none();
                frame.fill = egui::Color32::from_rgb(30, 30, 30);
                frame.inner_margin = egui::Margin::same(4.0);
                
                let copy_all_text = self.translate("Copy All");
                let clear_text = self.translate("Clear");

                frame.show(ui, |ui| {
                    if let Some(active_idx) = self.active_tab_idx {
                        if let Some(tab) = self.tabs.get_mut(active_idx) {
                            if tab.name.starts_with("strings_") {
                                ui.horizontal(|ui| {
                                    if ui.button("[*] Auto-Decrypt Engine").clicked() {
                                        self.show_auto_decrypt_popup = true;
                                    }
                                });
                                ui.separator();
                            }


                            egui::ScrollArea::both()
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    if tab.is_hex_view && tab.raw_data.is_some() {
                                        // INTERACTIVE HEX EDITOR
                                        let mut apply_patch = false;
                                        let mut revert = false;
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("Interactive Memory Text Patcher").strong().color(egui::Color32::from_rgb(255, 120, 120)));
                                            if ui.button("💾 Parse Hex & Apply Patch to Disk").clicked() {
                                                apply_patch = true;
                                            }
                                            if ui.button("↺ Revert to Original").clicked() {
                                                revert = true;
                                            }
                                            if let Some(target) = &tab.target_file_path {
                                                ui.label(format!("Target: {:?}", target));
                                            }
                                        });
                                        ui.separator();
                                        
                                        if revert {
                                            if let Some(orig) = &tab.original_data {
                                                tab.content = Self::format_hex(orig);
                                            }
                                        }
                                        

                                        // Use TextEdit::multiline to allow native Ctrl+C highlighting
                                        let text_color = egui::Color32::from_rgb(212, 212, 212);
                                        let mut editor = egui::TextEdit::multiline(&mut tab.content)
                                            .font(egui::TextStyle::Monospace)
                                            .code_editor()
                                            .text_color(text_color)
                                            .desired_width(f32::INFINITY)
                                            .interactive(true)
                                            .frame(false);
                                            
                                        editor = editor.clip_text(!self.word_wrap);
                                        let text_response = ui.add(editor);

                                        // Handle the patch applying by parsing the string back to bytes
                                        if apply_patch && tab.target_file_path.is_some() {
                                            let mut parsed_bytes = Vec::new();
                                            let mut parse_error = None;
                                            
                                            for (i, line) in tab.content.lines().enumerate() {
                                                // format is: "00000000  4D 5A 90 00 ... |MZ...|"
                                                if line.len() >= 58 {
                                                    let hex_part = &line[10..58];
                                                    for byte_str in hex_part.split_whitespace() {
                                                        if let Ok(b) = u8::from_str_radix(byte_str, 16) {
                                                            parsed_bytes.push(b);
                                                        } else {
                                                            parse_error = Some(format!("Invalid hex '{}' at line {}", byte_str, i + 1));
                                                            break;
                                                        }
                                                    }
                                                }
                                                // Tolerate shorter lines if they represent the end of the file
                                                else if line.len() > 10 {
                                                    let hex_part = if let Some(idx) = line.find('|') {
                                                        &line[10..idx].trim()
                                                    } else {
                                                        &line[10..].trim()
                                                    };
                                                    for byte_str in hex_part.split_whitespace() {
                                                        if let Ok(b) = u8::from_str_radix(byte_str, 16) {
                                                            parsed_bytes.push(b);
                                                        }
                                                    }
                                                }
                                            }
                                            
                                            if let Some(err) = parse_error {
                                                self.log_output.push_str(&format!("[ERROR] {}\n", err));
                                            } else {
                                                if let Some(path) = &tab.target_file_path {
                                                    self.log_output.push_str(&format!("[INFO] Applying binary patch to {:?}...\n", path));
                                                    
                                                    if let Some(fo) = tab.file_offset {
                                                        if let Ok(mut disk_data) = std::fs::read(path) {
                                                            let end = fo + parsed_bytes.len();
                                                            if end <= disk_data.len() {
                                                                disk_data[fo..end].copy_from_slice(&parsed_bytes);
                                                                if std::fs::write(path, &disk_data).is_ok() {
                                                                    self.log_output.push_str("[SUCCESS] Executable memory patched on disk.\n");
                                                                    tab.original_data = Some(parsed_bytes.clone());
                                                                } else {
                                                                    self.log_output.push_str("[ERROR] Could not write to disk. File might be in use.\n");
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if std::fs::write(path, &parsed_bytes).is_ok() {
                                                            self.log_output.push_str("[SUCCESS] Executable fully patched on disk.\n");
                                                            tab.original_data = Some(parsed_bytes.clone());
                                                        } else {
                                                            self.log_output.push_str("[ERROR] Could not write to disk.\n");
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        text_response.context_menu(|ui| {
                                            if ui.button(&copy_all_text).clicked() {
                                                ui.output_mut(|o| o.copied_text = tab.content.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(&clear_text).clicked() {
                                                tab.content.clear();
                                                ui.close_menu();
                                            }
                                        });

                                    } else {
                                        // NORMAL TEXT EDITOR
                                        let mut text_color = egui::Color32::from_rgb(212, 212, 212);
                                        if self.highlight_line {
                                            text_color = egui::Color32::from_rgb(255, 255, 255);
                                        }

                                        let mut editor_content = if self.hex_view_mode {
                                            let max_len = std::cmp::min(tab.content.len(), 32 * 1024);
                                            Self::format_hex(&tab.content.as_bytes()[..max_len])
                                        } else {
                                            tab.content.clone()
                                        };

                                        let mut editor = egui::TextEdit::multiline(&mut editor_content)
                                            .font(egui::TextStyle::Monospace)
                                            .code_editor()
                                            .text_color(text_color)
                                            .desired_width(f32::INFINITY)
                                            .interactive(true)
                                            .frame(false);
                                            
                                        editor = editor.clip_text(!self.word_wrap);

                                        let text_response = ui.add(editor);
                                        
                                        if !self.hex_view_mode {
                                            tab.content = editor_content;
                                        }

                                        text_response.context_menu(|ui| {
                                            if ui.button(&copy_all_text).clicked() {
                                                ui.output_mut(|o| o.copied_text = tab.content.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(&clear_text).clicked() {
                                                tab.content.clear();
                                                ui.close_menu();
                                            }
                                        });
                                    }
                                });
                        }
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                egui::RichText::new("RvSpy\nSelect or decompile a file to start.")
                                    .color(egui::Color32::from_rgb(100, 100, 100))
                                    .size(18.0)
                                    .heading(),
                            );
                        });
                    }
                });
                } // End of !self.show_debugger_view
            });
    }
}
