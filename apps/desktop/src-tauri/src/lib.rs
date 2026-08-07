mod analysis;
#[cfg(not(feature = "fuzzing"))]
mod history_storage;
#[cfg(not(feature = "fuzzing"))]
mod window_lifecycle;

#[cfg(feature = "fuzzing")]
pub use analysis::fuzzing;

#[cfg(not(feature = "fuzzing"))]
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};
#[cfg(not(feature = "fuzzing"))]
use window_lifecycle::{CloseBehavior, WindowLifecycleState};

#[cfg(not(feature = "fuzzing"))]
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(not(feature = "fuzzing"))]
#[tauri::command]
fn set_close_behavior(behavior: CloseBehavior, state: tauri::State<'_, WindowLifecycleState>) {
    state.set_close_behavior(behavior);
}

#[cfg(not(feature = "fuzzing"))]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(WindowLifecycleState::default())
        .manage(analysis::JobRegistry::default())
        .manage(history_storage::HistoryStorageState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            analysis::analyze_local_file,
            analysis::analyze_local_archive,
            analysis::analyze_url_passive,
            analysis::analyze_url_active,
            analysis::cancel_analysis,
            analysis::inspect_local_paths,
            analysis::get_analysis_metadata,
            history_storage::history_load,
            history_storage::history_inspect,
            history_storage::history_save_report,
            history_storage::history_replace_all,
            history_storage::history_delete_report,
            history_storage::history_clear,
            set_close_behavior,
        ])
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }

            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let state = window.state::<WindowLifecycleState>();

                match state.close_behavior() {
                    CloseBehavior::Tray => {
                        let _ = window.hide();
                    }
                    CloseBehavior::Quit => window.app_handle().exit(0),
                }
            }
        })
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Открыть FileScope", true, None::<&str>)?;
            let scan_link =
                MenuItem::with_id(app, "scan_link", "Проверить ссылку", true, None::<&str>)?;
            let select_file =
                MenuItem::with_id(app, "select_file", "Выбрать файл", true, None::<&str>)?;
            let settings = MenuItem::with_id(app, "settings", "Настройки", true, None::<&str>)?;
            let updates =
                MenuItem::with_id(app, "updates", "Проверить обновления", true, None::<&str>)?;
            let first_separator = PredefinedMenuItem::separator(app)?;
            let second_separator = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &open,
                    &first_separator,
                    &scan_link,
                    &select_file,
                    &settings,
                    &updates,
                    &second_separator,
                    &quit,
                ],
            )?;

            let app_handle = app.handle().clone();
            let mut tray_builder = TrayIconBuilder::new()
                .tooltip("FileScope")
                .menu(&menu)
                .on_menu_event(move |_app, event| match event.id.as_ref() {
                    "open" => show_main_window(&app_handle),
                    "scan_link" => {
                        show_main_window(&app_handle);
                        let _ = app_handle.emit("filescope:navigate", "links");
                    }
                    "select_file" => {
                        show_main_window(&app_handle);
                        let _ = app_handle.emit("filescope:select-file", ());
                    }
                    "settings" | "updates" => {
                        show_main_window(&app_handle);
                        let _ = app_handle.emit("filescope:navigate", "settings");
                    }
                    "quit" => app_handle.exit(0),
                    _ => {}
                });

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }
            tray_builder.build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("не удалось запустить FileScope");
}
