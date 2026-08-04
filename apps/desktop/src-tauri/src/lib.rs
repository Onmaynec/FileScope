use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Открыть FileScope", true, None::<&str>)?;
            let scan_link = MenuItem::with_id(app, "scan_link", "Проверить ссылку", true, None::<&str>)?;
            let select_file = MenuItem::with_id(app, "select_file", "Выбрать файл", true, None::<&str>)?;
            let settings = MenuItem::with_id(app, "settings", "Настройки", true, None::<&str>)?;
            let updates = MenuItem::with_id(app, "updates", "Проверить обновления", true, None::<&str>)?;
            let first_separator = PredefinedMenuItem::separator(app)?;
            let second_separator = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&open, &first_separator, &scan_link, &select_file, &settings, &updates, &second_separator, &quit],
            )?;

            let app_handle = app.handle().clone();
            TrayIconBuilder::new()
                .tooltip("FileScope")
                .menu(&menu)
                .on_menu_event(move |_tray, event| match event.id.as_ref() {
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
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("не удалось запустить FileScope");
}
