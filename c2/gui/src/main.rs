use std::sync::{Arc, Mutex};

pub struct AppState {
    pub clients: Arc<Mutex<Vec<String>>>,
    pub logs: Arc<Mutex<Vec<String>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            clients: Arc::new(Mutex::new(vec![])),
            logs: Arc::new(Mutex::new(vec!["System initialized...".to_string()])),
        }
    }
}

#[tauri::command]
pub fn add_client(state: tauri::State<AppState>, id: String) -> String {
    let mut clients = state.clients.lock().unwrap();
    clients.push(id);
    let msg = format!("Added client {}", id);
    let mut logs = state.logs.lock().unwrap();
    logs.push(msg.clone());
    msg
}

#[tauri::command]
pub fn get_clients(state: tauri::State<AppState>) -> Vec<String> {
    let clients = state.clients.lock().unwrap();
    clients.clone()
}

#[tauri::command]
pub fn get_logs(state: tauri::State<AppState>) -> Vec<String> {
    let logs = state.logs.lock().unwrap();
    logs.clone()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![add_client, get_clients, get_logs])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
