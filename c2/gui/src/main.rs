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

impl AppState {
    fn add_client(&self, id: &str) -> String {
        let mut clients = self.clients.lock().expect("AppState lock poisoned");
        clients.push(id.to_string());
        let msg = format!("Added client {id}");
        let mut logs = self.logs.lock().expect("AppState lock poisoned");
        logs.push(msg.clone());
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::AppState;

    #[test]
    fn adding_a_client_updates_clients_and_logs() {
        let state = AppState::default();
        let message = state.add_client("agent-1");

        assert_eq!(message, "Added client agent-1");
        assert_eq!(state.clients.lock().unwrap().as_slice(), ["agent-1"]);
        assert_eq!(
            state.logs.lock().unwrap().last().map(String::as_str),
            Some("Added client agent-1")
        );
    }
}

#[tauri::command]
fn add_client(state: tauri::State<'_, AppState>, id: String) -> String {
    let message = state.add_client(&id);
    log::info!("Added client {id}");
    message
}

#[tauri::command]
fn get_clients(state: tauri::State<'_, AppState>) -> Vec<String> {
    let clients = state.clients.lock().expect("AppState lock poisoned");
    clients.clone()
}

#[tauri::command]
fn get_logs(state: tauri::State<'_, AppState>) -> Vec<String> {
    let logs = state.logs.lock().expect("AppState lock poisoned");
    logs.clone()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![add_client, get_clients, get_logs])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
