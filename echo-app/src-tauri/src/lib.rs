mod commands;
mod events;
mod poller;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "echo_app=info".into()),
        )
        .init();

    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::auth::create_account,
            commands::auth::sign_on,
            commands::auth::sign_off,
            commands::auth::vault_exists,
            commands::auth::generate_invites,
            commands::session::establish_session,
            commands::messaging::send_message,
            commands::messaging::load_chat_history,
            commands::messaging::mark_messages_read,
            commands::messaging::send_typing_indicator,
            commands::messaging::get_device_id,
            commands::messaging::send_file,
            commands::messaging::set_auto_delete,
            commands::messaging::get_auto_delete,
            commands::messaging::edit_message,
            commands::messaging::delete_message_cmd,
            commands::contacts::add_buddy,
            commands::contacts::remove_buddy,
            commands::contacts::list_buddies,
            commands::contacts::lookup_code,
            commands::contacts::get_short_code,
            commands::profile::update_profile,
            commands::profile::fetch_profile,
            commands::profile::check_screen_name,
            commands::profile::set_screen_name,
            commands::profile::get_screen_name,
            commands::groups::create_group,
            commands::groups::list_groups,
            commands::groups::send_group_message,
            commands::groups::load_group_history,
            commands::groups::leave_group,
        ])
        .setup(|app| {
            poller::start_poller(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running ECHO");
}
