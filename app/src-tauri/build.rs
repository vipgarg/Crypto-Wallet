// The reviewed list of UI→core commands (ARCHITECTURE.md §9.1). Each one gets
// an `allow-<name>` permission; only those listed in capabilities/main.json are
// callable. The test in src/commands.rs fails if a command is added in code but
// not here.
const COMMANDS: &[&str] = &[
    "list_wallets",
    "add_wallet",
    "remove_wallet",
    "get_portfolio",
    "app_info",
    "get_progress",
    "get_activity",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build configuration");
}
