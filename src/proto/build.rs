fn main() {
    tonic_build::configure()
        .build_server(true)
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .compile(
            &[
                "proto/base.proto",
                "proto/session.proto",
                "proto/mutation.proto",
                "proto/bill.proto",
                "proto/account.proto",
                "proto/node.proto",
                "proto/database.proto",
                "proto/message.proto",
                "proto/faucet.proto",
                "proto/event.proto",
            ],
            &["proto"],
        )
        .unwrap();
}