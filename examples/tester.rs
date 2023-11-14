//! This executable is used to for integration testing the library using:
//! https://github.com/portier/client-tester

use portier::Client;
use tokio::io::{self, AsyncBufReadExt};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let broker = std::env::args()
        .nth(1)
        .expect("broker required")
        .parse()
        .expect("invalid broker");
    let redirect_uri = "http://imaginary-client.test/fake-verify-route"
        .parse()
        .unwrap();
    let client = Client::builder(redirect_uri)
        .broker(broker)
        .build()
        .expect("could not build Portier client");

    let mut lines = io::BufReader::new(io::stdin()).lines();
    while let Some(line) = lines.next_line().await.expect("stdin error") {
        let cmd: Vec<_> = line.split('\t').collect();
        match cmd[0] {
            "echo" => println!("ok\t{}", cmd[1]),
            "auth" => match client.start_auth(&cmd[1]).await {
                Ok(url) => println!("ok\t{}", url),
                Err(err) => println!("err\t{}", err),
            },
            "verify" => match client.verify(&cmd[1]).await {
                Ok(url) => println!("ok\t{}", url),
                Err(err) => println!("err\t{}", err),
            },
            cmd => panic!("invalid command: {}", cmd),
        }
    }
}
