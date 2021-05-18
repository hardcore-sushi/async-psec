[PSEC](https://github.com/hardcore-sushi/PSEC) (Peer-to-peer Secure Ephemeral Communications) is a simplification/adaptation of TLS 1.3 for P2P networks which provides an encrypted and authenticated secure transport layer for ephemeral communications. PSEC ensures deniability, forward secrecy, future secrecy, and optional plaintext length obfuscation. This crate is an implementation of this protocol built in [rust](https://www.rust-lang.org) with the [tokio](https://tokio.rs) framework.

# Disclaimer
Neither the code of this crate or the PSEC protocol received any security audit and therefore shouldn't be considered fully secure. This software is provided "as is", without any warranty of any kind.

# Example
```rust
use rand::rngs::OsRng;
use tokio::net::TcpStream;
use async_psec::{Session, Identity, PsecReader, PsecWriter, PsecError};

#[tokio::main]
async fn main() -> Result<(), PsecError> {
    let identity = Identity::generate(&mut OsRng); //generate a new PSEC identity

    //connect to another PSEC node listening on 10.152.152.10:7530
    let stream = TcpStream::connect("10.152.152.10:7530").await.unwrap();

    let mut psec_session = Session::from(stream); //wrap the TcpStream into a PSEC session
    psec_session.do_handshake(&identity).await?; //perform the PSEC handshake
    
    //encrypt a message, obfuscate its length with padding then send it
    psec_session.encrypt_and_send(b"Hello I'm Alice", true).await?;
    //receive then decrypt a message
    println!("Received: {:?}", psec_session.receive_and_decrypt().await?);
}
```

# Intstallation
To add this crate to your project, add the following to your project's Cargo.toml:
```toml
[dependencies]
async-psec = { version = "0.2", git = "https://forge.chapril.org/hardcoresushi/async-psec" }
```

# Documentation
The API documentation can be build by running:
```
cargo doc --all-features
```
