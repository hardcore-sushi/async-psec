use rand::rngs::OsRng;
use tokio::{net::{TcpListener, TcpStream}};
use async_psec::{Session, Identity, PsecReader, PsecWriter, PsecError};

#[tokio::main]
async fn tokio_main() {
    let server_keypair = Identity::generate(&mut OsRng);
    let server_public_key = server_keypair.public.to_bytes();
    let client_keypair = Identity::generate(&mut OsRng);
    let client_public_key = client_keypair.public.to_bytes();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();

        let mut session = Session::from(stream);
        assert_eq!(session.peer_addr().unwrap(), addr);

        session.do_handshake(&server_keypair).await.unwrap();
        assert_eq!(session.peer_public_key.unwrap(), client_public_key);

        session.encrypt_and_send(b"Hello I'm Bob", true).await.unwrap();
        assert_eq!(session.receive_and_decrypt().await.unwrap(), b"Hello I'm Alice");

        session.encrypt_and_send("!".repeat(997).as_bytes(), true).await.unwrap();

        assert_eq!(session.receive_and_decrypt().await, Err(PsecError::TransmissionCorrupted));
    });

    let stream = TcpStream::connect(format!("127.0.0.1:{}", bind_addr.port())).await.unwrap();

    let mut session = Session::from(stream);
    assert_eq!(session.peer_addr().unwrap(), bind_addr);

    session.do_handshake(&client_keypair).await.unwrap();
    assert_eq!(session.peer_public_key.unwrap(), server_public_key);

    session.set_max_recv_size(996, false);

    session.encrypt_and_send(b"Hello I'm Alice", true).await.unwrap();
    assert_eq!(session.receive_and_decrypt().await.unwrap(), b"Hello I'm Bob");

    assert_eq!(session.receive_and_decrypt().await, Err(PsecError::BufferTooLarge));

    session.send(b"\x00\x00\x00\x00not encrypted data").await.unwrap();

    handle.await.unwrap();
}

#[test]
fn psec_session() {
    tokio_main();
}
