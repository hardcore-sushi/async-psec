/*! Asynchronous PSEC implementation.

[PSEC](https://github.com/hardcore-sushi/PSEC) (Peer-to-peer Secure Ephemeral Communications) is a simplification/adaptation of TLS 1.3 for P2P networks which provides an encrypted and authenticated secure transport layer for ephemeral communications. PSEC ensures deniability, forward secrecy, future secrecy, and optional plaintext length obfuscation. This crate is an implementation of this protocol built with the [tokio] framework.

# Usage
Add this in your `Cargo.toml`:
```toml
[dependencies]
async-psec = "0.3"
```
And then:
```no_run
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
#   Ok(())
}
```

# Split Feature
If you want to split the [`Session`] struct in two parts, you must enable the `split` feature:
```toml
[dependencies]
async-psec = { version = "0.3", feature = ["split"] }
```
This can be useful if you want to send data from one thread/task and receive from another in parallel.
*/

#![warn(missing_docs)]

mod crypto;
use std::{convert::TryInto, fmt::{self, Debug, Display, Formatter}, io::{self, ErrorKind}, net::SocketAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
#[cfg(feature = "split")]
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use async_trait::async_trait;
use ed25519_dalek::{ed25519::signature::Signature, Keypair, Signer, Verifier, SIGNATURE_LENGTH};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha384, Digest};
use aes_gcm::{Aes128Gcm, aead::Aead, NewAead, aead::Payload, Nonce};
use crypto::{HandshakeKeys, ApplicationKeys};

const RANDOM_LEN: usize = 64;
const MESSAGE_LEN_LEN: usize = 4;
type MessageLenType = u32;

const DEFAULT_PADDED_MAX_SIZE: usize = 32768000;
const DEFAULT_MAX_RECV_SIZE: usize = MESSAGE_LEN_LEN + DEFAULT_PADDED_MAX_SIZE + crypto::AES_TAG_LEN;

/// The length of a PSEC public key, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/** A PSEC Identity.

This is just a [curve25519 keypair](Keypair).*/
pub type Identity = Keypair;

///Errors that can be returned by PSEC operations.
#[derive(Debug, PartialEq, Eq)]
pub enum PsecError {
    /// The operation failed because a pipe was closed.
    BrokenPipe,
    /// The connection was reset by the remote peer.
    ConnectionReset,
    /// Authentication error. It often means that the AES GCM tag was invalid during a decryption operation.
    TransmissionCorrupted,
    /// The received buffer was too large and was discarded to prevent DOS attacks.
    BufferTooLarge,
    /// Failed to read the desired amout of bytes.
    UnexpectedEof,
    /// An unknown error occurred while reading or writing to the underlying [`TcpStream`].
    IoError {
        /// The [`ErrorKind`] of the I/O [`Error`](io::Error).
        error_kind: ErrorKind,
    },
    /// The plain text was not properly padded.
    BadPadding,
}

impl Display for PsecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PsecError::BrokenPipe => f.write_str("Broken pipe"),
            PsecError::ConnectionReset => f.write_str("Connection reset"),
            PsecError::TransmissionCorrupted => f.write_str("Transmission corrupted"),
            PsecError::BufferTooLarge => f.write_str("Received buffer is too large"),
            PsecError::UnexpectedEof => f.write_str("Unexpected EOF"),
            PsecError::IoError { error_kind } => f.write_str(&format!("{:?}", error_kind)),
            PsecError::BadPadding => f.write_str("Bad Padding"),
        }
    }
}

fn slice_to_public_key(buff: &[u8]) -> x25519_dalek::PublicKey {
    let array: [u8; PUBLIC_KEY_LENGTH] = buff.try_into().unwrap();
    x25519_dalek::PublicKey::from(array)
}

async fn receive<T: AsyncReadExt + Unpin>(reader: &mut T, buff: &mut [u8]) -> Result<usize, PsecError> {
    match reader.read_exact(buff).await {
        Ok(read) => {
            if read > 0 {
                Ok(read)
            } else {
                Err(PsecError::BrokenPipe)
            }
        }
        Err(e) => {
            match e.kind() {
                ErrorKind::UnexpectedEof => Err(PsecError::UnexpectedEof),
                ErrorKind::ConnectionReset => Err(PsecError::ConnectionReset),
                _ => Err(PsecError::IoError { error_kind: e.kind() })
            }
        }
    }
}

async fn send<T: AsyncWriteExt + Unpin>(writer: &mut T, buff: &[u8]) -> Result<(), PsecError> {
    match writer.write_all(buff).await {
        Ok(_) => Ok(()),
        Err(e) => Err(match e.kind() {
            ErrorKind::BrokenPipe => PsecError::BrokenPipe,
            ErrorKind::ConnectionReset => PsecError::ConnectionReset,
            _ => PsecError::IoError { error_kind: e.kind() }
        })
    }
}

fn pad(plain_text: &[u8], use_padding: bool) -> Vec<u8> {
    let encoded_msg_len = (plain_text.len() as MessageLenType).to_be_bytes();
    let msg_len = plain_text.len()+encoded_msg_len.len();
    let mut output = Vec::from(encoded_msg_len);
    if use_padding {
        let mut len = 1000;
        while len < msg_len {
            len *= 2;
        }
        output.reserve(len);
        output.extend(plain_text);
        output.resize(len, 0);
        OsRng.fill_bytes(&mut output[msg_len..]);
    } else {
        output.extend(plain_text);
    }
    output
}

fn unpad(input: Vec<u8>) -> Result<Vec<u8>, PsecError> {
    if input.len() < 4 {
        Err(PsecError::BadPadding)
    } else {
        let msg_len = MessageLenType::from_be_bytes(input[0..MESSAGE_LEN_LEN].try_into().unwrap()) as usize;
        Ok(Vec::from(&input[MESSAGE_LEN_LEN..MESSAGE_LEN_LEN+msg_len]))
    }
}

fn encrypt(local_cipher: &Aes128Gcm, local_iv: &[u8], local_counter: &mut usize, plain_text: &[u8], use_padding: bool) -> Vec<u8> {
    let padded_msg = pad(plain_text, use_padding);
    let cipher_len = (padded_msg.len() as MessageLenType).to_be_bytes();
    let payload = Payload {
        msg: &padded_msg,
        aad: &cipher_len
    };
    let nonce = crypto::iv_to_nonce(local_iv, local_counter);
    let cipher_text = local_cipher.encrypt(Nonce::from_slice(&nonce), payload).unwrap();
    [&cipher_len, cipher_text.as_slice()].concat()
}

async fn encrypt_and_send<T: AsyncWriteExt + Unpin>(writer: &mut T, local_cipher: &Aes128Gcm, local_iv: &[u8], local_counter: &mut usize, plain_text: &[u8], use_padding: bool) -> Result<(), PsecError> {
    let cipher_text = encrypt(local_cipher, local_iv, local_counter, plain_text, use_padding);
    send(writer, &cipher_text).await
}

async fn receive_and_decrypt<T: AsyncReadExt + Unpin>(reader: &mut T, peer_cipher: &Aes128Gcm, peer_iv: &[u8], peer_counter: &mut usize, max_recv_size: usize) -> Result<Vec<u8>, PsecError> {
    let mut message_len = [0; MESSAGE_LEN_LEN];
    receive(reader, &mut message_len).await?;
    let recv_len = MessageLenType::from_be_bytes(message_len) as usize + crypto::AES_TAG_LEN;
    if recv_len <= max_recv_size {
        let mut cipher_text = vec![0; recv_len];
        let mut read = 0;
        while read < recv_len {
            read += receive(reader, &mut cipher_text[read..]).await?;
        }
        let peer_nonce = crypto::iv_to_nonce(peer_iv, peer_counter);
        let payload = Payload {
            msg: &cipher_text,
            aad: &message_len
        };
        match peer_cipher.decrypt(Nonce::from_slice(&peer_nonce), payload) {
            Ok(plain_text) => unpad(plain_text),
            Err(_) => Err(PsecError::TransmissionCorrupted)
        }
    } else {
        Err(PsecError::BufferTooLarge)
    }
}

fn compute_max_recv_size(size: usize, is_raw_size: bool) -> usize {
    if is_raw_size {
        size
    } else {
        let max_not_padded_size = size+MESSAGE_LEN_LEN;
        let mut max_padded_size = 1000;
        while max_padded_size < max_not_padded_size {
            max_padded_size *= 2;
        }
        max_padded_size+crypto::AES_TAG_LEN
    }
}

/// Read from a PSEC session.
#[async_trait]
pub trait PsecReader {
    /** Set the maximum size of an acceptable buffer being received.
    
    Any received buffer larger than this value will be discarded and a [`BufferTooLarge`](PsecError::BufferTooLarge) error will be returned. Then, the PSEC session should be closed to prevent any DOS attacks.
    
    If `is_raw_size` is set to `true`, the specified `size` will correspond to the maximum encrypted buffer size, including potential padding. Otherwise, the maximum buffer size will correspond to the length of a message of this size after applying padding and encryption.
    
    The default value is 32 768 020, which allows to receive any messages under 32 768 000 bytes.*/
    fn set_max_recv_size(&mut self, size: usize, is_raw_size: bool);

    /** Read then decrypt from a PSEC session.

    # Panic
    Panics if the PSEC handshake is not finished and successful.*/
    async fn receive_and_decrypt(&mut self) -> Result<Vec<u8>, PsecError>;

    /** Take ownership of the `PsecReader`, read, decrypt, then return back the `PsecReader`. Useful when used with [`tokio::select!`].
    
    # Panic
    Panics if the PSEC handshake is not finished and successful.
    ```no_run
    # use tokio::net::TcpStream;
    # use async_psec::{Session, PsecReader};
    # #[tokio::main]
    # async fn main() {
    #   let stream = TcpStream::connect("10.152.152.10:7530").await.unwrap();
    #   let psec_session = Session::from(stream);
    let receiving = psec_session.into_receive_and_decrypt();
    tokio::pin!(receiving);

    loop {
        tokio::select! {
            result = &mut receiving => {
                let (buffer, psec_session) = result;

                receiving.set(psec_session.into_receive_and_decrypt());
                
                match buffer {
                    Ok(buffer) => println!("Received: {:?}", buffer),
                    Err(e) => println!("Error: {}", e)
                }
            }
            //other select! branches...
        }
    }
    # }
    ```
    */
    async fn into_receive_and_decrypt(self) -> (Result<Vec<u8>, PsecError>, Self);
}

/// Write to a PSEC session.
#[async_trait]
pub trait PsecWriter {
    /** Encrypt then send through a PSEC session.

    `use_padding` specifies whether or not the plain text length should be obfuscated with padding. Enabling padding will use more network bandwidth: all messages below 1KB will be padded to 1KB and then the padded length doubles at each step (2KB, 4KB, 8KB...). When sending a buffer of 17MB, it will padded to 32MB.
    
    # Panic
    Panics if the PSEC handshake is not finished and successful.
    */
    async fn encrypt_and_send(&mut self, plain_text: &[u8], use_padding: bool) -> Result<(), PsecError>;

    /** Encrypt a buffer but return it instead of sending it.
    
    All encrypted buffers must be sent __in the same order__ they have been encrypted otherwise the remote peer won't be able to decrypt them and should close the connection.

    # Panic
    Panics if the PSEC handshake is not finished and successful.
    ```no_run
    # use tokio::net::TcpStream;
    # use async_psec::{Session, PsecWriter, PsecError};
    # #[tokio::main]
    # async fn main() -> Result<(), PsecError> {
    # let stream = TcpStream::connect("10.152.152.10:7530").await.unwrap();
    # let mut psec_session = Session::from(stream);
    let buffer1 = psec_session.encrypt(b"Hello ", false);
    let buffer2 = psec_session.encrypt(b" world!", false);
    psec_session.send(&buffer1).await?;
    psec_session.send(&buffer2).await?;
    # Ok(())
    # }
    ```
    */
    fn encrypt(&mut self, plain_text: &[u8], use_padding: bool) -> Vec<u8>;

    /** Send a previously encrypted buffer.
    
    All encrypted buffers must be sent __in the same order__ they have been encrypted otherwise the remote peer won't be able to decrypt them and should close the connection.*/
    async fn send(&mut self, cipher_text: &[u8]) -> Result<(), PsecError>;
}

/// The read half of a PSEC session. Obtained with [`Session::into_split`].
#[cfg(feature = "split")]
pub struct SessionReadHalf {
    read_half: OwnedReadHalf,
    peer_cipher: Aes128Gcm,
    peer_iv: [u8; crypto::IV_LEN],
    peer_counter: usize,
    max_recv_size: usize,
}

#[cfg(feature = "split")]
impl Debug for SessionReadHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReadHalf")
            .field("read_half", &self.read_half)
            .field("max_recv_size", &self.max_recv_size)
            .field("peer_counter", &self.peer_counter)
            .field("peer_iv", &hex_encode(&self.peer_iv))
            .finish()
    }
}

#[cfg(feature = "split")]
#[async_trait]
impl PsecReader for SessionReadHalf {
    fn set_max_recv_size(&mut self, size: usize, is_raw_size: bool) {
        self.max_recv_size = compute_max_recv_size(size, is_raw_size)
    }
    async fn receive_and_decrypt(&mut self) -> Result<Vec<u8>, PsecError> {
        receive_and_decrypt(&mut self.read_half, &self.peer_cipher, &self.peer_iv, &mut self.peer_counter, self.max_recv_size).await
    }
    async fn into_receive_and_decrypt(mut self) -> (Result<Vec<u8>, PsecError>, Self) {
        (self.receive_and_decrypt().await, self)
    }
}

#[cfg(feature = "split")]
/// The write half of a PSEC session. Obtained with [`Session::into_split`].
pub struct SessionWriteHalf {
    write_half: OwnedWriteHalf,
    local_cipher: Aes128Gcm,
    local_iv: [u8; crypto::IV_LEN],
    local_counter: usize,
}

#[cfg(feature = "split")]
#[async_trait]
impl PsecWriter for SessionWriteHalf {
    async fn encrypt_and_send(&mut self, plain_text: &[u8], use_padding: bool) -> Result<(), PsecError> {
        encrypt_and_send(&mut self.write_half, &self.local_cipher, &self.local_iv, &mut self.local_counter, plain_text, use_padding).await
    }
    fn encrypt(&mut self, plain_text: &[u8], use_padding: bool) -> Vec<u8> {
        encrypt(&self.local_cipher, &self.local_iv, &mut self.local_counter, plain_text, use_padding)
    }
    async fn send(&mut self, cipher_text: &[u8]) -> Result<(), PsecError> {
        send(&mut self.write_half, cipher_text).await
    }
}

#[cfg(feature = "split")]
impl Debug for SessionWriteHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionWriteHalf")
            .field("write_half", &self.write_half)
            .field("local_counter", &self.local_counter)
            .field("local_iv", &hex_encode(&self.local_iv))
            .finish()
    }
}

/// A PSEC connection.
pub struct Session {
    stream: TcpStream,
    local_cipher: Option<Aes128Gcm>,
    local_iv: Option<[u8; crypto::IV_LEN]>,
    local_counter: usize,
    peer_cipher: Option<Aes128Gcm>,
    peer_iv: Option<[u8; crypto::IV_LEN]>,
    peer_counter: usize,
    max_recv_size: usize,
    /** The public key of the remote peer.
    
    It is `None` before the PSEC handshake was performed. After a successful call to [`do_handshake`](Session::do_handshake), the field is `Some`. If the handshake was not successful, the field can be either `Some` or `None` depending on where the handshake failed.
    ```no_run
    # use rand::rngs::OsRng;
    # use tokio::{net::TcpStream, io::Error};
    # use async_psec::{Identity, Session};
    # #[tokio::main]
    # async fn main() -> Result<(), Error> {
    # let identity = Identity::generate(&mut OsRng);
    let stream = TcpStream::connect("10.152.152.10:7530").await?;

    let mut psec_session = Session::from(stream);
    psec_session.do_handshake(&identity).await.unwrap();

    println!("Peer public key: {:?}", psec_session.peer_public_key.unwrap());
    # Ok(())
    # }
    ```*/
    pub peer_public_key: Option<[u8; PUBLIC_KEY_LENGTH]>,
}

impl Session {
    /** Split the `Session` in two parts: a reader and a writer.
    
    Calling this before a successful call to [`do_handshake`](Session::do_handshake) will return `None`.
    ```no_run
    # use std::io::Error;
    # use tokio::net::TcpStream;
    # use async_psec::{Session, PsecReader, PsecWriter};
    # #[tokio::main]
    # async fn main() -> Result<(), Error> {
    # let stream = TcpStream::connect("10.152.152.10:7530").await?;
    # let psec_session = Session::from(stream);
    let (mut session_read, mut session_write) = psec_session.into_split().unwrap();

    tokio::spawn(async move {
        session_write.encrypt_and_send(b"Hello world!", true).await.unwrap();
    });

    tokio::spawn(async move {
        println!("Received: {:?}", session_read.receive_and_decrypt().await.unwrap());
    });    
    # Ok(())
    # }
    ```*/
    #[cfg(feature = "split")]
    pub fn into_split(self) -> Option<(SessionReadHalf, SessionWriteHalf)> {
        let (read_half, write_half) = self.stream.into_split();
        Some((
            SessionReadHalf {
                read_half,
                peer_cipher: self.peer_cipher?,
                peer_iv: self.peer_iv?,
                peer_counter: self.peer_counter,
                max_recv_size: self.max_recv_size,
            },
            SessionWriteHalf {
                write_half,
                local_cipher: self.local_cipher?,
                local_iv: self.local_iv?,
                local_counter: self.local_counter,
            }
        ))
    }

    /** Return the remote address that this `Session` is connected to.
    ```no_run
    # use std::io::Error;
    use std::net::SocketAddr;
    # use tokio::net::TcpStream;
    # use async_psec::Session;
    # #[tokio::main]
    # async fn main() -> Result<(), Error> {
    
    let addr: SocketAddr = "10.152.152.10:7530".parse().unwrap();

    let stream = TcpStream::connect(addr).await?;
    let psec_session = Session::from(stream);

    assert_eq!(psec_session.peer_addr()?, addr);
    # Ok(())
    # }
    ```*/
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    async fn receive(&mut self, buff: &mut [u8]) -> Result<usize, PsecError> {
        receive(&mut self.stream, buff).await
    }

    async fn send(&mut self, buff: &[u8]) -> Result<(), PsecError> {
        send(&mut self.stream, buff).await
    }

    async fn handshake_read(&mut self, buff: &mut [u8], handshake_recv_buff: &mut Vec<u8>) -> Result<(), PsecError> {
        self.receive(buff).await?;
        handshake_recv_buff.extend(buff.as_ref());
        Ok(())
    }

    async fn handshake_write(&mut self, buff: &[u8], handshake_sent_buff: &mut Vec<u8>) -> Result<(), PsecError> {
        self.send(buff).await?;
        handshake_sent_buff.extend(buff);
        Ok(())
    }

    fn hash_handshake(i_am_bob: bool, handshake_sent_buff: &[u8], handshake_recv_buff: &[u8]) -> [u8; 48] {
        let handshake_bytes = if i_am_bob {
            [handshake_sent_buff, handshake_recv_buff].concat()
        } else {
            [handshake_recv_buff, handshake_sent_buff].concat()
        };
        let mut hasher = Sha384::new();
        hasher.update(handshake_bytes);
        let handshake_hash = hasher.finalize();
        handshake_hash.as_slice().try_into().unwrap()
    }

    fn init_ciphers(&mut self, application_keys: ApplicationKeys){
        self.local_cipher = Some(Aes128Gcm::new_from_slice(&application_keys.local_key).unwrap());
        self.local_iv = Some(application_keys.local_iv);
        self.peer_cipher = Some(Aes128Gcm::new_from_slice(&application_keys.peer_key).unwrap());
        self.peer_iv = Some(application_keys.peer_iv);
    }

    /** Performing a PSEC handshake.
    
    If successful, the `Session` is ready to send and receive data and you can retrieve the peer public key with the [`peer_public_key`](Session::peer_public_key) attribute. Otherwise, trying to encrypt or decrypt data with this session will panic.*/
    pub async fn do_handshake(&mut self, identity: &Identity) -> Result<(), PsecError> {
        let mut handshake_sent_buff = Vec::new();
        let mut handshake_recv_buff = Vec::new();
        //ECDHE initial exchange
        //generate random bytes
        let mut handshake_buffer = [0; RANDOM_LEN+PUBLIC_KEY_LENGTH];
        OsRng.fill_bytes(&mut handshake_buffer[..RANDOM_LEN]);
        //generate ephemeral x25519 keys
        let ephemeral_secret = x25519_dalek::EphemeralSecret::new(OsRng);
        let ephemeral_public_key = x25519_dalek::PublicKey::from(&ephemeral_secret);
        handshake_buffer[RANDOM_LEN..].copy_from_slice(&ephemeral_public_key.to_bytes());
        self.handshake_write(&handshake_buffer, &mut handshake_sent_buff).await?;
        self.handshake_read(&mut handshake_buffer, &mut handshake_recv_buff).await?;
        let peer_ephemeral_public_key = slice_to_public_key(&handshake_buffer[RANDOM_LEN..]);
        //computing handshake keys
        let i_am_bob = handshake_sent_buff < handshake_recv_buff; //mutual consensus for keys attribution
        let handshake_hash = Session::hash_handshake(i_am_bob, &handshake_sent_buff, &handshake_recv_buff);
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_ephemeral_public_key);
        let handshake_keys = HandshakeKeys::derive_keys(shared_secret.to_bytes(), handshake_hash, i_am_bob);


        //encrypted handshake
        //random bytes, public key & ephemeral public key signature
        let mut auth_msg = [0; RANDOM_LEN+PUBLIC_KEY_LENGTH+SIGNATURE_LENGTH];
        OsRng.fill_bytes(&mut auth_msg[..RANDOM_LEN]);
        auth_msg[RANDOM_LEN..RANDOM_LEN+PUBLIC_KEY_LENGTH].copy_from_slice(&identity.public.to_bytes());
        auth_msg[RANDOM_LEN+PUBLIC_KEY_LENGTH..].copy_from_slice(&identity.sign(ephemeral_public_key.as_bytes()).to_bytes());
        //encrypt auth_msg
        let local_cipher = Aes128Gcm::new_from_slice(&handshake_keys.local_key).unwrap();
        let encrypted_auth_msg = local_cipher.encrypt(Nonce::from_slice(&handshake_keys.local_iv), auth_msg.as_ref()).unwrap();
        self.handshake_write(&encrypted_auth_msg, &mut handshake_sent_buff).await?;

        let mut encrypted_peer_auth_msg = [0; RANDOM_LEN+PUBLIC_KEY_LENGTH+SIGNATURE_LENGTH+crypto::AES_TAG_LEN];
        self.handshake_read(&mut encrypted_peer_auth_msg, &mut handshake_recv_buff).await?;
        //decrypt peer_auth_msg
        let peer_cipher = Aes128Gcm::new_from_slice(&handshake_keys.peer_key).unwrap();
        let mut peer_handshake_counter = 0;
        let peer_nonce = crypto::iv_to_nonce(&handshake_keys.peer_iv, &mut peer_handshake_counter);
        match peer_cipher.decrypt(Nonce::from_slice(&peer_nonce), encrypted_peer_auth_msg.as_ref()) {
            Ok(peer_auth_msg) => {
                //verify ephemeral public key signature
                self.peer_public_key = Some(peer_auth_msg[RANDOM_LEN..RANDOM_LEN+PUBLIC_KEY_LENGTH].try_into().unwrap());
                let peer_public_key = ed25519_dalek::PublicKey::from_bytes(&self.peer_public_key.unwrap()).unwrap();
                let peer_signature = Signature::from_bytes(&peer_auth_msg[RANDOM_LEN+PUBLIC_KEY_LENGTH..]).unwrap();
                if peer_public_key.verify(peer_ephemeral_public_key.as_bytes(), &peer_signature).is_ok() {
                    let handshake_hash = Session::hash_handshake(i_am_bob, &handshake_sent_buff, &handshake_recv_buff);
                    //sending handshake finished
                    let handshake_finished = crypto::compute_handshake_finished(handshake_keys.local_handshake_traffic_secret, handshake_hash);
                    self.send(&handshake_finished).await?;
                    let mut peer_handshake_finished = [0; crypto::HASH_OUTPUT_LEN];
                    self.receive(&mut peer_handshake_finished).await?;
                    if crypto::verify_handshake_finished(peer_handshake_finished, handshake_keys.peer_handshake_traffic_secret, handshake_hash) {
                        //computing application keys
                        let application_keys = ApplicationKeys::derive_keys(handshake_keys.handshake_secret, handshake_hash, i_am_bob);
                        self.init_ciphers(application_keys);
                        return Ok(());
                    }
                }
            }
            Err(_) => {}
        }
        Err(PsecError::TransmissionCorrupted)
    }
}

#[async_trait]
impl PsecWriter for Session {
    async fn encrypt_and_send(&mut self, plain_text: &[u8], use_padding: bool) -> Result<(), PsecError> {
        encrypt_and_send(&mut self.stream, self.local_cipher.as_ref().unwrap(), self.local_iv.as_ref().unwrap(), &mut self.local_counter, plain_text, use_padding).await
    }

    fn encrypt(&mut self, plain_text: &[u8], use_padding: bool) -> Vec<u8> {
        encrypt(self.local_cipher.as_ref().unwrap(), &self.local_iv.unwrap(), &mut self.local_counter, plain_text, use_padding)
    }

    async fn send(&mut self, cipher_text: &[u8]) -> Result<(), PsecError> {
        send(&mut self.stream, cipher_text).await
    }
}

#[async_trait]
impl PsecReader for Session {
    fn set_max_recv_size(&mut self, size: usize, is_raw_size: bool) {
        self.max_recv_size = compute_max_recv_size(size, is_raw_size);
    }
    async fn receive_and_decrypt(&mut self) -> Result<Vec<u8>, PsecError> {
        receive_and_decrypt(&mut self.stream, &self.peer_cipher.as_ref().unwrap(), &self.peer_iv.unwrap(), &mut self.peer_counter, self.max_recv_size).await
    }
    async fn into_receive_and_decrypt(mut self) -> (Result<Vec<u8>, PsecError>, Self) {
        (self.receive_and_decrypt().await, self)
    }
}

impl From<TcpStream> for Session {
    fn from(stream: TcpStream) -> Self {
        Session {
            stream: stream,
            local_cipher: None,
            local_iv: None,
            local_counter: 0,
            peer_cipher: None,
            peer_iv: None,
            peer_counter: 0,
            peer_public_key: None,
            max_recv_size: DEFAULT_MAX_RECV_SIZE,
        }
    }
}

impl Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let handshake_successful = self.peer_cipher.is_some();
        let mut debug_struct = f.debug_struct("PSEC Session");
        debug_struct
            .field("stream", &self.stream)
            .field("max_recv_size", &self.max_recv_size)
            .field("handshake_successful", &handshake_successful);
        if let Some(peer_public_key) = self.peer_public_key {
            debug_struct.field("peer_public_key", &hex_encode(&peer_public_key));
        }
        if handshake_successful {
            debug_struct.field("local_counter", &self.local_counter)
                .field("local_iv", &hex_encode(&self.local_iv.unwrap()))
                .field("peer_counter", &self.peer_counter)
                .field("peer_iv", &hex_encode(&self.peer_iv.unwrap()));
        }
        debug_struct.finish()
    }
}

fn hex_encode(buff: &[u8]) -> String {
    let mut s = String::with_capacity(buff.len()*2);
    for i in buff {
        s += &format!("{:x}", i);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{pad, unpad, MESSAGE_LEN_LEN};

    #[test]
    fn padding() {
        let padded = pad(b"Hello world!", true);
        assert_eq!(padded.len(), 1000);
        let not_padded = pad(b"Hello world!", false);
        assert_eq!(not_padded.len(), "Hello world!".len()+MESSAGE_LEN_LEN);

        let unpadded = unpad(padded).unwrap();
        assert_eq!(unpadded, unpad(not_padded).unwrap());
        assert_eq!(unpadded, b"Hello world!");

        let large_msg = "a".repeat(5000);
        assert_eq!(pad(large_msg.as_bytes(), true).len(), 8000);
    }
}
