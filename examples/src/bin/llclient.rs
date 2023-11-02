use rustls::client::low_level::LlClientConnection;
use rustls::low_level::{AppDataRecord, EncodeError, InsufficientSizeError, State, Status};
use rustls::{ClientConfig, RootCertStore};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    {
        let certfile = File::open("/home/christian/.local/share/mkcert/rootCA.pem")?;
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?,
        );
    }

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut sock = std::net::TcpStream::connect("[::]:1443")?;
    let mut conn = LlClientConnection::new(Arc::new(config), "localhost".try_into()?)?;

    // .. configure / inititiaize `conn` and `sock`

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = vec![];
    let mut outgoing_used = 0;

    let mut open_connection = true;

    while open_connection {
        let Status { discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used])?;

        match state {
            // logic similar to the one presented in the 'handling InsufficientSizeError' section is
            // used in these states
            State::MustEncodeTlsData(mut state) => {
                let written = match state.encode(&mut outgoing_tls[outgoing_used..]) {
                    Ok(written) => written,
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        let new_len = outgoing_used + required_size;
                        outgoing_tls.resize(new_len, 0);
                        eprintln!("resized `outgoing_tls` buffer to {}B", new_len);

                        // don't forget to encrypt the handshake record after resizing!
                        state
                            .encode(&mut outgoing_tls[outgoing_used..])
                            .expect("should not fail this time")
                    }
                    Err(err) => return Err(err.into()),
                };
                outgoing_used += written;
            }
            State::MustTransmitTlsData(state) => {
                sock.write_all(&outgoing_tls[..outgoing_used])?;

                outgoing_used = 0;

                state.done();
            }

            State::NeedsMoreTlsData { .. } => {
                // NOTE real code needs to handle the scenario where `incoming_tls` is not big enough
                let read = sock.read(&mut incoming_tls[incoming_used..])?;
                incoming_used += read;
            }

            State::AppDataAvailable(mut records) => {
                while let Some(result) = records.next_record() {
                    let AppDataRecord { payload, .. } = result?;

                    assert_eq!(payload, b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n");
                }
            }

            State::TrafficTransit(mut traffic_transit) => {
                // post-handshake logic
                let req = b"GET / HTTP/1.0\r\nHost: llclient\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n";
                let len = traffic_transit.encrypt(req, outgoing_tls.as_mut_slice())?;
                sock.write_all(&outgoing_tls[..len])?;

                let read = sock.read(&mut incoming_tls[incoming_used..])?;
                incoming_used += read;
            }

            State::ConnectionClosed => open_connection = false,
        }

        // discard TLS records
        if discard != 0 {
            assert!(discard <= incoming_used);

            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;
        }
    }

    assert!(incoming_tls[..incoming_used].is_empty());

    Ok(())
}
