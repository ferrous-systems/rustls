use rustls::low_level::client::LlClientConnection;
use rustls::low_level::common::{AppDataRecord, State, Status};
use rustls::{ClientConfig, RootCertStore};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;

fn main() -> io::Result<()> {
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
            rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
        );
    }

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut sock = std::net::TcpStream::connect("[::]:1443")?;
    let mut conn =
        LlClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();

    // .. configure / inititiaize `conn` and `sock`

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = vec![0; 16 * 1024];
    let mut outgoing_used = 0;

    loop {
        let Status { discard, state } = conn
            .process_tls_records(&mut incoming_tls)
            .unwrap();

        match state {
            // logic similar to the one presented in the 'handling InsufficientSizeError' section is
            // used in these states
            State::MustEncryptTlsData(mut state) => {
                let n = state
                    .encrypt(&mut outgoing_tls)
                    .unwrap();
                outgoing_used += n;
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

            State::AppDataAvailable(records) => {
                for res in records {
                    let AppDataRecord {
                        discard: _new_discard,
                        payload,
                    } = res.unwrap();

                    assert_eq!(payload, b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n");

                    return Ok(());
                }
            }

            State::TrafficTransit(mut traffic_transit) => {
                // post-handshake logic
                let req = b"GET / HTTP/1.0\r\nHost: llclient\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n";
                let len = traffic_transit
                    .encrypt(req, outgoing_tls.as_mut_slice())
                    .unwrap();
                sock.write_all(&outgoing_tls[..len])
                    .unwrap();

                let read = sock.read(&mut incoming_tls[incoming_used..])?;
                incoming_used += read;
            }
        }

        // discard TLS records
        if discard != 0 {
            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;
        }
    }
}
