use rustls::low_level::client::LlClientConnection;
use rustls::low_level::common::{AppDataRecord, State, Status};
use rustls::{ClientConfig, RootCertStore};
use std::io::{self, Read, Write};
use std::sync::Arc;

fn main() -> io::Result<()> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut sock = std::net::TcpStream::connect("[::]:1443")?;
    let mut conn =
        LlClientConnection::new(Arc::new(config), "example.com".try_into().unwrap()).unwrap();

    // .. configure / inititiaize `conn` and `sock`

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = vec![0; 16 * 1024];
    let mut outgoing_used = 0;

    loop {
        let Status { mut discard, state } = conn
            .process_tls_records(&mut incoming_tls)
            .unwrap();

        dbg!(outgoing_used);
        match dbg!(state) {
            // logic similar to the one presented in the 'handling InsufficientSizeError' section is
            // used in these states
            State::MustEncryptTlsData(mut state) => {
                let n = state
                    .encrypt(&mut outgoing_tls)
                    .unwrap();
                outgoing_used += n;
            }
            State::MayEncryptAppData(_) => { /* .. */ }

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
                        discard: new_discard,
                        payload: _,
                    } = res.unwrap();

                    discard += new_discard.get();

                    // do app-specific stuff with `payload`
                }
            }

            State::TrafficTransit(_) => {
                // post-handshake logic
            }
        }

        // discard TLS records
        if discard != 0 {
            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;
        }
    }
}
