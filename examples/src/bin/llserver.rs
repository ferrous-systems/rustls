use rustls::low_level::{AppDataRecord, EncodeError, InsufficientSizeError, State, Status};
use rustls::server::low_level::LlServerConnection;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suites = rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();

    let versions = vec![&rustls::version::TLS12];

    let certs = {
        let certfile =
            fs::File::open("/home/christian/Workspace/ferrous-systems/rustls/localhost.pem")
                .expect("cannot open certificate file");
        let mut reader = BufReader::new(certfile);
        rustls_pemfile::certs(&mut reader)
            .map(|result| result.unwrap())
            .collect()
    };

    let privkey = {
        let keyfile =
            fs::File::open("/home/christian/Workspace/ferrous-systems/rustls/localhost-key.pem")
                .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file")
            {
                Some(rustls_pemfile::Item::Pkcs1Key(key)) => break Some(key.into()),
                Some(rustls_pemfile::Item::Pkcs8Key(key)) => break Some(key.into()),
                Some(rustls_pemfile::Item::Sec1Key(key)) => break Some(key.into()),
                None => break None,
                _ => {}
            }
        }
        .unwrap()
    };

    let config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_no_client_auth()
        .with_single_cert(certs, privkey)
        .unwrap();

    let config = Arc::new(config);

    let listener = std::net::TcpListener::bind("[::]:1443")?;

    for stream in listener.incoming() {
        let mut stream = stream?;

        let config = Arc::clone(&config);

        std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
                let mut conn = LlServerConnection::new(config)?;

                let mut incoming_tls = [0; 16 * 1024];
                let mut incoming_used = 0;

                let mut outgoing_tls = vec![];
                let mut outgoing_used = 0;

                let mut open_connection = true;

                let mut host = None;
                let mut connection = None;

                while open_connection {
                    let Status { discard, state } =
                        conn.process_tls_records(&mut incoming_tls[..incoming_used])?;

                    match state {
                        // logic similar to the one presented in the 'handling InsufficientSizeError' section is
                        // used in these states
                        State::MustEncodeTlsData(mut state) => {
                            let written = match state.encode(&mut outgoing_tls[outgoing_used..]) {
                                Ok(written) => written,
                                Err(EncodeError::InsufficientSize(InsufficientSizeError {
                                    required_size,
                                })) => {
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
                            stream.write_all(&outgoing_tls[..outgoing_used])?;

                            outgoing_used = 0;

                            state.done();
                        }

                        State::NeedsMoreTlsData { .. } => {
                            // NOTE real code needs to handle the scenario where `incoming_tls` is not big enough
                            let read = stream.read(&mut incoming_tls[incoming_used..])?;
                            incoming_used += read;
                        }

                        State::AppDataAvailable(mut records) => {
                            while let Some(result) = records.next_record() {
                                let AppDataRecord { payload, .. } = result?;

                                let payload = String::from_utf8(payload.to_vec()).unwrap();

                                for line in payload
                                    .strip_prefix("GET / HTTP/1.0\r\n")
                                    .unwrap()
                                    .lines()
                                {
                                    if let Some(arg) = line.strip_prefix("Host: ") {
                                        host = Some(arg.to_owned());
                                    } else if let Some(arg) = line.strip_prefix("Connection: ") {
                                        connection = Some(arg.to_owned());
                                    }
                                }
                            }
                        }

                        State::TrafficTransit(mut traffic_transit) => {
                            let host = host.take().unwrap();
                            let connection = connection.take().unwrap();

                            let resp = format!(
                                "HTTP/1.0 200 OK\r\nConnection: {}\r\n\r\nHello {}\r\n",
                                connection, host
                            );

                            let len = traffic_transit
                                .encrypt(resp.as_bytes(), outgoing_tls.as_mut_slice())?;
                            stream.write_all(&outgoing_tls[..len])?;
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
            },
        );
    }

    Ok(())
}
