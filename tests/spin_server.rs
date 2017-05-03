// 
// cargo test -- --ignored --nocapture
// 
extern crate minimal_tls;
use minimal_tls::*;

use std::net::{TcpListener, TcpStream};
use std::io::{BufReader, BufWriter};
use std::io::BufRead;
use std::thread;
use std::str;
use std::rc::Rc;
use std::io::{Read, Write, Result};

fn handle_client(stream: TcpStream, tlsconfig : &TLS_config){

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    let mut connection : TLS_session = tls_init(&mut reader, &mut writer).unwrap();
    
    
    match connection.tls_start(tlsconfig){
        Ok(n) => println!("tls_start() returned {:?}", n),
        Err(e) => println!("tls_start() exited with {:?}", e)
    }

    let mut buf = vec![0; 16];
    connection.tls_receive(&mut buf);
    println!("data: {:?}", buf); 
    println!("closing connection");
}


#[test]
fn spin_server() {
    println!("RUNNING TEST: spin_server()");

    // point TLS 1.3 browser to https://localhost 
    let addr = "127.0.0.1:8080";
    let certpath = "/tmp/certs/server.pem";
    let keypath = "/tmp/certs/key.pem";

    let tlsconfig = tls_configure(certpath, keypath).unwrap();

    let listener = TcpListener::bind(addr).unwrap();
    println!("Listening on addr: {}", addr);

    // handle one connection then return from test case 
    match listener.accept() {
        Ok((stream, addr)) => {
            println!("connection from {:?}", addr);
            handle_client(stream, &tlsconfig);
        }
        Err(e) => println!("error getting connection {:?}", e),
    }
    assert!(false)
}
