#![allow(warnings)]

use std::io;
use std::collections::HashMap;

mod tcp;

fn main() -> io::Result<()>{
    let mut connections: HashMap<tcp::Quad, tcp::State> = Default::default();
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("failed to cr");
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        if proto != 0x0800 {
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(iph) => { 
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4+iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        let datai = iph.slice().len() + tcph.slice().len();
                        connections.entry(tcp::Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        }).or_default().on_packet(iph, tcph, &buf[datai..nbytes]);
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet: {:?}", e);
                    }
                }
            },
            Err(e) => {
                eprintln!("ignoring weird packet: {:?}", e);
            }
        }

        if nbytes == 0 {
            break;
        }
    }

    Ok(())
}

// 1:08:18
