#![allow(warnings)]

use std::io;
use std::collections::HashMap;

mod tcp;

fn main() -> io::Result<()> {
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = Default::default();
    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun).expect("failed to cr");
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // if s/without_packet_info/new/:
        // let flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let proto = u16::from_be_bytes([buf[2], buf[3]]);
        //
        // if proto != 0x0800 {
        //     // not a ipv4 packet
        //     continue;
        // }
        //
        // also include on send

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => { 
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph.slice().len() + tcph.slice().len();
                        match connections.entry(tcp::Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
                            },
                            Entry::Vacant(e) => {
                                if let Some(c) =tcp::Connection::accept(&mut nic, iph, tcph, &buf[datai..nbytes])? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet: {:?}", e);
                    }
                }
            },
            Err(e) => {
                // eprintln!("ignoring weird packet: {:?}", e);
            }
        }

        if nbytes == 0 {
            break;
        }
    }

    Ok(())
}

// 4:05:57
