use std::net::Ipv4Addr;

use etherparse;

pub struct State {

}

impl Default for State {
    fn default() -> Self {
        Self {
        }
    }
}

#[derive(Clone, Copy, Hash, Eq, Debug, PartialEq)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

impl State {
    pub fn new() -> Self {
        Self{}
    }

    pub fn on_packet<'a>(&mut self, iph: etherparse::Ipv4HeaderSlice<'a>, tcph: etherparse::TcpHeaderSlice<'a>, data: &'a [u8]) {
        eprintln!(
            "{}:{} -> {}:{} {}b of tcp", 
            iph.source_addr(), 
            tcph.source_port(),
            iph.destination_addr(), 
            tcph.destination_port(),
            tcph.slice().len(), 
        );
    }
}
