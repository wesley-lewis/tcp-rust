use bitflags::bitflags;
use std::collections::{BTreeMap, VecDeque};
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::{io, time, time::Instant};

use etherparse;

bitflags! {
    pub(crate) struct Available: u8 {
        const READ  = 0b00000001;
        const WRITE = 0b00000010;
    }
}

pub enum State {
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
    Closing,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            Self::SynRcvd => false,
            Self::Estab | Self::FinWait1 | Self::FinWait2 | Self::Closing | Self::TimeWait => true,
        }
    }
}

struct Timers {
    send_times: BTreeMap<u32, Instant>,
    srtt: f64,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,
    pub incoming: VecDeque<u8>,
    pub unacked: VecDeque<u8>,
    pub closed: bool,
    pub closed_at: Option<u32>,
}

struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment acknowledgement number used for last window
    wl1: usize,
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial request sequence number
    irs: u32,
}

#[derive(Clone, Copy, Hash, Eq, Debug, PartialEq)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
            tcp: etherparse::TcpHeader::new(
                tcph.destination_port(),
                tcph.source_port(),
                iss, // random number for the sequence number
                wnd,
            ),
        };

        // need to start establishing a connection.
        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, &[])?;

        Ok(Some(c))
    }

    fn write<'a>(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() + payload.len(),
        );
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        // Calculating the checksum
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;

        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        //
        // acceptable ACK check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!

        // valid segment check. okay if it acks at least one byte, which means that at least one of
        // the following is true
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
        // RCV.NXT =< SEG.SEQ + SEG.LEN + 1 < RCV.NXT + RCV.WND
        //
        // TODO: handle synchronized RST
        //
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    self.write(nic, &[])?;
                    return Ok(());
                }
            } else {
                if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                    self.write(nic, &[])?;
                    return Ok(());
                }
            }
        } else {
            if self.recv.wnd == 0 {
                self.write(nic, &[])?;
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                self.write(nic, &[])?;
                return Ok(());
            }
        }
        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO: if not acceptable, send ACK

        if !tcph.ack() {
            return Ok(());
        }

        let ackn = tcph.acknowledgment_number();
        // if !is_between_wrapped(self.send.una, ackn, self.send.nxt) {
        //     if !self.state.is_synchronized() {
        //         // according to RESET generation send a RST
        //         self.send_rst(nic);
        //     }else {
        //         return Ok(());
        //     }
        // }
        // self.send.una = ackn;
        //
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            } else {
                // TODO: RST
            }
        }
        // State::SynRcvd => {
        //
        // // expect to get an ACK for our syn
        // if !tcph.ack() {
        //     return Ok(());
        // }
        //
        // must have ACKed our SYN, since we detected at least one acked byte, and we have
        // only sent one byte (the SYN).
        // self.state = State::Estab;
        // },

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            // TODO:
            assert!(data.is_empty());

            // now let's terminate the connection
            // TODO: needs to be stored in the retransmission queue
            if let State::Estab = self.state {
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection

                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        if let State::FinWait2 = self.state {
            if !tcph.fin() || !data.is_empty() {
                unimplemented!();
            }

            // they must have ACKed our FIN, since we detected at least one acked
            // byte, and we must have only sent one byte ( the FIN )
            self.tcp.fin = false;
            self.write(nic, &[])?;
            self.state = State::Closing;

            self.tcp.fin = false;
            self.write(nic, &[])?;
            self.state = State::Closing;
        }

        Ok(())
    }

    pub fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            return Ok(());
        }

        let nunacked_data = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una);
        let nunset_data = self.unacked.len() as u32 - nunacked_data;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());
        unimplemented!()
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::{Ord, Ordering};
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // check is violated iff end is between start and x
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // check is okay iff n is between u and a
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }

    true
}
