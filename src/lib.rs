// Copyright (C) 2017  Miroslav Lichvar
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::convert::TryInto;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::time::SystemTime;

#[derive(Debug, Copy, Clone)]
struct NtpTimestamp {
    ts: u64,
}

impl NtpTimestamp {
    fn from_system_time(now: SystemTime) -> NtpTimestamp {
        let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        let secs = dur.as_secs() + 2208988800; // 1900 epoch
        let nanos = dur.subsec_nanos();

        NtpTimestamp {
            ts: (secs << 32) + (nanos as f64 * 4.294967296) as u64,
        }
    }

    fn read(buf: &[u8]) -> NtpTimestamp {
        NtpTimestamp {
            ts: u64::from_be_bytes(buf.try_into().unwrap()),
        }
    }

    fn write(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.ts.to_be_bytes());
    }
}

impl PartialEq for NtpTimestamp {
    fn eq(&self, other: &NtpTimestamp) -> bool {
        self.ts == other.ts
    }
}

#[derive(Debug)]
struct NtpRequest {
    version: u8,
    mode: u8,
    poll: i8,
    tx_ts: NtpTimestamp,
}

pub trait TimeSource {
    fn now(&mut self) -> SystemTime;
}

pub struct NtpServer<TS: TimeSource> {
    socket: UdpSocket,
    time_source: TS,
}

impl<TS: TimeSource> NtpServer<TS> {
    pub fn new(socket: UdpSocket, time_source: TS) -> NtpServer<TS> {
        NtpServer {
            socket,
            time_source,
        }
    }

    fn receive(&mut self) -> io::Result<(NtpRequest, SocketAddr)> {
        let mut buf = [0; 256];

        let (len, addr) = self.socket.recv_from(&mut buf)?;

        if len < 48 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Packet too short"));
        }

        let version = (buf[0] >> 3) & 0x7;
        let mode = buf[0] & 0x7;

        if version < 1 || version > 4 {
            return Err(Error::new(ErrorKind::Other, "Unsupported version"));
        }

        Ok((
            NtpRequest {
                version,
                mode,
                poll: buf[2] as i8,
                tx_ts: NtpTimestamp::read(&buf[40..48]),
            },
            addr,
        ))
    }

    pub fn run(&mut self) {
        let mut buf = [0; 48];

        loop {
            match self.receive() {
                Ok((request, remote_addr)) => {
                    let mode = if request.mode == 1 { 2 } else { 4 };
                    let precision = -16i8;
                    let version = request.version;
                    let stratum = 1u8;
                    let poll = request.poll;
                    let orig_ts = request.tx_ts;
                    let now_ts = NtpTimestamp::from_system_time(self.time_source.now());

                    buf[0] = version << 3 | mode;
                    buf[1] = stratum;
                    buf[2] = poll as u8;
                    buf[3] = precision as u8;
                    // delay.write(&mut buf[4..8]);
                    // dispersion.write(&mut buf[8..12]);
                    // BigEndian::write_u32(&mut buf[12..16], ref_id);
                    now_ts.write(&mut buf[16..24]);
                    orig_ts.write(&mut buf[24..32]);
                    now_ts.write(&mut buf[32..40]);
                    now_ts.write(&mut buf[40..48]);

                    match self.socket.send_to(&buf, remote_addr) {
                        Err(e) => {
                            println!("Failed to send packet to {}: {}", remote_addr, e)
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    println!("Failed to receive packet: {}", e);
                }
            }
        }
    }
}
