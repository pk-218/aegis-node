#![no_std]
#![no_main]

use aegis_node_common::{packet_info::PacketInfo, Direct};
use aegis_node_common::EventData;
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::{XdpContext, ProbeContext}, macros::{map}, maps::{PerfEventArray, HashMap}, macros::{kprobe, kretprobe}, helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel}};
use aya_log_ebpf::info;
// use chrono;
use core::{mem, u16};
// use std::time::SystemTime;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

mod consts;

type SockPtr = *mut u8;

#[map]
static mut SOCK_MAP: HashMap<u32, SockPtr> = HashMap::with_max_entries(1024, 0);
#[map(name = "EVENTS")]
static mut PERF_EVENTS: PerfEventArray<EventData> = PerfEventArray::with_max_entries(1024, 0);



#[no_mangle]
static FILTER_PID: u32 = 0;

fn get_filter_pid() -> u32 {
    unsafe { core::ptr::read_volatile(&FILTER_PID) }
}

#[map(name="PACKETS")]
static mut PACKETS: PerfEventArray<PacketInfo> = PerfEventArray::<PacketInfo>::with_max_entries(1024, 0);

fn tcp_sendentry(ctx: ProbeContext) -> Result<(), i64> {
    info!(&ctx, "Running##########################");
    let pid_tid = bpf_get_current_pid_tgid();
    let tid = pid_tid as u32;
    let pid = (pid_tid >> 32) as u32;
    if pid != get_filter_pid() {
        return Ok(());
    }
    let sk: SockPtr = ctx.arg(0).ok_or(1i64)?;
    let sk_family = unsafe { bpf_probe_read_kernel(sk.add(16) as *const u16) }?;
    if sk_family != consts::AF_INET {
        return Ok(());
    }
    unsafe { SOCK_MAP.insert(&tid, &sk, 0) }?;

    Ok(())
}

fn tcp_sendstat(ctx: ProbeContext) -> Result<(), i64> {
    let size: u32 = ctx.ret().unwrap_or(0);
    if size == 0 {
        return Ok(());
    }
    let pid_tid = bpf_get_current_pid_tgid();
    let pid = (pid_tid >> 32) as u32;
    let tid = pid_tid as u32;
    if pid != get_filter_pid() {
        return Ok(());
    }
    let sock: SockPtr = *unsafe { SOCK_MAP.get(&tid) }.ok_or(1)?;
    let daddr: u32 = unsafe { bpf_probe_read_kernel(sock as *mut u32) }?;
    let dport: u16 = unsafe { bpf_probe_read_kernel(sock.add(12) as *mut u16) }?;
    unsafe {
        PERF_EVENTS.output(
            &ctx,
            &EventData {
                addr: daddr,
                port: dport.into(),
                size,
                direct: Direct::TX,
            },
            0,
        )
    };
    unsafe { SOCK_MAP.remove(&tid) }?;
    info!(&ctx, "{} {} TCP_NEW!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", daddr, dport);
    Ok(())
}

#[kprobe(name = "tcp_send")]
pub fn kprobe_tcp_send(ctx: ProbeContext) -> u32 {
    match tcp_sendentry(ctx) {
        Ok(()) => 0,
        Err(ret) => ret as u32,
    }
}

#[kretprobe(name = "ret_tcp_send")]
pub fn kretprobe_tcp_send(ctx: ProbeContext) -> u32 {
    match tcp_sendstat(ctx) {
        Ok(()) => 0,
        Err(ret) => ret as u32,
    }
}

#[xdp(name="get_packet_info")]
pub fn get_packet_info(ctx: XdpContext) -> u32 {
    match try_get_packet_info(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] 
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_get_packet_info(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; 
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe{(*ipv4hdr).dst_addr});
    let h_proto= u16::from_be(unsafe {*ptr_at(&ctx, EthHdr::LEN+16)?});

    let mut source_port:u16 = 0;
    let mut dest_port:u16 = 0;
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            source_port = u16::from_be(unsafe { (*tcphdr).source })
        },
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            source_port = u16::from_be(unsafe { (*udphdr).source })
        },
        _ => {
            source_port = 0;
            
        }
    };

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            dest_port = u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            dest_port = u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => {
            dest_port = 0;
        },
    };


    let protocol_used = match unsafe{(*ipv4hdr).proto} {
        IpProto::HopOpt => {
            0
        },
        IpProto::Icmp => {1},
        IpProto::Igmp => {2},
        IpProto::Ggp => {3},
        IpProto::Ipv4 => {4},
        IpProto::Stream => {5},
        IpProto::Tcp => {6},
        IpProto::Cbt => {7},
        IpProto::Egp => {8},
        IpProto::Igp => {9},
        IpProto::Udp => {10},
        IpProto::Ipv6 => {11},
        _ => {100},
    };

    let packet_info = PacketInfo {
        src_ip: source_addr,
        dest_ip: dest_addr,
        src_port: source_port,
        dest_port: dest_port,
        protocol: protocol_used,
        packet_length: h_proto,
        // time: SystemTime::now(),
    };

    unsafe {
        PACKETS.output(&ctx, &packet_info, 0);
    };

    // let j = serde_json::to_string(&packetInfo)?;

    info!(&ctx, "{:ipv4} {}", source_addr, h_proto);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}