#![no_std]
#![no_main]

use aegis_node_common::packet_info::PacketInfo;
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext, macros::{map}, maps::PerfEventArray};
use aya_log_ebpf::info;

use core::{mem};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};




#[map(name="PACKETS")]
static mut PACKETS: PerfEventArray<PacketInfo> = PerfEventArray::<PacketInfo>::with_max_entries(1024, 0);


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

    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, EthHdr::LEN+16)? });

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