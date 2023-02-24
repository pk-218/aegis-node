
#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn get_packet_info(ctx: XdpContext) -> u32 {
    match try_get_packet_info(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // 

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
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // 

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe{(*ipv4hdr).dst_addr});
    // let mut protocol_used:&str = "";

    let mut source_port:u16 = 0;
    let mut dest_port:u16 = 0;
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            // protocol_used = "TCP";
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            source_port = u16::from_be(unsafe { (*tcphdr).source })
        },
        IpProto::Udp => {
            // protocol_used = "UDP";
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
            "HopOpt"
        },
        IpProto::Icmp => {"Icmp"},
        IpProto::Igmp => {"Igmp"},
        IpProto::Ggp => {"Ggp"},
        IpProto::Ipv4 => {"Ipv4"},
        IpProto::Stream => {"Stream"},
        IpProto::Tcp => {"Tcp"},
        IpProto::Cbt => {"Cbt"},
        IpProto::Egp => {"Egp"},
        IpProto::Igp => {"Igp"},
        IpProto::Udp => {"Udp"},
        IpProto::Ipv6 => {"Ipv6"},
        _ => {"Other"},
    };
    



    info!(
        &ctx,
        "SRC IP: {:ipv4},  DEST IP: {:ipv4}, SOURCE PORT: {}, DEST PORT: {},PROTOCOL: {}", source_addr, dest_addr, source_port, dest_port, protocol_used
    );

    Ok(xdp_action::XDP_PASS)
}