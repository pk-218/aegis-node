use std::net;

use aegis_node_common::packet_info::PacketInfo;
use aya::{include_bytes_aligned, Bpf, maps::perf::AsyncPerfEventArray, util::online_cpus};
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, spawn};
use serde::Serialize;
use bytes::BytesMut;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    iface: String,
}

#[derive(Serialize, Debug)]
struct PacketInfoDto {
    src_ip: String,
    dest_ip: String,
    src_port: u16,
    dest_port: u16,
    protocol: i32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("get_packet_info").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;


    let mut packets: AsyncPerfEventArray<_> = bpf.map_mut("PACKETS").unwrap().try_into().unwrap();
    for cpu_id in online_cpus()? {
        let mut packets_buf = packets.open(cpu_id, Some(256))?;
        spawn(async move {
            let mut bufs = (0..10)
                .map(|_| BytesMut::with_capacity(128 * 4096))
                .collect::<Vec<_>>();
            loop {
                let events = packets_buf.read_events(&mut bufs).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut bufs[i];
                    let ptr = buf.as_ptr() as *const PacketInfo;
                    let data = unsafe { ptr.read_unaligned() };

                    let packet_dto = PacketInfoDto {
                        src_ip: net::Ipv4Addr::from(data.src_ip).to_string(),
                        dest_ip: net::Ipv4Addr::from(data.dest_ip).to_string(),
                        src_port: data.src_port,
                        dest_port: data.dest_port,
                        protocol: data.protocol
                    };

                    let j = serde_json::to_string(&packet_dto).unwrap();
                    println!("Packet JSON {:}", j);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}