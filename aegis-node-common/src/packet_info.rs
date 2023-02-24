#[derive(Clone, Copy)]
#[repr(packed)]
pub struct PacketInfo {
    pub src_ip: u32,
    pub dest_ip: u32,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: i32,
    pub packet_length: u16,
    // pub time: u32,
}