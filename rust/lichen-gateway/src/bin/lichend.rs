//! lichend — LICHEN border router daemon.
//!
//! Bridges the LoRa mesh (SLIP over serial or TCP simulator) to the Linux
//! IPv6 stack via a TUN device. Acts as RPL DODAG root in Non-Storing Mode.
//!
//! Usage:
//!   lichend --config /etc/lichen/gateway.toml
//!   lichend --sim                          # TCP simulator, TUN device
//!   lichend --sim --no-tun                 # TCP simulator, logging only (CI)

use clap::Parser;
use lichen_core::addr::NodeId;
use lichen_gateway::{config::Config, slip, Gateway};
use std::path::PathBuf;
use tokio::{io::AsyncWriteExt, io::BufReader, signal};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[cfg(target_os = "linux")]
use lichen_gateway::tun::TunDevice;

#[derive(Parser)]
#[command(name = "lichend", about = "LICHEN border router daemon")]
struct Args {
    /// Path to TOML configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Connect to the simulator instead of a real serial port.
    #[arg(long)]
    sim: bool,

    /// Simulator address (used with --sim).
    #[arg(long, default_value = "127.0.0.1:4444")]
    sim_addr: String,

    /// Node identifier (8-byte hex EUI-64, e.g. `0200000000000001`).
    #[arg(long, default_value = "0200000000000001")]
    node_id: String,

    /// Skip TUN device creation (logs packets instead of forwarding).
    /// Required when running without CAP_NET_ADMIN (e.g. CI).
    #[arg(long)]
    no_tun: bool,

    /// Log level filter (e.g. `info`, `debug`, `lichen_gateway=trace`).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    fmt().with_env_filter(EnvFilter::new(&args.log)).init();

    let config = if let Some(path) = &args.config {
        match Config::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                error!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        Config::default_sim()
    };

    let node_id = parse_node_id(&args.node_id).unwrap_or_else(|e| {
        error!("invalid --node-id: {e}");
        std::process::exit(1);
    });

    let use_sim = args.sim || config.mesh.interface == "sim";

    info!(
        interface = if use_sim { &args.sim_addr } else { &config.mesh.interface },
        ?node_id,
        prefix = %config.ipv6.prefix,
        rpl_mode = %config.rpl.mode,
        "lichend starting"
    );

    // Open TUN device unless --no-tun or non-Linux.
    #[cfg(target_os = "linux")]
    let tun = if args.no_tun {
        warn!("--no-tun: TUN device skipped; packets will be logged only");
        None
    } else {
        match TunDevice::open("lichen0") {
            Ok(dev) => {
                if let Err(e) = lichen_gateway::tun::configure("lichen0", &config.ipv6.prefix) {
                    error!("TUN configure: {e} (try running as root or with CAP_NET_ADMIN)");
                    std::process::exit(1);
                }
                Some(dev)
            }
            Err(e) => {
                error!("TUN open: {e} (try running as root or with CAP_NET_ADMIN)");
                std::process::exit(1);
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let tun: Option<()> = {
        if !args.no_tun {
            warn!("TUN is only supported on Linux; running in --no-tun mode");
        }
        None
    };

    let mut gw = Gateway::new(node_id);

    if use_sim {
        run_sim(&mut gw, &args.sim_addr, tun).await;
    } else {
        run_serial(&mut gw, &config.mesh.interface, config.mesh.baud, tun).await;
    }
}

// ── forwarding helpers ────────────────────────────────────────────────────────

/// Resolves to never — used in select! when TUN is absent.
async fn tun_recv_none(_buf: &mut [u8]) -> std::io::Result<usize> {
    std::future::pending().await
}

/// Resolves to never — used in select! when TUN is absent.
async fn tun_send_none(_buf: &[u8]) -> std::io::Result<()> {
    std::future::pending().await
}

// ── sim mode ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_sim(gw: &mut Gateway, addr: &str, tun: Option<TunDevice>) {
    run_sim_inner(gw, addr, tun).await
}

#[cfg(not(target_os = "linux"))]
async fn run_sim(gw: &mut Gateway, addr: &str, _tun: Option<()>) {
    run_sim_inner(gw, addr, None::<()>).await
}

async fn run_sim_inner<T>(gw: &mut Gateway, addr: &str, tun: Option<T>)
where
    T: TunLike,
{
    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("cannot connect to simulator at {addr}: {e}");
            return;
        }
    };
    info!("connected to simulator at {addr}");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut slip_buf = vec![0u8; 1500];
    let mut tun_buf = vec![0u8; 1500];

    loop {
        tokio::select! {
            result = slip::recv_packet(&mut reader, &mut slip_buf) => {
                match result {
                    Ok(n) => forward_mesh_to_upstream(gw, &slip_buf[..n], &tun).await,
                    Err(e) => { error!("SLIP recv: {e}"); break; }
                }
            }
            result = async { match &tun {
                Some(t) => t.recv_pkt(&mut tun_buf).await,
                None => tun_recv_none(&mut tun_buf).await,
            }} => {
                match result {
                    Ok(n) => forward_upstream_to_mesh(gw, &tun_buf[..n], &mut writer).await,
                    Err(e) => { error!("TUN recv: {e}"); break; }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

// ── serial mode ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_serial(gw: &mut Gateway, interface: &str, baud: u32, tun: Option<TunDevice>) {
    run_serial_inner(gw, interface, baud, tun).await
}

#[cfg(not(target_os = "linux"))]
async fn run_serial(gw: &mut Gateway, interface: &str, baud: u32, _tun: Option<()>) {
    run_serial_inner(gw, interface, baud, None::<()>).await
}

async fn run_serial_inner<T>(gw: &mut Gateway, interface: &str, baud: u32, tun: Option<T>)
where
    T: TunLike,
{
    info!(interface, "opening serial port");
    let mut tty = match tokio_serial::SerialStream::open(&tokio_serial::new(interface, baud)) {
        Ok(p) => p,
        Err(e) => {
            error!("cannot open {interface}: {e}");
            return;
        }
    };

    let mut slip_buf = vec![0u8; 1500];
    let mut tun_buf = vec![0u8; 1500];

    loop {
        tokio::select! {
            result = slip::recv_packet(&mut tty, &mut slip_buf) => {
                match result {
                    Ok(n) => forward_mesh_to_upstream(gw, &slip_buf[..n], &tun).await,
                    Err(e) => { error!("SLIP recv: {e}"); break; }
                }
            }
            result = async { match &tun {
                Some(t) => t.recv_pkt(&mut tun_buf).await,
                None => tun_recv_none(&mut tun_buf).await,
            }} => {
                match result {
                    Ok(n) => {
                        if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]) {
                            if let Err(e) = slip::send_packet(&mut tty, &schc).await {
                                error!("SLIP send: {e}"); break;
                            }
                        }
                    }
                    Err(e) => { error!("TUN recv: {e}"); break; }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }
}

// ── packet forwarding ─────────────────────────────────────────────────────────

async fn forward_mesh_to_upstream<T: TunLike>(gw: &mut Gateway, frame: &[u8], tun: &Option<T>) {
    if let Some(ipv6) = gw.mesh_to_upstream(frame) {
        if let Some(t) = tun {
            if let Err(e) = t.send_pkt(&ipv6).await {
                error!("TUN write: {e}");
            }
        }
    }
}

async fn forward_upstream_to_mesh<W: AsyncWriteExt + Unpin>(
    gw: &mut Gateway,
    packet: &[u8],
    writer: &mut W,
) {
    if let Some(schc) = gw.upstream_to_mesh(packet) {
        if let Err(e) = slip::send_packet(writer, &schc).await {
            error!("SLIP send: {e}");
        }
    }
}

// ── TunLike trait (abstracts TunDevice vs. no-op placeholder) ─────────────────

trait TunLike {
    fn recv_pkt<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a;
    fn send_pkt<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = std::io::Result<()>> + 'a;
}

#[cfg(target_os = "linux")]
impl TunLike for TunDevice {
    fn recv_pkt<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a {
        self.recv(buf)
    }
    fn send_pkt<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = std::io::Result<()>> + 'a {
        self.send(buf)
    }
}

// Placeholder for non-Linux builds (never instantiated).
impl TunLike for () {
    fn recv_pkt<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a {
        tun_recv_none(buf)
    }
    fn send_pkt<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = std::io::Result<()>> + 'a {
        tun_send_none(buf)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse_node_id(hex: &str) -> Result<NodeId, String> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<u8>, _>>()?;
    if bytes.len() != 8 {
        return Err(format!("expected 8 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(NodeId(arr))
}
