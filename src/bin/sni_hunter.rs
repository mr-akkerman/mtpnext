use reqwest;
use serde::Deserialize;
use std::env;
use std::net::ToSocketAddrs;
use std::process::exit;

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct IpApiResp {
    status: String,
    message: Option<String>,
    query: String,
    as_name: Option<String>,
    #[serde(rename = "as")]
    asn_str: Option<String>,
    isp: Option<String>,
}

fn extract_as_number(asn_str: &str) -> Option<String> {
    // "AS24940 Hetzner Online GmbH" -> "AS24940"
    asn_str.split_whitespace().next().map(|s| s.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Telemt SNI-Hunter: Cross-Border TSPU Mismatch Analyzer");
    println!("------------------------------------------------------------");
    
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: cargo run --bin sni_hunter -- <domain_to_check>");
        println!("Example: cargo run --bin sni_hunter -- google.com");
        exit(1);
    }
    
    let target_domain = &args[1];

    // 1. Get the local server's public IP and ASN
    println!("⏳ Fetching Local Server ASN...");
    let client = reqwest::Client::new();
    let local_resp = client
        .get("http://ip-api.com/json/?fields=status,message,query,as,isp")
        .send()
        .await?
        .json::<IpApiResp>()
        .await?;

    if local_resp.status != "success" {
        println!("❌ Failed to get local ASN: {:?}", local_resp.message);
        exit(1);
    }
    
    let local_asn_raw = local_resp.asn_str.unwrap_or_default();
    let local_asn = extract_as_number(&local_asn_raw).unwrap_or_else(|| "UNKNOWN".to_string());
    println!("✅ Local Server IP: {}", local_resp.query);
    println!("✅ Local Server ASN: {} ({})", local_asn, local_resp.isp.unwrap_or_default());
    println!("");

    // 2. Resolve the target domain
    println!("⏳ Resolving Domain '{}'...", target_domain);
    let socket_str = format!("{}:443", target_domain);
    let addrs: Vec<_> = socket_str.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        println!("❌ Failed to resolve domain {}", target_domain);
        exit(1);
    }
    
    let target_ip = addrs[0].ip().to_string();
    println!("✅ Domain resolved to IP: {}", target_ip);
    
    // 3. Get the target domain's ASN
    println!("⏳ Fetching Domain ASN...");
    let target_resp = client
        .get(&format!("http://ip-api.com/json/{}?fields=status,message,query,as,isp", target_ip))
        .send()
        .await?
        .json::<IpApiResp>()
        .await?;

    if target_resp.status != "success" {
        println!("❌ Failed to get target ASN: {:?}", target_resp.message);
        exit(1);
    }
    
    let target_asn_raw = target_resp.asn_str.unwrap_or_default();
    let target_asn = extract_as_number(&target_asn_raw).unwrap_or_else(|| "UNKNOWN".to_string());
    println!("✅ Domain ASN: {} ({})", target_asn, target_resp.isp.unwrap_or_default());
    println!("");
    
    // 4. Compare ASNs
    println!("------------------------------------------------------------");
    if local_asn == target_asn {
        println!("🟢 EXCELLENT! ASN Match.");
        println!("The domain '{}' and this server share the same ASN ({}).", target_domain, local_asn);
        println!("TSPU / DPI SNI-IP Mismatch filters will NOT block this configuration.");
        println!("You can safely use this domain as your `tls_domain`.");
    } else {
        println!("🔴 DANGER! DPI Block Imminent.");
        println!("SNI-to-IP Mismatch Detected:");
        println!("   Server ASN: {}", local_asn);
        println!("   Domain ASN: {}", target_asn);
        println!("If you use this domain, the Russian TSPU will detect that you are requesting '{}'", target_domain);
        println!("but the IP address does not belong to the domain's network.");
        println!("The connection will be dropped exactly at the ClientHello stage.");
        println!("FIX: Find a domain that is hosted on the same provider as this server.");
    }

    Ok(())
}
