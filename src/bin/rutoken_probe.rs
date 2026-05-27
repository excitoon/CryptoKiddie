use cryptokiddie::{
    CliError,
    apdu::{CommandApdu, ResponseApdu},
    pcsc_transport::PcscDevice,
    rutoken,
};

fn main() -> Result<(), CliError> {
    let mut card = PcscDevice::open_with_exchange_log(Some("Rutoken ECP"), None)?;
    let mf = tx(&mut card, "select-mf", &rutoken::select_master_file())?;
    println!(
        "select-mf sw={:02x}{:02x} data={}",
        mf.sw1,
        mf.sw2,
        hex(&mf.data)
    );

    if let Ok(pin) = std::env::var("TOKEN_PIN") {
        let mut verify = tx(&mut card, "verify", &rutoken::verify_pin(pin.as_bytes()))?;
        if verify.sw1 == 0x6f && verify.sw2 == 0x86 {
            let logout = tx(&mut card, "logout", &rutoken::logout())?;
            println!("logout sw={:02x}{:02x}", logout.sw1, logout.sw2);
            verify = tx(&mut card, "verify", &rutoken::verify_pin(pin.as_bytes()))?;
        }
        println!("verify sw={:02x}{:02x}", verify.sw1, verify.sw2);
    }

    let roots = [
        vec![0x3f, 0x00],
        vec![0x10, 0x00],
        vec![0x10, 0x00, 0x10, 0x00],
    ];
    for root in roots {
        println!("\nroot {}", path_hex(&root));
        if select_path_fci(&mut card, &root).is_ok() {
            list_dir(&mut card, &root, 0)?;
        }
    }
    Ok(())
}

fn list_dir(card: &mut PcscDevice, path: &[u8], depth: usize) -> Result<(), CliError> {
    select_path_fci(card, path)?;
    let children = list_current_dir(card)?;
    for child in children {
        let mut child_path = path.to_vec();
        if child_path.ends_with(&[0x3f, 0x00]) && child == [0x3f, 0x00] {
            continue;
        }
        child_path.extend_from_slice(&child);
        let indent = "  ".repeat(depth);
        match select_path_fci(card, &child_path) {
            Ok(fci) => {
                let kind = file_descriptor(&fci.data)
                    .map(|byte| format!("fd={byte:02x}"))
                    .unwrap_or_else(|| "fd=?".to_string());
                println!(
                    "{indent}{} {} fci={}",
                    path_hex(&child_path),
                    kind,
                    hex(&fci.data)
                );
                if looks_transparent_ef(&fci.data) {
                    let data = read_current_binary(card, 4096)?;
                    if !data.is_empty() {
                        println!(
                            "{indent}  data len={} head={}",
                            data.len(),
                            hex_prefix(&data, 96)
                        );
                        if let Some(cert) = extract_der_certificate(&data) {
                            let out = format!("target/rutoken-probe-{}.der", path_hex(&child_path));
                            std::fs::write(&out, &cert).map_err(|error| {
                                CliError::Message(format!("failed to write {out}: {error}"))
                            })?;
                            println!("{indent}  certificate_der={} len={}", out, cert.len());
                        }
                    }
                }
                if looks_df(&fci.data) && depth < 6 {
                    let _ = list_dir(card, &child_path, depth + 1);
                }
            }
            Err(error) => println!("{indent}{} select-error={error}", path_hex(&child_path)),
        }
    }
    Ok(())
}

fn list_current_dir(card: &mut PcscDevice) -> Result<Vec<[u8; 2]>, CliError> {
    let mut out = Vec::new();
    let mut command = CommandApdu::new(0x00, 0xa4, 0x00, 0x00).with_le(0);
    loop {
        let resp = tx(card, "list", &command)?;
        if resp.sw1 == 0x6a && resp.sw2 == 0x82 {
            break;
        }
        if !resp.is_success() {
            break;
        }
        let Some(fid) = find_tlv_value(&resp.data, 0x83)
            .and_then(|value| (value.len() == 2).then_some([value[0], value[1]]))
        else {
            break;
        };
        out.push(fid);
        if file_descriptor(&resp.data) == Some(0x38) {
            let _ = tx(
                card,
                "parent",
                &CommandApdu::new(0x00, 0xa4, 0x03, 0x00).with_le(0),
            );
        }
        command = CommandApdu::new(0x00, 0xa4, 0x00, 0x02)
            .with_data(fid)
            .with_le(0);
    }
    Ok(out)
}

fn select_path_fci(card: &mut PcscDevice, path: &[u8]) -> Result<ResponseApdu, CliError> {
    let resp = tx(
        card,
        "select-path-fci",
        &CommandApdu::new(0x00, 0xa4, 0x08, 0x00)
            .with_data(path.to_vec())
            .with_le(0),
    )?;
    if resp.is_success() {
        Ok(resp)
    } else {
        Err(CliError::Message(format!(
            "SELECT {} failed: {:02x}{:02x}",
            path_hex(path),
            resp.sw1,
            resp.sw2
        )))
    }
}

fn read_current_binary(card: &mut PcscDevice, limit: usize) -> Result<Vec<u8>, CliError> {
    let mut data = Vec::new();
    while data.len() < limit {
        let resp = tx(card, "read", &rutoken::read_binary(data.len(), 0))?;
        if resp.sw1 == 0x6b || resp.sw1 == 0x6a || resp.sw1 == 0x67 {
            break;
        }
        if resp.sw1 == 0x62 && resp.sw2 == 0x82 {
            data.extend_from_slice(&resp.data);
            break;
        }
        if !resp.is_success() || resp.data.is_empty() {
            break;
        }
        let n = resp.data.len();
        data.extend_from_slice(&resp.data);
        if n < 256 {
            break;
        }
    }
    Ok(data)
}

fn tx(
    card: &mut PcscDevice,
    _label: &str,
    command: &CommandApdu,
) -> Result<ResponseApdu, CliError> {
    card.transmit(command)
}

fn looks_df(fci: &[u8]) -> bool {
    file_descriptor(fci) == Some(0x38)
}

fn looks_transparent_ef(fci: &[u8]) -> bool {
    matches!(file_descriptor(fci), Some(0x01 | 0x02 | 0x04)) || !looks_df(fci)
}

fn file_descriptor(fci: &[u8]) -> Option<u8> {
    find_tlv_value(fci, 0x82).and_then(|value| value.first().copied())
}

fn find_tlv_value(data: &[u8], wanted: u8) -> Option<&[u8]> {
    let mut stack = vec![data];
    while let Some(mut input) = stack.pop() {
        while input.len() >= 2 {
            let tag = input[0];
            let (len, header_len) = der_len(&input[1..])?;
            let start = 1 + header_len;
            let end = start.checked_add(len)?;
            if end > input.len() {
                return None;
            }
            let value = &input[start..end];
            if tag == wanted {
                return Some(value);
            }
            if tag & 0x20 != 0 {
                stack.push(value);
            }
            input = &input[end..];
        }
    }
    None
}

fn der_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let len_len = (first & 0x7f) as usize;
    if len_len == 0 || len_len > 4 || data.len() < 1 + len_len {
        return None;
    }
    let mut len = 0usize;
    for byte in &data[1..1 + len_len] {
        len = (len << 8) | *byte as usize;
    }
    Some((len, 1 + len_len))
}

fn extract_der_certificate(data: &[u8]) -> Option<Vec<u8>> {
    for start in 0..data.len() {
        if data[start] != 0x30 {
            continue;
        }
        let (len, len_header) = der_len(&data[start + 1..])?;
        let total = 1 + len_header + len;
        if start + total <= data.len() {
            return Some(data[start..start + total].to_vec());
        }
    }
    None
}

fn path_hex(path: &[u8]) -> String {
    path.chunks(2).map(hex).collect::<Vec<_>>().join(":")
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    let mut text = hex(&bytes[..bytes.len().min(limit)]);
    if bytes.len() > limit {
        text.push_str("...");
    }
    text
}
