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

    if std::env::var("ACL_DUMP").is_ok() {
        acl_dump(&mut card)?;
        return Ok(());
    }

    if std::env::var("VKO_SERSF").is_ok() {
        vko_sersf_test(&mut card)?;
        return Ok(());
    }

    if std::env::var("VKO_PROVISION").is_ok() {
        vko_provision(&mut card)?;
        return Ok(());
    }

    if std::env::var("VKO_CSP").is_ok() {
        vko_csp(&mut card)?;
        return Ok(());
    }

    if std::env::var("VKO_SWEEP").is_ok() {
        vko_algo_sweep(&mut card)?;
        return Ok(());
    }

    if std::env::var("VKO_DIRECT").is_ok() {
        vko_direct(&mut card)?;
        return Ok(());
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
                        let raw = format!("target/rutoken-ef-{}.bin", path_hex(&child_path));
                        std::fs::write(&raw, &data).map_err(|error| {
                            CliError::Message(format!("failed to write {raw}: {error}"))
                        })?;
                        println!("{indent}  raw_ef={} len={}", raw, data.len());
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

/// Read-only FCP/ACL dump: fetch the full FCP (P2=0x04) of the SE-RSF directory
/// 1000/1000/6005, the key directory 1000/1000/6002, and the key EF
/// 1000/1000/6002/0003, then print and best-effort decode the 0x86 security
/// attribute (create access rule). This answers whether creating the per-key
/// SE-RSF file 6005/0003 needs SO/admin auth or just the user PIN. Pure SELECTs;
/// nothing is written and the PIN counter is untouched.
fn acl_dump(card: &mut PcscDevice) -> Result<(), CliError> {
    let targets: &[(&str, Vec<u8>)] = &[
        (
            "SE-RSF dir 1000/1000/6005",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05],
        ),
        (
            "key dir   1000/1000/6002",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x02],
        ),
        (
            "key EF    1000/1000/6002/0003",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, 0x03],
        ),
        (
            "SE-RSF dir 1000/1000/6001",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x01],
        ),
        (
            "dir       1000/1000/6003",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x03],
        ),
    ];
    for (label, path) in targets {
        // Request FCP template explicitly (P2=0x04); fall back to FCI (P2=0x00).
        let mut resp = card.transmit(
            &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
                .with_data(path.clone())
                .with_le(0),
        )?;
        if !resp.is_success() {
            resp = card.transmit(
                &CommandApdu::new(0x00, 0xA4, 0x08, 0x00)
                    .with_data(path.clone())
                    .with_le(0),
            )?;
        }
        println!(
            "\n[{label}] SELECT {} -> sw={:02x}{:02x}",
            path_hex(path),
            resp.sw1,
            resp.sw2
        );
        if !resp.is_success() {
            continue;
        }
        println!("  FCP = {}", hex(&resp.data));
        if let Some(fd) = file_descriptor(&resp.data) {
            println!("  file-descriptor (82) = {fd:02x}");
        }
        if let Some(sa) = find_tlv_value(&resp.data, 0x86) {
            println!("  security-attr (86) = {}  (len {})", hex(sa), sa.len());
            decode_rtecp_acl(sa);
        } else {
            println!("  (no 0x86 security-attribute present)");
        }
    }
    Ok(())
}

/// Best-effort decode of a Rutoken rtecp 0x86 security attribute: surface each
/// per-operation access-condition reference byte. Reference semantics (verified
/// live: verify_pin uses P2=USER_PIN_REFERENCE=0x02 and succeeds, so 0x02=user):
/// 00=always/anybody, 01=SO/admin PIN, 02=USER PIN, ff=never.
fn decode_rtecp_acl(sa: &[u8]) {
    for (i, b) in sa.iter().enumerate() {
        let meaning = match b {
            0x00 => "always/anybody",
            0x01 => "SO/admin pin",
            0x02 => "USER pin",
            0xff => "NEVER",
            _ => "?",
        };
        println!("    [{i}] = {b:02x} ({meaning})");
    }
}

/// SE-RSF VKO test. The step performed before MSE/PSO is selecting the
/// Security-Environment RSF directory (DF 1000/1001/6005) and the per-key SE-RSF
/// file, THEN issuing `00 22 41 A6 09 95 01 40 84 01 <keyId> 80 01 <algo>` and
/// `00 2A 80 86 <peer-point-LE>`. All read-only / param-validation APDUs here
/// (SELECT + MSE + PSO); none touch the PIN counter, so this is lockout-safe.
/// We do NOT attempt the SE-RSF card-write path.
fn vko_sersf_test(card: &mut PcscDevice) -> Result<(), CliError> {
    let key_id = 0x03u8;

    // 1. SELECT the SE-RSF directory: 00 A4 08 04 06 1000 1000 6005
    //    (DF 1000/1000/6005 — same parent as the private keys 1000/1000/6002/03;
    //    path prefix 10 00 10 00 = 1000/1000, file id 6005).
    let sel_dir = CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
        .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05]);
    let d = card.transmit(&sel_dir)?;
    println!(
        "SELECT SE-RSF dir (1000/1000/6005) -> sw={:02x}{:02x} data={}",
        d.sw1,
        d.sw2,
        hex_prefix(&d.data, 48)
    );

    // 2. SELECT the per-key SE-RSF file under 6005. The library's
    //    SelectSE_RSF_File selects a crypto object of type 5 with arg4=keyId.
    //    Try the same DF-path SELECT with the key id appended, and a couple of
    //    plausible file-id encodings, to learn which the card accepts.
    let sersf_selects: &[(&str, Vec<u8>)] = &[
        (
            "path 6005:000id",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05, 0x00, key_id],
        ),
        (
            "path 6005:id",
            vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05, key_id],
        ),
        ("fid 6005:0003", vec![0x60, 0x05, 0x00, key_id]),
        ("fid 6005", vec![0x60, 0x05]),
    ];
    let mut sersf_ok = false;
    for (label, data) in sersf_selects {
        let s = card.transmit(&CommandApdu::new(0x00, 0xA4, 0x08, 0x0C).with_data(data.clone()))?;
        println!(
            "  SELECT SE-RSF file [{label}] {} -> sw={:02x}{:02x}",
            hex(data),
            s.sw1,
            s.sw2
        );
        if s.sw1 == 0x90 {
            sersf_ok = true;
            break;
        }
    }
    if !sersf_ok {
        println!("  (no SE-RSF file selectable; the file may not be provisioned for this key)");
    }

    // 3. Load the peer point (client cert's own on-curve GOST point as stand-in),
    //    converted to the card's per-coordinate LE order.
    let cert = std::fs::read("target/client-leaf.der").unwrap_or_default();
    let point = match cryptokiddie::gost_login::extract_subject_public_point(&cert) {
        Ok(p) if p.len() == 64 => p,
        _ => {
            println!("(no usable client point; skipping MSE/PSO)");
            return Ok(());
        }
    };
    let pt_le: Vec<u8> = point
        .chunks_exact(32)
        .flat_map(|c| c.iter().rev().copied())
        .collect();

    // 4. MSE SET A6 with the derived body, sweeping the candidate algo byte.
    //    algo=0xAA is the strongest candidate (SE template 8506..AA, privkey FCI
    //    8506032001AA). Also try 0x00 (omit) and a few neighbours.
    let algos: &[u8] = &[0xAA, 0x00, 0x40, 0x3D, 0x01];
    println!("--- SE-RSF MSE A6 + PSO sweep (algo candidates) ---");
    for &algo in algos {
        let mut body = vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id];
        if algo != 0x00 {
            body.extend_from_slice(&[0x80, 0x01, algo]);
        }
        let mse = CommandApdu::new(0x00, 0x22, 0x41, 0xA6).with_data(body.clone());
        let m = card.transmit(&mse)?;
        // PSO key agreement with the LE peer point (00 padding indicator first).
        let operand = [&[0x00u8][..], &pt_le].concat();
        let p = card.transmit(&CommandApdu::new(0x00, 0x2A, 0x80, 0x86).with_data(operand))?;
        println!(
            "  algo={algo:02x}  MSE A6 [{}] mse={:02x}{:02x}  pso={:02x}{:02x} data={}",
            hex(&body),
            m.sw1,
            m.sw2,
            p.sw1,
            p.sw2,
            hex_prefix(&p.data, 16)
        );
    }
    println!("--- SE-RSF test done ---");
    Ok(())
}

/// Mode B VKO (direct MSE + PSO, no SE-RSF file). Unlike `vko_sersf_test`, the
/// peer point lives INSIDE the MSE `a6` key-agreement template (tag `87`):
///
///   MSE = 00 22 41 · a6 L { 95 01 40 · 84 01 <keyId> · 80 01 <mech> · 87 <len> <peer> }
///   PSO = 00 2A 80 86 <ukm/data>
///
/// `mech` is written raw (=3 for GOST-2012-256). All operations are transient
/// (no persistent card writes), so iterating is lockout-safe as long as the PIN
/// is never mis-entered.
fn vko_direct(card: &mut PcscDevice) -> Result<(), CliError> {
    let key_id = std::env::var("VKO_KEY_ID")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x03);
    let mech = std::env::var("VKO_MECH")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x03);

    // Peer point: use the client cert's own on-curve GOST point as a stand-in
    // (a valid curve point is enough to probe MSE acceptance), in the card's
    // per-coordinate little-endian order.
    let cert = std::fs::read("target/client-leaf.der").unwrap_or_default();
    let point = match cryptokiddie::gost_login::extract_subject_public_point(&cert) {
        Ok(p) if p.len() == 64 => p,
        _ => {
            println!("(no usable 64-byte client point at target/client-leaf.der; aborting)");
            return Ok(());
        }
    };
    let pt_le: Vec<u8> = point
        .chunks_exact(32)
        .flat_map(|c| c.iter().rev().copied())
        .collect();

    // The keyId embedded in `84 01 <ref>` is a RUNTIME object field, i.e. the
    // on-card key reference — not necessarily the PKCS#11 CKA_ID 0x03.
    // mech/peer-order were already
    // swept with no effect (all 6a80), so the rejected DO is the key reference
    // (84) or the usage qualifier (95). Optionally SELECT the private-key EF
    // first (some cards require the key be current), then sweep the 84-ref.
    if std::env::var("VKO_SELECT_KEY").is_ok() {
        let selk = card.transmit(
            &CommandApdu::new(0x00, 0xA4, 0x08, 0x0C)
                .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, key_id]),
        )?;
        println!(
            "SELECT privkey EF 1000/1000/6002/{key_id:04x} -> sw={:02x}{:02x}",
            selk.sw1, selk.sw2
        );
    }

    let keyrefs: &[u8] = &[
        key_id, 0x01, 0x02, 0x04, 0x05, 0x00, 0x30, 0x33, 0xa0, 0x10, 0x20,
    ];
    let mut hit = false;
    for &kr in keyrefs {
        // Vmain inner = 95 01 40 · 84 01 <kr> · 80 01 <mech> · 87 40 <peer(LE)>.
        let mut inner = vec![0x95, 0x01, 0x40, 0x84, 0x01, kr, 0x80, 0x01, mech];
        inner.push(0x87);
        inner.push(pt_le.len() as u8);
        inner.extend_from_slice(&pt_le);
        let m =
            card.transmit(&CommandApdu::new(0x00, 0x22, 0x41, 0xA6).with_data(inner.clone()))?;
        println!(
            "  keyref={kr:02x} (84 01 {kr:02x}, mech {mech:02x})  MSE -> sw={:02x}{:02x}",
            m.sw1, m.sw2
        );
        if m.is_success() {
            hit = true;
            println!("  *** MSE ACCEPTED (keyref={kr:02x}) — sending PSO");
            let p =
                card.transmit(&CommandApdu::new(0x00, 0x2A, 0x80, 0x86).with_data(vec![0u8; 8]))?;
            println!(
                "      PSO 00 2A 80 86 -> sw={:02x}{:02x} data={}",
                p.sw1,
                p.sw2,
                hex_prefix(&p.data, 32)
            );
            let _ = card.transmit(&CommandApdu::new(0x00, 0x22, 0xF3, 0x00))?;
            break;
        }
    }

    if !hit {
        // Key reference exhausted — try a minimal template (drop 95, drop 80) to
        // see whether the usage/algorithm DOs are the offenders.
        println!("  --- minimal-template probes (mech={mech:02x}, keyref={key_id:02x}) ---");
        let variants: &[(&str, Vec<u8>)] = &[
            ("no-95", {
                let mut v = vec![0x84, 0x01, key_id, 0x80, 0x01, mech, 0x87, 0x40];
                v.extend_from_slice(&pt_le);
                v
            }),
            ("no-80", {
                let mut v = vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id, 0x87, 0x40];
                v.extend_from_slice(&pt_le);
                v
            }),
            ("83-ref", {
                let mut v = vec![
                    0x95, 0x01, 0x40, 0x83, 0x01, key_id, 0x80, 0x01, mech, 0x87, 0x40,
                ];
                v.extend_from_slice(&pt_le);
                v
            }),
        ];
        for (label, inner) in variants {
            let m =
                card.transmit(&CommandApdu::new(0x00, 0x22, 0x41, 0xA6).with_data(inner.clone()))?;
            println!("    [{label}] MSE -> sw={:02x}{:02x}", m.sw1, m.sw2);
        }
        println!("  (no keyref/template combo accepted by MSE)");
    }
    Ok(())
}

/// Provisioning helper for the missing per-key SE-RSF EF (1000/1000/6005/<key>).
///
/// DRY-RUN BY DEFAULT (read-only, lockout-safe): reads the live sibling key EF
/// FCP, derives the ACL condition body from it, prints the exact CREATE FILE
/// APDU that [`rutoken::create_se_rsf_file_for_vko`] would emit, and stops
/// WITHOUT writing. The actual CREATE FILE is only sent when the operator also
/// sets `VKO_PROVISION_CONFIRM=write` — a persistent (user-PIN-reversible)
/// card-state change that must be an explicit, deliberate choice.
fn vko_provision(card: &mut PcscDevice) -> Result<(), CliError> {
    let key_id = 0x03u8;

    // 1. Read the sibling private-key EF FCP to recover the real ACL body. The
    //    SE-RSF EF reuses the same hdr 0x47 ACL (ops {0,1,2,6}); the sibling EF
    //    is our ground truth for the otherwise runtime-built condition bytes.
    let sib = card.transmit(
        &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
            .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, key_id])
            .with_le(0),
    )?;
    println!(
        "sibling key EF 6002:{key_id:04x} SELECT -> sw={:02x}{:02x}",
        sib.sw1, sib.sw2
    );
    if !sib.is_success() {
        println!("  cannot read sibling EF FCP; aborting (no reference ACL).");
        return Ok(());
    }
    let Some(sa) = find_tlv_value(&sib.data, 0x86) else {
        println!("  sibling EF has no 0x86 security-attribute; aborting.");
        return Ok(());
    };
    println!("  sibling security-attr (86) = {}", hex(sa));
    decode_rtecp_acl(sa);

    // The 0x86 value is <hdr><7 cond><7 pad>; the 14 bytes after the header are
    // the ACL condition body our CREATE FILE must replicate.
    if sa.len() < 15 || sa[0] != 0x47 {
        println!(
            "  unexpected ACL shape (len {}, hdr {:02x}); expected hdr 0x47 + 14 bytes; aborting.",
            sa.len(),
            sa.first().copied().unwrap_or(0)
        );
        return Ok(());
    }
    let mut conditions = [0u8; 14];
    conditions.copy_from_slice(&sa[1..15]);

    // 2. Build the CREATE FILE APDU. The 2nd field is the EF file-size byte
    //    (`80 02 00 SZ`), NOT an algorithm id. The SE-RSF EF is created with
    //    size = (recordLen - 11) & 0xff, where the SE-RSF record is the MSE
    //    key-agreement template `a6 L { 95 01 40 · 84 01 kid · 80 01 mech ·
    //    87 <pkLen> <peerPubKey> }`. The subtracted 11 == `a6 L`(2) +
    //    `95 01 40`(3) + `84 01 kid`(3) + `80 01 mech`(3), so SZ = pkLen + 2.
    //    Span1 (the `87` payload) is CK_GOSTR3410_DERIVE_PARAMS.pPublicData,
    //    a 64-byte GOST-2012-256 peer point => SZ = 0x42. The old 0xAA was a
    //    mislabelled guess and was rejected 6a89. Override via VKO_SERSF_SIZE.
    let file_size = std::env::var("VKO_SERSF_SIZE")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x42);
    let create = rutoken::create_se_rsf_file_for_vko(key_id, file_size, conditions);
    let create_bytes = create.to_bytes()?;
    println!("\nCREATE FILE 6005:{key_id:04x} (file-size {file_size:#04x}) — built from");
    println!("CREATE FILE for SE-RSF EF, ACL from live sibling EF:");
    println!("  {}", hex(&create_bytes));

    // 3. Gate the actual write behind an explicit confirmation.
    if std::env::var("VKO_PROVISION_CONFIRM").as_deref() != Ok("write") {
        println!(
            "\nDRY RUN — not written. Set VKO_PROVISION_CONFIRM=write to send this\n\
             CREATE FILE to the token (persistent, reversible via a USER-PIN\n\
             DELETE FILE). Review the bytes above first."
        );
        return Ok(());
    }

    println!("\nVKO_PROVISION_CONFIRM=write set — sending CREATE FILE...");
    // Replicate the SE-RSF create sequence EXACTLY: SelectSE_RSF_Dir then
    // SelectSE_RSF_File(keyId) before CREATE. Both use
    // SELECT header 00 A4 08 04 (P2=0x04, return FCP) — NOT 0x0C. The file
    // select is expected to fail 6a82 (file absent); that failing select is
    // part of the sequence that leaves the card in the correct DF context.
    let seldir = card.transmit(
        &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
            .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05])
            .with_le(0),
    )?;
    println!(
        "  SelectSE_RSF_Dir (00A40804 1000100060 05) -> sw={:02x}{:02x}",
        seldir.sw1, seldir.sw2
    );
    if !seldir.is_success() {
        println!("  could not select 6005 dir; aborting before CREATE.");
        return Ok(());
    }
    let selfile = card.transmit(
        &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
            .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05, 0x00, key_id])
            .with_le(0),
    )?;
    println!(
        "  SelectSE_RSF_File 6005:{key_id:04x} -> sw={:02x}{:02x} (expect 6a82)",
        selfile.sw1, selfile.sw2
    );
    let cr = card.transmit(&create)?;
    println!("  CREATE FILE -> sw={:02x}{:02x}", cr.sw1, cr.sw2);
    if cr.is_success() {
        let sel = card.transmit(&rutoken::select_se_rsf_file(key_id))?;
        println!(
            "  SELECT new SE-RSF EF 6005:{key_id:04x} -> sw={:02x}{:02x} (expect 9000)",
            sel.sw1, sel.sw2
        );
    }
    Ok(())
}

/// Live test of the alternate CSP Rutoken CREATE FILE dialect
/// ([`rutoken::create_se_rsf_file_csp`]) for the missing per-key SE-RSF EF.
///
/// DRY-RUN BY DEFAULT (lockout-safe): prints the exact CREATE FILE APDU and
/// stops. Sweeps `prop_flags` (R2) candidates only when
/// `VKO_CSP_CONFIRM=write` is set — each CREATE attempt that fails is an
/// atomic no-op (6a89/6a80), and a CREATE that succeeds is reversible via a
/// USER-PIN DELETE FILE. A wrong PIN is never sent here, so the retry counter is
/// untouched. After a 9000 CREATE it runs MSE + PSO to see if VKO now completes.
fn vko_csp(card: &mut PcscDevice) -> Result<(), CliError> {
    let key_id = 0x03u8;
    let coord_len = 0x20u8;

    // prop_flags (R2) is the one byte that depends on CSP orchestration and
    // can't be derived from the descriptor format alone. Default to the GOST-256
    // XchA candidate 0x43; override/sweep via VKO_CP_FLAGS=43,03,00,...
    let flags: Vec<u8> = std::env::var("VKO_CP_FLAGS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|t| u8::from_str_radix(t.trim().trim_start_matches("0x"), 16).ok())
                .collect()
        })
        .unwrap_or_else(|| vec![0x43]);

    println!("--- alternate CSP CREATE FILE dialect ---");
    for &f in &flags {
        let create = rutoken::create_se_rsf_file_csp(key_id, coord_len, f);
        let bytes = create.to_bytes()?;
        println!("prop_flags={f:#04x} -> CREATE FILE = {}", hex(&bytes));
    }

    if std::env::var("VKO_CSP_CONFIRM").as_deref() != Ok("write") {
        println!(
            "\nDRY RUN — nothing written. Set VKO_CSP_CONFIRM=write to send\n\
             these CREATE FILE APDUs to the token (persistent, reversible via a\n\
             USER-PIN DELETE FILE). Failed CREATEs are atomic no-ops."
        );
        return Ok(());
    }

    // Ground-truth probe: read the real sibling key EF (6002:0003) FCP — the
    // card's own accepted on-disk FCP shape — and try CREATEing a clone of it
    // under the 6005 DF. This tells us whether the card rejects our *structure*
    // (missing 81/8a TLVs, TLV order) vs the descriptor bytes specifically.
    if std::env::var("VKO_CP_CLONE").is_ok() {
        let sib = card.transmit(
            &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
                .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, key_id])
                .with_le(0),
        )?;
        println!(
            "\nsibling EF 6002:{key_id:04x} SELECT -> sw={:02x}{:02x} FCP={}",
            sib.sw1,
            sib.sw2,
            hex(&sib.data)
        );
        if let Some(fcp) = find_tlv_value(&sib.data, 0x62) {
            // Re-wrap the live FCP template verbatim as CREATE FILE data.
            let mut data = vec![0x62, fcp.len() as u8];
            data.extend_from_slice(fcp);
            let clone = CommandApdu::new(0x00, 0xE0, 0x00, 0x00).with_data(data);
            println!("clone CREATE FILE = {}", hex(&clone.to_bytes()?));
            card.transmit(
                &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
                    .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05])
                    .with_le(0),
            )?;
            let cr = card.transmit(&clone)?;
            println!("clone CREATE under 6005 -> sw={:02x}{:02x}", cr.sw1, cr.sw2);
            if cr.is_success() {
                let sel = card.transmit(&rutoken::select_se_rsf_file(key_id))?;
                println!(
                    "  SELECT new 6005:{key_id:04x} -> sw={:02x}{:02x}",
                    sel.sw1, sel.sw2
                );
            }
        }
        return Ok(());
    }

    // Load the peer point (client cert's own on-curve GOST point as a stand-in)
    // for the post-CREATE MSE/PSO check.
    let cert = std::fs::read("target/client-leaf.der").unwrap_or_default();
    let peer_point = cryptokiddie::gost_login::extract_subject_public_point(&cert).ok();

    for &f in &flags {
        println!("\n=== prop_flags={f:#04x} — CONFIRMED write ===");
        // Replicate the library's pre-CREATE context: select the 6005 DF (P2=04,
        // return FCP), then attempt the per-key file select (expected 6a82).
        let seldir = card.transmit(
            &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
                .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05])
                .with_le(0),
        )?;
        println!(
            "  SELECT 6005 dir -> sw={:02x}{:02x}",
            seldir.sw1, seldir.sw2
        );
        if !seldir.is_success() {
            println!("  could not select 6005 dir; skipping this flag.");
            continue;
        }
        let selfile = card.transmit(
            &CommandApdu::new(0x00, 0xA4, 0x08, 0x04)
                .with_data(vec![0x10, 0x00, 0x10, 0x00, 0x60, 0x05, 0x00, key_id])
                .with_le(0),
        )?;
        println!(
            "  SELECT 6005:{key_id:04x} file -> sw={:02x}{:02x} (expect 6a82)",
            selfile.sw1, selfile.sw2
        );

        let create = rutoken::create_se_rsf_file_csp(key_id, coord_len, f);
        let cr = card.transmit(&create)?;
        println!("  CREATE FILE -> sw={:02x}{:02x}", cr.sw1, cr.sw2);
        if !cr.is_success() {
            continue;
        }

        // CREATE succeeded — verify the EF is now selectable, then try VKO.
        let sel = card.transmit(&rutoken::select_se_rsf_file(key_id))?;
        println!(
            "  SELECT new SE-RSF EF 6005:{key_id:04x} -> sw={:02x}{:02x} (expect 9000)",
            sel.sw1, sel.sw2
        );

        let Some(point) = peer_point.as_ref().filter(|p| p.len() == 64) else {
            println!("  (no usable client point; skipping MSE/PSO)");
            continue;
        };
        let token_point = rutoken::pubkey_to_token_point(point, 32)?;
        for &algo in &[0x00u8, 0xAA, 0x40] {
            let mse = rutoken::manage_security_environment_for_vko(key_id, algo);
            let m = card.transmit(&mse)?;
            println!("  MSE B8 algo={algo:#04x} -> sw={:02x}{:02x}", m.sw1, m.sw2);
            if !m.is_success() {
                continue;
            }
            let pso = rutoken::pso_key_agreement(&token_point);
            let p = card.transmit(&pso)?;
            println!(
                "  PSO 2A8086 -> sw={:02x}{:02x} data={}",
                p.sw1,
                p.sw2,
                hex(&p.data)
            );
            if p.is_success() {
                println!("  *** VKO SUCCEEDED — KEK = {} ***", hex(&p.data));
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Diagnostic: after SELECT MF + VERIFY PIN, select the id=3 private key and try
/// every MSE SET (key agreement) `algo` mechanism byte, printing the status word.
fn vko_algo_sweep(card: &mut PcscDevice) -> Result<(), CliError> {
    let key_id = 0x03u8;
    let sel = tx(
        card,
        "select-prkey",
        &rutoken::select_private_key_file(key_id),
    )?;
    println!(
        "select private key id={key_id} sw={:02x}{:02x}",
        sel.sw1, sel.sw2
    );

    // Enumerate which private-key files exist (select 9000) and, for each, whether
    // PSO DECIPHER (VKO) is permitted vs 6994. A signing-only key returns 6994; a
    // derive/agreement-capable key should behave differently. All read-only; the
    // PIN counter is untouched. Uses a 65-byte 00||point dummy operand.
    let probe_cert = std::fs::read("target/client-leaf.der").unwrap_or_default();
    let probe_point =
        cryptokiddie::gost_login::extract_subject_public_point(&probe_cert).unwrap_or_default();
    let dummy_operand: Vec<u8> = if probe_point.len() == 64 {
        [&[0x00u8][..], &probe_point].concat()
    } else {
        vec![0x00; 65]
    };
    println!("--- private-key-file enumeration (select / MSE B8 / PSO decipher) ---");
    for kid in 0x00u8..=0x10 {
        let s = card.transmit(&rutoken::select_private_key_file(kid))?;
        if !(s.sw1 == 0x90) {
            continue; // file absent
        }
        let m = card.transmit(
            &CommandApdu::new(0x00, 0x22, 0x41, 0xB8)
                .with_data(vec![0x95, 0x01, 0x40, 0x84, 0x01, kid]),
        )?;
        let p = card
            .transmit(&CommandApdu::new(0x00, 0x2A, 0x80, 0x86).with_data(dummy_operand.clone()))?;
        println!(
            "  key id=0x{kid:02x}  select=9000  mseB8={:02x}{:02x}  psoDecipher={:02x}{:02x}",
            m.sw1, m.sw2, p.sw1, p.sw2
        );
    }
    // restore selection to id=03 for the rest of the sweep
    let _ = card.transmit(&rutoken::select_private_key_file(key_id))?;

    // Try several MSE SET (P1,P2,data) structural templates. MSE SET only
    // validates parameters (no PSO) so wrong templates just return 6a80 and never
    // touch the PIN counter. Look for SW 9000.
    let templates: &[(&str, u8, u8, Vec<u8>)] = &[
        ("B8 84only", 0x41, 0xB8, vec![0x84, 0x01, key_id]),
        (
            "B8 qual+key",
            0x41,
            0xB8,
            vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id],
        ),
    ];
    println!("--- VKO MSE SET structural sweep (key 0x{key_id:02x}) ---");
    for (label, p1, p2, data) in templates {
        let apdu = CommandApdu::new(0x00, 0x22, *p1, *p2).with_data(data.clone());
        let resp = card.transmit(&apdu)?;
        println!(
            "  {label:<16} 00 22 {p1:02x} {p2:02x} [{}] -> sw={:02x}{:02x}",
            hex(data),
            resp.sw1,
            resp.sw2
        );
    }

    // Probe PSO key-agreement operand formats. Use the client cert's own public
    // point (a valid on-curve GOST point on the same paramset) as a stand-in
    // peer point, plus a dummy 8-byte UKM. PSO is read-only crypto and never
    // touches the PIN counter, so wrong operands just return an error SW. We
    // look for SW 9000 (or a 61xx "more data") to learn the accepted layout.
    let cert = std::fs::read("target/client-leaf.der").unwrap_or_default();
    let point = if cert.is_empty() {
        eprintln!("(no target/client-leaf.der; skipping PSO operand probe)");
        return Ok(());
    } else {
        match cryptokiddie::gost_login::extract_subject_public_point(&cert) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("(could not extract client point: {e})");
                return Ok(());
            }
        }
    };
    println!("client point ({} bytes): {}", point.len(), hex(&point));
    // token-point order = each coord reversed (LE on the card)
    let pt_rev: Vec<u8> = point
        .chunks_exact(point.len() / 2)
        .flat_map(|c| c.iter().rev().copied())
        .collect();
    let ukm = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    // Each operand layout, retried after a fresh MSE SET B8.
    let operands: Vec<(String, Vec<u8>)> = vec![
        ("point_be".into(), point.clone()),
        ("point_le".into(), pt_rev.clone()),
        // PSO DECIPHER (2A 80 86) wants a leading padding-indicator byte 0x00:
        ("00||point_be".into(), [&[0x00u8][..], &point].concat()),
        ("00||point_le".into(), [&[0x00u8][..], &pt_rev].concat()),
        // OCTET STRING (04 40 ...) wrapping, as the cert stores the point:
        (
            "00||0440||pt_be".into(),
            [&[0x00u8, 0x04, 0x40][..], &point].concat(),
        ),
        (
            "00||0440||pt_le".into(),
            [&[0x00u8, 0x04, 0x40][..], &pt_rev].concat(),
        ),
        ("0440||pt_be".into(), [&[0x04u8, 0x40][..], &point].concat()),
        (
            "0440||pt_le".into(),
            [&[0x04u8, 0x40][..], &pt_rev].concat(),
        ),
        // X9.62 uncompressed (04 || X || Y) after padding byte:
        (
            "00||04||pt_be".into(),
            [&[0x00u8, 0x04][..], &point].concat(),
        ),
        (
            "00||04||pt_le".into(),
            [&[0x00u8, 0x04][..], &pt_rev].concat(),
        ),
    ];
    println!("--- PSO 2A8086 operand-format probe ---");
    for (label, operand) in &operands {
        // fresh MSE SET B8 before each PSO
        let mse = CommandApdu::new(0x00, 0x22, 0x41, 0xB8)
            .with_data(vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id]);
        let m = card.transmit(&mse)?;
        if !(m.sw1 == 0x90) {
            println!("  (MSE before {label} sw={:02x}{:02x})", m.sw1, m.sw2);
        }
        let apdu = CommandApdu::new(0x00, 0x2A, 0x80, 0x86).with_data(operand.clone());
        let resp = card.transmit(&apdu)?;
        println!(
            "  {label:<18} len={:<3} -> sw={:02x}{:02x} data={}",
            operand.len(),
            resp.sw1,
            resp.sw2,
            hex_prefix(&resp.data, 8)
        );
    }
    // Also try UKM carried in the MSE via tag 0x91, point-only PSO.
    println!("--- MSE w/ UKM tag 0x91 + point-only PSO ---");
    for (label, pt) in [("le", &pt_rev), ("be", &point)] {
        let mut mdata = vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id, 0x91, 0x08];
        mdata.extend_from_slice(&ukm);
        let m = card.transmit(&CommandApdu::new(0x00, 0x22, 0x41, 0xB8).with_data(mdata))?;
        let apdu = CommandApdu::new(0x00, 0x2A, 0x80, 0x86).with_data((*pt).clone());
        let resp = card.transmit(&apdu)?;
        println!(
            "  MSE91+point_{label:<3} mse={:02x}{:02x} pso={:02x}{:02x} data={}",
            m.sw1,
            m.sw2,
            resp.sw1,
            resp.sw2,
            hex_prefix(&resp.data, 8)
        );
    }

    // Sweep PSO instruction (CLA, P1, P2) with the padded LE point operand. Each
    // attempt re-runs MSE SET B8 first. PSO is read-only crypto: errors never
    // touch the PIN counter. Look for SW 9000 / 61xx.
    let operand = [&[0x00u8][..], &pt_rev].concat();
    let combos: &[(u8, u8, u8, &str)] = &[
        (0x00, 0x80, 0x86, "decipher 80/86"),
        (0x00, 0x80, 0x84, "80/84"),
        (0x00, 0x84, 0x86, "84/86"),
        (0x00, 0x86, 0x80, "86/80"),
        (0x00, 0x80, 0xA6, "80/A6"),
        (0x00, 0xA6, 0x80, "A6/80"),
        (0x00, 0x80, 0x88, "80/88"),
        (0x80, 0x80, 0x86, "CLA80 80/86"),
        (0x80, 0x86, 0x80, "CLA80 86/80"),
        (0x00, 0x48, 0x80, "48/80 (DERIVE?)"),
    ];
    println!("--- PSO instruction (CLA/P1/P2) sweep, operand=00||point_le ---");
    for (cla, p1, p2, label) in combos {
        let _ = card.transmit(
            &CommandApdu::new(0x00, 0x22, 0x41, 0xB8)
                .with_data(vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id]),
        )?;
        let apdu = CommandApdu::new(*cla, 0x2A, *p1, *p2).with_data(operand.clone());
        let resp = card.transmit(&apdu)?;
        if !(resp.sw1 == 0x6a && resp.sw2 == 0x80) || resp.sw1 == 0x90 || resp.sw1 == 0x61 {
            println!(
                "  {label:<16} {cla:02x} 2a {p1:02x} {p2:02x} -> sw={:02x}{:02x}",
                resp.sw1, resp.sw2
            );
        }
    }
    println!("--- sweep done ---");
    Ok(())
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
