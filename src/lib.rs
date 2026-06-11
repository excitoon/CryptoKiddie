use std::{
    ffi::OsString,
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
};

pub mod gost28147;
pub mod gost_bridge;
pub mod gost_client;
pub mod gost_ec;
pub mod gost_handshake;
pub mod gost_keytransport;
pub mod gost_keywrap;
pub mod gost_login;
pub mod gost_prf;
pub mod gost_record;
pub mod gost_vko;
pub mod tls;

pub mod apdu {
    use super::CliError;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CommandApdu {
        pub cla: u8,
        pub ins: u8,
        pub p1: u8,
        pub p2: u8,
        pub data: Vec<u8>,
        pub le: Option<u8>,
    }

    impl CommandApdu {
        pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
            Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            }
        }

        pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Self {
            self.data = data.into();
            self
        }

        pub fn with_le(mut self, le: u8) -> Self {
            self.le = Some(le);
            self
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, CliError> {
            if self.data.len() > u8::MAX as usize {
                return Err(CliError::Message(
                    "extended-length APDU encoding is not implemented yet".to_string(),
                ));
            }

            let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];
            if !self.data.is_empty() {
                bytes.push(self.data.len() as u8);
                bytes.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                bytes.push(le);
            }
            Ok(bytes)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ResponseApdu {
        pub data: Vec<u8>,
        pub sw1: u8,
        pub sw2: u8,
    }

    impl ResponseApdu {
        pub fn parse(bytes: &[u8]) -> Result<Self, CliError> {
            if bytes.len() < 2 {
                return Err(CliError::Message(
                    "APDU response must contain SW1/SW2 status bytes".to_string(),
                ));
            }
            let split = bytes.len() - 2;
            Ok(Self {
                data: bytes[..split].to_vec(),
                sw1: bytes[split],
                sw2: bytes[split + 1],
            })
        }

        pub fn is_success(&self) -> bool {
            self.sw1 == 0x90 && self.sw2 == 0x00
        }
    }
}

pub mod ccid {
    use super::{
        CliError,
        apdu::{CommandApdu, ResponseApdu},
    };
    use rusb::{Direction, GlobalContext, TransferType};
    use std::{
        fs::{self, File, OpenOptions},
        io::Write as _,
        path::{Path, PathBuf},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    pub const RUTOKEN_ECP3_USB_VID: u16 = 0x0a89;
    pub const RUTOKEN_ECP3_USB_PID: u16 = 0x0030;
    pub const RUTOKEN_ECP3_PRODUCT: &str = "Rutoken ECP (Рутокен ЭЦП 3.0)";

    /// CCID USB interface class code (USB Device Class Definition for Smart Card Devices).
    const CCID_CLASS: u8 = 0x0B;

    /// Timeout for all USB bulk transfers.
    const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);

    // CCID message type identifiers (USB CCID spec §6).
    pub const PC_TO_RDR_ICCPOWERON: u8 = 0x62;
    pub const PC_TO_RDR_XFRBLOCK: u8 = 0x6f;
    pub const RDR_TO_PC_DATABLOCK: u8 = 0x80;

    #[derive(Debug)]
    pub struct ExchangeLogger {
        path: PathBuf,
        file: File,
    }

    impl ExchangeLogger {
        pub fn create(path: &Path) -> Result<Self, CliError> {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::Message(format!(
                        "failed to create exchange log directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .map_err(|error| {
                    CliError::Message(format!(
                        "failed to create exchange log {}: {error}",
                        path.display()
                    ))
                })?;
            writeln!(file, "# cryptokiddie CCID exchange log").map_err(log_write_error)?;
            Ok(Self {
                path: path.to_path_buf(),
                file,
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn note(&mut self, message: &str) -> Result<(), CliError> {
            writeln!(self.file, "{} note {}", timestamp_ms(), message).map_err(log_write_error)
        }

        pub(crate) fn bytes(
            &mut self,
            direction: &str,
            layer: &str,
            label: &str,
            sequence: u8,
            bytes: &[u8],
            redacted: bool,
        ) -> Result<(), CliError> {
            writeln!(
                self.file,
                "{} direction={} layer={} label={} seq={} len={} redacted={} bytes={}",
                timestamp_ms(),
                direction,
                layer,
                label,
                sequence,
                bytes.len(),
                redacted,
                super::hex_encode(bytes)
            )
            .map_err(log_write_error)
        }

        fn response_summary(&mut self, response: &RdrDataBlock) -> Result<(), CliError> {
            writeln!(
                self.file,
                "{} direction=in layer=ccid-summary seq={} status=0x{:02x} error=0x{:02x} chain=0x{:02x} data_len={}",
                timestamp_ms(),
                response.sequence,
                response.status,
                response.error,
                response.chain_param,
                response.data.len()
            )
            .map_err(log_write_error)
        }

        pub(crate) fn flush(&mut self) -> Result<(), CliError> {
            self.file.flush().map_err(log_write_error)
        }
    }

    fn timestamp_ms() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    }

    fn log_write_error(error: std::io::Error) -> CliError {
        CliError::Message(format!("failed to write CCID exchange log: {error}"))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct XfrBlock {
        pub slot: u8,
        pub sequence: u8,
        pub block_waiting_integer: u8,
        pub level_parameter: u16,
        pub apdu: CommandApdu,
    }

    impl XfrBlock {
        pub fn new(slot: u8, sequence: u8, apdu: CommandApdu) -> Self {
            Self {
                slot,
                sequence,
                block_waiting_integer: 0,
                level_parameter: 0,
                apdu,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, CliError> {
            let apdu = self.apdu.to_bytes()?;
            let apdu_len = u32::try_from(apdu.len()).map_err(|_| {
                CliError::Message("APDU is too large for a CCID XfrBlock".to_string())
            })?;

            let mut bytes = Vec::with_capacity(10 + apdu.len());
            bytes.push(PC_TO_RDR_XFRBLOCK);
            bytes.extend_from_slice(&apdu_len.to_le_bytes());
            bytes.push(self.slot);
            bytes.push(self.sequence);
            bytes.push(self.block_waiting_integer);
            bytes.extend_from_slice(&self.level_parameter.to_le_bytes());
            bytes.extend_from_slice(&apdu);
            Ok(bytes)
        }
    }

    /// PC_to_RDR_IccPowerOn message (CCID spec §6.1.1).
    ///
    /// Powers on the ICC inserted in the given slot. The reader responds with
    /// `RDR_to_PC_DataBlock` whose data field carries the ATR.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IccPowerOn {
        pub slot: u8,
        pub sequence: u8,
        /// 0x00 = automatic voltage selection.
        pub power_select: u8,
    }

    impl IccPowerOn {
        pub fn new(slot: u8, sequence: u8) -> Self {
            Self {
                slot,
                sequence,
                power_select: 0x00,
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            vec![
                PC_TO_RDR_ICCPOWERON,
                0x00,
                0x00,
                0x00,
                0x00, // dwLength = 0
                self.slot,
                self.sequence,
                self.power_select,
                0x00,
                0x00, // abRFU
            ]
        }
    }

    /// Parsed `RDR_to_PC_DataBlock` response from the reader (CCID spec §6.2.1).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RdrDataBlock {
        pub slot: u8,
        pub sequence: u8,
        /// `bStatus`: upper two bits are bmCommandStatus, lower two bits are bmICCStatus.
        pub status: u8,
        pub error: u8,
        pub chain_param: u8,
        pub data: Vec<u8>,
    }

    impl RdrDataBlock {
        /// Parse a raw byte slice from a USB bulk-in transfer.
        pub fn parse(bytes: &[u8]) -> Result<Self, CliError> {
            if bytes.len() < 10 {
                return Err(CliError::Message(format!(
                    "CCID response too short: {} bytes (minimum 10)",
                    bytes.len()
                )));
            }
            if bytes[0] != RDR_TO_PC_DATABLOCK {
                return Err(CliError::Message(format!(
                    "expected RDR_to_PC_DataBlock (0x{RDR_TO_PC_DATABLOCK:02x}), got 0x{:02x}",
                    bytes[0]
                )));
            }
            let data_len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
            if bytes.len() < 10 + data_len {
                return Err(CliError::Message(format!(
                    "CCID response data truncated: header claims {} bytes, got {}",
                    data_len,
                    bytes.len().saturating_sub(10)
                )));
            }
            Ok(Self {
                slot: bytes[5],
                sequence: bytes[6],
                status: bytes[7],
                error: bytes[8],
                chain_param: bytes[9],
                data: bytes[10..10 + data_len].to_vec(),
            })
        }

        /// Returns `true` when bmCommandStatus (bits 7:6 of `bStatus`) is 00 (command processed).
        pub fn is_success(&self) -> bool {
            (self.status & 0xC0) == 0x00
        }
    }

    /// An open CCID interface on a Rutoken ECP USB device.
    ///
    /// Discovered via [`CcidDevice::open`]. Each [`CcidDevice::transmit`] call sends one
    /// `PC_to_RDR_XfrBlock` and receives one `RDR_to_PC_DataBlock`, keeping sequence numbers
    /// monotonically incrementing per the CCID spec.
    pub struct CcidDevice {
        handle: rusb::DeviceHandle<GlobalContext>,
        interface: u8,
        bulk_in: u8,
        bulk_out: u8,
        slot: u8,
        sequence: u8,
        logger: Option<ExchangeLogger>,
    }

    impl CcidDevice {
        /// Find and open the first Rutoken ECP device whose USB product string contains
        /// `reader_filter` (when supplied), claim its CCID interface, and return a ready device.
        pub fn open(reader_filter: Option<&str>) -> Result<Self, CliError> {
            Self::open_with_exchange_log(reader_filter, None)
        }

        pub fn open_with_exchange_log(
            reader_filter: Option<&str>,
            exchange_log: Option<&Path>,
        ) -> Result<Self, CliError> {
            let devices = rusb::devices().map_err(|error| {
                CliError::Message(format!("failed to enumerate USB devices: {error}"))
            })?;

            for device in devices.iter() {
                let descriptor = match device.device_descriptor() {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                if descriptor.vendor_id() != RUTOKEN_ECP3_USB_VID
                    || descriptor.product_id() != RUTOKEN_ECP3_USB_PID
                {
                    continue;
                }

                let handle = match device.open() {
                    Ok(h) => h,
                    Err(error) => {
                        return Err(CliError::Message(format!(
                            "failed to open Rutoken USB device: {error}"
                        )));
                    }
                };

                if let Some(filter) = reader_filter {
                    match handle.read_product_string_ascii(&descriptor) {
                        Ok(ref product) if !product.contains(filter) => continue,
                        Err(_) => continue,
                        _ => {}
                    }
                }

                let config = match device.active_config_descriptor() {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                for iface in config.interfaces() {
                    for iface_desc in iface.descriptors() {
                        if iface_desc.class_code() != CCID_CLASS {
                            continue;
                        }

                        let interface_num = iface_desc.interface_number();
                        let mut bulk_in: Option<u8> = None;
                        let mut bulk_out: Option<u8> = None;

                        for ep in iface_desc.endpoint_descriptors() {
                            if ep.transfer_type() == TransferType::Bulk {
                                match ep.direction() {
                                    Direction::In => bulk_in = Some(ep.address()),
                                    Direction::Out => bulk_out = Some(ep.address()),
                                }
                            }
                        }

                        let (Some(bulk_in), Some(bulk_out)) = (bulk_in, bulk_out) else {
                            continue;
                        };

                        // On Linux, detach any kernel driver that claimed the interface.
                        #[cfg(target_os = "linux")]
                        let _ = handle.detach_kernel_driver(interface_num);

                        handle.claim_interface(interface_num).map_err(|error| {
                            CliError::Message(format!(
                                "failed to claim CCID interface {interface_num}: {error}"
                            ))
                        })?;

                        let mut logger = exchange_log.map(ExchangeLogger::create).transpose()?;
                        if let Some(logger) = logger.as_mut() {
                            logger.note(&format!(
                                "opened vid=0x{:04x} pid=0x{:04x} interface={} bulk_in=0x{:02x} bulk_out=0x{:02x}",
                                descriptor.vendor_id(),
                                descriptor.product_id(),
                                interface_num,
                                bulk_in,
                                bulk_out
                            ))?;
                        }

                        return Ok(CcidDevice {
                            handle,
                            interface: interface_num,
                            bulk_in,
                            bulk_out,
                            slot: 0,
                            sequence: 0,
                            logger,
                        });
                    }
                }
            }

            Err(CliError::Message(
                "Rutoken ECP device (VID 0x0a89 / PID 0x0030) not found. \
                 Ensure the token is connected and you have access to the USB device."
                    .to_string(),
            ))
        }

        /// Power on the ICC and return the ATR bytes.
        pub fn power_on(&mut self) -> Result<Vec<u8>, CliError> {
            let seq = self.next_sequence();
            let cmd = IccPowerOn::new(self.slot, seq);
            let bytes = cmd.to_bytes();
            self.log_bytes("out", "ccid", "PC_to_RDR_IccPowerOn", seq, &bytes, false)?;
            self.handle
                .write_bulk(self.bulk_out, &bytes, TRANSFER_TIMEOUT)
                .map_err(|error| {
                    CliError::Message(format!("CCID IccPowerOn write failed: {error}"))
                })?;
            let response = self.read_response("RDR_to_PC_DataBlock")?;
            if !response.is_success() {
                return Err(CliError::Message(format!(
                    "CCID IccPowerOn failed: status=0x{:02x} error=0x{:02x}",
                    response.status, response.error
                )));
            }
            Ok(response.data)
        }

        /// Send an APDU via `PC_to_RDR_XfrBlock` and return the response APDU.
        pub fn transmit(&mut self, apdu: &CommandApdu) -> Result<ResponseApdu, CliError> {
            let seq = self.next_sequence();
            let block = XfrBlock::new(self.slot, seq, apdu.clone());
            let bytes = block.to_bytes()?;
            let (apdu_log_bytes, apdu_redacted) = redacted_apdu_bytes_for_log(apdu)?;
            self.log_bytes(
                "out",
                "apdu",
                apdu_label(apdu),
                seq,
                &apdu_log_bytes,
                apdu_redacted,
            )?;
            let (ccid_log_bytes, ccid_redacted) = redacted_ccid_block_for_log(apdu, &bytes);
            self.log_bytes(
                "out",
                "ccid",
                "PC_to_RDR_XfrBlock",
                seq,
                &ccid_log_bytes,
                ccid_redacted,
            )?;
            self.handle
                .write_bulk(self.bulk_out, &bytes, TRANSFER_TIMEOUT)
                .map_err(|error| {
                    CliError::Message(format!("CCID XfrBlock write failed: {error}"))
                })?;
            let response = self.read_response("RDR_to_PC_DataBlock")?;
            if !response.is_success() {
                return Err(CliError::Message(format!(
                    "CCID XfrBlock failed: status=0x{:02x} error=0x{:02x}",
                    response.status, response.error
                )));
            }
            ResponseApdu::parse(&response.data)
        }

        pub fn exchange_log_path(&self) -> Option<&Path> {
            self.logger.as_ref().map(ExchangeLogger::path)
        }

        fn next_sequence(&mut self) -> u8 {
            let seq = self.sequence;
            self.sequence = self.sequence.wrapping_add(1);
            seq
        }

        fn read_response(&mut self, label: &str) -> Result<RdrDataBlock, CliError> {
            // 10-byte CCID header + up to 258 bytes APDU response (256 data + 2 SW).
            let mut buf = vec![0u8; 1024];
            let n = self
                .handle
                .read_bulk(self.bulk_in, &mut buf, TRANSFER_TIMEOUT)
                .map_err(|error| CliError::Message(format!("CCID bulk read failed: {error}")))?;
            self.log_bytes(
                "in",
                "ccid",
                label,
                self.sequence.wrapping_sub(1),
                &buf[..n],
                false,
            )?;
            let response = RdrDataBlock::parse(&buf[..n])?;
            if let Some(logger) = self.logger.as_mut() {
                logger.response_summary(&response)?;
                logger.flush()?;
            }
            Ok(response)
        }

        fn log_bytes(
            &mut self,
            direction: &str,
            layer: &str,
            label: &str,
            sequence: u8,
            bytes: &[u8],
            redacted: bool,
        ) -> Result<(), CliError> {
            if let Some(logger) = self.logger.as_mut() {
                logger.bytes(direction, layer, label, sequence, bytes, redacted)?;
            }
            Ok(())
        }
    }

    impl Drop for CcidDevice {
        fn drop(&mut self) {
            let _ = self.handle.release_interface(self.interface);
            #[cfg(target_os = "linux")]
            let _ = self.handle.attach_kernel_driver(self.interface);
        }
    }

    pub(crate) fn redacted_apdu_bytes_for_log(
        apdu: &CommandApdu,
    ) -> Result<(Vec<u8>, bool), CliError> {
        let mut bytes = apdu.to_bytes()?;
        let redacted = redact_verify_pin_data(&mut bytes, 0, apdu.data.len());
        Ok((bytes, redacted))
    }

    pub(crate) fn redacted_ccid_block_for_log(apdu: &CommandApdu, bytes: &[u8]) -> (Vec<u8>, bool) {
        let mut redacted = bytes.to_vec();
        let did_redact = redact_verify_pin_data(&mut redacted, 10, apdu.data.len());
        (redacted, did_redact)
    }

    fn redact_verify_pin_data(bytes: &mut [u8], apdu_offset: usize, data_len: usize) -> bool {
        if data_len == 0 || bytes.len() < apdu_offset + 5 + data_len {
            return false;
        }
        let ins = bytes[apdu_offset + 1];
        if ins != 0x20 {
            return false;
        }
        let data_offset = apdu_offset + 5;
        for byte in &mut bytes[data_offset..data_offset + data_len] {
            *byte = b'*';
        }
        true
    }

    pub(crate) fn apdu_label(apdu: &CommandApdu) -> &'static str {
        match (apdu.cla, apdu.ins, apdu.p1, apdu.p2) {
            (0x00, 0xA4, 0x00, 0x0C) => "SELECT_MF",
            (0x00, 0x20, _, _) => "VERIFY_PIN",
            (0x00, 0x22, 0x41, 0xB6) => "MSE_SET_DST",
            (0x00, 0x22, 0x41, 0xA6) => "MSE_SET_KEY_AGREEMENT",
            (0x00, 0x22, 0x41, 0xB8) => "MSE_SET_KEY_AGREEMENT",
            (0x00, 0x2A, 0x9E, 0x9A) => "PSO_COMPUTE_DIGITAL_SIGNATURE",
            (0x00, 0x2A, 0x80, 0x86) => "PSO_KEY_AGREEMENT",
            _ => "APDU",
        }
    }
}

#[cfg(feature = "pcsc")]
pub mod pcsc_transport {
    use super::{
        CliError,
        apdu::{CommandApdu, ResponseApdu},
        ccid,
    };
    use pcsc::{Context, Protocols, Scope, ShareMode};
    use std::path::Path;

    pub struct PcscDevice {
        _context: Context,
        card: pcsc::Card,
        logger: Option<ccid::ExchangeLogger>,
        sequence: u8,
    }

    impl PcscDevice {
        pub fn open_with_exchange_log(
            reader_filter: Option<&str>,
            exchange_log: Option<&Path>,
        ) -> Result<Self, CliError> {
            let context = Context::establish(Scope::User).map_err(|error| {
                CliError::Message(format!("failed to establish PC/SC context: {error}"))
            })?;
            let readers = context.list_readers_owned().map_err(|error| {
                CliError::Message(format!("failed to list PC/SC readers: {error}"))
            })?;
            let reader = readers
                .iter()
                .find(|reader| match (reader.to_str(), reader_filter) {
                    (Ok(name), Some(filter)) => name.contains(filter),
                    (Ok(_), None) => true,
                    _ => false,
                })
                .ok_or_else(|| {
                    let available = readers
                        .iter()
                        .filter_map(|reader| reader.to_str().ok())
                        .collect::<Vec<_>>()
                        .join(", ");
                    CliError::Message(format!(
                        "no matching PC/SC reader found{}{}",
                        reader_filter
                            .map(|filter| format!(" for filter '{filter}'"))
                            .unwrap_or_default(),
                        if available.is_empty() {
                            String::new()
                        } else {
                            format!("; available readers: {available}")
                        }
                    ))
                })?;
            let card = context
                .connect(reader, ShareMode::Shared, Protocols::ANY)
                .map_err(|error| {
                    CliError::Message(format!("failed to connect to PC/SC reader: {error}"))
                })?;
            let mut logger = exchange_log.map(ccid::ExchangeLogger::create).transpose()?;
            if let Some(logger) = logger.as_mut() {
                logger.note(&format!("opened pcsc_reader={}", reader.to_string_lossy()))?;
            }
            Ok(Self {
                _context: context,
                card,
                logger,
                sequence: 0,
            })
        }

        pub fn transmit(&mut self, apdu: &CommandApdu) -> Result<ResponseApdu, CliError> {
            let seq = self.sequence;
            self.sequence = self.sequence.wrapping_add(1);
            let request = apdu.to_bytes()?;
            let (apdu_log_bytes, redacted) = ccid::redacted_apdu_bytes_for_log(apdu)?;
            if let Some(logger) = self.logger.as_mut() {
                logger.bytes(
                    "out",
                    "pcsc-apdu",
                    ccid::apdu_label(apdu),
                    seq,
                    &apdu_log_bytes,
                    redacted,
                )?;
            }
            let mut response = [0u8; 4096];
            let response = self
                .card
                .transmit(&request, &mut response)
                .map_err(|error| CliError::Message(format!("PC/SC transmit failed: {error}")))?;
            if let Some(logger) = self.logger.as_mut() {
                logger.bytes("in", "pcsc-apdu", "RESPONSE", seq, response, false)?;
                logger.flush()?;
            }
            ResponseApdu::parse(response)
        }

        pub fn exchange_log_path(&self) -> Option<&Path> {
            self.logger.as_ref().map(ccid::ExchangeLogger::path)
        }
    }
}

pub mod gost {
    use super::{CliError, DigestAlgorithm};
    use streebog::{Digest, Streebog256, Streebog512};

    pub fn hash(data: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
        match algorithm {
            DigestAlgorithm::Gost3411_2012_256 => Streebog256::digest(data).to_vec(),
            DigestAlgorithm::Gost3411_2012_512 => Streebog512::digest(data).to_vec(),
            _ => panic!("non-GOST algorithm {algorithm:?} passed to gost::hash"),
        }
    }

    pub fn parse_digest(name: &str) -> Result<DigestAlgorithm, CliError> {
        DigestAlgorithm::parse(name)
    }
}

/// Direct Rutoken ECP APDU sequences for hardware-backed GOST signing over CCID.
///
/// These helpers construct ISO 7816-4/8 APDUs for the operations needed to
/// sign a digest with a GOST R 34.10-2012 private key stored on a Rutoken ECP
/// token, following the same protocol as OpenSC's `card-rtecp.c`:
///
/// 1. SELECT MF (reset file system navigation)
/// 2. VERIFY PIN (authenticate the user)
/// 3. MSE SET (select the target private key via DST key reference)
/// 4. PSO COMPUTE DIGITAL SIGNATURE (sign the pre-computed digest)
pub mod rutoken {
    use super::{CliError, apdu::CommandApdu};

    #[derive(Debug, Clone)]
    pub struct SelectSequence {
        pub label: &'static str,
        pub commands: Vec<CommandApdu>,
    }

    /// Rutoken ECP administrator/SO PIN reference (P2 for VERIFY).
    pub const ADMIN_PIN_REFERENCE: u8 = 0x01;

    /// Rutoken ECP user PIN reference (P2 for VERIFY).
    pub const USER_PIN_REFERENCE: u8 = 0x02;

    /// Parsed `rutoken:slot=N;id=XX` key URI used for the CCID transport path.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RutokenUri {
        /// Index into the CCID slot array (typically 0 for a single-slot reader).
        pub slot: u8,
        /// One-byte key object identifier, percent-decoded from the `id=` attribute.
        pub id: u8,
    }

    impl RutokenUri {
        /// Parse a `rutoken:slot=N;id=%XX` URI into its components.
        pub fn parse(uri: &str) -> Result<Self, CliError> {
            let attributes = uri.strip_prefix("rutoken:").ok_or_else(|| {
                CliError::Usage("--key-uri must start with rutoken: for CCID transport".to_string())
            })?;

            let mut slot = 0u8;
            let mut id: Option<u8> = None;

            for pair in attributes.split(';').filter(|p| !p.is_empty()) {
                let (name, value) = pair.split_once('=').ok_or_else(|| {
                    CliError::Usage(format!("invalid rutoken URI attribute: {pair}"))
                })?;
                match name {
                    "slot" => {
                        slot = value.parse::<u8>().map_err(|error| {
                            CliError::Usage(format!("invalid rutoken URI slot: {value} ({error})"))
                        })?;
                    }
                    "id" => {
                        let decoded = super::percent_decode_bytes(value)?;
                        if decoded.len() != 1 {
                            return Err(CliError::Usage(
                                "rutoken URI id= must encode exactly one byte".to_string(),
                            ));
                        }
                        id = Some(decoded[0]);
                    }
                    _ => {}
                }
            }

            Ok(Self {
                slot,
                id: id.ok_or_else(|| {
                    CliError::Usage(
                        "rutoken URI must include id= to identify the private key".to_string(),
                    )
                })?,
            })
        }
    }

    /// SELECT File: Master File (3F00) — reset the DF navigation before further commands.
    pub fn select_master_file() -> CommandApdu {
        CommandApdu::new(0x00, 0xA4, 0x00, 0x0C).with_data([0x3F, 0x00])
    }

    /// SELECT File: Rutoken ECP private-key EF under 3F00/1000/1000/6002.
    pub fn select_private_key_file(key_id: u8) -> CommandApdu {
        CommandApdu::new(0x00, 0xA4, 0x08, 0x0C)
            .with_data([0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, key_id])
    }

    /// SELECT File: the per-key SE-RSF EF under 3F00/1000/1000/6005, required by
    /// the on-card GOST VKO (key-agreement security environment). On stock
    /// tokens this EF (`6005:<key_id>`) is absent until provisioned with
    /// [`create_se_rsf_file_for_vko`].
    pub fn select_se_rsf_file(key_id: u8) -> CommandApdu {
        CommandApdu::new(0x00, 0xA4, 0x08, 0x0C)
            .with_data([0x10, 0x00, 0x10, 0x00, 0x60, 0x05, 0x00, key_id])
    }

    /// Build the CREATE FILE APDU that provisions the missing SE-RSF EF
    /// (`6005:<key_id>`) used by on-card VKO. The on-wire format below is the
    /// one the token firmware accepts: the size TLV (`80 …`) is emitted *before*
    /// the descriptor TLV (`82 …`); the opposite order is rejected (6a89) on this
    /// firmware, so field order matters.
    ///
    /// On-wire (44 bytes, `INS=E0` CREATE FILE):
    /// ```text
    /// 00 E0 00 00 27
    /// 62 25                       FCP template (37 bytes)
    ///    80 02 00 <size>          file size  (= record length - 11)
    ///    82 02 10 00              file descriptor
    ///    83 02 00 <key_id>        file id (low byte = key_id)
    ///    85 06 1F 00 00 FF 00 00  proprietary SE-RSF descriptor
    ///    86 0F 47 <conditions…>   ACL: hdr 0x47 (ops 0,1,2,6) + 14 cond/pad bytes
    /// ```
    /// `conditions` is the 14-byte SecureAttr body following the `47` header
    /// (seven condition slots + seven pad bytes). The reference value `0x02`
    /// means USER PIN; mirror the sibling key EF (`02 02 02 00 00 00 02` + pad).
    /// The four enforced condition bytes depend on runtime card state and cannot
    /// be derived statically, so the caller must supply them explicitly.
    ///
    /// This is a **builder only** — it never transmits. Provisioning writes
    /// persistent card state (reversible via a USER-PIN DELETE FILE) and must
    /// only be performed with explicit user consent.
    pub fn create_se_rsf_file_for_vko(key_id: u8, size: u8, conditions: [u8; 14]) -> CommandApdu {
        let mut fcp = vec![
            0x80, 0x02, 0x00, size, // file size (emitted first)
            0x82, 0x02, 0x10, 0x00, // file descriptor
            0x83, 0x02, 0x00, key_id, // file id (low byte = key_id)
            0x85, 0x06, 0x1F, 0x00, 0x00, 0xFF, 0x00, 0x00, // proprietary descriptor
            0x86, 0x0F, 0x47, // ACL: tag, len 15, header bitmask 0x47
        ];
        fcp.extend_from_slice(&conditions);
        let mut data = vec![0x62, fcp.len() as u8];
        data.extend_from_slice(&fcp);
        CommandApdu::new(0x00, 0xE0, 0x00, 0x00).with_data(data)
    }

    /// Build the CREATE FILE APDU in the alternate dialect used when the card was
    /// personalised by a GOST Cryptographic Service Provider (CSP) rather than
    /// the PKCS#11 module. This is a *different dialect* from the PKCS#11
    /// [`create_se_rsf_file_for_vko`]: the card's key object is owned by the CSP
    /// dialect, which is why the PKCS#11 create is refused (6a89) while this one
    /// was never tried.
    ///
    /// CSP here means *Cryptographic Service Provider*: a Microsoft CryptoAPI
    /// provider module that implements the GOST algorithms and drives the token;
    /// it owns the on-card key objects it provisions, hence the distinct CREATE
    /// FILE dialect reproduced here.
    ///
    /// On-wire (44 bytes, `INS=E0` CREATE FILE):
    /// ```text
    /// 00 E0 00 00 27
    /// 62 25                          FCP template (37 bytes)
    ///    82 02 10 00                 file descriptor       (DESC before SIZE)
    ///    80 02 00 <size>             file size  = 2 * coord_len  (0x40 for GOST-256)
    ///    83 02 00 <key_id>           file id (low byte = key_id)
    ///    85 06 <r0> <hh> <r2> FF 00 00   proprietary SE-RSF descriptor
    ///    86 0F 46 00 02 00 …(12×00)  ACL: header 0x46 (ops 1,2,6) + 14 body bytes
    /// ```
    /// Decoded derivation of the variable prop-attr (`85 06 …`) bytes:
    /// * `r0` = `(coord_len == 0x20 ? 0x03 : 0x43) | 0x10`  → `0x13` for GOST-256.
    /// * `hh` = letter-gate of `coord_len`: A→0x20 B→0x30 C→0x40 T→0x10
    ///   E→0x50 F→0x20 G→0x30 H→0x40, else `0x00`. For `coord_len = 0x20` → `0x00`.
    /// * `r2` = caller flags from the CSP orchestration; cannot be pinned from
    ///   the descriptor format alone, so it is passed in explicitly (`prop_flags`).
    ///
    /// `key_id` and `prop_flags` are the only bytes that depend on runtime card
    /// state; everything else is derived here exactly as the binary does.
    ///
    /// This is a **builder only** — it never transmits. Provisioning writes
    /// persistent card state (reversible via a USER-PIN DELETE FILE) and must
    /// only be performed with explicit user consent on a present session.
    pub fn create_se_rsf_file_csp(key_id: u8, coord_len: u8, prop_flags: u8) -> CommandApdu {
        let size = coord_len.wrapping_mul(2); // r11b = r15 + r15
        let r0 = if coord_len == 0x20 { 0x03 } else { 0x43 } | 0x10; // cmovne + or 0x10
        let hh = se_rsf_letter_gate(coord_len);
        let fcp = vec![
            0x82, 0x02, 0x10, 0x00, // file descriptor (emitted before size)
            0x80, 0x02, 0x00, size, // file size = 2 * coord_len
            0x83, 0x02, 0x00, key_id, // file id (low byte = key_id)
            0x85, 0x06, r0, hh, prop_flags, 0xFF, 0x00, 0x00, // proprietary descriptor
            0x86, 0x0F, 0x46, // ACL: tag, len 15, header bitmask 0x46
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 condition slots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 pad bytes
        ];
        let mut data = vec![0x62, fcp.len() as u8];
        data.extend_from_slice(&fcp);
        CommandApdu::new(0x00, 0xE0, 0x00, 0x00).with_data(data)
    }

    /// Letter→code map used to derive the
    /// middle byte of the SE-RSF proprietary descriptor (`85 06 r0 hh …`).
    /// Returns `0x00` for any input that is not one of the recognised letters.
    pub(crate) fn se_rsf_letter_gate(b: u8) -> u8 {
        match b {
            b'A' | b'F' => 0x20,
            b'B' | b'G' => 0x30,
            b'C' | b'H' => 0x40,
            b'T' => 0x10,
            b'E' => 0x50,
            _ => 0x00,
        }
    }

    /// SELECT File: Rutoken ECP certificate EF under 3F00/1000/1000/6004.
    pub fn select_certificate_file(key_id: u8) -> CommandApdu {
        let file_id = certificate_file_id(key_id);
        CommandApdu::new(0x00, 0xA4, 0x08, 0x0C).with_data([
            0x10,
            0x00,
            0x10,
            0x00,
            0x60,
            0x04,
            (file_id >> 8) as u8,
            file_id as u8,
        ])
    }

    pub fn private_key_file_select_sequences(key_id: u8) -> Vec<SelectSequence> {
        let pkcs15_private_key_id = 0x0100u16 | key_id as u16;
        vec![
            SelectSequence {
                label: "PrKey-DF relative path",
                commands: vec![select_private_key_file(key_id)],
            },
            SelectSequence {
                label: "PrKey-DF absolute path",
                commands: vec![select_file_by_path([
                    0x3F, 0x00, 0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, key_id,
                ])],
            },
            SelectSequence {
                label: "PrKey-DF stepwise file IDs",
                commands: vec![
                    select_file_by_id(0x1000),
                    select_file_by_id(0x1000),
                    select_file_by_id(0x6002),
                    select_file_by_id(key_id as u16),
                ],
            },
            SelectSequence {
                label: "PKCS15-AppDF private-key path",
                commands: vec![select_file_by_path([
                    0x50,
                    0x00,
                    (pkcs15_private_key_id >> 8) as u8,
                    pkcs15_private_key_id as u8,
                ])],
            },
            SelectSequence {
                label: "PKCS15-AppDF stepwise private-key file IDs",
                commands: vec![
                    select_file_by_id(0x5000),
                    select_file_by_id(pkcs15_private_key_id),
                ],
            },
        ]
    }

    pub fn certificate_file_select_sequences(key_id: u8) -> Vec<SelectSequence> {
        let certificate_id = certificate_file_id(key_id);
        vec![
            SelectSequence {
                label: "Cer-DF relative path",
                commands: vec![select_certificate_file(key_id)],
            },
            SelectSequence {
                label: "Cer-DF absolute path",
                commands: vec![select_file_by_path([
                    0x3F,
                    0x00,
                    0x10,
                    0x00,
                    0x10,
                    0x00,
                    0x60,
                    0x04,
                    (certificate_id >> 8) as u8,
                    certificate_id as u8,
                ])],
            },
            SelectSequence {
                label: "Cer-DF stepwise file IDs",
                commands: vec![
                    select_file_by_id(0x1000),
                    select_file_by_id(0x1000),
                    select_file_by_id(0x6004),
                    select_file_by_id(certificate_id),
                ],
            },
            SelectSequence {
                label: "PKCS15-AppDF certificate path",
                commands: vec![select_file_by_path([
                    0x50,
                    0x00,
                    (certificate_id >> 8) as u8,
                    certificate_id as u8,
                ])],
            },
            SelectSequence {
                label: "PKCS15-AppDF stepwise certificate file IDs",
                commands: vec![select_file_by_id(0x5000), select_file_by_id(certificate_id)],
            },
        ]
    }

    fn certificate_file_id(key_id: u8) -> u16 {
        0x0300u16 | key_id as u16
    }

    pub fn select_file_by_path(path: impl Into<Vec<u8>>) -> CommandApdu {
        CommandApdu::new(0x00, 0xA4, 0x08, 0x0C).with_data(path)
    }

    pub fn select_file_by_id(file_id: u16) -> CommandApdu {
        CommandApdu::new(0x00, 0xA4, 0x00, 0x0C).with_data([(file_id >> 8) as u8, file_id as u8])
    }

    /// VERIFY — present the user PIN against `USER_PIN_REFERENCE`.
    pub fn verify_pin(pin: &[u8]) -> CommandApdu {
        CommandApdu::new(0x00, 0x20, 0x00, USER_PIN_REFERENCE).with_data(pin)
    }

    /// VERIFY status query used by OpenSC after Rutoken ECP reports `6300`.
    pub fn verify_pin_status() -> CommandApdu {
        CommandApdu::new(0x00, 0x20, 0x00, USER_PIN_REFERENCE)
    }

    /// Rutoken ECP logout command used by OpenSC before retrying VERIFY after `6f86`.
    pub fn logout() -> CommandApdu {
        CommandApdu::new(0x80, 0x40, 0x00, 0x00)
    }

    /// MSE SET (Manage Security Environment, SET, Digital Signature Template).
    ///
    /// Instructs the token to use the private key identified by `key_id` for the
    /// next COMPUTE DIGITAL SIGNATURE command.
    ///
    /// Template TLV: `[84 01 key_id]` (Key Reference tag per ISO 7816-8 §5.2).
    pub fn manage_security_environment_for_signing(key_id: u8) -> CommandApdu {
        CommandApdu::new(0x00, 0x22, 0x41, 0xB6).with_data([0x84, 0x01, key_id])
    }

    /// PSO: COMPUTE DIGITAL SIGNATURE.
    ///
    /// Presents the pre-hashed `digest` bytes to the token in Rutoken ECP byte
    /// order and requests a raw GOST R 34.10-2012 signature. `signature_len` is
    /// 64 for 256-bit keys and 128 for 512-bit keys.
    pub fn pso_compute_digital_signature(digest: &[u8], signature_len: u8) -> CommandApdu {
        CommandApdu::new(0x00, 0x2A, 0x9E, 0x9A)
            .with_data(digest.to_vec())
            .with_le(signature_len)
    }

    /// MSE SET (Manage Security Environment, SET, Key-Agreement Template).
    ///
    /// Selects the private key `key_id` and cryptographic mechanism `algo` for
    /// the following PERFORM SECURITY OPERATION key-agreement command (GOST VKO).
    ///
    /// This is the key-agreement analogue of
    /// [`manage_security_environment_for_signing`]; the Control Reference
    /// Template tag is `A6` (key agreement) instead of `B6` (digital signature).
    ///
    /// On-wire APDU (validated live against the Osnovanie Rutoken ECP):
    /// `00 22 41 B8 06  95 01 40  84 01 <key_id>`
    /// where `B8` is the Confidentiality / key-agreement Control Reference
    /// Template (this card rejects the `A6` template with `6a80`), `95 01 40` =
    /// Usage Qualifier "key agreement / decipher", and `84 01 key_id` =
    /// private-key reference. No `80` cryptographic-mechanism CRDO is needed —
    /// the paramset is taken from the selected key — so `algo` is accepted for
    /// backwards compatibility but only appended (as `80 01 algo`) when non-zero.
    pub fn manage_security_environment_for_vko(key_id: u8, algo: u8) -> CommandApdu {
        manage_security_environment_for_vko_with_ukm(key_id, algo, &[])
    }

    /// MSE SET for VKO with an optional User Keying Material (UKM) operand.
    ///
    /// Identical to [`manage_security_environment_for_vko`] but appends the UKM
    /// as a `87 <len> <ukm>` CRDO inside the control-reference template, after
    /// the `80` mechanism CRDO. The build order is
    /// `95 01 40 · 84 01 <key_id> · [80 01 <algo>] · [87 <Lu> <ukm>]`,
    /// where `appendTlv(body, 0x87, ukm)` is emitted only when `ukm` is
    /// non-empty. Passing an empty `ukm` reproduces the original APDU exactly.
    pub fn manage_security_environment_for_vko_with_ukm(
        key_id: u8,
        algo: u8,
        ukm: &[u8],
    ) -> CommandApdu {
        let mut data = vec![0x95, 0x01, 0x40, 0x84, 0x01, key_id];
        if algo != 0 {
            data.extend_from_slice(&[0x80, 0x01, algo]);
        }
        if !ukm.is_empty() {
            data.push(0x87);
            data.push(ukm.len() as u8);
            data.extend_from_slice(ukm);
        }
        CommandApdu::new(0x00, 0x22, 0x41, 0xB8).with_data(data)
    }

    /// PSO: PERFORM SECURITY OPERATION — GOST VKO key agreement.
    ///
    /// Presents the peer public point (already in Rutoken token-point byte order,
    /// see [`pubkey_to_token_point`]) and returns the shared-secret / KEK bytes.
    ///
    /// On-wire APDU: `00 2A 80 86 <Lc> <peer_token_point…>`.
    pub fn pso_key_agreement(peer_token_point: &[u8]) -> CommandApdu {
        CommandApdu::new(0x00, 0x2A, 0x80, 0x86).with_data(peer_token_point.to_vec())
    }

    /// Convert a raw GOST public point `X‖Y` (big-endian per coordinate) into the
    /// Rutoken "token point" format expected by [`pso_key_agreement`].
    ///
    /// The card stores and consumes each affine coordinate in little-endian byte
    /// order, so each `coord_len`-byte half is reversed independently.
    /// `coord_len` is 32 for GOST-2012-256
    /// and 64 for GOST-2012-512.
    pub fn pubkey_to_token_point(pubkey_xy: &[u8], coord_len: usize) -> Result<Vec<u8>, CliError> {
        if coord_len == 0 || pubkey_xy.len() != coord_len * 2 {
            return Err(CliError::Usage(format!(
                "VKO peer public key must be {} bytes (X||Y), got {}",
                coord_len * 2,
                pubkey_xy.len()
            )));
        }
        let mut point = Vec::with_capacity(pubkey_xy.len());
        for chunk in pubkey_xy.chunks_exact(coord_len) {
            point.extend(chunk.iter().rev().copied());
        }
        Ok(point)
    }

    /// READ BINARY from the currently selected transparent EF.
    pub fn read_binary(offset: usize, le: u8) -> CommandApdu {
        CommandApdu::new(0x00, 0xB0, (offset >> 8) as u8, offset as u8).with_le(le)
    }

    /// Convert the Rutoken ECP signature byte order back to the caller-facing order.
    pub fn signature_from_token(mut signature: Vec<u8>) -> Vec<u8> {
        signature.reverse();
        signature
    }
}

pub fn compute_digest(data: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
    use sha2::Digest as _;
    match algorithm {
        DigestAlgorithm::Gost3411_2012_256 | DigestAlgorithm::Gost3411_2012_512 => {
            gost::hash(data, algorithm)
        }
        DigestAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        DigestAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        DigestAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

pub mod cms_envelope {
    use super::{CliError, DigestAlgorithm, KeyAlgorithm};
    use cms::{
        cert::{CertificateChoices, IssuerAndSerialNumber, x509::Certificate},
        content_info::{CmsVersion, ContentInfo},
        signed_data::{
            CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
            SignedAttributes, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
        },
    };
    use der::{Any, AnyRef, Decode, Encode, asn1::OctetString};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::attr::Attribute;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CmsSigningInput {
        pub content_digest: Vec<u8>,
        pub digest_algorithm: DigestAlgorithm,
        pub key_algorithm: KeyAlgorithm,
        pub signer_certificate: Vec<u8>,
        pub detached: bool,
    }

    impl CmsSigningInput {
        pub fn new(
            content_digest: Vec<u8>,
            digest_algorithm: DigestAlgorithm,
            key_algorithm: KeyAlgorithm,
            signer_certificate: Vec<u8>,
            detached: bool,
        ) -> Self {
            Self {
                content_digest,
                digest_algorithm,
                key_algorithm,
                signer_certificate,
                detached,
            }
        }

        pub fn validate(&self) -> Result<(), CliError> {
            if self.content_digest.len() != self.digest_algorithm.output_len() {
                return Err(CliError::Message(format!(
                    "{} digest must be {} bytes, got {}",
                    self.digest_algorithm.name(),
                    self.digest_algorithm.output_len(),
                    self.content_digest.len()
                )));
            }
            if self.signer_certificate.is_empty() {
                return Err(CliError::Message(
                    "signer certificate must not be empty".to_string(),
                ));
            }
            Ok(())
        }

        fn signature_oid(&self) -> Result<const_oid::ObjectIdentifier, CliError> {
            self.key_algorithm.signature_oid(self.digest_algorithm)
        }
    }

    pub fn build_signed_data_der(
        input: &CmsSigningInput,
        document: &[u8],
        signature: Vec<u8>,
        signed_attrs: SignedAttributes,
    ) -> Result<Vec<u8>, CliError> {
        input.validate()?;
        if signature.is_empty() {
            return Err(CliError::Message("signature must not be empty".to_string()));
        }

        let certificate = Certificate::from_der(&input.signer_certificate)
            .map_err(|error| CliError::Message(format!("failed to parse --cert DER: {error}")))?;
        let digest_algorithm = algorithm_identifier(input.digest_algorithm.digest_oid());
        let signature_algorithm = algorithm_identifier(input.signature_oid()?);
        let econtent = if input.detached {
            None
        } else {
            Some(any_from_der(
                &OctetString::new(document)
                    .map_err(|error| {
                        CliError::Message(format!(
                            "failed to construct content OCTET STRING: {error}"
                        ))
                    })?
                    .to_der()
                    .map_err(|error| {
                        CliError::Message(format!("failed to serialize content DER: {error}"))
                    })?,
            )?)
        };

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: DigestAlgorithmIdentifiers::try_from(vec![digest_algorithm.clone()])
                .map_err(|error| {
                    CliError::Message(format!("failed to encode digest algorithms: {error}"))
                })?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: const_oid::db::rfc5911::ID_DATA,
                econtent,
            },
            certificates: Some(
                CertificateSet::try_from(vec![CertificateChoices::Certificate(
                    certificate.clone(),
                )])
                .map_err(|error| {
                    CliError::Message(format!("failed to encode certificate set: {error}"))
                })?,
            ),
            crls: None,
            signer_infos: SignerInfos::try_from(vec![SignerInfo {
                version: CmsVersion::V1,
                sid: signer_identifier(&certificate),
                digest_alg: digest_algorithm,
                signed_attrs: Some(signed_attrs),
                signature_algorithm,
                signature: SignatureValue::new(signature).map_err(|error| {
                    CliError::Message(format!("failed to encode signature value: {error}"))
                })?,
                unsigned_attrs: None,
            }])
            .map_err(|error| CliError::Message(format!("failed to encode signer info: {error}")))?,
        };

        let signed_data_der = signed_data
            .to_der()
            .map_err(|error| CliError::Message(format!("failed to encode SignedData: {error}")))?;
        let content_info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: any_from_der(&signed_data_der)?,
        };
        content_info.to_der().map_err(|error| {
            CliError::Message(format!("failed to encode CMS ContentInfo: {error}"))
        })
    }

    pub fn prepare_signed_attributes(
        input: &CmsSigningInput,
    ) -> Result<(SignedAttributes, Vec<u8>), CliError> {
        input.validate()?;
        let attributes = SignedAttributes::try_from(vec![
            single_value_attribute(
                const_oid::db::rfc5911::ID_CONTENT_TYPE,
                &const_oid::db::rfc5911::ID_DATA.to_der().map_err(|error| {
                    CliError::Message(format!("failed to encode contentType value: {error}"))
                })?,
            )?,
            single_value_attribute(
                const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
                &OctetString::new(input.content_digest.clone())
                    .map_err(|error| {
                        CliError::Message(format!(
                            "failed to construct messageDigest value: {error}"
                        ))
                    })?
                    .to_der()
                    .map_err(|error| {
                        CliError::Message(format!("failed to encode messageDigest value: {error}"))
                    })?,
            )?,
        ])
        .map_err(|error| {
            CliError::Message(format!("failed to encode signed attributes: {error}"))
        })?;
        let der = attributes.to_der().map_err(|error| {
            CliError::Message(format!("failed to serialize signed attributes: {error}"))
        })?;
        Ok((attributes, der))
    }

    pub fn cms_crate_backend() -> &'static str {
        std::any::type_name::<cms::content_info::ContentInfo>()
    }

    fn algorithm_identifier(oid: const_oid::ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    fn signer_identifier(certificate: &Certificate) -> SignerIdentifier {
        let tbs = certificate.tbs_certificate();
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: tbs.serial_number().clone(),
        })
    }

    fn single_value_attribute(
        oid: const_oid::ObjectIdentifier,
        value_der: &[u8],
    ) -> Result<Attribute, CliError> {
        let mut values = der::asn1::SetOfVec::new();
        values.insert(any_from_der(value_der)?).map_err(|error| {
            CliError::Message(format!("failed to add signed attribute value: {error}"))
        })?;
        Ok(Attribute { oid, values })
    }

    fn any_from_der(der: &[u8]) -> Result<Any, CliError> {
        AnyRef::try_from(der)
            .map(Any::from)
            .map_err(|error| CliError::Message(format!("failed to wrap ASN.1 value: {error}")))
    }
}

pub mod token {
    use super::{CliError, DigestAlgorithm, KeyAlgorithm};
    use cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        mechanism::{Mechanism, MechanismType, vendor_defined::VendorDefinedMechanism},
        object::{Attribute, ObjectClass},
        session::UserType,
        slot::Slot,
        types::AuthPin,
    };
    use cryptoki_sys::CKM_GOSTR3410;
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Pkcs11SignerConfig {
        pub module: PathBuf,
        pub key_uri: String,
        pub pin_env: Option<String>,
        pub key_algorithm: KeyAlgorithm,
    }

    impl Pkcs11SignerConfig {
        pub fn new(
            module: PathBuf,
            key_uri: String,
            pin_env: Option<String>,
            key_algorithm: KeyAlgorithm,
        ) -> Self {
            Self {
                module,
                key_uri,
                pin_env,
                key_algorithm,
            }
        }

        pub fn validate(&self) -> Result<(), CliError> {
            if self.key_uri.trim().is_empty() {
                return Err(CliError::Usage("--key-uri must not be empty".to_string()));
            }
            if !self.module.is_file() {
                return Err(CliError::Message(format!(
                    "--pkcs11-module does not exist: {}",
                    self.module.display()
                )));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CcidSignerConfig {
        pub reader: Option<String>,
        pub key_uri: String,
        pub pin_env: Option<String>,
        pub key_algorithm: KeyAlgorithm,
        pub exchange_log: Option<PathBuf>,
    }

    impl CcidSignerConfig {
        pub fn new(
            reader: Option<String>,
            key_uri: String,
            pin_env: Option<String>,
            key_algorithm: KeyAlgorithm,
            exchange_log: Option<PathBuf>,
        ) -> Self {
            Self {
                reader,
                key_uri,
                pin_env,
                key_algorithm,
                exchange_log,
            }
        }
    }

    pub fn pkcs11_crate_backend() -> &'static str {
        std::any::type_name::<cryptoki::context::Pkcs11>()
    }

    pub trait TokenSigner {
        fn sign_digest(
            &self,
            digest_algorithm: DigestAlgorithm,
            digest: &[u8],
        ) -> Result<Vec<u8>, CliError>;
    }

    impl TokenSigner for Pkcs11SignerConfig {
        fn sign_digest(
            &self,
            digest_algorithm: DigestAlgorithm,
            digest: &[u8],
        ) -> Result<Vec<u8>, CliError> {
            self.validate()?;
            if digest.len() != digest_algorithm.output_len() {
                return Err(CliError::Message(format!(
                    "{} digest must be {} bytes, got {}",
                    digest_algorithm.name(),
                    digest_algorithm.output_len(),
                    digest.len()
                )));
            }
            let selector = KeyUriSelector::parse(&self.key_uri)?;
            let ctx = Pkcs11::new(&self.module).map_err(|error| {
                CliError::Message(format!(
                    "failed to load PKCS#11 module {}: {error}",
                    self.module.display()
                ))
            })?;
            ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|error| {
                    CliError::Message(format!("failed to initialize PKCS#11: {error}"))
                })?;
            let slot = selector.select_slot(&ctx)?;
            let session = ctx.open_rw_session(slot).map_err(|error| {
                CliError::Message(format!("failed to open PKCS#11 session: {error}"))
            })?;
            let pin = self.pin_env.as_deref().map(load_pin).transpose()?;
            session
                .login(UserType::User, pin.as_ref())
                .map_err(|error| {
                    CliError::Message(format!("failed to login to PKCS#11 token: {error}"))
                })?;
            let template = selector.private_key_template();
            let key = session
                .find_objects(&template)
                .map_err(|error| {
                    CliError::Message(format!("failed to search PKCS#11 objects: {error}"))
                })?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    CliError::Message("--key-uri did not match a token private key".to_string())
                })?;
            let mechanism = signing_mechanism(self.key_algorithm)?;
            let sign_input = prepare_sign_input(self.key_algorithm, digest_algorithm, digest)?;

            session
                .sign(&mechanism, key, &sign_input)
                .map_err(|error| CliError::Message(format!("PKCS#11 C_Sign failed: {error}")))
        }
    }

    impl TokenSigner for CcidSignerConfig {
        fn sign_digest(
            &self,
            digest_algorithm: DigestAlgorithm,
            digest: &[u8],
        ) -> Result<Vec<u8>, CliError> {
            if digest.len() != digest_algorithm.output_len() {
                return Err(CliError::Message(format!(
                    "{} digest must be {} bytes, got {}",
                    digest_algorithm.name(),
                    digest_algorithm.output_len(),
                    digest.len()
                )));
            }

            let uri = super::rutoken::RutokenUri::parse(&self.key_uri)?;

            let pin: Option<Vec<u8>> = self.pin_env.as_deref().map(load_pin_bytes).transpose()?;

            sign_digest_direct(self, uri.id, pin.as_deref(), digest_algorithm, digest)
        }
    }

    pub fn read_certificate_der(config: &CcidSignerConfig) -> Result<Vec<u8>, CliError> {
        let uri = super::rutoken::RutokenUri::parse(&config.key_uri)?;
        let pin: Option<Vec<u8>> = config.pin_env.as_deref().map(load_pin_bytes).transpose()?;
        read_certificate_direct(config, uri.id, pin.as_deref())
    }

    /// Perform a hardware GOST VKO (key agreement) against the Rutoken ECP token.
    ///
    /// Runs the native Rutoken ECP key-agreement exchange:
    /// SELECT MF → VERIFY PIN → SELECT private-key file → MSE SET (key-agreement
    /// template) → PSO (key agreement). Returns the shared-secret / KEK bytes the
    /// card produces from the peer public key.
    ///
    /// `peer_public_xy` is the peer GOST public point as `X‖Y` big-endian
    /// (64 bytes for GOST-2012-256). `algo` is the card-reported cryptographic
    /// mechanism byte for the target paramset (see [`super::rutoken`] docs).
    pub fn derive_vko(
        config: &CcidSignerConfig,
        peer_public_xy: &[u8],
        algo: u8,
        ukm: &[u8],
    ) -> Result<Vec<u8>, CliError> {
        let uri = super::rutoken::RutokenUri::parse(&config.key_uri)?;
        let pin: Option<Vec<u8>> = config.pin_env.as_deref().map(load_pin_bytes).transpose()?;
        derive_vko_direct(config, uri.id, pin.as_deref(), peer_public_xy, algo, ukm)
    }

    enum ApduDevice {
        Ccid(super::ccid::CcidDevice),
        #[cfg(feature = "pcsc")]
        Pcsc(super::pcsc_transport::PcscDevice),
    }

    impl ApduDevice {
        fn open(config: &CcidSignerConfig) -> Result<Self, CliError> {
            match super::ccid::CcidDevice::open_with_exchange_log(
                config.reader.as_deref(),
                config.exchange_log.as_deref(),
            ) {
                Ok(mut device) => match device.power_on() {
                    Ok(_) => Ok(Self::Ccid(device)),
                    Err(usb_error) => Self::open_after_ccid_error(config, usb_error),
                },
                Err(usb_error) => Self::open_after_ccid_error(config, usb_error),
            }
        }

        #[cfg(feature = "pcsc")]
        fn open_after_ccid_error(
            config: &CcidSignerConfig,
            usb_error: CliError,
        ) -> Result<Self, CliError> {
            match super::pcsc_transport::PcscDevice::open_with_exchange_log(
                config.reader.as_deref(),
                config.exchange_log.as_deref(),
            ) {
                Ok(device) => Ok(Self::Pcsc(device)),
                Err(pcsc_error) => Err(CliError::Message(format!(
                    "failed to open Rutoken via raw CCID ({usb_error}) or PC/SC ({pcsc_error})"
                ))),
            }
        }

        #[cfg(not(feature = "pcsc"))]
        fn open_after_ccid_error(
            _config: &CcidSignerConfig,
            usb_error: CliError,
        ) -> Result<Self, CliError> {
            Err(CliError::Message(format!(
                "failed to open Rutoken via raw CCID: {usb_error}"
            )))
        }

        fn transmit(
            &mut self,
            apdu: &super::apdu::CommandApdu,
        ) -> Result<super::apdu::ResponseApdu, CliError> {
            match self {
                Self::Ccid(device) => device.transmit(apdu),
                #[cfg(feature = "pcsc")]
                Self::Pcsc(device) => device.transmit(apdu),
            }
        }
    }

    fn sign_digest_direct(
        config: &CcidSignerConfig,
        key_id: u8,
        pin: Option<&[u8]>,
        digest_algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, CliError> {
        let mut device = ApduDevice::open(config)?;
        let resp = device.transmit(&super::rutoken::select_master_file())?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "SELECT MF failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        verify_pin_if_present(&mut device, pin)?;

        select_private_key_file(&mut device, key_id)?;

        let resp = device.transmit(&super::rutoken::manage_security_environment_for_signing(
            key_id,
        ))?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "MSE SET (key reference 0x{key_id:02x}) failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        let signature_len = match digest_algorithm {
            DigestAlgorithm::Gost3411_2012_256 => 64u8,
            DigestAlgorithm::Gost3411_2012_512 => 128u8,
            _ => {
                return Err(CliError::Message(format!(
                    "CCID/Rutoken transport only supports GOST digests, got {}",
                    digest_algorithm.name()
                )));
            }
        };
        let resp = device.transmit(&super::rutoken::pso_compute_digital_signature(
            digest,
            signature_len,
        ))?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "PSO COMPUTE DIGITAL SIGNATURE failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        if resp.data.len() != signature_len as usize {
            return Err(CliError::Message(format!(
                "CCID signature length mismatch: expected {} bytes, token returned {}",
                signature_len,
                resp.data.len()
            )));
        }

        Ok(super::rutoken::signature_from_token(resp.data))
    }

    fn derive_vko_direct(
        config: &CcidSignerConfig,
        key_id: u8,
        pin: Option<&[u8]>,
        peer_public_xy: &[u8],
        algo: u8,
        ukm: &[u8],
    ) -> Result<Vec<u8>, CliError> {
        let coord_len = peer_public_xy.len() / 2;
        let token_point = super::rutoken::pubkey_to_token_point(peer_public_xy, coord_len)?;

        let mut device = ApduDevice::open(config)?;
        let resp = device.transmit(&super::rutoken::select_master_file())?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "SELECT MF failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        verify_pin_if_present(&mut device, pin)?;

        select_private_key_file(&mut device, key_id)?;

        let resp = device.transmit(
            &super::rutoken::manage_security_environment_for_vko_with_ukm(key_id, algo, ukm),
        )?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "MSE SET key agreement (key 0x{key_id:02x}, algo 0x{algo:02x}) failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        let resp = device.transmit(&super::rutoken::pso_key_agreement(&token_point))?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "PSO key agreement failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        Ok(resp.data)
    }

    fn read_certificate_direct(
        config: &CcidSignerConfig,
        key_id: u8,
        pin: Option<&[u8]>,
    ) -> Result<Vec<u8>, CliError> {
        let mut device = ApduDevice::open(config)?;
        let resp = device.transmit(&super::rutoken::select_master_file())?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "SELECT MF failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }
        verify_pin_if_present(&mut device, pin)?;
        match select_certificate_file(&mut device, key_id) {
            Ok(()) => match read_selected_certificate(&mut device) {
                Ok(certificate) => Ok(certificate),
                Err(read_error) => scan_certificate_files(&mut device, key_id, Some(read_error)),
            },
            Err(select_error) => scan_certificate_files(&mut device, key_id, Some(select_error)),
        }
    }

    fn verify_pin_if_present(device: &mut ApduDevice, pin: Option<&[u8]>) -> Result<(), CliError> {
        let Some(pin_bytes) = pin else {
            return Ok(());
        };
        let mut resp = device.transmit(&super::rutoken::verify_pin(pin_bytes))?;
        if resp.sw1 == 0x6F && resp.sw2 == 0x86 {
            let logout = device.transmit(&super::rutoken::logout())?;
            if !logout.is_success() {
                return Err(CliError::Message(format!(
                    "LOGOUT failed after VERIFY returned 6f86: SW {:02x}{:02x}",
                    logout.sw1, logout.sw2
                )));
            }
            resp = device.transmit(&super::rutoken::verify_pin(pin_bytes))?;
        }
        if !resp.is_success() {
            let resp = if resp.sw1 == 0x63 && resp.sw2 == 0x00 {
                device.transmit(&super::rutoken::verify_pin_status())?
            } else {
                resp
            };
            return Err(CliError::Message(format!(
                "VERIFY PIN failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }
        Ok(())
    }

    fn select_private_key_file(device: &mut ApduDevice, key_id: u8) -> Result<(), CliError> {
        let mut failures = Vec::new();
        for sequence in super::rutoken::private_key_file_select_sequences(key_id) {
            let reset = device.transmit(&super::rutoken::select_master_file())?;
            if !reset.is_success() {
                return Err(CliError::Message(format!(
                    "SELECT MF before private key selection failed: SW {:02x}{:02x}",
                    reset.sw1, reset.sw2
                )));
            }

            let mut selected = true;
            for apdu in sequence.commands {
                let resp = device.transmit(&apdu)?;
                if !resp.is_success() {
                    failures.push(format!(
                        "{} -> {:02x}{:02x}",
                        sequence.label, resp.sw1, resp.sw2
                    ));
                    selected = false;
                    break;
                }
            }
            if selected {
                return Ok(());
            }
        }

        Err(CliError::Message(format!(
            "SELECT private key file (key reference 0x{key_id:02x}) failed: {}",
            failures.join(", ")
        )))
    }

    fn select_certificate_file(device: &mut ApduDevice, key_id: u8) -> Result<(), CliError> {
        let mut failures = Vec::new();
        for sequence in super::rutoken::certificate_file_select_sequences(key_id) {
            let reset = device.transmit(&super::rutoken::select_master_file())?;
            if !reset.is_success() {
                return Err(CliError::Message(format!(
                    "SELECT MF before certificate selection failed: SW {:02x}{:02x}",
                    reset.sw1, reset.sw2
                )));
            }

            let mut selected = true;
            for apdu in sequence.commands {
                let resp = device.transmit(&apdu)?;
                if !resp.is_success() {
                    failures.push(format!(
                        "{} -> {:02x}{:02x}",
                        sequence.label, resp.sw1, resp.sw2
                    ));
                    selected = false;
                    break;
                }
            }
            if selected {
                return Ok(());
            }
        }

        Err(CliError::Message(format!(
            "SELECT certificate file (key reference 0x{key_id:02x}) failed: {}",
            failures.join(", ")
        )))
    }

    fn read_selected_certificate(device: &mut ApduDevice) -> Result<Vec<u8>, CliError> {
        let mut data = Vec::new();
        let mut offset = 0usize;
        while offset < 16 * 1024 {
            let resp = device.transmit(&super::rutoken::read_binary(offset, 0))?;
            if resp.sw1 == 0x6B || resp.sw1 == 0x6A || resp.sw1 == 0x67 {
                break;
            }
            if resp.sw1 == 0x62 && resp.sw2 == 0x82 {
                data.extend_from_slice(&resp.data);
                break;
            }
            if !resp.is_success() {
                return Err(CliError::Message(format!(
                    "READ BINARY certificate failed at offset {offset}: SW {:02x}{:02x}",
                    resp.sw1, resp.sw2
                )));
            }
            if resp.data.is_empty() {
                break;
            }
            offset += resp.data.len();
            data.extend_from_slice(&resp.data);
            if resp.data.len() < 256 {
                break;
            }
        }
        extract_first_der_certificate(&data).ok_or_else(|| {
            CliError::Message(format!(
                "certificate file did not contain a DER certificate (read {} bytes)",
                data.len()
            ))
        })
    }

    fn scan_certificate_files(
        device: &mut ApduDevice,
        key_id: u8,
        previous_error: Option<CliError>,
    ) -> Result<Vec<u8>, CliError> {
        let directories: Vec<(&str, Vec<super::apdu::CommandApdu>)> = vec![
            (
                "Cer-DF",
                vec![
                    super::rutoken::select_file_by_id(0x1000),
                    super::rutoken::select_file_by_id(0x1000),
                    super::rutoken::select_file_by_id(0x6004),
                ],
            ),
            (
                "SysKey-DF",
                vec![
                    super::rutoken::select_file_by_id(0x1000),
                    super::rutoken::select_file_by_id(0x1000),
                ],
            ),
            (
                "PKCS15-AppDF",
                vec![super::rutoken::select_file_by_id(0x5000)],
            ),
            ("MF", Vec::new()),
        ];
        let candidates = certificate_candidate_file_ids(key_id);
        let mut selected_files = Vec::new();

        for (directory, commands) in directories {
            for file_id in &candidates {
                let reset = device.transmit(&super::rutoken::select_master_file())?;
                if !reset.is_success() {
                    continue;
                }
                let mut directory_selected = true;
                for command in &commands {
                    let resp = device.transmit(command)?;
                    if !resp.is_success() {
                        directory_selected = false;
                        break;
                    }
                }
                if !directory_selected {
                    continue;
                }
                let select = device.transmit(&super::rutoken::select_file_by_id(*file_id))?;
                if !select.is_success() {
                    continue;
                }
                selected_files.push(format!("{directory}/{file_id:04x}"));
                if let Ok(certificate) = read_selected_certificate(device) {
                    return Ok(certificate);
                }
            }
        }

        let previous = previous_error
            .map(|error| format!("; initial path error: {error}"))
            .unwrap_or_default();
        Err(CliError::Message(format!(
            "no DER certificate found in Rutoken certificate scan for key reference 0x{key_id:02x}; selected files tried: {}{}",
            if selected_files.is_empty() {
                "none".to_string()
            } else {
                selected_files.join(", ")
            },
            previous
        )))
    }

    fn certificate_candidate_file_ids(key_id: u8) -> Vec<u16> {
        let mut ids = Vec::new();
        for base in [
            0x0000u16, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x4000, 0x5000,
        ] {
            ids.push(base | key_id as u16);
            for suffix in 1u16..=0x20 {
                ids.push(base | suffix);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn extract_first_der_certificate(data: &[u8]) -> Option<Vec<u8>> {
        for start in 0..data.len() {
            if data[start] != 0x30 {
                continue;
            }
            let Some(total_len) = der_sequence_total_len(&data[start..]) else {
                continue;
            };
            if start + total_len <= data.len() {
                return Some(data[start..start + total_len].to_vec());
            }
        }
        None
    }

    fn der_sequence_total_len(data: &[u8]) -> Option<usize> {
        if data.len() < 2 || data[0] != 0x30 {
            return None;
        }
        let len_byte = data[1];
        if len_byte & 0x80 == 0 {
            return Some(2 + len_byte as usize);
        }
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 || len_len > 4 || data.len() < 2 + len_len {
            return None;
        }
        let mut len = 0usize;
        for byte in &data[2..2 + len_len] {
            len = (len << 8) | *byte as usize;
        }
        Some(2 + len_len + len)
    }

    pub fn ensure_module_path(path: &Path) -> Result<(), CliError> {
        if path.is_file() {
            Ok(())
        } else {
            Err(CliError::Message(format!(
                "--pkcs11-module does not exist: {}",
                path.display()
            )))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct KeyUriSelector {
        pub token: Option<String>,
        pub slot: Option<u64>,
        pub id: Option<Vec<u8>>,
        pub object: Option<String>,
    }

    impl KeyUriSelector {
        pub fn parse(uri: &str) -> Result<Self, CliError> {
            let attributes = uri
                .strip_prefix("pkcs11:")
                .ok_or_else(|| CliError::Usage("--key-uri must start with pkcs11:".to_string()))?;
            let mut selector = Self {
                token: None,
                slot: None,
                id: None,
                object: None,
            };

            // Supports the RFC 7512 attributes needed for this token path: token/slot/id/object.
            for pair in attributes.split(';').filter(|pair| !pair.is_empty()) {
                let Some((name, value)) = pair.split_once('=') else {
                    return Err(CliError::Usage(format!(
                        "invalid --key-uri attribute: {pair}"
                    )));
                };
                match name {
                    "token" => selector.token = Some(percent_decode_text(value)?),
                    "slot" | "slot-id" => {
                        selector.slot = Some(value.parse::<u64>().map_err(|error| {
                            CliError::Usage(format!(
                                "invalid numeric --key-uri {name}: {value} ({error})"
                            ))
                        })?)
                    }
                    "id" => selector.id = Some(super::percent_decode_bytes(value)?),
                    "object" => selector.object = Some(percent_decode_text(value)?),
                    _ => {}
                }
            }

            if selector.id.is_none() && selector.object.is_none() {
                return Err(CliError::Usage(
                    "--key-uri must include id= or object= to locate the private key".to_string(),
                ));
            }
            Ok(selector)
        }

        fn select_slot(&self, ctx: &Pkcs11) -> Result<Slot, CliError> {
            if let Some(slot) = self.slot {
                return Slot::try_from(slot)
                    .map_err(|error| CliError::Message(format!("invalid PKCS#11 slot: {error}")));
            }

            let slots = ctx.get_slots_with_token().map_err(|error| {
                CliError::Message(format!("failed to list PKCS#11 slots: {error}"))
            })?;
            if let Some(token) = &self.token {
                for slot in slots {
                    let info = ctx.get_token_info(slot).map_err(|error| {
                        CliError::Message(format!("failed to read PKCS#11 token info: {error}"))
                    })?;
                    if info.label().trim() == token {
                        return Ok(slot);
                    }
                }
                return Err(CliError::Message(format!(
                    "--key-uri token={token} did not match an inserted token"
                )));
            }

            slots
                .into_iter()
                .next()
                .ok_or_else(|| CliError::Message("no PKCS#11 token slots found".to_string()))
        }

        pub fn private_key_template(&self) -> Vec<Attribute> {
            let mut template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Sign(true),
            ];
            if let Some(id) = &self.id {
                template.push(Attribute::Id(id.clone()));
            }
            if let Some(object) = &self.object {
                template.push(Attribute::Label(object.as_bytes().to_vec()));
            }
            template
        }
    }

    fn signing_mechanism(key_algorithm: KeyAlgorithm) -> Result<Mechanism<'static>, CliError> {
        match key_algorithm {
            KeyAlgorithm::Gost3410_2012_256 | KeyAlgorithm::Gost3410_2012_512 => {
                Ok(gost3410_mechanism())
            }
            KeyAlgorithm::Ecdsa => Ok(Mechanism::Ecdsa),
            KeyAlgorithm::Rsa => Ok(Mechanism::RsaPkcs),
        }
    }

    /// Prepare the data buffer passed to `C_Sign`.
    ///
    /// - GOST and ECDSA accept raw digest bytes.
    /// - RSA PKCS#1 v1.5 (`CKM_RSA_PKCS`) requires a DER-encoded DigestInfo wrapper so that
    ///   the token can apply the correct PKCS#1 block format without knowing the hash algorithm.
    fn prepare_sign_input(
        key_algorithm: KeyAlgorithm,
        digest_algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, CliError> {
        match key_algorithm {
            KeyAlgorithm::Rsa => wrap_digest_info(digest_algorithm, digest),
            _ => Ok(digest.to_vec()),
        }
    }

    /// Build a DER-encoded `DigestInfo` structure for RSA PKCS#1 v1.5 signing.
    ///
    /// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`
    ///
    /// The prefix bytes are the fixed DER encoding of the outer SEQUENCE header and the
    /// AlgorithmIdentifier for each supported hash; the hash bytes follow immediately.
    fn wrap_digest_info(
        digest_algorithm: DigestAlgorithm,
        hash: &[u8],
    ) -> Result<Vec<u8>, CliError> {
        // Each prefix encodes:
        //   30 <total-len>          -- SEQUENCE (DigestInfo)
        //     30 0d                 -- SEQUENCE (AlgorithmIdentifier), length 13
        //       06 09 <oid-bytes>   -- OID (hash algorithm)
        //       05 00               -- NULL (parameters)
        //     04 <hash-len>         -- OCTET STRING (digest value)
        //
        // SHA-256: OID 2.16.840.1.101.3.4.2.1 (9 bytes), hash 32 bytes → total 49 (0x31)
        // SHA-384: OID 2.16.840.1.101.3.4.2.2 (9 bytes), hash 48 bytes → total 65 (0x41)
        // SHA-512: OID 2.16.840.1.101.3.4.2.3 (9 bytes), hash 64 bytes → total 81 (0x51)
        let prefix: &[u8] = match digest_algorithm {
            DigestAlgorithm::Sha256 => &[
                0x30, 0x31, // SEQUENCE, 49 bytes
                0x30, 0x0d, // SEQUENCE (AlgorithmIdentifier), 13 bytes
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, // OID sha-256
                0x05, 0x00, // NULL
                0x04, 0x20, // OCTET STRING, 32 bytes
            ],
            DigestAlgorithm::Sha384 => &[
                0x30, 0x41, // SEQUENCE, 65 bytes
                0x30, 0x0d, // SEQUENCE (AlgorithmIdentifier), 13 bytes
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, // OID sha-384
                0x05, 0x00, // NULL
                0x04, 0x30, // OCTET STRING, 48 bytes
            ],
            DigestAlgorithm::Sha512 => &[
                0x30, 0x51, // SEQUENCE, 81 bytes
                0x30, 0x0d, // SEQUENCE (AlgorithmIdentifier), 13 bytes
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, // OID sha-512
                0x05, 0x00, // NULL
                0x04, 0x40, // OCTET STRING, 64 bytes
            ],
            other => {
                return Err(CliError::Message(format!(
                    "RSA DigestInfo wrapping is not supported for {}",
                    other.name()
                )));
            }
        };
        Ok([prefix, hash].concat())
    }

    fn gost3410_mechanism() -> Mechanism<'static> {
        const _: [(); std::mem::size_of::<cryptoki_sys::CK_MECHANISM_TYPE>()] =
            [(); std::mem::size_of::<MechanismType>()];
        let mechanism_type = unsafe {
            // cryptoki 0.12 exposes CKM_GOSTR3410 through cryptoki-sys, but not its safe Mechanism enum.
            std::mem::transmute::<cryptoki_sys::CK_MECHANISM_TYPE, MechanismType>(CKM_GOSTR3410)
        };
        Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(mechanism_type, None))
    }

    fn load_pin(name: &str) -> Result<AuthPin, CliError> {
        load_env_value(name).map(|pin| AuthPin::new(pin.into()))
    }

    fn load_pin_bytes(name: &str) -> Result<Vec<u8>, CliError> {
        load_env_value(name).map(String::into_bytes)
    }

    fn load_env_value(name: &str) -> Result<String, CliError> {
        match env::var(name) {
            Ok(value) => return Ok(value),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(CliError::Usage(format!(
                    "--pin-env variable {name} contains invalid UTF-8"
                )));
            }
            Err(env::VarError::NotPresent) => {}
        }

        let Ok(contents) = fs::read_to_string(".env") else {
            return Err(CliError::Usage(format!(
                "--pin-env variable {name} is not set and .env was not found"
            )));
        };

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == name {
                return Ok(unquote_env_value(value.trim()).to_string());
            }
        }

        Err(CliError::Usage(format!(
            "--pin-env variable {name} is not set in the environment or .env"
        )))
    }

    fn unquote_env_value(value: &str) -> &str {
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        }
    }

    fn percent_decode_text(value: &str) -> Result<String, CliError> {
        String::from_utf8(super::percent_decode_bytes(value)?)
            .map_err(|_| CliError::Usage("PKCS#11 URI contains non-UTF-8 text".to_string()))
    }
}

pub mod gosuslugi_bridge {
    use super::{
        CliError, DigestAlgorithm, KeyAlgorithm, cms_envelope, compute_digest, hex_encode, token,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use cms::cert::x509::{Certificate, ext::pkix::name::DirectoryString, name::Name};
    use der::{Decode, Encode, Tag, Tagged, asn1::Ia5StringRef};
    use serde::{Deserialize, Serialize};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream, ToSocketAddrs},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug, Clone)]
    pub struct BridgeConfig {
        pub bind: String,
        pub certificate: CertificateRecord,
        pub certificate_der: Option<Vec<u8>>,
        pub signer: token::CcidSignerConfig,
        pub digest_algorithm: DigestAlgorithm,
        pub key_algorithm: KeyAlgorithm,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CertificateRecord {
        pub raw: String,
        pub serial_number: String,
        pub subject: String,
        pub issuer: String,
        pub not_before: u64,
        pub not_after: u64,
        pub signature_algorithm: String,
        pub container: String,
        pub version: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum SignatureRequest {
        Envelope(SignatureEnvelope),
        File(BridgeFile),
    }

    #[derive(Debug, Deserialize)]
    struct SignatureEnvelope {
        files: Vec<BridgeFile>,
        #[allow(dead_code)]
        certificate: Option<BridgeFile>,
        #[allow(dead_code)]
        #[serde(default)]
        r#type: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BridgeFile {
        #[serde(default)]
        content: String,
        #[serde(default)]
        content_encoding: String,
        #[allow(dead_code)]
        #[serde(default)]
        name: String,
    }

    #[derive(Debug, Serialize)]
    struct CertificatesResponse<'a> {
        certificates: &'a [CertificateRecord],
    }

    #[derive(Debug, Serialize)]
    struct SignatureResponse {
        contents: Vec<String>,
    }

    pub fn certificate_record_from_der(
        der: &[u8],
        container: impl Into<String>,
    ) -> Result<CertificateRecord, CliError> {
        let certificate = Certificate::from_der(der)
            .map_err(|error| CliError::Message(format!("failed to parse --cert DER: {error}")))?;
        let tbs = certificate.tbs_certificate();
        let validity = tbs.validity();
        Ok(CertificateRecord {
            raw: BASE64.encode(der),
            serial_number: hex_encode(tbs.serial_number().as_bytes()).to_uppercase(),
            subject: name_to_gosuslugi_dn(tbs.subject()),
            issuer: name_to_gosuslugi_dn(tbs.issuer()),
            not_before: validity.not_before.to_unix_duration().as_secs(),
            not_after: validity.not_after.to_unix_duration().as_secs(),
            signature_algorithm: certificate.signature_algorithm().oid.to_string(),
            container: container.into(),
            version: format!("{:?}", tbs.version()),
        })
    }

    pub fn certificate_der_from_record_raw(
        record: &CertificateRecord,
    ) -> Result<Option<Vec<u8>>, CliError> {
        if record.raw.trim().is_empty() {
            return Ok(None);
        }
        let der = BASE64.decode(record.raw.as_bytes()).map_err(|error| {
            CliError::Message(format!("invalid certificate record raw base64: {error}"))
        })?;
        Certificate::from_der(&der).map_err(|error| {
            CliError::Message(format!(
                "certificate record raw is not a DER certificate: {error}"
            ))
        })?;
        Ok(Some(der))
    }

    pub fn serve(config: BridgeConfig) -> Result<(), CliError> {
        let addr = config
            .bind
            .to_socket_addrs()
            .map_err(|error| CliError::Message(format!("invalid --bind address: {error}")))?
            .next()
            .ok_or_else(|| {
                CliError::Message(format!("--bind resolved no addresses: {}", config.bind))
            })?;
        let listener = TcpListener::bind(addr).map_err(|error| {
            CliError::Message(format!("failed to bind {}: {error}", config.bind))
        })?;
        let config = Arc::new(config);
        eprintln!(
            "gosuslugi bridge listening on http://{}",
            listener
                .local_addr()
                .map_err(|error| CliError::Message(format!(
                    "failed to read listener address: {error}"
                )))?
        );
        eprintln!(
            "inject browser/gosuslugi-inject.js into the Gosuslugi tab, then reload the page if certificate search already failed"
        );

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let config = Arc::clone(&config);
                    if let Err(error) = handle_connection(stream, &config) {
                        eprintln!("gosuslugi bridge request failed: {error}");
                    }
                }
                Err(error) => eprintln!("gosuslugi bridge accept failed: {error}"),
            }
        }
        Ok(())
    }

    fn handle_connection(mut stream: TcpStream, config: &BridgeConfig) -> Result<(), CliError> {
        let request = HttpRequest::read_from(&mut stream)?;
        let response = match (request.method.as_str(), request.path.as_str()) {
            ("OPTIONS", _) => HttpResponse::empty(204),
            ("GET", "/health") => HttpResponse::json(
                200,
                &serde_json::json!({
                    "ok": true,
                    "time": unix_now(),
                }),
            )?,
            ("POST", "/certificates") => HttpResponse::json(
                200,
                &CertificatesResponse {
                    certificates: std::slice::from_ref(&config.certificate),
                },
            )?,
            ("POST", "/signature") => {
                let request: SignatureRequest =
                    serde_json::from_slice(&request.body).map_err(|error| {
                        CliError::Message(format!("invalid signature JSON: {error}"))
                    })?;
                let signatures = sign_files(config, request)?;
                HttpResponse::json(
                    200,
                    &SignatureResponse {
                        contents: signatures,
                    },
                )?
            }
            _ => HttpResponse::text(404, "not found"),
        };
        response.write_to(&mut stream)
    }

    fn sign_files(
        config: &BridgeConfig,
        request: SignatureRequest,
    ) -> Result<Vec<String>, CliError> {
        let (files, detached) = match request {
            SignatureRequest::Envelope(envelope) => {
                if envelope.files.is_empty() {
                    return Err(CliError::Message(
                        "signature request did not include files".to_string(),
                    ));
                }
                (
                    envelope.files,
                    envelope.r#type.eq_ignore_ascii_case("detached"),
                )
            }
            SignatureRequest::File(file) => (vec![file], false),
        };
        files
            .into_iter()
            .map(|file| sign_file(config, file, detached))
            .collect()
    }

    fn sign_file(
        config: &BridgeConfig,
        file: BridgeFile,
        detached: bool,
    ) -> Result<String, CliError> {
        if file.content.trim().is_empty() {
            return Err(CliError::Message(
                "signature request file did not include content".to_string(),
            ));
        }
        if !file.content_encoding.is_empty() && file.content_encoding != "base64" {
            return Err(CliError::Message(format!(
                "unsupported file contentEncoding: {}",
                file.content_encoding
            )));
        }
        let document = BASE64
            .decode(file.content.as_bytes())
            .map_err(|error| CliError::Message(format!("invalid base64 file content: {error}")))?;
        let digest = compute_digest(&document, config.digest_algorithm);
        let Some(certificate_der) = config.certificate_der.clone() else {
            return Err(CliError::Message(
                "signature request requires signer certificate DER; provide --cert or a certificate record with base64 DER in raw".to_string(),
            ));
        };
        let cms_input = cms_envelope::CmsSigningInput::new(
            digest,
            config.digest_algorithm,
            config.key_algorithm,
            certificate_der,
            detached,
        );
        let (signed_attrs, signed_attrs_der) = cms_envelope::prepare_signed_attributes(&cms_input)?;
        let signed_attrs_digest = compute_digest(&signed_attrs_der, config.digest_algorithm);
        let signature = token::TokenSigner::sign_digest(
            &config.signer,
            config.digest_algorithm,
            &signed_attrs_digest,
        )?;
        let cms_der =
            cms_envelope::build_signed_data_der(&cms_input, &document, signature, signed_attrs)?;
        Ok(BASE64.encode(cms_der))
    }

    fn name_to_gosuslugi_dn(name: &Name) -> String {
        name.iter()
            .map(|attribute| {
                format!(
                    "{}={}",
                    attribute.oid,
                    any_to_string(&attribute.value).replace(';', ",")
                )
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    fn any_to_string(any: &der::asn1::Any) -> String {
        if let Ok(value) = DirectoryString::try_from(any) {
            return value.value().into_owned();
        }
        if matches!(
            any.tag(),
            Tag::NumericString
                | Tag::PrintableString
                | Tag::TeletexString
                | Tag::VideotexString
                | Tag::VisibleString
                | Tag::GeneralString
        ) && let Ok(value) = std::str::from_utf8(any.value())
        {
            return value.to_string();
        }
        if let Ok(value) = Ia5StringRef::try_from(any) {
            return value.as_str().to_string();
        }
        any.to_der()
            .map(|der| hex_encode(&der))
            .unwrap_or_else(|_| String::new())
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
    }

    #[derive(Debug)]
    struct HttpRequest {
        method: String,
        path: String,
        body: Vec<u8>,
    }

    impl HttpRequest {
        fn read_from(stream: &mut TcpStream) -> Result<Self, CliError> {
            let mut buffer = Vec::new();
            let mut temp = [0u8; 4096];
            loop {
                let read = stream.read(&mut temp).map_err(|error| {
                    CliError::Message(format!("failed to read HTTP request: {error}"))
                })?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..read]);
                if header_end(&buffer).is_some() {
                    break;
                }
                if buffer.len() > 64 * 1024 {
                    return Err(CliError::Message(
                        "HTTP request headers are too large".to_string(),
                    ));
                }
            }
            let Some(header_end) = header_end(&buffer) else {
                return Err(CliError::Message(
                    "HTTP request missing header terminator".to_string(),
                ));
            };
            let headers = String::from_utf8_lossy(&buffer[..header_end]);
            let mut lines = headers.lines();
            let request_line = lines
                .next()
                .ok_or_else(|| CliError::Message("HTTP request line is missing".to_string()))?;
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts
                .next()
                .ok_or_else(|| CliError::Message("HTTP method is missing".to_string()))?
                .to_string();
            let path = request_parts
                .next()
                .ok_or_else(|| CliError::Message("HTTP path is missing".to_string()))?
                .split('?')
                .next()
                .unwrap_or("/")
                .to_string();
            let content_length = lines
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);

            let body_start = header_end + 4;
            while buffer.len() < body_start + content_length {
                let read = stream.read(&mut temp).map_err(|error| {
                    CliError::Message(format!("failed to read HTTP body: {error}"))
                })?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..read]);
            }
            let body_end = (body_start + content_length).min(buffer.len());
            Ok(Self {
                method,
                path,
                body: buffer[body_start..body_end].to_vec(),
            })
        }
    }

    struct HttpResponse {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
    }

    impl HttpResponse {
        fn empty(status: u16) -> Self {
            Self {
                status,
                content_type: "text/plain; charset=utf-8",
                body: Vec::new(),
            }
        }

        fn text(status: u16, body: impl Into<String>) -> Self {
            Self {
                status,
                content_type: "text/plain; charset=utf-8",
                body: body.into().into_bytes(),
            }
        }

        fn json(status: u16, value: &impl Serialize) -> Result<Self, CliError> {
            Ok(Self {
                status,
                content_type: "application/json; charset=utf-8",
                body: serde_json::to_vec(value).map_err(|error| {
                    CliError::Message(format!("failed to encode JSON: {error}"))
                })?,
            })
        }

        fn write_to(&self, stream: &mut TcpStream) -> Result<(), CliError> {
            let reason = match self.status {
                200 => "OK",
                204 => "No Content",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "OK",
            };
            let header = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Private-Network: true\r\nConnection: close\r\n\r\n",
                self.status,
                reason,
                self.content_type,
                self.body.len()
            );
            stream
                .write_all(header.as_bytes())
                .and_then(|_| stream.write_all(&self.body))
                .map_err(|error| {
                    CliError::Message(format!("failed to write HTTP response: {error}"))
                })
        }
    }

    fn header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Gost3411_2012_256,
    Gost3411_2012_512,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Gost3410_2012_256,
    Gost3410_2012_512,
    Ecdsa,
    Rsa,
}

const OID_GOST3410_2012_256_WITH_GOST3411_2012_256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.643.7.1.1.3.2");
const OID_GOST3410_2012_512_WITH_GOST3411_2012_512: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.643.7.1.1.3.3");
const OID_GOST3411_2012_256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.643.7.1.1.2.2");
const OID_GOST3411_2012_512: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.643.7.1.1.2.3");

// SHA-2 digest OIDs (RFC 5912)
const OID_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// ECDSA signature OIDs (RFC 5912)
const OID_ECDSA_WITH_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_WITH_SHA384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_WITH_SHA512: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

// RSA PKCS#1 v1.5 signature OIDs (RFC 5912)
const OID_SHA256_WITH_RSA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_WITH_RSA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_WITH_RSA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

impl DigestAlgorithm {
    pub fn parse(name: &str) -> Result<Self, CliError> {
        match name {
            "gost3411-2012-256" | "gost12-256" => Ok(Self::Gost3411_2012_256),
            "gost3411-2012-512" | "gost12-512" => Ok(Self::Gost3411_2012_512),
            "sha256" | "sha-256" => Ok(Self::Sha256),
            "sha384" | "sha-384" => Ok(Self::Sha384),
            "sha512" | "sha-512" => Ok(Self::Sha512),
            _ => Err(CliError::Usage(format!(
                "unsupported --digest {name}; expected gost12-256, gost12-512, sha256, sha384, or sha512\n\n{}",
                usage()
            ))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Gost3411_2012_256 => "ГОСТ Р 34.11-2012-256",
            Self::Gost3411_2012_512 => "ГОСТ Р 34.11-2012-512",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Gost3411_2012_256 => "gost12-256",
            Self::Gost3411_2012_512 => "gost12-512",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Self::Gost3411_2012_256 => 32,
            Self::Gost3411_2012_512 => 64,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest_oid(self) -> const_oid::ObjectIdentifier {
        match self {
            Self::Gost3411_2012_256 => OID_GOST3411_2012_256,
            Self::Gost3411_2012_512 => OID_GOST3411_2012_512,
            Self::Sha256 => OID_SHA256,
            Self::Sha384 => OID_SHA384,
            Self::Sha512 => OID_SHA512,
        }
    }
}

impl KeyAlgorithm {
    pub fn parse(name: &str) -> Result<Self, CliError> {
        match name {
            "gost3410-2012-256" | "gost3410-256" => Ok(Self::Gost3410_2012_256),
            "gost3410-2012-512" | "gost3410-512" => Ok(Self::Gost3410_2012_512),
            "ecdsa" => Ok(Self::Ecdsa),
            "rsa" => Ok(Self::Rsa),
            _ => Err(CliError::Usage(format!(
                "unsupported --key-algorithm {name}; expected gost3410-2012-256, gost3410-2012-512, ecdsa, or rsa\n\n{}",
                usage()
            ))),
        }
    }

    /// Returns the default key algorithm implied by the chosen digest algorithm.
    ///
    /// GOST digests pair with GOST signing keys; SHA-2 digests default to ECDSA.
    pub fn default_for_digest(digest: DigestAlgorithm) -> Self {
        match digest {
            DigestAlgorithm::Gost3411_2012_256 => Self::Gost3410_2012_256,
            DigestAlgorithm::Gost3411_2012_512 => Self::Gost3410_2012_512,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512 => {
                Self::Ecdsa
            }
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Gost3410_2012_256 => "gost3410-2012-256",
            Self::Gost3410_2012_512 => "gost3410-2012-512",
            Self::Ecdsa => "ecdsa",
            Self::Rsa => "rsa",
        }
    }

    /// Returns the CMS `signatureAlgorithm` OID for this key algorithm combined with the
    /// given digest algorithm.
    ///
    /// Returns an error if the combination is semantically invalid (e.g. ECDSA with a GOST
    /// digest), since the CMS signatureAlgorithm must accurately reflect both the key type
    /// and the hash algorithm used (RFC 5652 §5.4).
    pub fn signature_oid(
        self,
        digest: DigestAlgorithm,
    ) -> Result<const_oid::ObjectIdentifier, CliError> {
        match (self, digest) {
            (Self::Gost3410_2012_256, DigestAlgorithm::Gost3411_2012_256) => {
                Ok(OID_GOST3410_2012_256_WITH_GOST3411_2012_256)
            }
            (Self::Gost3410_2012_512, DigestAlgorithm::Gost3411_2012_512) => {
                Ok(OID_GOST3410_2012_512_WITH_GOST3411_2012_512)
            }
            (Self::Ecdsa, DigestAlgorithm::Sha256) => Ok(OID_ECDSA_WITH_SHA256),
            (Self::Ecdsa, DigestAlgorithm::Sha384) => Ok(OID_ECDSA_WITH_SHA384),
            (Self::Ecdsa, DigestAlgorithm::Sha512) => Ok(OID_ECDSA_WITH_SHA512),
            (Self::Rsa, DigestAlgorithm::Sha256) => Ok(OID_SHA256_WITH_RSA),
            (Self::Rsa, DigestAlgorithm::Sha384) => Ok(OID_SHA384_WITH_RSA),
            (Self::Rsa, DigestAlgorithm::Sha512) => Ok(OID_SHA512_WITH_RSA),
            (key_alg, digest_alg) => Err(CliError::Usage(format!(
                "--key-algorithm {} is not compatible with --digest {}; \
                 the signature algorithm OID must accurately reflect both the key type \
                 and the hash algorithm\n\n{}",
                key_alg.cli_name(),
                digest_alg.cli_name(),
                usage()
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Pkcs11,
    Ccid,
}

impl Transport {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "pkcs11" => Ok(Self::Pkcs11),
            "ccid" => Ok(Self::Ccid),
            _ => Err(CliError::Usage(format!(
                "unsupported --transport {value}; expected pkcs11 or ccid\n\n{}",
                usage()
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pkcs11 => "pkcs11",
            Self::Ccid => "ccid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignCommand {
    pub input: PathBuf,
    pub output: PathBuf,
    pub cert: PathBuf,
    pub key_uri: String,
    pub digest: DigestAlgorithm,
    pub key_algorithm: KeyAlgorithm,
    pub transport: Transport,
    pub pkcs11_module: Option<PathBuf>,
    pub pin_env: Option<String>,
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
    pub embed_content: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcidProbeCommand {
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcidRawSignCommand {
    pub input: PathBuf,
    pub output: PathBuf,
    pub key_uri: String,
    pub digest: DigestAlgorithm,
    pub key_algorithm: KeyAlgorithm,
    pub pin_env: String,
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcidReadCertCommand {
    pub output: PathBuf,
    pub key_uri: String,
    pub pin_env: Option<String>,
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GosuslugiBridgeCommand {
    pub bind: String,
    pub cert: Option<PathBuf>,
    pub cert_record: Option<PathBuf>,
    pub key_uri: String,
    pub digest: DigestAlgorithm,
    pub key_algorithm: KeyAlgorithm,
    pub pin_env: String,
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
}

/// Live mutual-auth GOST TLS 1.2 login (cipher suite 0xFF85) over a token.
///
/// Connects to `host:port`, runs the full handshake via
/// [`gost_login::run_login`], using the Rutoken for the VKO key agreement and
/// the `CertificateVerify` signature, then sends one HTTP request over the
/// established channel and prints the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GostLoginCommand {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub key_uri: String,
    pub pin_env: String,
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
    /// Card-reported VKO mechanism/paramset byte for the target key.
    pub vko_algo: u8,
    /// Treat the certificate's stored public point as little-endian per
    /// coordinate (reverse each 32-byte half to big-endian `X‖Y` before the
    /// token VKO). RFC 4491 stores GOST coordinates little-endian, but the exact
    /// order the token expects has no offline oracle, so it is selectable.
    pub peer_key_little_endian: bool,
    /// HTTP request target path (e.g. `/`); used to build a minimal GET.
    pub request_path: String,
    /// Optional client leaf certificate (DER) loaded from a file instead of
    /// reading it off the token. The signing key on the token still produces the
    /// CertificateVerify signature; only the certificate bytes come from here.
    pub client_cert: Option<PathBuf>,
}

/// `gost-bridge`: a local HTTP reverse proxy in front of a GOST mutual-TLS
/// endpoint (suite 0xFF85). The browser talks plain HTTP to `bind`; each request
/// triggers a fresh token-authenticated GOST handshake to `host:port`, the
/// request is replayed upstream, and the rewritten response is returned. A
/// server-side cookie jar keeps the authenticated session (`PHPSESSID`) alive
/// across the short-lived upstream connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GostBridgeCommand {
    /// Local address to listen on for the browser, e.g. `127.0.0.1:18888`.
    pub bind: String,
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub key_uri: String,
    pub pin_env: String,
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
    /// Optional client leaf certificate (DER) from a file instead of the token.
    pub client_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    Message(String),
    Usage(String),
}

impl CliError {
    pub fn is_usage(&self) -> bool {
        matches!(self, Self::Usage(_))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) | Self::Usage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CliError {}

pub fn run_cli<I>(args: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    match args.next() {
        None => Err(CliError::Usage(usage())),
        Some(command) if command == "--help" || command == "-h" || command == "help" => Ok(usage()),
        Some(command) if command == "sign" => {
            let sign_command = SignCommand::parse(args)?;
            sign_command.run()
        }
        Some(command) if command == "ccid-probe" => {
            let command = CcidProbeCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "ccid-apdu" => {
            let command = CcidApduCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "ccid-sign-raw" => {
            let command = CcidRawSignCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "ccid-read-cert" => {
            let command = CcidReadCertCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "gosuslugi-bridge" => {
            let command = GosuslugiBridgeCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "tls-probe" => {
            let command = TlsProbeCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "gost-login" => {
            let command = GostLoginCommand::parse(args)?;
            command.run()
        }
        Some(command) if command == "gost-bridge" => {
            let command = GostBridgeCommand::parse(args)?;
            command.run()
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown command: {}\n\n{}",
            command.to_string_lossy(),
            usage()
        ))),
    }
}

impl GosuslugiBridgeCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut bind = String::from("127.0.0.1:18765");
        let mut cert = None;
        let mut cert_record = None;
        let mut key_uri = None;
        let mut digest = DigestAlgorithm::Gost3411_2012_256;
        let mut key_algorithm_override: Option<KeyAlgorithm> = None;
        let mut pin_env = None;
        let mut ccid_reader = None;
        let mut exchange_log = None;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--bind" => bind = next_value(&mut iter, "--bind")?.to_string_lossy().into(),
                "--cert" => cert = Some(PathBuf::from(next_value(&mut iter, "--cert")?)),
                "--cert-record" => {
                    cert_record = Some(PathBuf::from(next_value(&mut iter, "--cert-record")?))
                }
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--digest" => {
                    digest = DigestAlgorithm::parse(
                        next_value(&mut iter, "--digest")?
                            .to_string_lossy()
                            .as_ref(),
                    )?
                }
                "--key-algorithm" => {
                    key_algorithm_override = Some(KeyAlgorithm::parse(
                        next_value(&mut iter, "--key-algorithm")?
                            .to_string_lossy()
                            .as_ref(),
                    )?)
                }
                "--pin-env" => {
                    pin_env = Some(
                        next_value(&mut iter, "--pin-env")?
                            .to_string_lossy()
                            .into_owned(),
                    )
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                flag => {
                    return Err(CliError::Usage(format!(
                        "unknown option: {flag}\n\n{}",
                        usage()
                    )));
                }
            }
        }

        let key_algorithm =
            key_algorithm_override.unwrap_or_else(|| KeyAlgorithm::default_for_digest(digest));
        let command = Self {
            bind,
            cert,
            cert_record,
            key_uri: required_string(key_uri, "--key-uri")?,
            digest,
            key_algorithm,
            pin_env: required_string(pin_env, "--pin-env")?,
            ccid_reader,
            exchange_log,
        };
        command.validate()?;
        Ok(command)
    }

    fn validate(&self) -> Result<(), CliError> {
        if let Some(cert) = &self.cert {
            ensure_file_exists(cert, "--cert")?;
        }
        if let Some(cert_record) = &self.cert_record {
            ensure_file_exists(cert_record, "--cert-record")?;
        }
        if self.cert.is_some() && self.cert_record.is_some() {
            return Err(CliError::Usage(
                String::from("use either --cert or --cert-record, not both\n\n") + &usage(),
            ));
        }
        rutoken::RutokenUri::parse(&self.key_uri)?;
        match (self.digest, self.key_algorithm) {
            (DigestAlgorithm::Gost3411_2012_256, KeyAlgorithm::Gost3410_2012_256)
            | (DigestAlgorithm::Gost3411_2012_512, KeyAlgorithm::Gost3410_2012_512) => Ok(()),
            _ => Err(CliError::Usage(
                String::from(
                    "gosuslugi-bridge currently supports only Rutoken GOST signing; use --digest \
                     gost12-256/512 with the matching --key-algorithm \
                     gost3410-2012-256/512\n\n",
                ) + &usage(),
            )),
        }
    }

    pub fn run(&self) -> Result<String, CliError> {
        let signer = token::CcidSignerConfig::new(
            self.ccid_reader.clone(),
            self.key_uri.clone(),
            Some(self.pin_env.clone()),
            self.key_algorithm,
            self.exchange_log.clone(),
        );
        let (certificate, certificate_der) = if let Some(cert) = &self.cert {
            let certificate_der = fs::read(cert).map_err(|error| {
                CliError::Message(format!("failed to read --cert {}: {error}", cert.display()))
            })?;
            let certificate = gosuslugi_bridge::certificate_record_from_der(
                &certificate_der,
                self.key_uri.clone(),
            )?;
            (certificate, Some(certificate_der))
        } else if let Some(cert_record) = &self.cert_record {
            let record_json = fs::read(cert_record).map_err(|error| {
                CliError::Message(format!(
                    "failed to read --cert-record {}: {error}",
                    cert_record.display()
                ))
            })?;
            let certificate: gosuslugi_bridge::CertificateRecord =
                serde_json::from_slice(&record_json).map_err(|error| {
                    CliError::Message(format!(
                        "failed to parse --cert-record {}: {error}",
                        cert_record.display()
                    ))
                })?;
            let certificate_der = gosuslugi_bridge::certificate_der_from_record_raw(&certificate)?;
            (certificate, certificate_der)
        } else {
            let certificate_der = token::read_certificate_der(&signer)?;
            let certificate = gosuslugi_bridge::certificate_record_from_der(
                &certificate_der,
                self.key_uri.clone(),
            )?;
            (certificate, Some(certificate_der))
        };
        gosuslugi_bridge::serve(gosuslugi_bridge::BridgeConfig {
            bind: self.bind.clone(),
            certificate,
            certificate_der,
            signer,
            digest_algorithm: self.digest,
            key_algorithm: self.key_algorithm,
        })?;
        Ok(String::new())
    }
}

impl CcidReadCertCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut output = None;
        let mut key_uri = None;
        let mut pin_env = None;
        let mut ccid_reader = None;
        let mut exchange_log = None;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--output" => output = Some(PathBuf::from(next_value(&mut iter, "--output")?)),
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--pin-env" => {
                    pin_env = Some(
                        next_value(&mut iter, "--pin-env")?
                            .to_string_lossy()
                            .into_owned(),
                    )
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                flag => {
                    return Err(CliError::Usage(format!(
                        "unknown option: {flag}\n\n{}",
                        usage()
                    )));
                }
            }
        }

        let command = Self {
            output: required_path(output, "--output")?,
            key_uri: required_string(key_uri, "--key-uri")?,
            pin_env,
            ccid_reader,
            exchange_log,
        };
        command.validate()?;
        Ok(command)
    }

    fn validate(&self) -> Result<(), CliError> {
        ensure_parent_exists(&self.output, "--output")?;
        rutoken::RutokenUri::parse(&self.key_uri)?;
        Ok(())
    }

    pub fn run(&self) -> Result<String, CliError> {
        let signer = token::CcidSignerConfig::new(
            self.ccid_reader.clone(),
            self.key_uri.clone(),
            self.pin_env.clone(),
            KeyAlgorithm::Gost3410_2012_256,
            self.exchange_log.clone(),
        );
        let certificate_der = token::read_certificate_der(&signer)?;
        let certificate =
            gosuslugi_bridge::certificate_record_from_der(&certificate_der, self.key_uri.clone())?;
        fs::write(&self.output, certificate_der).map_err(|error| {
            CliError::Message(format!(
                "failed to write --output {}: {error}",
                self.output.display()
            ))
        })?;
        Ok(format!(
            "wrote Rutoken certificate to {}\nserial_number={}\nsubject={}",
            self.output.display(),
            certificate.serial_number,
            certificate.subject
        ))
    }
}

impl SignCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut input = None;
        let mut output = None;
        let mut cert = None;
        let mut key_uri = None;
        let mut digest = DigestAlgorithm::Gost3411_2012_256;
        let mut key_algorithm_override: Option<KeyAlgorithm> = None;
        let mut transport = Transport::Pkcs11;
        let mut pkcs11_module = None;
        let mut pin_env = None;
        let mut ccid_reader = None;
        let mut exchange_log = None;
        let mut embed_content = false;
        let mut dry_run = false;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--input" => input = Some(PathBuf::from(next_value(&mut iter, "--input")?)),
                "--output" => output = Some(PathBuf::from(next_value(&mut iter, "--output")?)),
                "--cert" => cert = Some(PathBuf::from(next_value(&mut iter, "--cert")?)),
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--digest" => {
                    digest = DigestAlgorithm::parse(
                        next_value(&mut iter, "--digest")?
                            .to_string_lossy()
                            .as_ref(),
                    )?
                }
                "--key-algorithm" => {
                    key_algorithm_override = Some(KeyAlgorithm::parse(
                        next_value(&mut iter, "--key-algorithm")?
                            .to_string_lossy()
                            .as_ref(),
                    )?)
                }
                "--transport" => {
                    transport = Transport::parse(
                        next_value(&mut iter, "--transport")?
                            .to_string_lossy()
                            .as_ref(),
                    )?
                }
                "--pkcs11-module" => {
                    pkcs11_module = Some(PathBuf::from(next_value(&mut iter, "--pkcs11-module")?))
                }
                "--pin-env" => {
                    let name = next_value(&mut iter, "--pin-env")?
                        .to_string_lossy()
                        .into_owned();
                    pin_env = Some(name);
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--embed-content" => embed_content = true,
                "--dry-run" => dry_run = true,
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                flag => {
                    return Err(CliError::Usage(format!(
                        "unknown option: {flag}\n\n{}",
                        usage()
                    )));
                }
            }
        }

        let key_algorithm =
            key_algorithm_override.unwrap_or_else(|| KeyAlgorithm::default_for_digest(digest));

        let command = Self {
            input: required_path(input, "--input")?,
            output: required_path(output, "--output")?,
            cert: required_path(cert, "--cert")?,
            key_uri: required_string(key_uri, "--key-uri")?,
            digest,
            key_algorithm,
            transport,
            pkcs11_module,
            pin_env,
            ccid_reader,
            exchange_log,
            embed_content,
            dry_run,
        };

        command.validate()?;
        Ok(command)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        ensure_file_exists(&self.input, "--input")?;
        ensure_parent_exists(&self.output, "--output")?;
        ensure_file_exists(&self.cert, "--cert")?;

        if self.key_uri.trim().is_empty() {
            return Err(CliError::Usage(
                String::from("--key-uri must not be empty\n\n") + &usage(),
            ));
        }

        self.key_algorithm.signature_oid(self.digest)?;

        match self.transport {
            Transport::Pkcs11 => {
                let Some(module) = &self.pkcs11_module else {
                    return Err(CliError::Usage(
                        String::from("--pkcs11-module is required for --transport pkcs11\n\n")
                            + &usage(),
                    ));
                };
                token::ensure_module_path(module)?;
                if !self.dry_run && self.pin_env.is_none() {
                    return Err(CliError::Usage(
                        String::from("--pin-env is required for live PKCS#11 signing\n\n")
                            + &usage(),
                    ));
                }
            }
            Transport::Ccid => {
                rutoken::RutokenUri::parse(&self.key_uri)?;
                match (self.digest, self.key_algorithm) {
                    (DigestAlgorithm::Gost3411_2012_256, KeyAlgorithm::Gost3410_2012_256)
                    | (DigestAlgorithm::Gost3411_2012_512, KeyAlgorithm::Gost3410_2012_512) => {}
                    _ => {
                        return Err(CliError::Usage(
                            String::from(
                                "--transport ccid currently supports only Rutoken GOST signing; \
                                 use --digest gost12-256/512 with the matching \
                                 --key-algorithm gost3410-2012-256/512\n\n",
                            ) + &usage(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn run(&self) -> Result<String, CliError> {
        let document = fs::read(&self.input).map_err(|error| {
            CliError::Message(format!(
                "failed to read --input {}: {error}",
                self.input.display()
            ))
        })?;
        let certificate = fs::read(&self.cert).map_err(|error| {
            CliError::Message(format!(
                "failed to read --cert {}: {error}",
                self.cert.display()
            ))
        })?;
        let digest = compute_digest(&document, self.digest);
        let cms_input = cms_envelope::CmsSigningInput::new(
            digest.clone(),
            self.digest,
            self.key_algorithm,
            certificate,
            !self.embed_content,
        );
        cms_input.validate()?;
        let (signed_attrs, signed_attrs_der) = cms_envelope::prepare_signed_attributes(&cms_input)?;
        let signed_attrs_digest = compute_digest(&signed_attrs_der, self.digest);

        if self.dry_run {
            return Ok(self.render_plan(&digest));
        }

        let signature = match self.transport {
            Transport::Pkcs11 => {
                let signer = token::Pkcs11SignerConfig::new(
                    self.pkcs11_module.clone().expect("validated module"),
                    self.key_uri.clone(),
                    self.pin_env.clone(),
                    self.key_algorithm,
                );
                token::TokenSigner::sign_digest(&signer, self.digest, &signed_attrs_digest)
            }
            Transport::Ccid => {
                let signer = token::CcidSignerConfig::new(
                    self.ccid_reader.clone(),
                    self.key_uri.clone(),
                    self.pin_env.clone(),
                    self.key_algorithm,
                    self.exchange_log.clone(),
                );
                token::TokenSigner::sign_digest(&signer, self.digest, &signed_attrs_digest)
            }
        }?;
        let cms_der =
            cms_envelope::build_signed_data_der(&cms_input, &document, signature, signed_attrs)?;
        fs::write(&self.output, cms_der).map_err(|error| {
            CliError::Message(format!(
                "failed to write --output {}: {error}",
                self.output.display()
            ))
        })?;
        Ok(format!("wrote CMS signature to {}", self.output.display()))
    }

    pub fn render_plan(&self, digest: &[u8]) -> String {
        let mut lines = vec![
            "native signing plan".to_string(),
            format!("input={}", self.input.display()),
            format!("output={}", self.output.display()),
            format!("cert={}", self.cert.display()),
            format!("transport={}", self.transport.name()),
            format!("key_uri={}", self.key_uri),
            format!("digest_algorithm={}", self.digest.cli_name()),
            format!("key_algorithm={}", self.key_algorithm.cli_name()),
            format!("digest_hex={}", hex_encode(digest)),
            format!("cms_backend={}", cms_envelope::cms_crate_backend()),
        ];

        match self.transport {
            Transport::Pkcs11 => {
                lines.push(format!("pkcs11_backend={}", token::pkcs11_crate_backend()));
                if let Some(module) = &self.pkcs11_module {
                    lines.push(format!("pkcs11_module={}", module.display()));
                }
            }
            Transport::Ccid => {
                if let Some(reader) = &self.ccid_reader {
                    lines.push(format!("ccid_reader={reader}"));
                }
                if let Some(exchange_log) = &self.exchange_log {
                    lines.push(format!("exchange_log={}", exchange_log.display()));
                }
            }
        }

        if self.embed_content {
            lines.push("cms_content=attached".to_string());
        } else {
            lines.push("cms_content=detached".to_string());
        }

        lines.join("\n")
    }
}

impl CcidProbeCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut ccid_reader = None;
        let mut exchange_log = None;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                flag => {
                    return Err(CliError::Usage(format!(
                        "unknown option: {flag}\n\n{}",
                        usage()
                    )));
                }
            }
        }

        Ok(Self {
            ccid_reader,
            exchange_log,
        })
    }

    pub fn run(&self) -> Result<String, CliError> {
        self.run_direct()
    }

    fn run_direct(&self) -> Result<String, CliError> {
        let mut device = ccid::CcidDevice::open_with_exchange_log(
            self.ccid_reader.as_deref(),
            self.exchange_log.as_deref(),
        )?;
        let atr = device.power_on()?;
        let select = device.transmit(&rutoken::select_master_file())?;

        let mut lines = vec![
            "ccid probe".to_string(),
            format!("atr_hex={}", hex_encode(&atr)),
            format!("select_mf_sw={:02x}{:02x}", select.sw1, select.sw2),
        ];
        if let Some(path) = device.exchange_log_path() {
            lines.push(format!("exchange_log={}", path.display()));
        }
        Ok(lines.join("\n"))
    }
}

/// Diagnostic: send raw APDUs to the token and print each response (SW + data).
/// Used to walk a token's real PKCS#15 directory when the fixed cert-scan paths
/// miss the certificate (e.g. a Контур-issued Rutoken whose Cer-DF isn't 6004).
pub struct CcidApduCommand {
    pub ccid_reader: Option<String>,
    pub exchange_log: Option<PathBuf>,
    pub pin_env: Option<String>,
    pub apdus: Vec<String>,
}

impl CcidApduCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut ccid_reader = None;
        let mut exchange_log = None;
        let mut pin_env = None;
        let mut apdus = Vec::new();
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--ccid-reader" => {
                    ccid_reader =
                        Some(next_value(&mut iter, "--ccid-reader")?.to_string_lossy().into())
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--pin-env" => {
                    pin_env = Some(next_value(&mut iter, "--pin-env")?.to_string_lossy().into_owned())
                }
                "--apdu" => {
                    apdus.push(next_value(&mut iter, "--apdu")?.to_string_lossy().into_owned())
                }
                other => return Err(CliError::Usage(format!("unknown option: {other}"))),
            }
        }
        Ok(Self {
            ccid_reader,
            exchange_log,
            pin_env,
            apdus,
        })
    }

    pub fn run(&self) -> Result<String, CliError> {
        let mut device = ccid::CcidDevice::open_with_exchange_log(
            self.ccid_reader.as_deref(),
            self.exchange_log.as_deref(),
        )?;
        let atr = device.power_on()?;
        let mut lines = vec![format!("atr_hex={}", hex_encode(&atr))];
        if let Some(env) = &self.pin_env {
            let pin = std::env::var(env)
                .map_err(|_| CliError::Message(format!("PIN env var {env} not set")))?;
            let _ = device.transmit(&rutoken::select_master_file())?;
            let mut resp = device.transmit(&rutoken::verify_pin(pin.as_bytes()))?;
            if resp.sw1 == 0x6F && resp.sw2 == 0x86 {
                let _ = device.transmit(&rutoken::logout())?;
                resp = device.transmit(&rutoken::verify_pin(pin.as_bytes()))?;
            }
            lines.push(format!("verify_pin_sw={:02x}{:02x}", resp.sw1, resp.sw2));
        }
        for h in &self.apdus {
            let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
            if clean.len() % 2 != 0 {
                return Err(CliError::Message(format!("odd-length apdu hex: {h}")));
            }
            let raw = (0..clean.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|e| CliError::Message(format!("bad apdu hex {h}: {e}")))?;
            if raw.len() < 4 {
                return Err(CliError::Message(format!("apdu too short: {h}")));
            }
            let mut cmd = apdu::CommandApdu::new(raw[0], raw[1], raw[2], raw[3]);
            if raw.len() == 5 {
                cmd = cmd.with_le(raw[4]);
            } else if raw.len() > 5 {
                let lc = raw[4] as usize;
                let data_end = 5 + lc;
                if data_end <= raw.len() {
                    cmd = cmd.with_data(raw[5..data_end].to_vec());
                    if raw.len() == data_end + 1 {
                        cmd = cmd.with_le(raw[data_end]);
                    }
                }
            }
            let resp = device.transmit(&cmd)?;
            lines.push(format!(
                "> {h}\n< sw={:02x}{:02x} len={} data={}",
                resp.sw1,
                resp.sw2,
                resp.data.len(),
                hex_encode(&resp.data)
            ));
        }
        Ok(lines.join("\n"))
    }
}

impl CcidRawSignCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut input = None;
        let mut output = None;
        let mut key_uri = None;
        let mut digest = DigestAlgorithm::Gost3411_2012_256;
        let mut key_algorithm_override: Option<KeyAlgorithm> = None;
        let mut pin_env = None;
        let mut ccid_reader = None;
        let mut exchange_log = None;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--input" => input = Some(PathBuf::from(next_value(&mut iter, "--input")?)),
                "--output" => output = Some(PathBuf::from(next_value(&mut iter, "--output")?)),
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--digest" => {
                    digest = DigestAlgorithm::parse(
                        next_value(&mut iter, "--digest")?
                            .to_string_lossy()
                            .as_ref(),
                    )?
                }
                "--key-algorithm" => {
                    key_algorithm_override = Some(KeyAlgorithm::parse(
                        next_value(&mut iter, "--key-algorithm")?
                            .to_string_lossy()
                            .as_ref(),
                    )?)
                }
                "--pin-env" => {
                    pin_env = Some(
                        next_value(&mut iter, "--pin-env")?
                            .to_string_lossy()
                            .into_owned(),
                    )
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                flag => {
                    return Err(CliError::Usage(format!(
                        "unknown option: {flag}\n\n{}",
                        usage()
                    )));
                }
            }
        }

        let key_algorithm =
            key_algorithm_override.unwrap_or_else(|| KeyAlgorithm::default_for_digest(digest));
        let command = Self {
            input: required_path(input, "--input")?,
            output: required_path(output, "--output")?,
            key_uri: required_string(key_uri, "--key-uri")?,
            digest,
            key_algorithm,
            pin_env: required_string(pin_env, "--pin-env")?,
            ccid_reader,
            exchange_log,
        };
        command.validate()?;
        Ok(command)
    }

    fn validate(&self) -> Result<(), CliError> {
        ensure_file_exists(&self.input, "--input")?;
        ensure_parent_exists(&self.output, "--output")?;
        rutoken::RutokenUri::parse(&self.key_uri)?;
        match (self.digest, self.key_algorithm) {
            (DigestAlgorithm::Gost3411_2012_256, KeyAlgorithm::Gost3410_2012_256)
            | (DigestAlgorithm::Gost3411_2012_512, KeyAlgorithm::Gost3410_2012_512) => Ok(()),
            _ => Err(CliError::Usage(
                String::from(
                    "ccid-sign-raw supports only Rutoken GOST signing; use --digest \
                     gost12-256/512 with the matching --key-algorithm \
                     gost3410-2012-256/512\n\n",
                ) + &usage(),
            )),
        }
    }

    pub fn run(&self) -> Result<String, CliError> {
        let document = fs::read(&self.input).map_err(|error| {
            CliError::Message(format!(
                "failed to read --input {}: {error}",
                self.input.display()
            ))
        })?;
        let digest = compute_digest(&document, self.digest);
        let signer = token::CcidSignerConfig::new(
            self.ccid_reader.clone(),
            self.key_uri.clone(),
            Some(self.pin_env.clone()),
            self.key_algorithm,
            self.exchange_log.clone(),
        );
        let signature = token::TokenSigner::sign_digest(&signer, self.digest, &digest)?;
        fs::write(&self.output, &signature).map_err(|error| {
            CliError::Message(format!(
                "failed to write --output {}: {error}",
                self.output.display()
            ))
        })?;

        let mut lines = vec![
            format!("wrote raw signature to {}", self.output.display()),
            format!("digest_algorithm={}", self.digest.cli_name()),
            format!("digest_hex={}", hex_encode(&digest)),
            format!("signature_len={}", signature.len()),
        ];
        if let Some(exchange_log) = &self.exchange_log {
            lines.push(format!("exchange_log={}", exchange_log.display()));
        }
        Ok(lines.join("\n"))
    }
}

fn next_value<I>(iter: &mut I, flag: &str) -> Result<OsString, CliError>
where
    I: Iterator<Item = OsString>,
{
    iter.next()
        .ok_or_else(|| CliError::Usage(format!("missing value for {flag}\n\n{}", usage())))
}

fn required_path(value: Option<PathBuf>, flag: &str) -> Result<PathBuf, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required option {flag}\n\n{}", usage())))
}

fn required_string(value: Option<String>, flag: &str) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required option {flag}\n\n{}", usage())))
}

fn ensure_file_exists(path: &Path, flag: &str) -> Result<(), CliError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(CliError::Message(format!(
            "{flag} must reference a file: {}",
            path.display()
        ))),
        Err(_) => Err(CliError::Message(format!(
            "{flag} does not exist: {}",
            path.display()
        ))),
    }
}

fn ensure_parent_exists(path: &Path, flag: &str) -> Result<(), CliError> {
    match path.parent() {
        None => Ok(()),
        Some(parent) if parent.as_os_str().is_empty() => Ok(()),
        Some(parent) if parent.exists() => Ok(()),
        Some(parent) => Err(CliError::Message(format!(
            "{flag} parent directory does not exist: {}",
            parent.display()
        ))),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    // Keep this tiny diagnostic encoder local instead of adding another dependency.
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Decode a percent-encoded byte string from a PKCS#11 or `rutoken:` URI component.
///
/// Used by both [`token::KeyUriSelector`] (for `pkcs11:` URIs) and
/// [`rutoken::RutokenUri`] (for `rutoken:` URIs).
fn percent_decode_bytes(value: &str) -> Result<Vec<u8>, CliError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(CliError::Usage(format!(
                    "incomplete percent escape at end of URI value: {value}"
                )));
            }
            let high = hex_nibble(bytes[index + 1]).ok_or_else(|| {
                CliError::Usage(format!(
                    "invalid hex character '{}' in percent escape in URI value: {value}",
                    bytes[index + 1] as char
                ))
            })?;
            let low = hex_nibble(bytes[index + 2]).ok_or_else(|| {
                CliError::Usage(format!(
                    "invalid hex character '{}' in percent escape in URI value: {value}",
                    bytes[index + 2] as char
                ))
            })?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct TlsProbeCommand {
    host: String,
    port: u16,
    timeout_secs: u64,
}

impl TlsProbeCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut host: Option<String> = None;
        let mut port: u16 = 443;
        let mut timeout_secs: u64 = 10;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg.to_string_lossy().into_owned();
            match arg.as_str() {
                "--host" => {
                    host = Some(
                        args.next()
                            .ok_or_else(|| CliError::Usage("--host requires a value".into()))?
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                "--port" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::Usage("--port requires a value".into()))?
                        .to_string_lossy()
                        .into_owned();
                    port = value
                        .parse()
                        .map_err(|_| CliError::Usage(format!("invalid --port: {value}")))?;
                }
                "--timeout" => {
                    let value = args
                        .next()
                        .ok_or_else(|| CliError::Usage("--timeout requires a value".into()))?
                        .to_string_lossy()
                        .into_owned();
                    timeout_secs = value
                        .parse()
                        .map_err(|_| CliError::Usage(format!("invalid --timeout: {value}")))?;
                }
                other => {
                    return Err(CliError::Usage(format!(
                        "unknown tls-probe option: {other}"
                    )));
                }
            }
        }

        let host = host.ok_or_else(|| CliError::Usage("tls-probe requires --host".into()))?;
        Ok(Self {
            host,
            port,
            timeout_secs,
        })
    }

    fn run(&self) -> Result<String, CliError> {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        use tls::{ClientHello, TlsTransport, cipher_suite};

        // ClientHello.random: 4-byte gmt_unix_time + 28 nonce bytes. Without a
        // CSPRNG dependency, derive deterministic-but-unique nonce bytes from the
        // clock; this is sufficient for a probe (the secure handshake stage will
        // supply real entropy).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CliError::Message(format!("clock error: {e}")))?;
        let mut random = [0u8; 32];
        random[..4].copy_from_slice(&(now.as_secs() as u32).to_be_bytes());
        let nanos = now.subsec_nanos() as u64 ^ (now.as_secs().wrapping_mul(0x9E3779B97F4A7C15));
        for (i, slot) in random[4..].iter_mut().enumerate() {
            *slot = (nanos.rotate_left((i as u32) * 7) & 0xFF) as u8;
        }

        let hello = ClientHello::new_gost(self.host.clone(), random);
        let mut transport = TlsTransport::connect(
            &self.host,
            self.port,
            Duration::from_secs(self.timeout_secs),
        )?;
        let flight = transport.opening_handshake(&hello)?;

        let suite_name = match flight.server_hello.cipher_suite {
            cipher_suite::GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC => {
                "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"
            }
            cipher_suite::GOSTR341112_256_WITH_MAGMA_CTR_OMAC => {
                "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"
            }
            cipher_suite::GOSTR341112_256_WITH_28147_CNT_IMIT => {
                "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
            }
            cipher_suite::LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT => {
                "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT (legacy 0xFF85)"
            }
            cipher_suite::LEGACY_GOSTR341001_WITH_28147_CNT_IMIT => {
                "TLS_GOSTR341001_WITH_28147_CNT_IMIT (legacy)"
            }
            other => {
                return Ok(format!(
                    "connected to {}:{} — server negotiated NON-GOST suite 0x{other:04X}; \
                     server may not be a GOST endpoint or requires a different ClientHello",
                    self.host, self.port
                ));
            }
        };

        let mut out = String::new();
        let _ = writeln!(
            out,
            "GOST TLS handshake reached ServerHelloDone with {}:{}",
            self.host, self.port
        );
        let version_name = match (
            flight.server_hello.server_version.0,
            flight.server_hello.server_version.1,
        ) {
            (3, 3) => "1.2",
            (3, 2) => "1.1",
            (3, 1) => "1.0",
            _ => "unknown",
        };
        let _ = writeln!(
            out,
            "  negotiated version: TLS {} ({}.{})",
            version_name,
            flight.server_hello.server_version.0,
            flight.server_hello.server_version.1
        );
        let _ = writeln!(
            out,
            "  negotiated suite:   0x{:04X} {}",
            flight.server_hello.cipher_suite, suite_name
        );
        let _ = writeln!(
            out,
            "  certificates:       {} in chain",
            flight.certificates.len()
        );
        if let Some(leaf) = flight.certificates.first() {
            let _ = writeln!(out, "  leaf cert size:     {} bytes (DER)", leaf.len());
        }
        let _ = writeln!(
            out,
            "  ServerKeyExchange:  {}",
            if flight.server_key_exchange.is_some() {
                "present"
            } else {
                "absent"
            }
        );
        let _ = writeln!(
            out,
            "  CertificateRequest: {}",
            if flight.certificate_request.is_some() {
                "present (mutual TLS — client cert needed)"
            } else {
                "absent"
            }
        );
        let _ = write!(
            out,
            "  next stage: GOST VKO key exchange + record encryption (token-backed)"
        );
        Ok(out)
    }
}

/// Reorder a GOST R 34.10-2012-256 signature for the RFC 9189 §4.2.5
/// CertificateVerify `digitally-signed` block, where `sgn = str_l(r) | str_l(s)`
/// (little-endian r, then little-endian s).
///
/// The input is the CMS-order signature returned by the token signer (a full
/// byte-reverse of the card's native PSO output). The exact mapping is selected
/// by the `GOST_TLS_SIG_ORDER` environment variable so it can be confirmed
/// against the live server:
/// - `rev` (default): reverse the whole value (native card order)
/// - `asis`: pass the CMS value through unchanged
/// - `swap`: swap the two 32-byte halves
/// - `revhalves`: reverse each 32-byte half independently
fn tls_certificate_verify_signature(cms: Vec<u8>) -> Vec<u8> {
    let mode = std::env::var("GOST_TLS_SIG_ORDER").unwrap_or_else(|_| "rev".to_string());
    if cms.len() != 64 {
        // Unexpected length: leave untouched.
        return cms;
    }
    match mode.as_str() {
        "asis" => cms,
        "swap" => {
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&cms[32..64]);
            out.extend_from_slice(&cms[0..32]);
            out
        }
        "revhalves" => {
            let mut out = Vec::with_capacity(64);
            out.extend(cms[0..32].iter().rev().copied());
            out.extend(cms[32..64].iter().rev().copied());
            out
        }
        // "rev" and anything else: full reverse (= card's native byte order).
        _ => cms.into_iter().rev().collect(),
    }
}

/// Perform one token-authenticated GOST TLS 1.2 (suite 0xFF85) request:
/// connect to `host:port`, run the full mutual-auth handshake with the token
/// signing the `CertificateVerify`, send `request_bytes` as ApplicationData,
/// and drain the complete response. Returns `(response_bytes, server_leaf_len)`.
///
/// Each call is a fresh handshake and re-presents the token PIN, because the
/// upstream closes the connection after every response (`Connection: close`).
fn gost_mtls_request(
    host: &str,
    port: u16,
    timeout_secs: u64,
    signer: &token::CcidSignerConfig,
    client_chain: &[Vec<u8>],
    request_bytes: &[u8],
) -> Result<(Vec<u8>, usize), CliError> {
    use std::time::Duration;
    use tls::{TlsTransport, cipher_suite};

    let entropy = read_os_random(64)?;
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&entropy[..32]);
    let mut premaster = [0u8; 32];
    premaster.copy_from_slice(&entropy[32..]);

    let mut transport = TlsTransport::connect(host, port, Duration::from_secs(timeout_secs))?;

    let params = gost_login::LoginParams {
        server_name: host,
        client_random,
        premaster,
        client_cert_chain: client_chain,
        cipher_suites: &[cipher_suite::LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT],
    };

    let mut session = gost_login::run_login(
        &mut transport,
        &params,
        |buf| getrandom::getrandom(buf).map_err(|e| e.to_string()),
        |digest| {
            use token::TokenSigner as _;
            let sig = signer
                .sign_digest(DigestAlgorithm::Gost3411_2012_256, digest)
                .map_err(|e| e.to_string())?;
            Ok(tls_certificate_verify_signature(sig))
        },
    )
    .map_err(|e| CliError::Message(format!("gost-mtls handshake failed: {e}")))?;

    let leaf_len = session.server_leaf_cert().len();

    session
        .send_application_data(&mut transport, request_bytes)
        .map_err(|e| CliError::Message(format!("send request failed: {e}")))?;
    let response = session
        .recv_all_application_data(&mut transport)
        .map_err(|e| CliError::Message(format!("read response failed: {e}")))?;

    Ok((response, leaf_len))
}

/// Sign `content` as a detached CAdES-style CMS SignedData (GOST R 34.10-2012-256
/// + Streebog-256) using the token, returning the base64 of the CMS DER.
///
/// This mirrors `sign_file` but takes raw bytes instead of a base64 document.
/// The signed attributes are the minimal CMS set (contentType + messageDigest);
/// `messageDigest` = Streebog-256(content). Used for the ФНС ЛКЮЛ in-page
/// certificate-login challenge (the content is the UTF-8 bytes of the
/// `challenge` string returned by `GET api/auth/challenge`).
/// Split a browser request target into `(upstream_host, origin_path)`.
///
/// A `/__up/<host>/<path>` target selects an explicit upstream host (how the
/// bridge reaches the cabinet's sibling hosts, e.g. `mf-lk.nalog.ru`, after
/// their absolute URLs are rewritten into this form); any other target uses the
/// default host unchanged.
fn route_upstream(target: &str, default_host: &str) -> (String, String) {
    if let Some(rest) = target.strip_prefix("/__up/") {
        let slash = rest.find('/').unwrap_or(rest.len());
        let host = rest[..slash].to_string();
        let path = if slash < rest.len() {
            rest[slash..].to_string()
        } else {
            "/".to_string()
        };
        (host, path)
    } else {
        (default_host.to_string(), target.to_string())
    }
}

/// Only ФНС hosts may be proxied, so the universal `/__up/` router cannot be
/// turned into an open relay to arbitrary infrastructure.
fn host_allowed(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    h == "nalog.ru" || h.ends_with(".nalog.ru")
}

/// A ФНС "GOST front" is a `*.nalog.ru` host whose leftmost label contains
/// `gost` (e.g. `lkulgost.nalog.ru` for ЛКЮЛ, `lkipgost2.nalog.ru` for ЛК ИП).
/// Only these speak GOST TLS with the token; every other ФНС host
/// (`service.nalog.ru`, `mf-lk.nalog.ru`, `lkip2.nalog.ru`, …) is ordinary TLS.
///
/// Matching by label rather than `ends_with("gost.nalog.ru")` is deliberate:
/// the ИП front is `lkipgost2.nalog.ru`, which ends with `gost2.nalog.ru`, so a
/// plain suffix test would misroute it to plain TLS and the handshake would fail.
fn is_gost_front(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    h.ends_with(".nalog.ru") && h.split('.').next().is_some_and(|label| label.contains("gost"))
}

/// Load a client certificate chain from `path`, leaf first.
///
/// A single DER file yields a one-element chain (the historical behaviour). A
/// PEM file is parsed into one DER entry per `CERTIFICATE` block, in file order
/// — so a `leaf + intermediate(s)` bundle is sent as a proper TLS certificate
/// chain. This is needed for leafs issued by a commercial УЦ (e.g. СКБ Контур
/// for ЛК ИП): the GOST front (`lkipgost2.nalog.ru`) rejects a leaf-only message
/// with `unknown_ca`, whereas a ФНС-issued leaf (ЛКЮЛ) validates on its own.
fn load_client_cert_chain(path: &std::path::Path) -> Result<Vec<Vec<u8>>, CliError> {
    use base64::Engine as _;
    let bytes = fs::read(path)
        .map_err(|e| CliError::Message(format!("read client cert {}: {e}", path.display())))?;
    let is_pem = std::str::from_utf8(&bytes)
        .map(|t| t.contains("-----BEGIN CERTIFICATE-----"))
        .unwrap_or(false);
    if !is_pem {
        return Ok(vec![bytes]);
    }
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(&bytes);
    let mut chain = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else { break };
        let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| {
                CliError::Message(format!("client cert {}: bad base64 in PEM: {e}", path.display()))
            })?;
        chain.push(der);
        rest = &after[end + END.len()..];
    }
    if chain.is_empty() {
        return Err(CliError::Message(format!(
            "client cert {}: no CERTIFICATE blocks found",
            path.display()
        )));
    }
    Ok(chain)
}

/// Origins permitted to invoke the token-signing oracle (`/__bridge/sign`,
/// `/__bridge/cert-info`): the ФНС registration page (when the shim is injected
/// into the natively-loaded `service.nalog.ru` page), the bridge's own origin
/// (proxy / same-origin case), or no `Origin` at all (local curl). Everything
/// else is refused, so a foreign web page cannot drive the УКЭП.
fn sign_origin_allowed(origin: &str, bridge_origin: &str) -> bool {
    if origin.is_empty() || origin == bridge_origin {
        return true;
    }
    // Confine the УКЭП oracle to ФНС pages: any https origin whose host is a
    // nalog.ru or nalog.gov.ru host — the legacy cabinets (service.nalog.ru,
    // *.nalog.ru) and the new unified ЕЛК (elk.nalog.gov.ru). A foreign page's
    // browser-set Origin won't match, so it still cannot drive the token.
    match origin.strip_prefix("https://") {
        Some(rest) => {
            let host = rest.split('/').next().unwrap_or(rest);
            let host = host.split(':').next().unwrap_or(host);
            host == "nalog.ru"
                || host.ends_with(".nalog.ru")
                || host == "nalog.gov.ru"
                || host.ends_with(".nalog.gov.ru")
        }
        None => false,
    }
}

/// `Access-Control-Allow-Origin` header line echoing an allowed `Origin`, or
/// empty when there is none to echo.
fn cors_allow_header(origin: &str) -> String {
    if origin.is_empty() {
        String::new()
    } else {
        format!("Access-Control-Allow-Origin: {origin}\r\n")
    }
}

/// Proxy a request to a *plain-TLS* `*.nalog.ru` backend.
///
/// The cabinet's GOST auth front (`lkulgost.nalog.ru`) speaks GOST TLS with the
/// token; its micro-frontend/API backend (`mf-lk.nalog.ru`) speaks ordinary
/// TLS and authenticates by bearer token (issued by the `elk_sys_idp` service),
/// not a client certificate — so it is reached over a standard TLS connection.
///
/// The backend's certificate is fully verified against the platform trust store
/// (`*.nalog.ru`, issued by GlobalSign), so no verification is weakened.
fn plain_tls_request(
    host: &str,
    port: u16,
    timeout_secs: u64,
    request: &[u8],
) -> Result<Vec<u8>, CliError> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = format!("{host}:{port}");
    let sockaddr = addr
        .to_socket_addrs()
        .map_err(|e| CliError::Message(format!("resolve {addr}: {e}")))?
        .next()
        .ok_or_else(|| CliError::Message(format!("no address for {addr}")))?;
    let timeout = Duration::from_secs(timeout_secs);
    let tcp = TcpStream::connect_timeout(&sockaddr, timeout)
        .map_err(|e| CliError::Message(format!("connect {addr}: {e}")))?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let connector = native_tls::TlsConnector::new()
        .map_err(|e| CliError::Message(format!("tls connector: {e}")))?;
    let mut stream = connector
        .connect(host, tcp)
        .map_err(|e| CliError::Message(format!("plain-tls handshake {host}: {e}")))?;

    stream
        .write_all(request)
        .map_err(|e| CliError::Message(format!("write {host}: {e}")))?;
    let _ = stream.flush();

    // The request forces `Connection: close`, so the server closes the stream
    // after the response and `read_to_end` returns the full bytes. A TLS
    // close without `close_notify` surfaces as an error after the body — keep
    // whatever we already read in that case.
    let mut buf = Vec::new();
    match stream.read_to_end(&mut buf) {
        Ok(_) => {}
        Err(_) if !buf.is_empty() => {}
        Err(e) => return Err(CliError::Message(format!("read {host}: {e}"))),
    }
    Ok(buf)
}

fn sign_detached_cms_b64(
    signer: &token::CcidSignerConfig,
    certificate_der: Vec<u8>,
    content: &[u8],
) -> Result<String, CliError> {
    use base64::Engine as _;

    let digest_algorithm = DigestAlgorithm::Gost3411_2012_256;
    let key_algorithm = KeyAlgorithm::Gost3410_2012_256;
    let digest = compute_digest(content, digest_algorithm);
    let cms_input = cms_envelope::CmsSigningInput::new(
        digest,
        digest_algorithm,
        key_algorithm,
        certificate_der,
        true,
    );
    let (signed_attrs, signed_attrs_der) = cms_envelope::prepare_signed_attributes(&cms_input)?;
    let signed_attrs_digest = compute_digest(&signed_attrs_der, digest_algorithm);
    let signature =
        token::TokenSigner::sign_digest(signer, digest_algorithm, &signed_attrs_digest)?;
    let cms_der =
        cms_envelope::build_signed_data_der(&cms_input, content, signature, signed_attrs)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(cms_der))
}

impl GostLoginCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut host: Option<String> = None;
        let mut port: u16 = 443;
        let mut timeout_secs: u64 = 15;
        let mut key_uri: Option<String> = None;
        let mut pin_env: Option<String> = None;
        let mut ccid_reader: Option<String> = None;
        let mut exchange_log: Option<PathBuf> = None;
        let mut vko_algo: Option<u8> = None;
        let mut peer_key_little_endian = false;
        let mut request_path = String::from("/");
        let mut client_cert: Option<PathBuf> = None;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--host" => host = Some(next_value(&mut iter, "--host")?.to_string_lossy().into()),
                "--port" => {
                    let value = next_value(&mut iter, "--port")?
                        .to_string_lossy()
                        .into_owned();
                    port = value
                        .parse()
                        .map_err(|_| CliError::Usage(format!("invalid --port: {value}")))?;
                }
                "--timeout" => {
                    let value = next_value(&mut iter, "--timeout")?
                        .to_string_lossy()
                        .into_owned();
                    timeout_secs = value
                        .parse()
                        .map_err(|_| CliError::Usage(format!("invalid --timeout: {value}")))?;
                }
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--pin-env" => {
                    pin_env = Some(next_value(&mut iter, "--pin-env")?.to_string_lossy().into())
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--vko-algo" => {
                    let value = next_value(&mut iter, "--vko-algo")?
                        .to_string_lossy()
                        .into_owned();
                    let trimmed = value.strip_prefix("0x").unwrap_or(&value);
                    vko_algo = Some(u8::from_str_radix(trimmed, 16).map_err(|_| {
                        CliError::Usage(format!("invalid --vko-algo (expect hex byte): {value}"))
                    })?);
                }
                "--peer-key-le" => peer_key_little_endian = true,
                "--request-path" => {
                    request_path = next_value(&mut iter, "--request-path")?
                        .to_string_lossy()
                        .into_owned();
                }
                "--client-cert" => {
                    client_cert = Some(PathBuf::from(next_value(&mut iter, "--client-cert")?))
                }
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                other => {
                    return Err(CliError::Usage(format!(
                        "unknown gost-login option: {other}"
                    )));
                }
            }
        }

        let command = Self {
            host: required_string(host, "--host")?,
            port,
            timeout_secs,
            key_uri: required_string(key_uri, "--key-uri")?,
            pin_env: required_string(pin_env, "--pin-env")?,
            ccid_reader,
            exchange_log,
            // `--vko-algo` / `--peer-key-le` are legacy no-ops: the 0xFF85 suite
            // uses a software ephemeral key (RFC 9189), not a token VKO.
            vko_algo: vko_algo.unwrap_or(0),
            peer_key_little_endian,
            request_path,
            client_cert,
        };
        rutoken::RutokenUri::parse(&command.key_uri)?;
        Ok(command)
    }

    fn run(&self) -> Result<String, CliError> {
        let signer = token::CcidSignerConfig::new(
            self.ccid_reader.clone(),
            self.key_uri.clone(),
            Some(self.pin_env.clone()),
            KeyAlgorithm::Gost3410_2012_256,
            self.exchange_log.clone(),
        );

        // Client certificate chain: from a file if given (DER leaf, or a PEM
        // leaf+intermediate bundle), else read the leaf off the token.
        let client_chain = match &self.client_cert {
            Some(path) => load_client_cert_chain(path)?,
            None => vec![token::read_certificate_der(&signer)?],
        };

        // Send a minimal HTTP/1.1 GET over the established channel.
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            self.request_path, self.host
        );
        let (response, leaf_len) = gost_mtls_request(
            &self.host,
            self.port,
            self.timeout_secs,
            &signer,
            &client_chain,
            request.as_bytes(),
        )?;

        let mut out = String::new();
        let _ = writeln!(
            out,
            "GOST TLS 1.2 login to {}:{} succeeded (server Finished verified)",
            self.host, self.port
        );
        let _ = writeln!(out, "  server leaf cert: {leaf_len} bytes (DER)");
        let _ = writeln!(out, "  --- response ({} bytes) ---", response.len());
        let _ = write!(out, "{}", String::from_utf8_lossy(&response));
        Ok(out)
    }
}

impl GostBridgeCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut bind = String::from("127.0.0.1:18888");
        let mut host: Option<String> = None;
        let mut port: u16 = 443;
        let mut timeout_secs: u64 = 15;
        let mut key_uri: Option<String> = None;
        let mut pin_env: Option<String> = None;
        let mut ccid_reader: Option<String> = None;
        let mut exchange_log: Option<PathBuf> = None;
        let mut client_cert: Option<PathBuf> = None;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--bind" => bind = next_value(&mut iter, "--bind")?.to_string_lossy().into(),
                "--host" => host = Some(next_value(&mut iter, "--host")?.to_string_lossy().into()),
                "--port" => {
                    let value = next_value(&mut iter, "--port")?
                        .to_string_lossy()
                        .into_owned();
                    port = value
                        .parse()
                        .map_err(|_| CliError::Usage(format!("invalid --port: {value}")))?;
                }
                "--timeout" => {
                    let value = next_value(&mut iter, "--timeout")?
                        .to_string_lossy()
                        .into_owned();
                    timeout_secs = value
                        .parse()
                        .map_err(|_| CliError::Usage(format!("invalid --timeout: {value}")))?;
                }
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--pin-env" => {
                    pin_env = Some(next_value(&mut iter, "--pin-env")?.to_string_lossy().into())
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--exchange-log" => {
                    exchange_log = Some(PathBuf::from(next_value(&mut iter, "--exchange-log")?))
                }
                "--client-cert" => {
                    client_cert = Some(PathBuf::from(next_value(&mut iter, "--client-cert")?))
                }
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                other => {
                    return Err(CliError::Usage(format!(
                        "unknown gost-bridge option: {other}"
                    )));
                }
            }
        }

        let command = Self {
            bind,
            host: required_string(host, "--host")?,
            port,
            timeout_secs,
            key_uri: required_string(key_uri, "--key-uri")?,
            pin_env: required_string(pin_env, "--pin-env")?,
            ccid_reader,
            exchange_log,
            client_cert,
        };
        rutoken::RutokenUri::parse(&command.key_uri)?;
        Ok(command)
    }

    fn run(&self) -> Result<String, CliError> {
        use gost_bridge::{CookieJar, build_upstream_request, read_request, rewrite_response};
        use std::io::Write as _;
        use std::net::TcpListener;

        let signer = token::CcidSignerConfig::new(
            self.ccid_reader.clone(),
            self.key_uri.clone(),
            Some(self.pin_env.clone()),
            KeyAlgorithm::Gost3410_2012_256,
            self.exchange_log.clone(),
        );

        // Load the client certificate chain once (from a file — DER leaf, or a
        // PEM leaf+intermediate bundle — or the token's leaf) so the per-request
        // handshakes reuse it.
        let client_chain = match &self.client_cert {
            Some(path) => load_client_cert_chain(path)?,
            None => vec![token::read_certificate_der(&signer)?],
        };

        let listener = TcpListener::bind(&self.bind)
            .map_err(|e| CliError::Message(format!("bind {}: {e}", self.bind)))?;
        let local = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| self.bind.clone());
        let bridge_origin = format!("http://{local}");

        eprintln!(
            "gost-bridge listening on {bridge_origin} -> https://{}:{} (GOST 0xFF85, token-authenticated)",
            self.host, self.port
        );
        eprintln!(
            "  open {bridge_origin}/ in your browser; each request triggers a fresh token handshake (PIN is re-presented)."
        );

        let mut jar = CookieJar::new();

        for incoming in listener.incoming() {
            let mut stream = match incoming {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("gost-bridge: accept error: {e}");
                    continue;
                }
            };

            let mut req = match read_request(&stream) {
                Ok(Some(r)) => r,
                Ok(None) => continue, // idle keep-alive closed
                Err(e) => {
                    eprintln!("gost-bridge: request parse error: {e}");
                    let _ = stream.write_all(
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    );
                    continue;
                }
            };

            let target = req.origin_form_target();
            eprintln!("gost-bridge: {} {target}", req.method);

            // Bridge-internal endpoint: expose the loaded client certificate to
            // the injected `window.cadesplugin` shim so its emulated CAPICOM
            // store enumerates the *real* signer cert (subject, validity, SHA-1
            // thumbprint). The page renders the real identity in its picker; the
            // actual token signing still happens server-side.
            if target == "/__bridge/cert-info" || target.starts_with("/__bridge/cert-info?") {
                let req_origin = req.header("origin").unwrap_or("").to_string();
                if !sign_origin_allowed(&req_origin, &bridge_origin) {
                    let _ = stream.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    );
                    continue;
                }
                let acao = cors_allow_header(&req_origin);
                let body = match Self::cert_info_json(&client_chain) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("gost-bridge: cert-info failed: {e}");
                        format!("{{\"error\":{:?}}}", e.to_string())
                    }
                };
                let mut msg = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n{acao}Cache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                msg.extend_from_slice(body.as_bytes());
                let _ = stream.write_all(&msg);
                let _ = stream.flush();
                continue;
            }

            // Bridge-internal endpoint: sign arbitrary content on the token for
            // the injected `cadesplugin` shim. CAdESCOM `SignedData` sets the
            // document via `propset_Content` (+ encoding) then calls `SignCades`;
            // the shim forwards `{content, encoding}` here. We sign the *real*
            // document bytes on the Rutoken as a detached CMS (the same path ФНС
            // accepted for login and the LK3 registration agreement) and return
            // the base64 signature, so the SPA's own submit carries a valid УКЭП.
            if req.method.eq_ignore_ascii_case("POST")
                && (target == "/__bridge/sign" || target.starts_with("/__bridge/sign?"))
            {
                // Origin gate: confine the УКЭП signing oracle to the ФНС
                // registration page (or local same-origin / non-browser). A
                // foreign web page's cross-origin POST carries its own
                // browser-set `Origin`, which JS cannot forge — so a malicious
                // site cannot make the token sign on its behalf.
                let req_origin = req.header("origin").unwrap_or("").to_string();
                if !sign_origin_allowed(&req_origin, &bridge_origin) {
                    eprintln!("gost-bridge: /__bridge/sign refused origin {req_origin:?}");
                    let _ = stream.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    );
                    continue;
                }
                let acao = cors_allow_header(&req_origin);
                let signed = (|| -> Result<(String, usize), CliError> {
                    use base64::Engine as _;
                    let v: serde_json::Value = serde_json::from_slice(&req.body)
                        .map_err(|e| CliError::Message(format!("sign: body not JSON: {e}")))?;
                    let content = v.get("content").and_then(|x| x.as_str()).unwrap_or("");
                    let encoding = v
                        .get("encoding")
                        .and_then(|x| x.as_str())
                        .unwrap_or("base64");
                    let bytes = match encoding {
                        "ucs2le" => content
                            .encode_utf16()
                            .flat_map(|u| u.to_le_bytes())
                            .collect::<Vec<u8>>(),
                        "binary" => content.as_bytes().to_vec(),
                        _ => base64::engine::general_purpose::STANDARD
                            .decode(content.trim())
                            .map_err(|e| {
                                CliError::Message(format!("sign: content not base64: {e}"))
                            })?,
                    };
                    let cert = client_chain
                        .first()
                        .cloned()
                        .ok_or_else(|| CliError::Message("sign: no client certificate".into()))?;
                    // Audit trail: persist the exact bytes about to be signed so
                    // the operator can review the document before/after submit.
                    let _ = std::fs::write("logs/usn-signed-content.bin", &bytes);
                    let sig = sign_detached_cms_b64(&signer, cert, &bytes)?;
                    Ok((sig, bytes.len()))
                })();
                let (status, reason, body) = match signed {
                    Ok((sig, n)) => {
                        eprintln!("gost-bridge: /__bridge/sign signed {n} bytes on token");
                        (
                            200u16,
                            "OK",
                            serde_json::json!({ "signature": sig }).to_string(),
                        )
                    }
                    Err(e) => {
                        eprintln!("gost-bridge: /__bridge/sign failed: {e}");
                        if e.to_string().to_ascii_lowercase().contains("pin") {
                            return Err(e);
                        }
                        (
                            500u16,
                            "Internal Server Error",
                            serde_json::json!({ "error": e.to_string() }).to_string(),
                        )
                    }
                };
                let mut msg = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\n{acao}Cache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                msg.extend_from_slice(body.as_bytes());
                let _ = stream.write_all(&msg);
                let _ = stream.flush();
                continue;
            }

            // Serve our `cadesplugin` emulation in place of the reference
            // implementation's loader (`cadesplugin_api.js`). The shim LOCKS
            // `window.cadesplugin` (non-configurable), so the sample helper file
            // `code.js` can no longer clobber it — therefore we let `code.js`
            // PROXY THROUGH instead of stubbing it. ФНС НБО's sign-in calls
            // `Common_CheckForPlugIn`/`FillCertList`/`Common_SignCadesBES`/
            // `CertificateObj` from that file directly; stubbing left them
            // undefined and broke НБО auth. They drive the `cadesplugin.*`
            // surface the shim provides.
            let is_cades_api = target.contains("cadesplugin_api.js");
            if std::env::var_os("CK_NO_SHIM").is_none() && is_cades_api {
                let body: &[u8] = gost_bridge::CADESPLUGIN_SHIM_JS.as_bytes();
                let mut msg = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                msg.extend_from_slice(body);
                let _ = stream.write_all(&msg);
                let _ = stream.flush();
                eprintln!("gost-bridge: served cadesplugin shim");
                continue;
            }

            // Bridge-internal endpoint: perform the in-page certificate login
            // server-side (token signs the auth challenge) so the shared
            // PHPSESSID becomes authenticated without the browser plugin.
            if target == "/__bridge/login" || target.starts_with("/__bridge/login?") {
                let (status_html, body_html) =
                    match self.perform_bridge_login(&signer, &client_chain, &mut jar) {
                        Ok(msg) => ("200 OK", msg),
                        Err(e) => {
                            eprintln!("gost-bridge: login failed: {e}");
                            if e.to_string().to_ascii_lowercase().contains("pin") {
                                return Err(e);
                            }
                            (
                                "502 Bad Gateway",
                                format!("<h1>Login failed</h1><pre>{e}</pre>"),
                            )
                        }
                    };
                let page = format!(
                    "<!doctype html><meta charset=\"utf-8\">\
                     <meta http-equiv=\"refresh\" content=\"2; url=/\">\
                     <body style=\"font-family:sans-serif\">{body_html}\
                     <p>Redirecting to the portal…</p></body>"
                );
                let mut msg = format!(
                    "HTTP/1.1 {status_html}\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    page.len()
                )
                .into_bytes();
                msg.extend_from_slice(page.as_bytes());
                let _ = stream.write_all(&msg);
                let _ = stream.flush();
                continue;
            }

            // Intercept the SPA's own certificate-login POST. The injected
            // `window.cadesplugin` shim lets the browser proceed past the dead
            // GOST signing plugin and POST here with *dummy* signature/certificate
            // values; we discard them and perform the real token-backed
            // GET+sign+POST, then hand the genuine upstream JSON (e.g. the
            // `registration_required` 400) back to the SPA so it renders its own
            // native next screen.
            if req.method.eq_ignore_ascii_case("POST")
                && (target == "/api/auth/challenge" || target.starts_with("/api/auth/challenge?"))
            {
                match self.auth_challenge_raw(&signer, &client_chain, &mut jar) {
                    Ok((st, body)) => {
                        let reason = match st {
                            200..=299 => "OK",
                            400 => "Bad Request",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            _ => "Error",
                        };
                        eprintln!("gost-bridge: SPA auth/challenge intercepted -> HTTP {st}");
                        let mut msg = format!(
                            "HTTP/1.1 {st} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        msg.extend_from_slice(&body);
                        let _ = stream.write_all(&msg);
                        let _ = stream.flush();
                    }
                    Err(e) => {
                        eprintln!("gost-bridge: SPA auth/challenge failed: {e}");
                        if e.to_string().to_ascii_lowercase().contains("pin") {
                            return Err(e);
                        }
                        let body = format!(
                            "{{\"code\":\"bridge_error\",\"message\":{:?}}}",
                            e.to_string()
                        );
                        let mut msg = format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        msg.extend_from_slice(body.as_bytes());
                        let _ = stream.write_all(&msg);
                        let _ = stream.flush();
                    }
                }
                continue;
            }

            // Intercept the SPA's Lk3 registration POST. The browser signs the
            // agreement with the shim's placeholder `SignCades`, so we re-sign
            // the real agreement on the token and forward the genuine form,
            // returning the real upstream response (success or a true denial).
            if req.method.eq_ignore_ascii_case("POST")
                && (target == "/api/register" || target.starts_with("/api/register?"))
            {
                match self.register_raw(&signer, &client_chain, &mut jar, &req) {
                    Ok((st, body)) => {
                        let reason = match st {
                            200..=299 => "OK",
                            400 => "Bad Request",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            _ => "Error",
                        };
                        eprintln!("gost-bridge: SPA register intercepted -> HTTP {st}");
                        let mut msg = format!(
                            "HTTP/1.1 {st} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        msg.extend_from_slice(&body);
                        let _ = stream.write_all(&msg);
                        let _ = stream.flush();
                    }
                    Err(e) => {
                        eprintln!("gost-bridge: SPA register failed: {e}");
                        if e.to_string().to_ascii_lowercase().contains("pin") {
                            return Err(e);
                        }
                        let body = format!(
                            "{{\"code\":\"bridge_error\",\"message\":{:?}}}",
                            e.to_string()
                        );
                        let mut msg = format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        msg.extend_from_slice(body.as_bytes());
                        let _ = stream.write_all(&msg);
                        let _ = stream.flush();
                    }
                }
                continue;
            }

            // Universal host routing: a `/__up/<host>/<path>` target proxies to
            // that explicit host (any `*.nalog.ru`); everything else goes to the
            // default host. The cabinet's micro-frontends and APIs live on a
            // sibling host (`mf-lk.nalog.ru`); `rewrite_response` rewrites their
            // absolute URLs into the `/__up/` form, funnelling the whole cabinet
            // through this one bridge with no per-host code.
            let (upstream_host, origin_path) = route_upstream(&target, &self.host);
            if upstream_host != self.host && !host_allowed(&upstream_host) {
                eprintln!("gost-bridge: refusing non-nalog.ru host {upstream_host}");
                let body = format!("gost-bridge: refusing to proxy host {upstream_host}");
                let msg = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(msg.as_bytes());
                continue;
            }
            req.target = origin_path;

            let upstream_bytes = build_upstream_request(&req, &upstream_host, &bridge_origin, &jar);

            // Transport per host by NAME, not "is it the default host": only the
            // GOST auth front (`*gost.nalog.ru`) speaks GOST TLS with the token;
            // every other ФНС host (service.nalog.ru, mf-lk.nalog.ru, …) is
            // ordinary TLS. This lets a bridge be launched with a plain-TLS
            // default host (e.g. --host service.nalog.ru) without trying GOST.
            let upstream_result = if is_gost_front(&upstream_host) {
                gost_mtls_request(
                    &upstream_host,
                    self.port,
                    self.timeout_secs,
                    &signer,
                    &client_chain,
                    &upstream_bytes,
                )
                .map(|(resp, _leaf_len)| resp)
            } else {
                plain_tls_request(
                    &upstream_host,
                    self.port,
                    self.timeout_secs,
                    &upstream_bytes,
                )
            };

            let response = match upstream_result {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("gost-bridge: upstream {upstream_host} request failed: {e}");
                    let body = format!("gost-bridge upstream error: {e}");
                    let mut msg = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    msg.extend_from_slice(body.as_bytes());
                    let _ = stream.write_all(&msg);
                    // Stop on the first failure: a bad PIN must not be retried.
                    if e.to_string().to_ascii_lowercase().contains("pin") {
                        return Err(e);
                    }
                    continue;
                }
            };

            // Rewrite for the browser: capture cookies, drop CSP, rewrite every
            // absolute `*.nalog.ru` URL (incl. the config's `mf_base_url`/
            // `api_host`) to the `/__up/` form, and inject the cadesplugin shim
            // into HTML so the SPA's CAdESCOM signing routes to the token. The
            // shim lets the portal's React SPA drive an emulated CAdESCOM object
            // model (no browser extension); `SignCades` POSTs to `/__bridge/sign`
            // and the token returns a real CMS. Set `CK_NO_SHIM` to disable.
            let inject_shim = std::env::var_os("CK_NO_SHIM").is_none();
            let rewritten = rewrite_response(&response, &bridge_origin, inject_shim, &mut jar);
            if let Err(e) = stream.write_all(&rewritten) {
                eprintln!("gost-bridge: write to browser failed: {e}");
            }
            let _ = stream.flush();
        }

        Ok(String::from("gost-bridge listener stopped"))
    }

    /// Perform the ФНС ЛКЮЛ in-page certificate login server-side.
    ///
    /// 1. `GET /api/auth/challenge` (over a fresh token handshake, jar cookies)
    ///    → JSON `{code, challenge}`.
    /// 2. Sign the UTF-8 bytes of `challenge` as a detached CMS on the token.
    /// 3. `POST /api/auth/challenge` as `multipart/form-data`
    ///    `{signature, certificate, code}`.
    /// 4. Absorb the resulting authenticated `Set-Cookie` into `jar`.
    ///
    /// The browser shares `jar`'s PHPSESSID, so after this the portal is logged
    /// in. Returns a short HTML status fragment for the redirect page.
    fn perform_bridge_login(
        &self,
        signer: &token::CcidSignerConfig,
        client_chain: &[Vec<u8>],
        jar: &mut gost_bridge::CookieJar,
    ) -> Result<String, CliError> {
        let (status2, body2) = self.auth_challenge_raw(signer, client_chain, jar)?;
        if (200..400).contains(&status2) {
            Ok(format!(
                "<h1>Logged in to ЛКЮЛ</h1><p>Server responded HTTP {status2}; the portal session is now authenticated.</p>"
            ))
        } else {
            Err(CliError::Message(format!(
                "login POST returned HTTP {status2}: {}",
                String::from_utf8_lossy(&body2)
            )))
        }
    }

    /// Run the real token-backed `GET`+sign+`POST /api/auth/challenge` flow and
    /// return the raw upstream POST response `(status, body)` verbatim.
    ///
    /// Used both by [`perform_bridge_login`] (friendly redirect page) and by the
    /// SPA `POST /api/auth/challenge` interceptor, which forwards the genuine
    /// JSON (e.g. the `registration_required` 400) straight to the browser so
    /// the portal's own React app renders its native next screen.
    fn auth_challenge_raw(
        &self,
        signer: &token::CcidSignerConfig,
        client_chain: &[Vec<u8>],
        jar: &mut gost_bridge::CookieJar,
    ) -> Result<(u16, Vec<u8>), CliError> {
        use base64::Engine as _;
        use gost_bridge::{absorb_response, build_multipart_form};

        // --- Step 1: fetch the challenge ---------------------------------
        let mut get_req = format!(
            "GET /api/auth/challenge HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n",
            self.host
        );
        if let Some(cookie) = jar.header_value() {
            get_req.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        get_req.push_str("Connection: close\r\n\r\n");

        let (raw, _) = gost_mtls_request(
            &self.host,
            self.port,
            self.timeout_secs,
            signer,
            client_chain,
            get_req.as_bytes(),
        )?;
        let (status, body) = absorb_response(&raw, jar);
        if status != 200 {
            return Err(CliError::Message(format!(
                "challenge request returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        let json: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            CliError::Message(format!(
                "challenge response was not JSON ({e}): {}",
                String::from_utf8_lossy(&body)
            ))
        })?;
        let challenge = json
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::Message("challenge response missing 'challenge'".into()))?;
        let code = json
            .get("code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::Message("challenge response missing 'code'".into()))?;
        eprintln!("gost-bridge: login challenge received (code={code})");

        // --- Step 2: sign the challenge on the token ---------------------
        let certificate_der = client_chain
            .first()
            .cloned()
            .ok_or_else(|| CliError::Message("no client certificate loaded".into()))?;
        let certificate_b64 = base64::engine::general_purpose::STANDARD.encode(&certificate_der);
        let signature_b64 = sign_detached_cms_b64(signer, certificate_der, challenge.as_bytes())?;

        // --- Step 3: POST the signed challenge as multipart/form-data ----
        let boundary = "----CryptoKiddieGostBridgeBoundary7e3b";
        let form = build_multipart_form(
            &[
                ("signature", signature_b64.as_str()),
                ("certificate", certificate_b64.as_str()),
                ("code", code),
            ],
            boundary,
        );
        let mut post_req = format!(
            "POST /api/auth/challenge HTTP/1.1\r\nHost: {}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n",
            self.host,
            form.len()
        )
        .into_bytes();
        if let Some(cookie) = jar.header_value() {
            post_req.extend_from_slice(format!("Cookie: {cookie}\r\n").as_bytes());
        }
        post_req.extend_from_slice(b"Connection: close\r\n\r\n");
        post_req.extend_from_slice(&form);

        let (raw2, _) = gost_mtls_request(
            &self.host,
            self.port,
            self.timeout_secs,
            signer,
            client_chain,
            &post_req,
        )?;
        let (status2, body2) = absorb_response(&raw2, jar);
        eprintln!("gost-bridge: login POST returned HTTP {status2}");
        Ok((status2, body2))
    }

    /// Re-sign and forward the SPA's Lk3 registration POST.
    ///
    /// The browser posts `multipart/form-data` `{agreement, inn, email,
    /// signature}` where `agreement` is a base64 string and `signature` is a
    /// detached CMS over its *decoded* bytes. The injected shim's `SignCades`
    /// returned only a placeholder, so we discard the incoming `signature`,
    /// re-sign the real agreement on the token, and forward the genuine form
    /// upstream — returning the real upstream `(status, body)` to the browser.
    fn register_raw(
        &self,
        signer: &token::CcidSignerConfig,
        client_chain: &[Vec<u8>],
        jar: &mut gost_bridge::CookieJar,
        req: &gost_bridge::HttpRequest,
    ) -> Result<(u16, Vec<u8>), CliError> {
        use base64::Engine as _;
        use gost_bridge::{
            absorb_response, build_multipart_form, multipart_boundary, parse_multipart_fields,
        };

        let content_type = req
            .header("content-type")
            .ok_or_else(|| CliError::Message("register POST missing Content-Type".into()))?;
        let boundary = multipart_boundary(content_type)
            .ok_or_else(|| CliError::Message("register POST is not multipart/form-data".into()))?;
        let fields = parse_multipart_fields(&req.body, &boundary);
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        };
        let agreement = get("agreement")
            .ok_or_else(|| CliError::Message("register POST missing 'agreement'".into()))?;
        let inn = get("inn").unwrap_or_default();
        let email = get("email").unwrap_or_default();

        // The signed content is the *decoded* agreement bytes (the SPA passes
        // messageFormat="base64", i.e. propset_Content = the base64 agreement
        // with ContentEncoding=BASE64_TO_BINARY).
        let agreement_bytes = base64::engine::general_purpose::STANDARD
            .decode(agreement.trim())
            .map_err(|e| CliError::Message(format!("agreement is not valid base64: {e}")))?;

        let certificate_der = client_chain
            .first()
            .cloned()
            .ok_or_else(|| CliError::Message("no client certificate loaded".into()))?;
        let signature_b64 = sign_detached_cms_b64(signer, certificate_der, &agreement_bytes)?;

        let boundary_out = "----CryptoKiddieGostBridgeRegister7e3b";
        let form = build_multipart_form(
            &[
                ("agreement", agreement.as_str()),
                ("inn", inn.as_str()),
                ("email", email.as_str()),
                ("signature", signature_b64.as_str()),
            ],
            boundary_out,
        );
        let mut post_req = format!(
            "POST /api/register HTTP/1.1\r\nHost: {}\r\nContent-Type: multipart/form-data; boundary={boundary_out}\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n",
            self.host,
            form.len()
        )
        .into_bytes();
        if let Some(cookie) = jar.header_value() {
            post_req.extend_from_slice(format!("Cookie: {cookie}\r\n").as_bytes());
        }
        post_req.extend_from_slice(b"Connection: close\r\n\r\n");
        post_req.extend_from_slice(&form);

        let (raw, _) = gost_mtls_request(
            &self.host,
            self.port,
            self.timeout_secs,
            signer,
            client_chain,
            &post_req,
        )?;
        let (status, body) = absorb_response(&raw, jar);
        eprintln!("gost-bridge: register POST returned HTTP {status} (email={email}, inn={inn})");
        Ok((status, body))
    }

    /// Build the JSON consumed by the injected `window.cadesplugin` shim's
    /// emulated CAPICOM store. Exposes the loaded client cert's SHA-1
    /// thumbprint (the CAdESCOM `Thumbprint`), base64 DER, subject/issuer DN,
    /// serial, and validity window so the SPA's certificate picker shows the
    /// real signer identity.
    fn cert_info_json(client_chain: &[Vec<u8>]) -> Result<String, CliError> {
        use sha1::{Digest as _, Sha1};
        let der = client_chain
            .first()
            .ok_or_else(|| CliError::Message("no client certificate loaded".into()))?;
        let record = gosuslugi_bridge::certificate_record_from_der(der, "rutoken")?;
        let thumbprint = hex_encode(&Sha1::digest(der)).to_uppercase();
        let subject_cn = extract_common_name(&record.subject);
        let subject = dn_to_capicom(&record.subject);
        let issuer = dn_to_capicom(&record.issuer);
        let json = serde_json::json!({
            "thumbprint": thumbprint,
            "certB64": record.raw,
            "subject": subject,
            "issuer": issuer,
            "serialNumber": record.serial_number,
            "notBefore": record.not_before,
            "notAfter": record.not_after,
            "subjectCN": subject_cn,
        });
        Ok(json.to_string())
    }
}

/// Extract the common-name (`CN` / OID `2.5.4.3`) value from a `;`-separated DN.
fn extract_common_name(dn: &str) -> String {
    for part in dn.split([';', '\n']) {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            if key.eq_ignore_ascii_case("CN") || key == "2.5.4.3" {
                return value.trim().to_string();
            }
        }
    }
    dn.trim().to_string()
}

/// Map an X.500 attribute OID to the short RDN key that reference implementation's CAdESCOM
/// `SubjectName` emits, so the SPA's `CertificateObj` parser can find them:
/// it reads the owner ФИО via `extract(SubjectName, 'SN=')` + `extract(…, 'G=')`
/// and the display name via `'CN='`. Without these friendly keys the parser
/// returns an empty owner and the declarant-match fails. The Russian-specific
/// OIDs (ИНН/СНИЛС/ОГРН under `1.2.643.*`) are intentionally left as dotted
/// OIDs — the SPA's `extractInns()` reads those directly by OID.
fn capicom_rdn_key(key: &str) -> &str {
    match key {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.42" => "G",
        "2.5.4.12" => "T",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.7" => "L",
        "2.5.4.8" => "S",
        "2.5.4.9" => "STREET",
        "2.5.4.6" => "C",
        "2.5.4.5" => "SERIALNUMBER",
        "1.2.840.113549.1.9.1" => "E",
        other => other,
    }
}

/// Convert a `;`-separated DN (as produced by `certificate_record_from_der`)
/// into the CAPICOM/CAdESCOM `SubjectName` form that the SPA's `reference implementation`
/// parser expects: `KEY=VALUE` pairs joined by `, `, with values that contain
/// commas or quotes wrapped in double quotes (internal quotes doubled).
fn dn_to_capicom(dn: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for part in dn.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let key = capicom_rdn_key(key.trim());
            let value = value.trim();
            if value.contains([',', '"', '+']) {
                let escaped = value.replace('"', "\"\"");
                out.push(format!("{key}=\"{escaped}\""));
            } else {
                out.push(format!("{key}={value}"));
            }
        } else {
            out.push(part.to_string());
        }
    }
    out.join(", ")
}

/// Reverse each 32-byte coordinate half of a 64-byte `X‖Y` point in place.
#[cfg_attr(not(test), allow(dead_code))]
fn reverse_coordinate_halves(point: &[u8]) -> Vec<u8> {
    if point.len() != 64 {
        // Unknown shape; return as-is and let the token reject it.
        return point.to_vec();
    }
    let mut out = Vec::with_capacity(64);
    out.extend(point[..32].iter().rev().copied());
    out.extend(point[32..].iter().rev().copied());
    out
}

/// Read `n` bytes of operating-system CSPRNG entropy (`/dev/urandom`).
fn read_os_random(n: usize) -> Result<Vec<u8>, CliError> {
    use std::io::Read as _;
    let mut f = fs::File::open("/dev/urandom")
        .map_err(|e| CliError::Message(format!("open /dev/urandom: {e}")))?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .map_err(|e| CliError::Message(format!("read /dev/urandom: {e}")))?;
    Ok(buf)
}

fn usage() -> String {
    String::from(
        "cryptokiddie <command> [options]\n\
         \n\
         Native Rust signing pipeline for PKCS#11 token-backed keys.\n\
         The document is hashed in-process; the token is responsible for the hardware\n\
         signature; CMS SignedData construction is kept behind the RustCrypto cms crate\n\
         boundary.\n\
                 \n\
                 Commands:\n\
                     sign                    Build a CMS signature using PKCS#11 or direct CCID\n\
                     ccid-probe              Open the Rutoken CCID interface and log ATR/SELECT MF\n\
                     ccid-sign-raw           Sign a document digest over direct CCID and write raw bytes\n\
                     ccid-read-cert          Read the Rutoken signer certificate to DER\n\
                     gosuslugi-bridge        Serve a localhost Gosuslugi plugin shim for Safari injection\n\
                     tls-probe               Open a GOST TLS 1.2 connection and report the server flight\n\
                     gost-login              Live mutual-auth GOST TLS 1.2 login over the Rutoken (0xFF85)\n\
                     gost-bridge             Local HTTP proxy fronting a GOST mTLS site so a browser can use it\n\
         \n\
         Options:\n\
           --digest <NAME>           Hash algorithm: gost12-256 (default), gost12-512,\n\
                                     sha256, sha384, or sha512\n\
           --key-algorithm <NAME>    Signing key algorithm: gost3410-2012-256 (default\n\
                                     for GOST digests), gost3410-2012-512, ecdsa\n\
                                     (default for SHA-2 digests), or rsa\n\
           --transport <NAME>        pkcs11 (default) or ccid\n\
           --pkcs11-module <FILE>    PKCS#11 module used by the cryptoki Rust crate\n\
           --cert-record <FILE>      Gosuslugi certificate metadata JSON for bridge listing\n\
           --pin-env <NAME>          Read the user PIN from an environment variable\n\
           --ccid-reader <NAME>      CCID reader selector for direct USB/APDU work\n\
           --exchange-log <FILE>     Write a redacted direct CCID/APDU exchange log\n\
           --embed-content           Produce an attached CMS object after signing\n\
           --dry-run                 Hash input and print the native signing plan\n\
         \n\
         Examples:\n\
           cryptokiddie sign --input contract.pdf --output contract.pdf.p7s \\\n\
               --cert signer.der --key-uri pkcs11:token=Signer;id=%01 \\\n\
               --digest sha256 --key-algorithm ecdsa \\\n\
               --pkcs11-module ./opensc-pkcs11.so --dry-run\n\
         \n\
           cryptokiddie sign --input contract.pdf --output contract.pdf.p7s \\\n\
               --cert signer.der --key-uri pkcs11:token=Signer;id=%01 \\\n\
               --digest gost12-256 --pkcs11-module ./gost-pkcs11.so --dry-run\n",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CcidProbeCommand, CcidRawSignCommand, CcidReadCertCommand, CliError, DigestAlgorithm,
        GostLoginCommand, GosuslugiBridgeCommand, KeyAlgorithm, SignCommand, Transport, apdu, ccid,
        cms_envelope, compute_digest, gost, reverse_coordinate_halves, run_cli, rutoken, token,
    };
    use std::{
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_native_pkcs11_sign_command() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--digest"),
            OsString::from("gost12-256"),
            OsString::from("--pkcs11-module"),
            module.clone().into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("command should parse");

        assert_eq!(command.digest, DigestAlgorithm::Gost3411_2012_256);
        assert_eq!(command.key_algorithm, KeyAlgorithm::Gost3410_2012_256);
        assert_eq!(command.transport, Transport::Pkcs11);
        assert_eq!(command.pkcs11_module.as_deref(), Some(module.as_path()));
        assert_eq!(command.pin_env, None);
    }

    #[test]
    fn parses_sign_command_exchange_log() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");
        let exchange_log = temp.path().join("ccid.log");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%01"),
            OsString::from("--transport"),
            OsString::from("ccid"),
            OsString::from("--exchange-log"),
            exchange_log.clone().into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("command should parse");

        assert_eq!(
            command.exchange_log.as_deref(),
            Some(exchange_log.as_path())
        );
    }

    #[test]
    fn parses_gosuslugi_bridge_command() {
        let temp = TempDir::new();
        let cert = temp.write_file("signer.der", "certificate");
        let exchange_log = temp.path().join("gosuslugi.log");

        let command = GosuslugiBridgeCommand::parse([
            OsString::from("--bind"),
            OsString::from("127.0.0.1:18766"),
            OsString::from("--cert"),
            cert.clone().into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--ccid-reader"),
            OsString::from("Rutoken ECP"),
            OsString::from("--exchange-log"),
            exchange_log.clone().into_os_string(),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
        ])
        .expect("command should parse");

        assert_eq!(command.bind, "127.0.0.1:18766");
        assert_eq!(command.cert.as_deref(), Some(cert.as_path()));
        assert_eq!(command.cert_record, None);
        assert_eq!(command.key_uri, "rutoken:slot=0;id=%03");
        assert_eq!(command.pin_env, "TOKEN_PIN");
        assert_eq!(command.ccid_reader.as_deref(), Some("Rutoken ECP"));
        assert_eq!(
            command.exchange_log.as_deref(),
            Some(exchange_log.as_path())
        );
        assert_eq!(command.digest, DigestAlgorithm::Gost3411_2012_256);
        assert_eq!(command.key_algorithm, KeyAlgorithm::Gost3410_2012_256);
    }

    #[test]
    fn parses_gosuslugi_bridge_command_without_cert() {
        let command = GosuslugiBridgeCommand::parse([
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
        ])
        .expect("command should parse");

        assert_eq!(command.cert, None);
        assert_eq!(command.cert_record, None);
        assert_eq!(command.bind, "127.0.0.1:18765");
    }

    #[test]
    fn parses_gosuslugi_bridge_command_with_cert_record() {
        let temp = TempDir::new();
        let cert_record = temp.write_file("cert-record.json", "{}");

        let command = GosuslugiBridgeCommand::parse([
            OsString::from("--cert-record"),
            cert_record.clone().into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
        ])
        .expect("command should parse");

        assert_eq!(command.cert, None);
        assert_eq!(command.cert_record.as_deref(), Some(cert_record.as_path()));
    }

    #[test]
    fn parses_gost_login_command() {
        let command = GostLoginCommand::parse([
            OsString::from("--host"),
            OsString::from("lkulgost.nalog.ru"),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
            OsString::from("--ccid-reader"),
            OsString::from("Rutoken ECP"),
            OsString::from("--vko-algo"),
            OsString::from("0x40"),
            OsString::from("--peer-key-le"),
            OsString::from("--request-path"),
            OsString::from("/index.html"),
        ])
        .expect("command should parse");

        assert_eq!(command.host, "lkulgost.nalog.ru");
        assert_eq!(command.port, 443);
        assert_eq!(command.key_uri, "rutoken:slot=0;id=%03");
        assert_eq!(command.pin_env, "TOKEN_PIN");
        assert_eq!(command.ccid_reader.as_deref(), Some("Rutoken ECP"));
        assert_eq!(command.vko_algo, 0x40);
        assert!(command.peer_key_little_endian);
        assert_eq!(command.request_path, "/index.html");
    }

    #[test]
    fn gost_login_requires_host_and_vko_algo() {
        // --vko-algo is now optional (legacy no-op): this parses.
        let command = GostLoginCommand::parse([
            OsString::from("--host"),
            OsString::from("example.ru"),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
        ])
        .expect("command should parse without --vko-algo");
        assert_eq!(command.host, "example.ru");

        // Missing --host is still a usage error.
        let err = GostLoginCommand::parse([
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
            OsString::from("--vko-algo"),
            OsString::from("40"),
        ])
        .unwrap_err();
        assert!(err.is_usage());
    }

    #[test]
    fn reverse_coordinate_halves_flips_each_32_byte_half() {
        let mut point = [0u8; 64];
        for (i, b) in point.iter_mut().enumerate() {
            *b = i as u8;
        }
        let flipped = reverse_coordinate_halves(&point);
        assert_eq!(flipped[0], 31); // first half reversed: 31,30,...,0
        assert_eq!(flipped[31], 0);
        assert_eq!(flipped[32], 63); // second half reversed: 63,62,...,32
        assert_eq!(flipped[63], 32);
        // Non-64-byte input is returned unchanged.
        assert_eq!(reverse_coordinate_halves(&[1, 2, 3]), vec![1, 2, 3]);
    }

    #[test]
    fn parses_ccid_read_cert_command() {
        let temp = TempDir::new();
        let output = temp.path().join("rutoken-cert.der");
        let exchange_log = temp.path().join("read-cert.log");

        let command = CcidReadCertCommand::parse([
            OsString::from("--output"),
            output.clone().into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%03"),
            OsString::from("--pin-env"),
            OsString::from("TOKEN_PIN"),
            OsString::from("--ccid-reader"),
            OsString::from("Rutoken ECP"),
            OsString::from("--exchange-log"),
            exchange_log.clone().into_os_string(),
        ])
        .expect("command should parse");

        assert_eq!(command.output, output);
        assert_eq!(command.key_uri, "rutoken:slot=0;id=%03");
        assert_eq!(command.pin_env.as_deref(), Some("TOKEN_PIN"));
        assert_eq!(command.ccid_reader.as_deref(), Some("Rutoken ECP"));
        assert_eq!(
            command.exchange_log.as_deref(),
            Some(exchange_log.as_path())
        );
    }

    #[test]
    fn parses_sha256_ecdsa_sign_command() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--digest"),
            OsString::from("sha256"),
            OsString::from("--key-algorithm"),
            OsString::from("ecdsa"),
            OsString::from("--pkcs11-module"),
            module.clone().into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("command should parse");

        assert_eq!(command.digest, DigestAlgorithm::Sha256);
        assert_eq!(command.key_algorithm, KeyAlgorithm::Ecdsa);
        assert_eq!(command.transport, Transport::Pkcs11);
    }

    #[test]
    fn parses_sha512_rsa_sign_command() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--digest"),
            OsString::from("sha512"),
            OsString::from("--key-algorithm"),
            OsString::from("rsa"),
            OsString::from("--pkcs11-module"),
            module.clone().into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("command should parse");

        assert_eq!(command.digest, DigestAlgorithm::Sha512);
        assert_eq!(command.key_algorithm, KeyAlgorithm::Rsa);
    }

    #[test]
    fn sha256_digest_defaults_to_ecdsa_key_algorithm() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--digest"),
            OsString::from("sha256"),
            OsString::from("--pkcs11-module"),
            module.into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("command should parse");

        assert_eq!(command.digest, DigestAlgorithm::Sha256);
        assert_eq!(command.key_algorithm, KeyAlgorithm::Ecdsa);
    }

    #[test]
    fn dry_run_hashes_with_streebog_and_renders_plan() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let output = run_cli([
            OsString::from("sign"),
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--pkcs11-module"),
            module.into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("dry run should succeed");

        assert!(output.contains("native signing plan"));
        assert!(output.contains("transport=pkcs11"));
        assert!(output.contains("digest_algorithm=gost12-256"));
        assert!(output.contains("key_algorithm=gost3410-2012-256"));
        assert!(output.contains("pkcs11_backend=cryptoki::context::Pkcs11"));
        assert!(output.contains("cms_backend=cms::content_info::ContentInfo"));
        assert!(!output.contains("openssl"));
    }

    #[test]
    fn dry_run_accepts_rutoken_gost_via_generic_pkcs11_uri() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let output = run_cli([
            OsString::from("sign"),
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Rutoken;id=%01"),
            OsString::from("--digest"),
            OsString::from("gost12-256"),
            OsString::from("--pkcs11-module"),
            module.into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("Rutoken/GOST dry run should use generic PKCS#11 path");

        assert!(output.contains("transport=pkcs11"));
        assert!(output.contains("key_uri=pkcs11:token=Rutoken;id=%01"));
        assert!(output.contains("digest_algorithm=gost12-256"));
        assert!(output.contains("key_algorithm=gost3410-2012-256"));
    }

    #[test]
    fn dry_run_sha256_ecdsa_renders_plan() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let output = run_cli([
            OsString::from("sign"),
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--digest"),
            OsString::from("sha256"),
            OsString::from("--key-algorithm"),
            OsString::from("ecdsa"),
            OsString::from("--pkcs11-module"),
            module.into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("dry run should succeed");

        assert!(output.contains("transport=pkcs11"));
        assert!(output.contains("digest_algorithm=sha256"));
        assert!(output.contains("key_algorithm=ecdsa"));
        assert!(!output.contains("openssl"));
    }

    #[test]
    fn renders_ccid_transport_in_dry_run() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");

        let output = run_cli([
            OsString::from("sign"),
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%01"),
            OsString::from("--transport"),
            OsString::from("ccid"),
            OsString::from("--ccid-reader"),
            OsString::from("Alcor Micro AU9560"),
            OsString::from("--dry-run"),
        ])
        .expect("dry run should succeed");

        assert!(output.contains("transport=ccid"));
        assert!(output.contains("ccid_reader=Alcor Micro AU9560"));
        assert!(!output.contains("vid="));
        assert!(!output.contains("pid="));
    }

    #[test]
    fn ccid_transport_requires_rutoken_key_uri() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");

        let error = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:slot=0;id=%01"),
            OsString::from("--transport"),
            OsString::from("ccid"),
            OsString::from("--dry-run"),
        ])
        .expect_err("CCID transport should require rutoken: key URIs");

        assert!(matches!(error, CliError::Usage(message) if message.contains("rutoken:")));
    }

    #[test]
    fn ccid_transport_rejects_non_gost_signing() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");

        let error = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%01"),
            OsString::from("--transport"),
            OsString::from("ccid"),
            OsString::from("--digest"),
            OsString::from("sha256"),
            OsString::from("--dry-run"),
        ])
        .expect_err("CCID transport should reject non-GOST signing");

        assert!(matches!(error, CliError::Usage(message) if message.contains("Rutoken GOST")));
    }

    #[test]
    fn streebog_digest_sizes_match_gost_3411_2012_variants() {
        assert_eq!(
            gost::hash(b"hello", DigestAlgorithm::Gost3411_2012_256).len(),
            32
        );
        assert_eq!(
            gost::hash(b"hello", DigestAlgorithm::Gost3411_2012_512).len(),
            64
        );
        assert_ne!(
            gost::hash(b"hello", DigestAlgorithm::Gost3411_2012_256),
            gost::hash(b"world", DigestAlgorithm::Gost3411_2012_256)
        );
    }

    #[test]
    fn sha2_digest_sizes_are_correct() {
        assert_eq!(compute_digest(b"hello", DigestAlgorithm::Sha256).len(), 32);
        assert_eq!(compute_digest(b"hello", DigestAlgorithm::Sha384).len(), 48);
        assert_eq!(compute_digest(b"hello", DigestAlgorithm::Sha512).len(), 64);
        assert_ne!(
            compute_digest(b"hello", DigestAlgorithm::Sha256),
            compute_digest(b"world", DigestAlgorithm::Sha256)
        );
    }

    #[test]
    fn sha2_digests_are_well_known_values() {
        // SHA-256 of "abc" (known test vector from FIPS 180-4)
        let digest = compute_digest(b"abc", DigestAlgorithm::Sha256);
        assert_eq!(
            digest,
            vec![
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn key_algorithm_defaults_gost_for_gost_digest() {
        assert_eq!(
            KeyAlgorithm::default_for_digest(DigestAlgorithm::Gost3411_2012_256),
            KeyAlgorithm::Gost3410_2012_256
        );
        assert_eq!(
            KeyAlgorithm::default_for_digest(DigestAlgorithm::Gost3411_2012_512),
            KeyAlgorithm::Gost3410_2012_512
        );
    }

    #[test]
    fn key_algorithm_defaults_ecdsa_for_sha2_digest() {
        assert_eq!(
            KeyAlgorithm::default_for_digest(DigestAlgorithm::Sha256),
            KeyAlgorithm::Ecdsa
        );
        assert_eq!(
            KeyAlgorithm::default_for_digest(DigestAlgorithm::Sha384),
            KeyAlgorithm::Ecdsa
        );
        assert_eq!(
            KeyAlgorithm::default_for_digest(DigestAlgorithm::Sha512),
            KeyAlgorithm::Ecdsa
        );
    }

    #[test]
    fn key_algorithm_produces_correct_signature_oids() {
        // GOST
        assert_eq!(
            KeyAlgorithm::Gost3410_2012_256
                .signature_oid(DigestAlgorithm::Gost3411_2012_256)
                .expect("valid combination")
                .to_string(),
            "1.2.643.7.1.1.3.2"
        );
        // ECDSA
        assert_eq!(
            KeyAlgorithm::Ecdsa
                .signature_oid(DigestAlgorithm::Sha256)
                .expect("valid combination")
                .to_string(),
            "1.2.840.10045.4.3.2"
        );
        assert_eq!(
            KeyAlgorithm::Ecdsa
                .signature_oid(DigestAlgorithm::Sha384)
                .expect("valid combination")
                .to_string(),
            "1.2.840.10045.4.3.3"
        );
        assert_eq!(
            KeyAlgorithm::Ecdsa
                .signature_oid(DigestAlgorithm::Sha512)
                .expect("valid combination")
                .to_string(),
            "1.2.840.10045.4.3.4"
        );
        // RSA
        assert_eq!(
            KeyAlgorithm::Rsa
                .signature_oid(DigestAlgorithm::Sha256)
                .expect("valid combination")
                .to_string(),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(
            KeyAlgorithm::Rsa
                .signature_oid(DigestAlgorithm::Sha384)
                .expect("valid combination")
                .to_string(),
            "1.2.840.113549.1.1.12"
        );
        assert_eq!(
            KeyAlgorithm::Rsa
                .signature_oid(DigestAlgorithm::Sha512)
                .expect("valid combination")
                .to_string(),
            "1.2.840.113549.1.1.13"
        );
    }

    #[test]
    fn incompatible_key_algorithm_and_digest_is_rejected() {
        assert!(matches!(
            KeyAlgorithm::Ecdsa.signature_oid(DigestAlgorithm::Gost3411_2012_256),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            KeyAlgorithm::Rsa.signature_oid(DigestAlgorithm::Gost3411_2012_512),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            KeyAlgorithm::Gost3410_2012_256.signature_oid(DigestAlgorithm::Sha256),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn usage_exposes_all_digest_names() {
        let help = run_cli([OsString::from("--help")]).expect("help should render");

        assert!(help.contains("gost12-256"));
        assert!(help.contains("gost12-512"));
        assert!(help.contains("sha256"));
        assert!(help.contains("sha384"));
        assert!(help.contains("sha512"));
        assert!(help.contains("ecdsa"));
        assert!(help.contains("rsa"));
        assert!(!help.to_ascii_lowercase().contains("openssl"));
    }

    #[test]
    fn command_apdu_serializes_short_apdu() {
        let apdu = apdu::CommandApdu::new(0x00, 0xa4, 0x04, 0x00)
            .with_data([0x3f, 0x00])
            .with_le(0x00);

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00, 0x00,]
        );
    }

    #[test]
    fn ccid_xfr_block_wraps_command_apdu() {
        let apdu = apdu::CommandApdu::new(0x00, 0xa4, 0x04, 0x00).with_le(0x00);
        let block = ccid::XfrBlock::new(0, 7, apdu);

        assert_eq!(
            block.to_bytes().expect("CCID block should serialize"),
            vec![
                0x6f, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x04, 0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn cms_input_rejects_wrong_digest_length() {
        let input = cms_envelope::CmsSigningInput::new(
            vec![1, 2, 3],
            DigestAlgorithm::Gost3411_2012_256,
            KeyAlgorithm::Gost3410_2012_256,
            vec![1],
            true,
        );

        assert!(
            matches!(input.validate(), Err(CliError::Message(message)) if message.contains("32 bytes"))
        );
    }

    #[test]
    fn pkcs11_transport_requires_module() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");

        let error = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
        ])
        .expect_err("missing PKCS#11 module should fail");

        assert!(matches!(error, CliError::Usage(message) if message.contains("--pkcs11-module")));
    }

    #[test]
    fn live_pkcs11_signing_requires_pin() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let error = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--pkcs11-module"),
            module.into_os_string(),
        ])
        .expect_err("live signing without pin should fail");

        assert!(matches!(error, CliError::Usage(message) if message.contains("--pin")));
    }

    #[test]
    fn parses_pkcs11_uri_private_key_selector() {
        let selector =
            token::KeyUriSelector::parse("pkcs11:token=Signer%20Token;id=%01%ab;object=Key")
                .expect("PKCS#11 URI should parse");

        assert_eq!(selector.token.as_deref(), Some("Signer Token"));
        assert_eq!(selector.id.as_deref(), Some(&[0x01, 0xab][..]));
        assert_eq!(selector.object.as_deref(), Some("Key"));
        assert_eq!(
            selector.private_key_template(),
            vec![
                cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
                cryptoki::object::Attribute::Sign(true),
                cryptoki::object::Attribute::Id(vec![0x01, 0xab]),
                cryptoki::object::Attribute::Label(b"Key".to_vec()),
            ]
        );
    }

    #[test]
    fn cms_builder_rejects_empty_signature() {
        let input = cms_envelope::CmsSigningInput::new(
            vec![0; DigestAlgorithm::Gost3411_2012_256.output_len()],
            DigestAlgorithm::Gost3411_2012_256,
            KeyAlgorithm::Gost3410_2012_256,
            vec![1],
            true,
        );

        let (signed_attrs, _) = cms_envelope::prepare_signed_attributes(&input)
            .expect("signed attributes should encode");
        let error = cms_envelope::build_signed_data_der(&input, b"hello", Vec::new(), signed_attrs)
            .expect_err("empty signatures should fail");

        assert!(matches!(error, CliError::Message(message) if message.contains("signature")));
    }

    // --- rutoken URI parsing ---

    #[test]
    fn rutoken_uri_parses_slot_and_id() {
        let uri =
            rutoken::RutokenUri::parse("rutoken:slot=0;id=%01").expect("rutoken URI should parse");

        assert_eq!(uri.slot, 0);
        assert_eq!(uri.id, 0x01);
    }

    #[test]
    fn rutoken_uri_parses_non_zero_slot_and_multi_hex_id() {
        let uri =
            rutoken::RutokenUri::parse("rutoken:slot=2;id=%0f").expect("rutoken URI should parse");

        assert_eq!(uri.slot, 2);
        assert_eq!(uri.id, 0x0f);
    }

    #[test]
    fn rutoken_uri_requires_id_attribute() {
        let error =
            rutoken::RutokenUri::parse("rutoken:slot=0").expect_err("missing id= should fail");

        assert!(matches!(error, CliError::Usage(msg) if msg.contains("id=")));
    }

    #[test]
    fn rutoken_uri_rejects_non_rutoken_prefix() {
        let error = rutoken::RutokenUri::parse("pkcs11:slot=0;id=%01")
            .expect_err("wrong scheme should fail");

        assert!(matches!(error, CliError::Usage(msg) if msg.contains("rutoken:")));
    }

    #[test]
    fn rutoken_uri_rejects_multi_byte_id() {
        let error = rutoken::RutokenUri::parse("rutoken:slot=0;id=%01%02")
            .expect_err("two-byte id should fail");

        assert!(matches!(error, CliError::Usage(msg) if msg.contains("one byte")));
    }

    // --- Rutoken APDU constructors ---

    #[test]
    fn rutoken_select_master_file_apdu() {
        let apdu = rutoken::select_master_file();

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]
        );
    }

    #[test]
    fn rutoken_select_private_key_file_apdu() {
        let apdu = rutoken::select_private_key_file(0x01);

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![
                0x00, 0xA4, 0x08, 0x0C, 0x08, 0x10, 0x00, 0x10, 0x00, 0x60, 0x02, 0x00, 0x01,
            ]
        );
    }

    #[test]
    fn rutoken_verify_pin_apdu() {
        let pin = b"12345678";
        let apdu = rutoken::verify_pin(pin);

        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(&bytes[..4], [0x00, 0x20, 0x00, rutoken::USER_PIN_REFERENCE]);
        assert_eq!(bytes[4] as usize, pin.len());
        assert_eq!(&bytes[5..], pin);
    }

    #[test]
    fn rutoken_pin_references_match_aktiv_apdu_samples() {
        assert_eq!(rutoken::ADMIN_PIN_REFERENCE, 0x01);
        assert_eq!(rutoken::USER_PIN_REFERENCE, 0x02);
    }

    #[test]
    fn rutoken_verify_pin_status_apdu() {
        let apdu = rutoken::verify_pin_status();

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![0x00, 0x20, 0x00, rutoken::USER_PIN_REFERENCE]
        );
    }

    #[test]
    fn rutoken_logout_apdu() {
        let apdu = rutoken::logout();

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![0x80, 0x40, 0x00, 0x00]
        );
    }

    #[test]
    fn rutoken_mse_set_apdu_embeds_key_reference() {
        let apdu = rutoken::manage_security_environment_for_signing(0x01);

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![0x00, 0x22, 0x41, 0xB6, 0x03, 0x84, 0x01, 0x01]
        );
    }

    #[test]
    fn rutoken_pso_cds_apdu_for_gost256() {
        let digest = (0u8..32).collect::<Vec<_>>();
        let apdu = rutoken::pso_compute_digital_signature(&digest, 64);
        let bytes = apdu.to_bytes().expect("APDU should serialize");

        // CLA INS P1 P2 Lc=32 digest[0..32] Le=64
        assert_eq!(&bytes[..4], [0x00, 0x2A, 0x9E, 0x9A]);
        assert_eq!(bytes[4], 32);
        assert_eq!(&bytes[5..37], digest.as_slice());
        assert_eq!(bytes[37], 64);
    }

    #[test]
    fn rutoken_pso_cds_apdu_for_gost512() {
        let digest = (0u8..64).collect::<Vec<_>>();
        let apdu = rutoken::pso_compute_digital_signature(&digest, 128);
        let bytes = apdu.to_bytes().expect("APDU should serialize");

        assert_eq!(&bytes[..4], [0x00, 0x2A, 0x9E, 0x9A]);
        assert_eq!(bytes[4], 64);
        assert_eq!(bytes[5..69], digest[..]);
        assert_eq!(bytes[69], 128);
    }

    #[test]
    fn rutoken_signature_from_token_reverses_bytes() {
        assert_eq!(
            rutoken::signature_from_token(vec![1, 2, 3, 4]),
            vec![4, 3, 2, 1]
        );
    }

    #[test]
    fn rutoken_mse_set_vko_apdu_bytes() {
        // Validated live against the Osnovanie Rutoken ECP (the A6 template is
        // rejected with 6a80; B8 is the accepted key-agreement CRT):
        // 00 22 41 B8 06 95 01 40 84 01 <key_id>  (no 80-mechanism CRDO).
        let apdu = rutoken::manage_security_environment_for_vko(0x03, 0x00);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(
            bytes,
            vec![
                0x00, 0x22, 0x41, 0xB8, 0x06, 0x95, 0x01, 0x40, 0x84, 0x01, 0x03
            ]
        );

        // When a non-zero mechanism byte is supplied it is appended as 80 01 AA.
        let apdu = rutoken::manage_security_environment_for_vko(0x03, 0x1E);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(
            bytes,
            vec![
                0x00, 0x22, 0x41, 0xB8, 0x09, 0x95, 0x01, 0x40, 0x84, 0x01, 0x03, 0x80, 0x01, 0x1E,
            ]
        );
    }

    #[test]
    fn rutoken_mse_set_vko_with_ukm_apdu_bytes() {
        // MSE build order: 95 01 40 · 84 01 KK · [80 01 AA] · 87 Lu <ukm>.
        let ukm = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let apdu = rutoken::manage_security_environment_for_vko_with_ukm(0x03, 0x1E, &ukm);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(
            bytes,
            vec![
                0x00, 0x22, 0x41, 0xB8, 0x13, 0x95, 0x01, 0x40, 0x84, 0x01, 0x03, 0x80, 0x01, 0x1E,
                0x87, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ]
        );

        // Empty UKM reproduces the original APDU exactly.
        let plain = rutoken::manage_security_environment_for_vko(0x03, 0x00)
            .to_bytes()
            .unwrap();
        let via_ukm = rutoken::manage_security_environment_for_vko_with_ukm(0x03, 0x00, &[])
            .to_bytes()
            .unwrap();
        assert_eq!(plain, via_ukm);
    }

    #[test]
    fn rutoken_pso_key_agreement_apdu_bytes() {
        // PSO key agreement: 00 2A 80 86 <Lc> <peer point>
        let point = (0u8..64).collect::<Vec<_>>();
        let apdu = rutoken::pso_key_agreement(&point);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(&bytes[..4], [0x00, 0x2A, 0x80, 0x86]);
        assert_eq!(bytes[4], 64);
        assert_eq!(&bytes[5..69], point.as_slice());
    }

    #[test]
    fn rutoken_create_se_rsf_file_apdu_bytes() {
        // CREATE FILE for the SE-RSF EF: the size TLV (80) is emitted before the
        // descriptor TLV (82). conditions = sibling key-EF ACL body (all USER PIN
        // where enforced).
        let conditions = [
            0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x02, // 7 condition slots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 pad bytes
        ];
        let apdu = rutoken::create_se_rsf_file_for_vko(0x03, 0x42, conditions);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(
            bytes,
            vec![
                0x00, 0xE0, 0x00, 0x00, 0x27, // CREATE FILE, Lc=0x27
                0x62, 0x25, // FCP template, len 37
                0x80, 0x02, 0x00, 0x42, // file size (emitted first)
                0x82, 0x02, 0x10, 0x00, // file descriptor
                0x83, 0x02, 0x00, 0x03, // file id low byte = key_id
                0x85, 0x06, 0x1F, 0x00, 0x00, 0xFF, 0x00, 0x00, // descriptor
                0x86, 0x0F, 0x47, // ACL tag/len/hdr
                0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x02, // conditions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pad
            ]
        );
    }

    #[test]
    fn rutoken_create_se_rsf_file_csp_apdu_bytes() {
        // Alternate CSP CREATE FILE dialect: descriptor TLV (82) before size TLV
        // (80), ACL header 0x46, prop-attr 85 06 <r0> <hh> <r2> FF 00 00. For the
        // GOST-2012-256 case coord_len = 0x20 ⇒ size 0x40, r0 0x13, hh 0x00
        // (letter gate default). prop_flags (r2) is caller-supplied.
        let apdu = rutoken::create_se_rsf_file_csp(0x03, 0x20, 0x43);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        assert_eq!(
            bytes,
            vec![
                0x00, 0xE0, 0x00, 0x00, 0x27, // CREATE FILE, Lc=0x27
                0x62, 0x25, // FCP template, len 37
                0x82, 0x02, 0x10, 0x00, // file descriptor (before size)
                0x80, 0x02, 0x00, 0x40, // file size = 2 * 0x20
                0x83, 0x02, 0x00, 0x03, // file id low byte = key_id
                0x85, 0x06, 0x13, 0x00, 0x43, 0xFF, 0x00, 0x00, // descriptor
                0x86, 0x0F, 0x46, // ACL tag/len/hdr (0x46)
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // conditions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pad
            ]
        );
    }

    #[test]
    fn rutoken_se_rsf_letter_gate_values() {
        // SE-RSF descriptor letter→code map.
        assert_eq!(rutoken::se_rsf_letter_gate(b'A'), 0x20);
        assert_eq!(rutoken::se_rsf_letter_gate(b'B'), 0x30);
        assert_eq!(rutoken::se_rsf_letter_gate(b'C'), 0x40);
        assert_eq!(rutoken::se_rsf_letter_gate(b'T'), 0x10);
        assert_eq!(rutoken::se_rsf_letter_gate(b'E'), 0x50);
        assert_eq!(rutoken::se_rsf_letter_gate(b'F'), 0x20);
        assert_eq!(rutoken::se_rsf_letter_gate(b'G'), 0x30);
        assert_eq!(rutoken::se_rsf_letter_gate(b'H'), 0x40);
        assert_eq!(rutoken::se_rsf_letter_gate(0x20), 0x00); // GOST-256 coord len
    }

    #[test]
    fn rutoken_pubkey_to_token_point_reverses_each_coordinate() {
        // X = 01..20 (32 bytes), Y = 21..40 (32 bytes); each half reversed in place.
        let mut xy = Vec::new();
        xy.extend(1u8..=32); // X
        xy.extend(33u8..=64); // Y
        let point = rutoken::pubkey_to_token_point(&xy, 32).expect("64-byte key");

        let mut expected = Vec::new();
        expected.extend((1u8..=32).rev()); // X reversed
        expected.extend((33u8..=64).rev()); // Y reversed
        assert_eq!(point, expected);
    }

    #[test]
    fn rutoken_pubkey_to_token_point_rejects_bad_length() {
        assert!(rutoken::pubkey_to_token_point(&[0u8; 63], 32).is_err());
    }

    // --- CCID protocol types ---

    #[test]
    fn ccid_icc_power_on_serializes() {
        let cmd = ccid::IccPowerOn::new(0, 3);

        assert_eq!(
            cmd.to_bytes(),
            vec![
                ccid::PC_TO_RDR_ICCPOWERON,
                0x00,
                0x00,
                0x00,
                0x00, // dwLength = 0
                0x00, // bSlot = 0
                0x03, // bSeq = 3
                0x00, // bPowerSelect = automatic
                0x00,
                0x00, // abRFU
            ]
        );
    }

    #[test]
    fn ccid_rdr_data_block_parses_success_response() {
        // Construct a minimal success RDR_to_PC_DataBlock carrying SW 9000.
        let mut bytes = vec![
            ccid::RDR_TO_PC_DATABLOCK,
            0x02,
            0x00,
            0x00,
            0x00, // dwLength = 2
            0x00, // bSlot
            0x01, // bSeq
            0x00, // bStatus (success)
            0x00, // bError
            0x00, // bChainParameter
        ];
        bytes.extend_from_slice(&[0x90, 0x00]); // SW 9000

        let block = ccid::RdrDataBlock::parse(&bytes).expect("should parse");
        assert!(block.is_success());
        assert_eq!(block.sequence, 1);
        assert_eq!(block.data, vec![0x90, 0x00]);
    }

    #[test]
    fn ccid_rdr_data_block_detects_command_error() {
        let bytes = vec![
            ccid::RDR_TO_PC_DATABLOCK,
            0x00,
            0x00,
            0x00,
            0x00, // dwLength = 0
            0x00, // bSlot
            0x02, // bSeq
            0x40, // bStatus: bmCommandStatus = 01 (failed)
            0xE0, // bError
            0x00, // bChainParameter
        ];

        let block = ccid::RdrDataBlock::parse(&bytes).expect("should parse");
        assert!(!block.is_success());
    }

    #[test]
    fn ccid_rdr_data_block_rejects_wrong_message_type() {
        let bytes = vec![
            0x81, // RDR_to_PC_SlotStatus, not DataBlock
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let error = ccid::RdrDataBlock::parse(&bytes).expect_err("wrong type should fail");
        assert!(matches!(error, CliError::Message(msg) if msg.contains("0x80")));
    }

    #[test]
    fn ccid_rdr_data_block_rejects_truncated_header() {
        let error = ccid::RdrDataBlock::parse(&[0x80, 0x00]).expect_err("short should fail");
        assert!(matches!(error, CliError::Message(msg) if msg.contains("too short")));
    }

    // --- CCID signer input validation ---

    #[test]
    fn ccid_signer_rejects_wrong_digest_length() {
        let config = token::CcidSignerConfig::new(
            None,
            "rutoken:slot=0;id=%01".to_string(),
            None,
            KeyAlgorithm::Gost3410_2012_256,
            None,
        );

        let error = token::TokenSigner::sign_digest(
            &config,
            DigestAlgorithm::Gost3411_2012_256,
            &[0u8; 16],
        )
        .expect_err("wrong digest length should fail");

        assert!(matches!(error, CliError::Message(msg) if msg.contains("32 bytes")));
    }

    #[test]
    fn ccid_signer_rejects_invalid_key_uri() {
        let config = token::CcidSignerConfig::new(
            None,
            "pkcs11:id=%01".to_string(),
            None,
            KeyAlgorithm::Gost3410_2012_256,
            None,
        );

        let error = token::TokenSigner::sign_digest(
            &config,
            DigestAlgorithm::Gost3411_2012_256,
            &[0u8; 32],
        )
        .expect_err("pkcs11 URI on CCID signer should fail");

        assert!(matches!(error, CliError::Usage(msg) if msg.contains("rutoken:")));
    }

    #[test]
    fn ccid_probe_command_parses_exchange_log() {
        let temp = TempDir::new();
        let exchange_log = temp.path().join("probe.log");

        let command = CcidProbeCommand::parse([
            OsString::from("--ccid-reader"),
            OsString::from("Rutoken ECP"),
            OsString::from("--exchange-log"),
            exchange_log.clone().into_os_string(),
        ])
        .expect("probe command should parse");

        assert_eq!(command.ccid_reader.as_deref(), Some("Rutoken ECP"));
        assert_eq!(
            command.exchange_log.as_deref(),
            Some(exchange_log.as_path())
        );
    }

    #[test]
    fn ccid_raw_sign_command_requires_pin_env() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let output = temp.path().join("document.sig");

        let error = CcidRawSignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%01"),
        ])
        .expect_err("raw sign should require a PIN environment variable");

        assert!(matches!(error, CliError::Usage(message) if message.contains("--pin-env")));
    }

    #[test]
    fn ccid_log_redacts_verify_pin_apdu() {
        let apdu = rutoken::verify_pin(b"12345678");

        let (bytes, redacted) = ccid::redacted_apdu_bytes_for_log(&apdu).expect("APDU encodes");

        assert!(redacted);
        assert!(!bytes.windows(8).any(|window| window == b"12345678"));
        assert_eq!(&bytes[5..13], b"********");
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be valid")
                .as_nanos();
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!("cryptokiddie-tests-{unique}-{seq}"));
            fs::create_dir_all(&path).expect("temp dir should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write_file(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("temp file should be written");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
