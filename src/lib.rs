use std::{
    ffi::OsString,
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
};

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
            (0x00, 0x2A, 0x9E, 0x9A) => "PSO_COMPUTE_DIGITAL_SIGNATURE",
            _ => "APDU",
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

pub mod pcsc_transport {
    use super::{
        CliError, DigestAlgorithm,
        apdu::{CommandApdu, ResponseApdu},
        ccid,
    };
    use pcsc::{Context, Protocols, Scope, ShareMode};
    use std::path::Path;

    pub struct PcscDevice {
        card: pcsc::Card,
        logger: Option<ccid::ExchangeLogger>,
        sequence: u8,
    }

    impl PcscDevice {
        pub fn open(
            reader_filter: Option<&str>,
            exchange_log: Option<&Path>,
        ) -> Result<Self, CliError> {
            let context = Context::establish(Scope::User).map_err(|error| {
                CliError::Message(format!("failed to initialize PC/SC: {error}"))
            })?;
            let mut readers_buf = [0; 2048];
            let readers = context.list_readers(&mut readers_buf).map_err(|error| {
                CliError::Message(format!("failed to list PC/SC readers: {error}"))
            })?;

            let mut skipped_readers = Vec::new();
            for reader in readers {
                let reader_name = reader.to_string_lossy().into_owned();
                if let Some(filter) = reader_filter
                    && !reader_name.contains(filter)
                {
                    skipped_readers.push(reader_name);
                    continue;
                }

                let card = context
                    .connect(reader, ShareMode::Shared, Protocols::ANY)
                    .map_err(|error| {
                        CliError::Message(format!(
                            "failed to connect to PC/SC reader {reader_name}: {error}"
                        ))
                    })?;
                let mut logger = exchange_log.map(ccid::ExchangeLogger::create).transpose()?;
                if let Some(logger) = logger.as_mut() {
                    logger.note(&format!("opened pcsc_reader={reader_name}"))?;
                }
                return Ok(Self {
                    card,
                    logger,
                    sequence: 0,
                });
            }

            if let Some(filter) = reader_filter {
                Err(CliError::Message(format!(
                    "PC/SC reader containing {filter:?} not found; saw readers: {}",
                    skipped_readers.join(", ")
                )))
            } else {
                Err(CliError::Message(
                    "no PC/SC smart-card readers found".to_string(),
                ))
            }
        }

        pub fn transmit(&mut self, apdu: &CommandApdu) -> Result<ResponseApdu, CliError> {
            let sequence = self.next_sequence();
            let command = apdu.to_bytes()?;
            let (log_command, redacted) = ccid::redacted_apdu_bytes_for_log(apdu)?;
            self.log_bytes(
                "out",
                "pcsc-apdu",
                ccid::apdu_label(apdu),
                sequence,
                &log_command,
                redacted,
            )?;

            let mut response_buf = [0u8; pcsc::MAX_BUFFER_SIZE];
            let response = self
                .card
                .transmit(&command, &mut response_buf)
                .map_err(|error| CliError::Message(format!("PC/SC transmit failed: {error}")))?;
            let response = response.to_vec();
            self.log_bytes("in", "pcsc-apdu", "RESPONSE", sequence, &response, false)?;
            if let Some(logger) = self.logger.as_mut() {
                logger.flush()?;
            }
            ResponseApdu::parse(&response)
        }

        fn next_sequence(&mut self) -> u8 {
            let sequence = self.sequence;
            self.sequence = self.sequence.wrapping_add(1);
            sequence
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

    pub fn probe(
        reader_filter: Option<&str>,
        exchange_log: Option<&Path>,
    ) -> Result<String, CliError> {
        let mut device = PcscDevice::open(reader_filter, exchange_log)?;
        let select = device.transmit(&super::rutoken::select_master_file())?;
        Ok(format!(
            "pcsc probe\nselect_mf_sw={:02x}{:02x}",
            select.sw1, select.sw2
        ))
    }

    pub fn sign_digest(
        reader_filter: Option<&str>,
        exchange_log: Option<&Path>,
        key_id: u8,
        pin: Option<&[u8]>,
        digest_algorithm: DigestAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, CliError> {
        let mut device = PcscDevice::open(reader_filter, exchange_log)?;

        let resp = device.transmit(&super::rutoken::select_master_file())?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "SELECT MF failed over PC/SC: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        if let Some(pin_bytes) = pin {
            let mut resp = device.transmit(&super::rutoken::verify_pin(pin_bytes))?;
            if resp.sw1 == 0x6F && resp.sw2 == 0x86 {
                let logout = device.transmit(&super::rutoken::logout())?;
                if !logout.is_success() {
                    return Err(CliError::Message(format!(
                        "LOGOUT failed over PC/SC after VERIFY returned 6f86: SW {:02x}{:02x}",
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
                    "VERIFY PIN failed over PC/SC: SW {:02x}{:02x}",
                    resp.sw1, resp.sw2
                )));
            }
        }

        select_private_key_file(&mut device, key_id)?;

        let resp = device.transmit(&super::rutoken::manage_security_environment_for_signing(
            key_id,
        ))?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "MSE SET (key reference 0x{key_id:02x}) failed over PC/SC: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        let signature_len = match digest_algorithm {
            DigestAlgorithm::Gost3411_2012_256 => 64u8,
            DigestAlgorithm::Gost3411_2012_512 => 128u8,
            _ => {
                return Err(CliError::Message(format!(
                    "PC/SC Rutoken transport only supports GOST digests, got {}",
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
                "PSO COMPUTE DIGITAL SIGNATURE failed over PC/SC: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        if resp.data.len() != signature_len as usize {
            return Err(CliError::Message(format!(
                "PC/SC signature length mismatch: expected {} bytes, token returned {}",
                signature_len,
                resp.data.len()
            )));
        }

        Ok(super::rutoken::signature_from_token(resp.data))
    }

    fn select_private_key_file(device: &mut PcscDevice, key_id: u8) -> Result<(), CliError> {
        let mut failures = Vec::new();
        for sequence in super::rutoken::private_key_file_select_sequences(key_id) {
            let reset = device.transmit(&super::rutoken::select_master_file())?;
            if !reset.is_success() {
                return Err(CliError::Message(format!(
                    "SELECT MF before private key selection failed over PC/SC: SW {:02x}{:02x}",
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
            "SELECT private key file (key reference 0x{key_id:02x}) failed over PC/SC: {}",
            failures.join(", ")
        )))
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

    fn select_file_by_path(path: impl Into<Vec<u8>>) -> CommandApdu {
        CommandApdu::new(0x00, 0xA4, 0x08, 0x0C).with_data(path)
    }

    fn select_file_by_id(file_id: u16) -> CommandApdu {
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
        let mut token_digest = digest.to_vec();
        token_digest.reverse();

        CommandApdu::new(0x00, 0x2A, 0x9E, 0x9A)
            .with_data(token_digest)
            .with_le(signature_len)
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
        cert::{CertificateChoices, x509::Certificate},
        content_info::{CmsVersion, ContentInfo},
        signed_data::{
            CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
            SignedData, SignerIdentifier, SignerInfo, SignerInfos,
        },
    };
    use der::{Any, AnyRef, Decode, Encode, asn1::OctetString};
    use spki::AlgorithmIdentifierOwned;

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
                sid: SignerIdentifier::from(&certificate),
                digest_alg: digest_algorithm,
                signed_attrs: None,
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

    pub fn cms_crate_backend() -> &'static str {
        std::any::type_name::<cms::content_info::ContentInfo>()
    }

    fn algorithm_identifier(oid: const_oid::ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
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

            match sign_digest_direct(self, uri.id, pin.as_deref(), digest_algorithm, digest) {
                Ok(signature) => Ok(signature),
                Err(error) if should_try_pcsc(&error) => super::pcsc_transport::sign_digest(
                    self.reader.as_deref(),
                    self.exchange_log.as_deref(),
                    uri.id,
                    pin.as_deref(),
                    digest_algorithm,
                    digest,
                ),
                Err(error) => Err(error),
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
        let mut device = super::ccid::CcidDevice::open_with_exchange_log(
            config.reader.as_deref(),
            config.exchange_log.as_deref(),
        )?;
        device.power_on()?;

        let resp = device.transmit(&super::rutoken::select_master_file())?;
        if !resp.is_success() {
            return Err(CliError::Message(format!(
                "SELECT MF failed: SW {:02x}{:02x}",
                resp.sw1, resp.sw2
            )));
        }

        if let Some(pin_bytes) = pin {
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
        }

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

    fn select_private_key_file(
        device: &mut super::ccid::CcidDevice,
        key_id: u8,
    ) -> Result<(), CliError> {
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

    fn should_try_pcsc(error: &CliError) -> bool {
        match error {
            CliError::Message(message) => {
                message.contains("failed to claim CCID interface")
                    || message.contains("Access denied")
            }
            CliError::Usage(_) => false,
        }
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

const OID_GOST3410_2012_256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.643.7.1.1.1.1");
const OID_GOST3410_2012_512: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.643.7.1.1.1.2");
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
                Ok(OID_GOST3410_2012_256)
            }
            (Self::Gost3410_2012_512, DigestAlgorithm::Gost3411_2012_512) => {
                Ok(OID_GOST3410_2012_512)
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
        Some(command) if command == "ccid-sign-raw" => {
            let command = CcidRawSignCommand::parse(args)?;
            command.run()
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown command: {}\n\n{}",
            command.to_string_lossy(),
            usage()
        ))),
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
                token::TokenSigner::sign_digest(&signer, self.digest, &digest)
            }
            Transport::Ccid => {
                let signer = token::CcidSignerConfig::new(
                    self.ccid_reader.clone(),
                    self.key_uri.clone(),
                    self.pin_env.clone(),
                    self.key_algorithm,
                    self.exchange_log.clone(),
                );
                token::TokenSigner::sign_digest(&signer, self.digest, &digest)
            }
        }?;
        let cms_der = cms_envelope::build_signed_data_der(&cms_input, &document, signature)?;
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
        match self.run_direct() {
            Ok(output) => Ok(output),
            Err(error) if should_try_pcsc_probe(&error) => {
                let output = pcsc_transport::probe(
                    self.ccid_reader.as_deref(),
                    self.exchange_log.as_deref(),
                )?;
                let mut lines = output.lines().map(str::to_string).collect::<Vec<_>>();
                if let Some(path) = &self.exchange_log {
                    lines.push(format!("exchange_log={}", path.display()));
                }
                Ok(lines.join("\n"))
            }
            Err(error) => Err(error),
        }
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

fn should_try_pcsc_probe(error: &CliError) -> bool {
    match error {
        CliError::Message(message) => {
            message.contains("failed to claim CCID interface") || message.contains("Access denied")
        }
        CliError::Usage(_) => false,
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
         \n\
         Options:\n\
           --digest <NAME>           Hash algorithm: gost12-256 (default), gost12-512,\n\
                                     sha256, sha384, or sha512\n\
           --key-algorithm <NAME>    Signing key algorithm: gost3410-2012-256 (default\n\
                                     for GOST digests), gost3410-2012-512, ecdsa\n\
                                     (default for SHA-2 digests), or rsa\n\
           --transport <NAME>        pkcs11 (default) or ccid\n\
           --pkcs11-module <FILE>    PKCS#11 module used by the cryptoki Rust crate\n\
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
        CcidProbeCommand, CcidRawSignCommand, CliError, DigestAlgorithm, KeyAlgorithm, SignCommand,
        Transport, apdu, ccid, cms_envelope, compute_digest, gost, run_cli, rutoken, token,
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
            "1.2.643.7.1.1.1.1"
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

        let error = cms_envelope::build_signed_data_der(&input, b"hello", Vec::new())
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
        let expected_digest = (0u8..32).rev().collect::<Vec<_>>();

        // CLA INS P1 P2 Lc=32 reversed digest[0..32] Le=64
        assert_eq!(&bytes[..4], [0x00, 0x2A, 0x9E, 0x9A]);
        assert_eq!(bytes[4], 32);
        assert_eq!(&bytes[5..37], expected_digest.as_slice());
        assert_eq!(bytes[37], 64);
    }

    #[test]
    fn rutoken_pso_cds_apdu_for_gost512() {
        let digest = (0u8..64).collect::<Vec<_>>();
        let apdu = rutoken::pso_compute_digital_signature(&digest, 128);
        let bytes = apdu.to_bytes().expect("APDU should serialize");
        let expected_digest = (0u8..64).rev().collect::<Vec<_>>();

        assert_eq!(&bytes[..4], [0x00, 0x2A, 0x9E, 0x9A]);
        assert_eq!(bytes[4], 64);
        assert_eq!(bytes[5..69], expected_digest[..]);
        assert_eq!(bytes[69], 128);
    }

    #[test]
    fn rutoken_signature_from_token_reverses_bytes() {
        assert_eq!(
            rutoken::signature_from_token(vec![1, 2, 3, 4]),
            vec![4, 3, 2, 1]
        );
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
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be valid")
                .as_nanos();
            let path = env::temp_dir().join(format!("cryptokiddie-tests-{unique}"));
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
