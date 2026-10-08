use super::mach_sys::{
    self, mach_msg_header_t, mach_msg_ool_descriptor_t, mach_msg_ool_ports_descriptor_t,
    mach_msg_port_descriptor_t, mach_port_t,
};
use super::{
    allocate_vm_pages, channel, mach_port_allocate, mach_port_mod_release, mach_task_self,
    mark_regions_for_deallocation, parse_message, read_at, MachError, Message, OsIpcOneShotServer,
    OsIpcSender, ReceivedPayload, KERN_SUCCESS, MACH_MSGH_BITS_COMPLEX, MACH_MSG_OOL_DESCRIPTOR,
    MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_SUCCESS, MACH_MSG_TIMEOUT_NONE, MACH_MSG_TYPE_COPY_SEND,
    MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_VIRTUAL_COPY, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE,
    MACH_PORT_RIGHT_SEND, MACH_SEND_MSG,
};
use mach2::message::{
    MACH_MSG_OOL_PORTS_DESCRIPTOR, MACH_MSG_OOL_VOLATILE_DESCRIPTOR, MACH_MSG_PHYSICAL_COPY,
};
use std::{mem, ptr, slice};

const HEADER_SIZE: usize = mem::size_of::<mach_msg_header_t>();

/// The bytes of an integer or of a Mach struct without padding.
fn as_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: callers pass types whose bytes are all initialized.
    unsafe { slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>()) }
}

/// A message assembled byte by byte in the layout `OsIpcSender::send` uses,
/// so that tests can make it malformed.
struct RawMessage {
    bits: u32,
    body: Vec<u8>,
}

impl RawMessage {
    fn new(complex: bool, descriptor_count: u32) -> RawMessage {
        let bits = if complex { MACH_MSGH_BITS_COMPLEX } else { 0 };
        RawMessage {
            bits,
            body: Vec::new(),
        }
        .push(&descriptor_count)
    }

    fn push<T>(mut self, value: &T) -> RawMessage {
        self.body.extend_from_slice(as_bytes(value));
        self
    }

    fn port(self, name: mach_port_t, disposition: u32) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_port_descriptor_t = unsafe { mem::zeroed() };
        descriptor.name = name;
        descriptor.set_disposition(disposition);
        descriptor.set_type(MACH_MSG_PORT_DESCRIPTOR);
        self.push(&descriptor)
    }

    /// Appends an out-of-line descriptor; `type_` may also be the volatile or
    /// the ports variant, which share its layout.
    fn region_with(self, address: *mut u8, size: usize, type_: u32, copy: u32) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_ool_descriptor_t = unsafe { mem::zeroed() };
        descriptor.address = address as *mut _;
        descriptor.size = size as u32;
        descriptor.set_copy(copy);
        descriptor.set_type(type_);
        self.push(&descriptor)
    }

    fn region(self, address: *mut u8, size: usize) -> RawMessage {
        self.region_with(
            address,
            size,
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
    }

    fn port_array(self, names: &[mach_port_t], disposition: u32) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_ool_ports_descriptor_t = unsafe { mem::zeroed() };
        descriptor.address = names.as_ptr() as *mut _;
        descriptor.count = names.len() as u32;
        descriptor.set_copy(MACH_MSG_VIRTUAL_COPY);
        descriptor.set_disposition(disposition);
        descriptor.set_type(MACH_MSG_OOL_PORTS_DESCRIPTOR);
        self.push(&descriptor)
    }

    /// Appends the inline data flag and, if `flag` is not zero, a payload
    /// whose size field says `declared_size`.
    fn payload(mut self, flag: u8, declared_size: usize, data: &[u8]) -> RawMessage {
        self = self.push(&flag);
        if flag == 0 {
            return self;
        }
        while (HEADER_SIZE + self.body.len()) % 8 != 0 {
            self = self.push(&0u8);
        }
        self = self.push(&declared_size);
        self.body.extend_from_slice(data);
        self
    }

    fn inline_payload(self, data: &[u8]) -> RawMessage {
        self.payload(1, data.len(), data)
    }

    fn out_of_line_payload(self) -> RawMessage {
        self.payload(0, 0, &[])
    }

    /// The header followed by the body, padded to a multiple of four bytes.
    fn bytes(&self, remote_port: mach_port_t) -> Vec<u8> {
        let size = (HEADER_SIZE + self.body.len()).next_multiple_of(4);
        let header = mach_msg_header_t {
            msgh_bits: MACH_MSG_TYPE_COPY_SEND as u32 | self.bits,
            msgh_size: size as u32,
            msgh_remote_port: remote_port,
            msgh_local_port: MACH_PORT_NULL,
            msgh_voucher_port: MACH_PORT_NULL,
            msgh_id: 0,
        };
        let mut bytes = as_bytes(&header).to_vec();
        bytes.extend_from_slice(&self.body);
        bytes.resize(size, 0);
        bytes
    }

    /// Sends the message to `port`, the name of a send right.
    fn send(&self, port: mach_port_t) {
        let bytes = self.bytes(port);
        let mut buffer = vec![0u64; bytes.len().div_ceil(8)];
        // SAFETY: `buffer` holds at least `bytes.len()` bytes and is aligned
        // for the header.
        let result = unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.as_mut_ptr() as *mut u8, bytes.len());
            mach_sys::mach_msg(
                buffer.as_mut_ptr() as *mut mach_msg_header_t,
                MACH_SEND_MSG,
                bytes.len() as u32,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(result, MACH_MSG_SUCCESS);
    }
}

fn send_refs(name: mach_port_t) -> u32 {
    let mut refs = 0;
    // SAFETY: a plain kernel call with a valid out pointer.
    let result = unsafe {
        mach_sys::mach_port_get_refs(mach_task_self(), name, MACH_PORT_RIGHT_SEND, &mut refs)
    };
    assert_eq!(result, KERN_SUCCESS);
    refs
}

/// A page of this task's memory filled with a known byte.
struct Page(*mut u8);

impl Page {
    const SIZE: usize = 4096;
    const FILL: u8 = 0xa5;

    fn new() -> Page {
        // SAFETY: `allocate_vm_pages` returns `SIZE` writable bytes.
        unsafe {
            let address = allocate_vm_pages(Page::SIZE);
            ptr::write_bytes(address, Page::FILL, Page::SIZE);
            Page(address)
        }
    }

    fn is_intact(&self) -> bool {
        // SAFETY: the page stays mapped until `drop`.
        unsafe { slice::from_raw_parts(self.0, Page::SIZE) }
            .iter()
            .all(|byte| *byte == Page::FILL)
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: deallocates the page allocated in `new`.
        let result =
            unsafe { mach_sys::vm_deallocate(mach_task_self(), self.0 as usize, Page::SIZE) };
        assert_eq!(result, KERN_SUCCESS);
    }
}

#[test]
fn one_shot_server_rejects_a_simple_message_that_claims_a_region() {
    let (server, name) = OsIpcOneShotServer::new().unwrap();
    let sender = OsIpcSender::connect(name).unwrap();
    let page = Page::new();
    // The kernel does not translate the body of a simple message, so this
    // "descriptor" is plain data naming an address in the receiver.
    RawMessage::new(false, 1)
        .region(page.0, Page::SIZE)
        .out_of_line_payload()
        .send(sender.port);

    let result = server.accept_with_peer_pid();

    assert_eq!(result.err(), Some(MachError::RcvMalformedMessage));
    assert!(page.is_intact());
}

#[test]
fn receiver_destroys_a_message_with_a_port_after_a_region() {
    let (sender, receiver) = channel().unwrap();
    let port = mach_port_allocate(MACH_PORT_RIGHT_RECEIVE).unwrap();
    let page = Page::new();
    RawMessage::new(true, 2)
        .region(page.0, Page::SIZE)
        .port(port, MACH_MSG_TYPE_MAKE_SEND as u32)
        .inline_payload(&[])
        .send(sender.port);

    let result = receiver.recv();

    assert_eq!(result.err(), Some(MachError::RcvMalformedMessage));
    assert_eq!(send_refs(port), 0);
    sender.send(b"still open", vec![], vec![]).unwrap();
    assert_eq!(receiver.recv().unwrap().data, b"still open");
    mach_port_mod_release(port, MACH_PORT_RIGHT_RECEIVE).unwrap();
}

#[test]
fn receiver_destroys_a_message_with_an_array_of_ports() {
    let (sender, receiver) = channel().unwrap();
    let port = mach_port_allocate(MACH_PORT_RIGHT_RECEIVE).unwrap();
    RawMessage::new(true, 1)
        .port_array(&[port, port], MACH_MSG_TYPE_MAKE_SEND as u32)
        .inline_payload(&[])
        .send(sender.port);

    let result = receiver.recv();

    assert_eq!(result.err(), Some(MachError::RcvMalformedMessage));
    assert_eq!(send_refs(port), 0);
    mach_port_mod_release(port, MACH_PORT_RIGHT_RECEIVE).unwrap();
}

#[test]
fn rejected_message_has_every_region_marked_for_deallocation() {
    let mut bytes = RawMessage::new(true, 4)
        .port(7, 0)
        .region_with(
            0x1000 as *mut u8,
            16,
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_PHYSICAL_COPY,
        )
        .region_with(
            0x2000 as *mut u8,
            16,
            MACH_MSG_OOL_VOLATILE_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
        .port_array(&[7], 0)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);
    let original = bytes.clone();

    mark_regions_for_deallocation(&mut bytes);

    let first_region = mem::size_of::<Message>() + mem::size_of::<mach_msg_port_descriptor_t>();
    assert_eq!(bytes[..first_region], original[..first_region]);
    let expected_types = [
        MACH_MSG_OOL_DESCRIPTOR,
        MACH_MSG_OOL_DESCRIPTOR,
        MACH_MSG_OOL_PORTS_DESCRIPTOR,
    ];
    for (index, expected_type) in expected_types.into_iter().enumerate() {
        let offset = first_region + index * mem::size_of::<mach_msg_ool_descriptor_t>();
        // SAFETY: the descriptor is made of integers and a raw pointer.
        let region: mach_msg_ool_descriptor_t = unsafe { read_at(&bytes, offset) }.unwrap();
        assert_eq!(region.deallocate(), 1);
        assert_eq!(region.type_(), expected_type);
    }
    let regions_end = first_region + 3 * mem::size_of::<mach_msg_ool_descriptor_t>();
    assert_eq!(bytes[regions_end..], original[regions_end..]);
}

#[test]
fn receiver_accepts_a_hand_built_well_formed_message() {
    let (sender, receiver) = channel().unwrap();
    RawMessage::new(true, 0)
        .inline_payload(b"hello")
        .send(sender.port);

    assert_eq!(receiver.recv().unwrap().data, b"hello");
}

#[test]
fn receiver_accepts_an_empty_out_of_line_payload() {
    let (sender, receiver) = channel().unwrap();
    RawMessage::new(true, 1)
        .region(ptr::null_mut(), 0)
        .out_of_line_payload()
        .send(sender.port);

    assert!(receiver.recv().unwrap().data.is_empty());
}

#[test]
fn parse_finds_ports_regions_and_an_inline_payload() {
    let bytes = RawMessage::new(true, 3)
        .port(7, 0)
        .port(8, 0)
        .region(0x1000 as *mut u8, 16)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    let parsed = parse_message(&bytes).unwrap();

    assert_eq!(parsed.port_names, [7, 8]);
    assert_eq!(parsed.shared_memory_regions, [(0x1000 as *mut u8, 16)]);
    match parsed.payload {
        ReceivedPayload::Inline(range) => assert_eq!(&bytes[range], b"hi"),
        ReceivedPayload::OutOfLine(..) => panic!("expected an inline payload"),
    }
}

#[test]
fn parse_accepts_an_inline_payload_that_ends_the_message() {
    let bytes = RawMessage::new(false, 0)
        .inline_payload(b"abcd")
        .bytes(MACH_PORT_NULL);

    let parsed = parse_message(&bytes).unwrap();

    match parsed.payload {
        ReceivedPayload::Inline(range) => {
            assert_eq!(range.end, bytes.len());
            assert_eq!(&bytes[range], b"abcd");
        },
        ReceivedPayload::OutOfLine(..) => panic!("expected an inline payload"),
    }
}

#[test]
fn parse_takes_an_out_of_line_payload_from_the_last_region() {
    let bytes = RawMessage::new(true, 2)
        .region(0x1000 as *mut u8, 16)
        .region(0x2000 as *mut u8, 32)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    let parsed = parse_message(&bytes).unwrap();

    assert_eq!(parsed.shared_memory_regions, [(0x1000 as *mut u8, 16)]);
    match parsed.payload {
        ReceivedPayload::OutOfLine(address, size) => {
            assert_eq!((address, size), (0x2000 as *mut u8, 32))
        },
        ReceivedPayload::Inline(_) => panic!("expected an out-of-line payload"),
    }
}

#[test]
fn parse_rejects_a_simple_message_that_claims_descriptors() {
    let bytes = RawMessage::new(false, 1)
        .region(0x1000 as *mut u8, 16)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_more_descriptors_than_the_message_holds() {
    let bytes = RawMessage::new(true, u32::MAX)
        .region(0x1000 as *mut u8, 16)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_a_port_after_a_region() {
    let bytes = RawMessage::new(true, 2)
        .region(0x1000 as *mut u8, 16)
        .port(7, 0)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_descriptor_types_that_send_does_not_use() {
    let bytes = RawMessage::new(true, 1)
        .region_with(
            0x1000 as *mut u8,
            16,
            MACH_MSG_OOL_PORTS_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_an_inline_data_flag_that_is_not_a_bool() {
    let bytes = RawMessage::new(false, 0)
        .payload(2, 2, b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_an_inline_payload_longer_than_the_message() {
    for declared_size in [4096, usize::MAX] {
        let bytes = RawMessage::new(false, 0)
            .payload(1, declared_size, b"hi")
            .bytes(MACH_PORT_NULL);

        assert!(parse_message(&bytes).is_none());
    }
}

#[test]
fn parse_rejects_an_out_of_line_payload_without_a_region() {
    let bytes = RawMessage::new(false, 0)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_a_truncated_message() {
    let bytes = RawMessage::new(false, 0)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    for length in [0, HEADER_SIZE, HEADER_SIZE + 4, bytes.len() - 4] {
        assert!(parse_message(&bytes[..length]).is_none());
    }
}
