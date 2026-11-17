//! Reading the first packet of each arriving connection attempt at the network card, on macOS and FreeBSD.
//!
//! These systems hand packets to a program through a device (`/dev/bpf`). The kernel is given a filter first, so
//! only the opening packet of a TCP connection ever reaches this program, and only its first bytes: who sent it
//! and which port it asked for. What follows in a connection is never read. Needs root.

#![cfg(any(target_os = "macos", target_os = "freebsd"))]

use std::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
struct Step {
    code: u16,
    yes: u8,
    no: u8,
    value: u32,
}

#[repr(C)]
struct Program {
    length: libc::c_uint,
    steps: *const Step,
}

// The words every packet record is rounded up to: the size the system itself uses.
#[cfg(target_os = "macos")]
const ROUND: usize = 4;
#[cfg(target_os = "freebsd")]
const ROUND: usize = std::mem::size_of::<libc::c_long>();

fn device() -> std::io::Result<libc::c_int> {
    // One name on FreeBSD; numbered devices on macOS, each for one reader at a time.
    let mut names = vec!["/dev/bpf".to_string()];
    names.extend((0..64).map(|number| format!("/dev/bpf{number}")));
    for name in names {
        let Ok(path) = std::ffi::CString::new(name) else { continue };
        let handle = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if handle >= 0 {
            return Ok(handle);
        }
    }
    Err(std::io::Error::last_os_error())
}

/// Read, at this network card, the opening packet of every TCP connection attempt that arrives, and hand each
/// (from its network header on) to `seen` until `stop` says so. Returns at once where the card cannot be opened
/// or is not an Ethernet-like one.
pub fn listen(stop: &AtomicBool, card: &str, mut seen: impl FnMut(&[u8])) -> std::io::Result<()> {
    let handle = device()?;
    let fail = |handle: libc::c_int| -> std::io::Error {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(handle) };
        error
    };
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(card.bytes().take(15)) {
        *slot = byte as libc::c_char;
    }
    let (mut size, mut kind, on, off): (libc::c_uint, libc::c_uint, libc::c_uint, libc::c_uint) = (32768, 0, 1, 0);
    let wait = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // Ethernet: fourteen bytes, then the network header. TCP, not a later piece of a split packet, with "open"
    // set and "answer" not set, of either kind of address: pass the first 128 bytes. Anything else: nothing.
    let steps = [
        Step { code: 0x28, yes: 0, no: 0, value: 12 },
        Step { code: 0x15, yes: 0, no: 8, value: 0x0800 },
        Step { code: 0x30, yes: 0, no: 0, value: 23 },
        Step { code: 0x15, yes: 0, no: 13, value: 6 },
        Step { code: 0x28, yes: 0, no: 0, value: 20 },
        Step { code: 0x45, yes: 11, no: 0, value: 0x1fff },
        Step { code: 0xb1, yes: 0, no: 0, value: 14 },
        Step { code: 0x50, yes: 0, no: 0, value: 27 },
        Step { code: 0x54, yes: 0, no: 0, value: 0x12 },
        Step { code: 0x15, yes: 6, no: 7, value: 0x02 },
        Step { code: 0x15, yes: 0, no: 6, value: 0x86dd },
        Step { code: 0x30, yes: 0, no: 0, value: 20 },
        Step { code: 0x15, yes: 0, no: 4, value: 6 },
        Step { code: 0x30, yes: 0, no: 0, value: 67 },
        Step { code: 0x54, yes: 0, no: 0, value: 0x12 },
        Step { code: 0x15, yes: 0, no: 1, value: 0x02 },
        Step { code: 0x06, yes: 0, no: 0, value: 128 },
        Step { code: 0x06, yes: 0, no: 0, value: 0 },
    ];
    let program = Program { length: steps.len() as libc::c_uint, steps: steps.as_ptr() };
    let set = unsafe {
        libc::ioctl(handle, libc::BIOCSBLEN, &mut size) == 0
            && libc::ioctl(handle, libc::BIOCSETIF, &request) == 0
            && libc::ioctl(handle, libc::BIOCGDLT, &mut kind) == 0
            && kind == 1 // Ethernet, and what looks like it
            && libc::ioctl(handle, libc::BIOCIMMEDIATE, &on) == 0
            && libc::ioctl(handle, libc::BIOCSSEESENT, &off) == 0 // only what arrives
            && libc::ioctl(handle, libc::BIOCSRTIMEOUT, &wait) == 0
            && libc::ioctl(handle, libc::BIOCSETF, &program) == 0
            && libc::ioctl(handle, libc::BIOCGBLEN, &mut size) == 0
    };
    if !set {
        return Err(fail(handle));
    }
    let mut data = vec![0u8; size as usize];
    while !stop.load(Ordering::SeqCst) {
        let got = unsafe { libc::read(handle, data.as_mut_ptr() as *mut libc::c_void, data.len()) };
        if got < 0 {
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if error == libc::EAGAIN || error == libc::EINTR || error == libc::ETIMEDOUT {
                continue;
            }
            break;
        }
        records(&data[..got as usize], &mut seen);
    }
    unsafe { libc::close(handle) };
    Ok(())
}

/// What one read gives: records one after another, each a small header saying how long it and its packet are.
fn records(data: &[u8], seen: &mut impl FnMut(&[u8])) {
    let header = std::mem::size_of::<libc::bpf_hdr>();
    let mut at = 0;
    while at + header <= data.len() {
        let record: libc::bpf_hdr = unsafe { std::ptr::read_unaligned(data[at..].as_ptr() as *const libc::bpf_hdr) };
        let (start, kept) = (at + record.bh_hdrlen as usize, record.bh_caplen as usize);
        if record.bh_hdrlen == 0 || start + kept > data.len() {
            break;
        }
        if kept > 14 {
            seen(&data[start + 14..start + kept]);
        }
        at += (record.bh_hdrlen as usize + kept).div_ceil(ROUND) * ROUND;
    }
}
