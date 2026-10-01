//! Reference eBPF interpreter: the semantic oracle for ePass tests.
//!
//! It shares no code with the compiler under test. Semantics follow RFC 9669
//! (BPF ISA) for ISA v1–v4: ALU32/ALU64 including sdiv/smod and movsx,
//! byte swaps, JMP/JMP32 including JSET and `gotol`, sign-extending loads,
//! atomics, LD_IMM64 pseudo sources, LD_ABS/IND, bpf-to-bpf calls, and a
//! deterministic model of common helpers.
//!
//! A run returns r0 (or a fault), the final ctx and stack bytes, which stack
//! bytes were written, and a trace of observable helper effects (arguments of
//! known helpers, perf/ringbuf output, map updates). Two programs are
//! equivalent for a given input when all of these agree (see [`compare`]).

pub mod asm;

use std::collections::BTreeMap;
use std::fmt;

/// Stack bytes per frame.
pub const STACK_SIZE: u64 = 512;
/// Maximum call depth (main frame included).
pub const MAX_FRAMES: u64 = 8;

/// Base address of the program context.
pub const CTX_BASE: u64 = 0x1000_0000;
/// Top (exclusive) of the main frame; frame k has r10 = STACK_TOP - k*512.
pub const STACK_TOP: u64 = 0x7000_0000;
/// Base of the map-value address space.
pub const MAPVAL_BASE: u64 = 0x2000_0000;
/// Base of map handles (value of an `ld_imm64 map_fd`).
pub const MAP_HANDLE_BASE: u64 = 0x5000_0000_0000;
/// Base of symbolic BTF-id / function values.
pub const SYM_BASE: u64 = 0x6000_0000_0000;
/// Poison written into r1..r5 after every helper call.
pub const CLOBBER_BASE: u64 = 0xdead_0000_0000_0000;
/// Initial stack fill byte (so reads of unwritten stack are deterministic).
pub const STACK_FILL: u8 = 0xaa;

/// A decoded instruction slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    pub fn decode(raw: u64) -> Insn {
        Insn {
            code: raw as u8,
            dst: ((raw >> 8) & 0xf) as u8,
            src: ((raw >> 12) & 0xf) as u8,
            off: (raw >> 16) as u16 as i16,
            imm: (raw >> 32) as u32 as i32,
        }
    }

    pub fn encode(self) -> u64 {
        (self.code as u64)
            | (((self.dst & 0xf) | ((self.src & 0xf) << 4)) as u64) << 8
            | (self.off as u16 as u64) << 16
            | (self.imm as u32 as u64) << 32
    }
}

/// Map definition for the helper model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapDef {
    pub key_size: u32,
    pub value_size: u32,
}

impl Default for MapDef {
    fn default() -> Self {
        MapDef {
            key_size: 4,
            value_size: 64,
        }
    }
}

/// Inputs to one run.
#[derive(Clone, Debug)]
pub struct Input {
    pub ctx: Vec<u8>,
    /// Packet bytes for LD_ABS/IND.
    pub packet: Vec<u8>,
    /// Map definitions by fd or index (as used in `ld_imm64` imm).
    pub maps: BTreeMap<u32, MapDef>,
    /// Map lookups of absent keys create a zero-filled entry (true) or
    /// return NULL (false).
    pub lookup_creates: bool,
    pub max_steps: u64,
}

impl Default for Input {
    fn default() -> Self {
        Input {
            ctx: vec![0; 256],
            packet: Vec::new(),
            maps: BTreeMap::new(),
            lookup_creates: true,
            max_steps: 1_000_000,
        }
    }
}

/// Why a run stopped without reaching `exit` of the main frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    OutOfBounds { pc: usize, addr: u64, size: u64 },
    BadInsn { pc: usize, code: u8 },
    PcOutOfRange { pc: i64 },
    StackOverflow { pc: usize },
    Unimplemented { pc: usize, what: &'static str },
    StepLimit,
}

/// Final state of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Exit(u64),
    Fault(Fault),
}

/// One observable helper effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A known helper was called with these arguments.
    Call { id: i32, args: Vec<u64> },
    /// Bytes emitted by perf_event_output / ringbuf_output / ringbuf_submit.
    Output { id: i32, data: Vec<u8> },
    /// A map entry was written.
    MapUpdate { map: u64, key: Vec<u8>, value: Vec<u8> },
    MapDelete { map: u64, key: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct RunResult {
    pub outcome: Outcome,
    pub ctx: Vec<u8>,
    /// Main-frame stack, index 0 = address STACK_TOP-512.
    pub stack: Vec<u8>,
    pub stack_written: Vec<bool>,
    pub events: Vec<Event>,
    pub steps: u64,
}

impl RunResult {
    pub fn r0(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Exit(v) => Some(v),
            Outcome::Fault(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
struct MapEntry {
    addr: u64,
    value: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct MapState {
    entries: BTreeMap<Vec<u8>, MapEntry>,
    /// Backing store for direct-value access (`ld_imm64 map_value`).
    direct: Option<(u64, Vec<u8>)>,
}

struct Frame {
    ret_pc: usize,
    saved: [u64; 4],
}

struct Machine<'a> {
    prog: &'a [Insn],
    input: &'a Input,
    regs: [u64; 11],
    ctx: Vec<u8>,
    stack: Vec<u8>,
    stack_written: Vec<bool>,
    maps: BTreeMap<u64, MapState>,
    /// Map-value regions: base address -> (map handle, key).
    regions: BTreeMap<u64, (u64, Option<Vec<u8>>)>,
    next_region: u64,
    ringbufs: BTreeMap<u64, Vec<u8>>,
    frames: Vec<Frame>,
    events: Vec<Event>,
    calls: u64,
    ktime: u64,
    prandom: u64,
    steps: u64,
}

fn sx(v: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

fn zx(v: u64, bits: u32) -> u64 {
    if bits >= 64 {
        v
    } else {
        v & ((1u64 << bits) - 1)
    }
}

fn size_bytes(code: u8) -> u64 {
    match code & 0x18 {
        0x00 => 4,
        0x08 => 2,
        0x10 => 1,
        _ => 8,
    }
}

/// Number of arguments recorded for known helpers.
fn helper_argc(id: i32) -> Option<usize> {
    Some(match id {
        1 => 2,           // map_lookup_elem
        2 => 4,           // map_update_elem
        3 => 2,           // map_delete_elem
        4 | 112 | 113 => 3, // probe_read{,_user,_kernel}
        45 | 114 | 115 => 3, // probe_read_str variants
        5 => 0,           // ktime_get_ns
        6 => 2,           // trace_printk (fmt, size)
        7 => 0,           // get_prandom_u32
        8 => 0,           // get_smp_processor_id
        12 => 3,          // tail_call
        14 => 0,          // get_current_pid_tgid
        15 => 0,          // get_current_uid_gid
        16 => 2,          // get_current_comm
        25 => 5,          // perf_event_output
        130 => 4,         // ringbuf_output
        131 => 3,         // ringbuf_reserve
        132 | 133 => 2,   // ringbuf_submit / discard
        _ => return None,
    })
}

impl<'a> Machine<'a> {
    fn new(prog: &'a [Insn], input: &'a Input) -> Self {
        let stack_len = (STACK_SIZE * MAX_FRAMES) as usize;
        let mut regs = [0u64; 11];
        regs[1] = CTX_BASE;
        regs[10] = STACK_TOP;
        Machine {
            prog,
            input,
            regs,
            ctx: input.ctx.clone(),
            stack: vec![STACK_FILL; stack_len],
            stack_written: vec![false; stack_len],
            maps: BTreeMap::new(),
            regions: BTreeMap::new(),
            next_region: MAPVAL_BASE,
            ringbufs: BTreeMap::new(),
            frames: Vec::new(),
            events: Vec::new(),
            calls: 0,
            ktime: 1_000_000,
            prandom: 0x1234_5678,
            steps: 0,
        }
    }

    fn map_def(&self, handle: u64) -> MapDef {
        let key = (handle.wrapping_sub(MAP_HANDLE_BASE)) as u32;
        self.input.maps.get(&key).copied().unwrap_or_default()
    }

    fn stack_base(&self) -> u64 {
        STACK_TOP - STACK_SIZE * MAX_FRAMES
    }

    /// Resolve an address range to (region kind, offset).
    fn locate(&self, addr: u64, size: u64) -> Option<Loc> {
        let end = addr.checked_add(size)?;
        if addr >= CTX_BASE && end <= CTX_BASE + self.ctx.len() as u64 {
            return Some(Loc::Ctx((addr - CTX_BASE) as usize));
        }
        if addr >= self.stack_base() && end <= STACK_TOP {
            return Some(Loc::Stack((addr - self.stack_base()) as usize));
        }
        for base in [
            self.regions.range(..=addr).next_back().map(|(&b, _)| b),
            self.ringbufs.range(..=addr).next_back().map(|(&b, _)| b),
        ]
        .into_iter()
        .flatten()
        {
            let len = self.region_len(base)?;
            if end <= base + len {
                return Some(Loc::Region(base, (addr - base) as usize));
            }
        }
        None
    }

    fn region_len(&self, base: u64) -> Option<u64> {
        if let Some(rb) = self.ringbufs.get(&base) {
            return Some(rb.len() as u64);
        }
        let (map, key) = self.regions.get(&base)?;
        let st = self.maps.get(map)?;
        match key {
            Some(k) => st.entries.get(k).map(|e| e.value.len() as u64),
            None => st.direct.as_ref().map(|(_, v)| v.len() as u64),
        }
    }

    fn region_bytes_mut(&mut self, base: u64) -> Option<&mut Vec<u8>> {
        if self.ringbufs.contains_key(&base) {
            return self.ringbufs.get_mut(&base);
        }
        let (map, key) = self.regions.get(&base)?.clone();
        let st = self.maps.get_mut(&map)?;
        match key {
            Some(k) => st.entries.get_mut(&k).map(|e| &mut e.value),
            None => st.direct.as_mut().map(|(_, v)| v),
        }
    }

    fn read(&mut self, pc: usize, addr: u64, size: u64) -> Result<u64, Fault> {
        let mut buf = [0u8; 8];
        self.read_bytes(pc, addr, &mut buf[..size as usize])?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_bytes(&mut self, pc: usize, addr: u64, out: &mut [u8]) -> Result<(), Fault> {
        let size = out.len() as u64;
        let fault = Fault::OutOfBounds { pc, addr, size };
        if size == 0 {
            return Ok(());
        }
        match self.locate(addr, size).ok_or(fault.clone())? {
            Loc::Ctx(o) => out.copy_from_slice(&self.ctx[o..o + out.len()]),
            Loc::Stack(o) => out.copy_from_slice(&self.stack[o..o + out.len()]),
            Loc::Region(base, o) => {
                let bytes = self.region_bytes_mut(base).ok_or(fault)?;
                out.copy_from_slice(&bytes[o..o + out.len()]);
            }
        }
        Ok(())
    }

    fn write_bytes(&mut self, pc: usize, addr: u64, data: &[u8]) -> Result<(), Fault> {
        let size = data.len() as u64;
        let fault = Fault::OutOfBounds { pc, addr, size };
        if size == 0 {
            return Ok(());
        }
        match self.locate(addr, size).ok_or(fault.clone())? {
            Loc::Ctx(o) => self.ctx[o..o + data.len()].copy_from_slice(data),
            Loc::Stack(o) => {
                self.stack[o..o + data.len()].copy_from_slice(data);
                for w in &mut self.stack_written[o..o + data.len()] {
                    *w = true;
                }
            }
            Loc::Region(base, o) => {
                let bytes = self.region_bytes_mut(base).ok_or(fault)?;
                bytes[o..o + data.len()].copy_from_slice(data);
            }
        }
        Ok(())
    }

    fn write(&mut self, pc: usize, addr: u64, size: u64, v: u64) -> Result<(), Fault> {
        let bytes = v.to_le_bytes();
        self.write_bytes(pc, addr, &bytes[..size as usize])
    }

    fn new_region(&mut self, len: u64) -> u64 {
        let base = self.next_region;
        // Keep regions 64 KiB apart so overruns fault instead of aliasing.
        self.next_region += len.max(1).div_ceil(0x1_0000) * 0x1_0000 + 0x1_0000;
        base
    }

    fn map_lookup(&mut self, pc: usize, map: u64, key_ptr: u64, create: bool) -> Result<u64, Fault> {
        let def = self.map_def(map);
        let mut key = vec![0u8; def.key_size as usize];
        self.read_bytes(pc, key_ptr, &mut key)?;
        if let Some(e) = self.maps.get(&map).and_then(|s| s.entries.get(&key)) {
            return Ok(e.addr);
        }
        if !create {
            return Ok(0);
        }
        let addr = self.new_region(def.value_size as u64);
        self.regions.insert(addr, (map, Some(key.clone())));
        self.maps.entry(map).or_default().entries.insert(
            key,
            MapEntry {
                addr,
                value: vec![0; def.value_size as usize],
            },
        );
        Ok(addr)
    }

    fn map_direct(&mut self, map: u64, off: u32) -> u64 {
        let def = self.map_def(map);
        if let Some((base, _)) = self.maps.get(&map).and_then(|s| s.direct.as_ref()) {
            return base + off as u64;
        }
        let base = self.new_region(def.value_size as u64);
        self.regions.insert(base, (map, None));
        self.maps.entry(map).or_default().direct = Some((base, vec![0; def.value_size as usize]));
        base + off as u64
    }

    /// Deterministic bytes standing in for kernel/user memory reads.
    fn foreign_bytes(src: u64, len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|i| {
                let x = src.wrapping_add(i).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                (x >> 56) as u8
            })
            .collect()
    }

    fn call_helper(&mut self, pc: usize, id: i32) -> Result<(), Fault> {
        let a = [self.regs[1], self.regs[2], self.regs[3], self.regs[4], self.regs[5]];
        if let Some(n) = helper_argc(id) {
            self.events.push(Event::Call {
                id,
                args: a[..n].to_vec(),
            });
        }
        let r0 = match id {
            1 => self.map_lookup(pc, a[0], a[1], self.input.lookup_creates)?,
            2 => {
                let def = self.map_def(a[0]);
                let mut key = vec![0u8; def.key_size as usize];
                let mut val = vec![0u8; def.value_size as usize];
                self.read_bytes(pc, a[1], &mut key)?;
                self.read_bytes(pc, a[2], &mut val)?;
                let addr = self.map_lookup(pc, a[0], a[1], true)?;
                let entry = self.region_bytes_mut(addr).ok_or(Fault::OutOfBounds {
                    pc,
                    addr,
                    size: 0,
                })?;
                entry.copy_from_slice(&val);
                self.events.push(Event::MapUpdate {
                    map: a[0],
                    key,
                    value: val,
                });
                0
            }
            3 => {
                let def = self.map_def(a[0]);
                let mut key = vec![0u8; def.key_size as usize];
                self.read_bytes(pc, a[1], &mut key)?;
                let existed = self
                    .maps
                    .get_mut(&a[0])
                    .and_then(|s| s.entries.remove(&key))
                    .is_some();
                self.events.push(Event::MapDelete { map: a[0], key });
                if existed { 0 } else { (-2i64) as u64 }
            }
            4 | 112 | 113 | 45 | 114 | 115 => {
                let len = (a[1] as u32) as usize;
                let len = len.min(1 << 16);
                let mut data = Self::foreign_bytes(a[2], len);
                let is_str = matches!(id, 45 | 114 | 115);
                if is_str && len > 0 {
                    // Terminate at a deterministic position.
                    let n = (a[2] % (len as u64)) as usize;
                    data[n] = 0;
                    data.truncate(n + 1);
                }
                self.write_bytes(pc, a[0], &data)?;
                if is_str { data.len() as u64 } else { 0 }
            }
            5 => {
                self.ktime += 1000;
                self.ktime
            }
            6 => 0,
            7 => {
                self.prandom = self.prandom.wrapping_mul(6364136223846793005).wrapping_add(1);
                self.prandom >> 32
            }
            8 => 0,
            12 => (-2i64) as u64, // tail_call: modeled as always failing
            14 => 0x0000_1234_0000_5678,
            15 => 0x0000_03e8_0000_03e8,
            16 => {
                let len = (a[1] as u32 as usize).min(64);
                let mut name = b"epass-test".to_vec();
                name.resize(len, 0);
                if let Some(last) = name.last_mut() {
                    *last = 0;
                }
                self.write_bytes(pc, a[0], &name)?;
                0
            }
            25 => {
                let len = (a[4] as u32 as usize).min(1 << 16);
                let mut data = vec![0u8; len];
                self.read_bytes(pc, a[3], &mut data)?;
                self.events.push(Event::Output { id, data });
                0
            }
            130 => {
                let len = (a[2] as u32 as usize).min(1 << 16);
                let mut data = vec![0u8; len];
                self.read_bytes(pc, a[1], &mut data)?;
                self.events.push(Event::Output { id, data });
                0
            }
            131 => {
                let len = (a[1] as u32 as u64).min(1 << 16);
                let base = self.new_region(len);
                self.ringbufs.insert(base, vec![0; len as usize]);
                base
            }
            132 | 133 => {
                if let Some(data) = self.ringbufs.remove(&a[0]) {
                    if id == 132 {
                        self.events.push(Event::Output { id, data });
                    }
                }
                0
            }
            _ => {
                // Unknown helper: a deterministic function of its id.
                (id as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 16
            }
        };
        self.calls += 1;
        self.regs[0] = r0;
        for r in 1..=5 {
            self.regs[r] = CLOBBER_BASE | (self.calls << 8) | r as u64;
        }
        Ok(())
    }

    fn run(&mut self) -> Outcome {
        let mut pc: i64 = 0;
        loop {
            if self.steps >= self.input.max_steps {
                return Outcome::Fault(Fault::StepLimit);
            }
            self.steps += 1;
            if pc < 0 || pc as usize >= self.prog.len() {
                return Outcome::Fault(Fault::PcOutOfRange { pc });
            }
            let upc = pc as usize;
            let i = self.prog[upc];
            match self.step(upc, i) {
                Ok(Step::Next) => pc += 1,
                Ok(Step::Skip2) => pc += 2,
                Ok(Step::Jump(t)) => pc = t,
                Ok(Step::Exit(v)) => return Outcome::Exit(v),
                Err(f) => return Outcome::Fault(f),
            }
        }
    }

    fn step(&mut self, pc: usize, i: Insn) -> Result<Step, Fault> {
        let class = i.code & 7;
        let dst = i.dst as usize;
        let src = i.src as usize;
        if dst > 10 || src > 10 {
            return Err(Fault::BadInsn { pc, code: i.code });
        }
        match class {
            0x04 | 0x07 => self.alu(pc, i, class == 0x07).map(|_| Step::Next),
            0x05 | 0x06 => self.jmp(pc, i, class == 0x05),
            0x00 => {
                // LD: IMM64, ABS, IND
                match i.code {
                    0x18 => {
                        let hi = self
                            .prog
                            .get(pc + 1)
                            .ok_or(Fault::BadInsn { pc, code: i.code })?;
                        let lo = i.imm as u32 as u64;
                        let hi32 = hi.imm as u32 as u64;
                        self.regs[dst] = match i.src {
                            0 => lo | (hi32 << 32),
                            1 | 5 => MAP_HANDLE_BASE + lo,
                            2 | 6 => self.map_direct(MAP_HANDLE_BASE + lo, hi32 as u32),
                            3 => SYM_BASE | lo,
                            4 => SYM_BASE | (1 << 40) | ((pc as i64 + i.imm as i64 + 1) as u64 & 0xffff_ffff),
                            _ => return Err(Fault::BadInsn { pc, code: i.code }),
                        };
                        Ok(Step::Skip2)
                    }
                    0x20 | 0x28 | 0x30 | 0x40 | 0x48 | 0x50 => {
                        let size = size_bytes(i.code) as usize;
                        let off = if i.code & 0xe0 == 0x40 {
                            (self.regs[src] as u32 as i64).wrapping_add(i.imm as i64)
                        } else {
                            i.imm as i64
                        };
                        let v = if off < 0 || off as usize + size > self.input.packet.len() {
                            None
                        } else {
                            let b = &self.input.packet[off as usize..off as usize + size];
                            let mut x = 0u64;
                            for &byte in b {
                                x = (x << 8) | byte as u64;
                            }
                            Some(x)
                        };
                        match v {
                            // Out-of-range packet access terminates with 0.
                            None => Ok(Step::Exit(0)),
                            Some(x) => {
                                self.regs[0] = x;
                                self.calls += 1;
                                for r in 1..=5 {
                                    self.regs[r] = CLOBBER_BASE | (self.calls << 8) | r as u64;
                                }
                                Ok(Step::Next)
                            }
                        }
                    }
                    _ => Err(Fault::BadInsn { pc, code: i.code }),
                }
            }
            0x01 => {
                let size = size_bytes(i.code);
                let addr = self.regs[src].wrapping_add(i.off as i64 as u64);
                let v = self.read(pc, addr, size)?;
                self.regs[dst] = match i.code & 0xe0 {
                    0x60 => v,
                    0x80 if size < 8 => sx(v, (size * 8) as u32),
                    _ => return Err(Fault::BadInsn { pc, code: i.code }),
                };
                Ok(Step::Next)
            }
            0x02 => {
                if i.code & 0xe0 != 0x60 {
                    return Err(Fault::BadInsn { pc, code: i.code });
                }
                let size = size_bytes(i.code);
                let addr = self.regs[dst].wrapping_add(i.off as i64 as u64);
                self.write(pc, addr, size, i.imm as i64 as u64)?;
                Ok(Step::Next)
            }
            0x03 => {
                let size = size_bytes(i.code);
                let addr = self.regs[dst].wrapping_add(i.off as i64 as u64);
                match i.code & 0xe0 {
                    0x60 => {
                        self.write(pc, addr, size, self.regs[src])?;
                        Ok(Step::Next)
                    }
                    0xc0 if size == 4 || size == 8 => {
                        self.atomic(pc, i, addr, size)?;
                        Ok(Step::Next)
                    }
                    _ => Err(Fault::BadInsn { pc, code: i.code }),
                }
            }
            _ => Err(Fault::BadInsn { pc, code: i.code }),
        }
    }

    fn atomic(&mut self, pc: usize, i: Insn, addr: u64, size: u64) -> Result<(), Fault> {
        let bits = (size * 8) as u32;
        let old = self.read(pc, addr, size)?;
        let s = zx(self.regs[i.src as usize], bits);
        let op = i.imm;
        let fetch = op & 0x01 != 0;
        let new = match op & !0x01 {
            0x00 => Some(old.wrapping_add(s)),
            0x40 => Some(old | s),
            0x50 => Some(old & s),
            0xa0 => Some(old ^ s),
            0xe0 if fetch => Some(s),
            0xf0 if fetch => {
                let expected = zx(self.regs[0], bits);
                self.regs[0] = old;
                if old == expected { Some(s) } else { None }
            }
            _ => return Err(Fault::BadInsn { pc, code: i.code }),
        };
        if let Some(n) = new {
            self.write(pc, addr, size, zx(n, bits))?;
        }
        if fetch && op & !0x01 != 0xf0 {
            self.regs[i.src as usize] = old;
        }
        Ok(())
    }

    fn alu(&mut self, pc: usize, i: Insn, is64: bool) -> Result<(), Fault> {
        let dst = i.dst as usize;
        let op = i.code & 0xf0;
        let use_reg = i.code & 0x08 != 0;
        let bits: u32 = if is64 { 64 } else { 32 };
        let a = zx(self.regs[dst], bits);
        let b_raw = if use_reg {
            self.regs[i.src as usize]
        } else {
            i.imm as i64 as u64
        };
        let b = zx(b_raw, bits);
        let signed = i.off == 1;
        let sa = sx(a, bits) as i64;
        let sb = sx(b, bits) as i64;
        let res: u64 = match op {
            0x00 => a.wrapping_add(b),
            0x10 => a.wrapping_sub(b),
            0x20 => a.wrapping_mul(b),
            0x30 => {
                if b == 0 {
                    0
                } else if signed {
                    if bits == 32 {
                        (sa as i32).wrapping_div(sb as i32) as i64 as u64
                    } else {
                        sa.wrapping_div(sb) as u64
                    }
                } else {
                    a / b
                }
            }
            0x90 => {
                if b == 0 {
                    a
                } else if signed {
                    if bits == 32 {
                        (sa as i32).wrapping_rem(sb as i32) as i64 as u64
                    } else {
                        sa.wrapping_rem(sb) as u64
                    }
                } else {
                    a % b
                }
            }
            0x40 => a | b,
            0x50 => a & b,
            0xa0 => a ^ b,
            0x60 => a.wrapping_shl((b & (bits as u64 - 1)) as u32),
            0x70 => a.wrapping_shr((b & (bits as u64 - 1)) as u32),
            0xc0 => (sa.wrapping_shr((b & (bits as u64 - 1)) as u32)) as u64,
            0x80 => (sa.wrapping_neg()) as u64,
            0xb0 => {
                if use_reg && i.off != 0 {
                    let from = i.off as u32;
                    if !matches!(from, 8 | 16 | 32) || (from == 32 && !is64) {
                        return Err(Fault::BadInsn { pc, code: i.code });
                    }
                    sx(self.regs[i.src as usize], from)
                } else {
                    b
                }
            }
            0xd0 => {
                let width = i.imm as u32;
                if !matches!(width, 16 | 32 | 64) {
                    return Err(Fault::BadInsn { pc, code: i.code });
                }
                let v = zx(self.regs[dst], width);
                let swap = if is64 { true } else { i.code & 0x08 != 0 };
                let out = if swap {
                    match width {
                        16 => (v as u16).swap_bytes() as u64,
                        32 => (v as u32).swap_bytes() as u64,
                        _ => v.swap_bytes(),
                    }
                } else {
                    v
                };
                self.regs[dst] = out;
                return Ok(());
            }
            _ => return Err(Fault::BadInsn { pc, code: i.code }),
        };
        if (op == 0x30 || op == 0x90) && i.off != 0 && i.off != 1 {
            return Err(Fault::BadInsn { pc, code: i.code });
        }
        self.regs[dst] = zx(res, bits);
        Ok(())
    }

    fn jmp(&mut self, pc: usize, i: Insn, is64: bool) -> Result<Step, Fault> {
        let op = i.code & 0xf0;
        let target = |off: i64| Step::Jump(pc as i64 + off + 1);
        match op {
            0x00 => {
                return Ok(if is64 {
                    target(i.off as i64)
                } else {
                    target(i.imm as i64)
                });
            }
            0x80 => {
                return match i.src {
                    0 => {
                        self.call_helper(pc, i.imm)?;
                        Ok(Step::Next)
                    }
                    1 => {
                        if self.frames.len() as u64 + 1 >= MAX_FRAMES {
                            return Err(Fault::StackOverflow { pc });
                        }
                        self.frames.push(Frame {
                            ret_pc: pc + 1,
                            saved: [self.regs[6], self.regs[7], self.regs[8], self.regs[9]],
                        });
                        self.regs[10] = STACK_TOP - STACK_SIZE * self.frames.len() as u64;
                        Ok(target(i.imm as i64))
                    }
                    _ => Err(Fault::Unimplemented { pc, what: "kfunc call" }),
                };
            }
            0x90 => {
                return match self.frames.pop() {
                    None => Ok(Step::Exit(self.regs[0])),
                    Some(f) => {
                        self.regs[6..10].copy_from_slice(&f.saved);
                        self.regs[10] = STACK_TOP - STACK_SIZE * self.frames.len() as u64;
                        for r in 1..=5 {
                            self.regs[r] = CLOBBER_BASE | (0xff << 8) | r as u64;
                        }
                        Ok(Step::Jump(f.ret_pc as i64))
                    }
                };
            }
            0xe0 => return Err(Fault::Unimplemented { pc, what: "may_goto" }),
            _ => {}
        }
        let bits = if is64 { 64 } else { 32 };
        let a = zx(self.regs[i.dst as usize], bits);
        let b = zx(
            if i.code & 0x08 != 0 {
                self.regs[i.src as usize]
            } else {
                i.imm as i64 as u64
            },
            bits,
        );
        let (sa, sb) = (sx(a, bits) as i64, sx(b, bits) as i64);
        let taken = match op {
            0x10 => a == b,
            0x20 => a > b,
            0x30 => a >= b,
            0x40 => a & b != 0,
            0x50 => a != b,
            0x60 => sa > sb,
            0x70 => sa >= sb,
            0xa0 => a < b,
            0xb0 => a <= b,
            0xc0 => sa < sb,
            0xd0 => sa <= sb,
            _ => return Err(Fault::BadInsn { pc, code: i.code }),
        };
        Ok(if taken { target(i.off as i64) } else { Step::Next })
    }
}

enum Loc {
    Ctx(usize),
    Stack(usize),
    Region(u64, usize),
}

enum Step {
    Next,
    Skip2,
    Jump(i64),
    Exit(u64),
}

/// Run a program (one `u64` per instruction slot) on `input`.
pub fn run(prog: &[u64], input: &Input) -> RunResult {
    let insns: Vec<Insn> = prog.iter().map(|&r| Insn::decode(r)).collect();
    let mut m = Machine::new(&insns, input);
    let outcome = m.run();
    let main_lo = (STACK_SIZE * (MAX_FRAMES - 1)) as usize;
    RunResult {
        outcome,
        ctx: m.ctx,
        stack: m.stack[main_lo..].to_vec(),
        stack_written: m.stack_written[main_lo..].to_vec(),
        events: m.events,
        steps: m.steps,
    }
}

/// A difference between two runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch(pub String);

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Compare an original run with a rewritten run.
///
/// Equal outcomes (r0, or "both faulted"), equal ctx bytes, equal helper
/// events, and equal bytes at every main-frame stack address the original
/// wrote. Addresses only the rewritten program wrote (its spill slots) are
/// allowed to differ.
pub fn compare(orig: &RunResult, new: &RunResult) -> Result<(), Mismatch> {
    match (&orig.outcome, &new.outcome) {
        (Outcome::Exit(a), Outcome::Exit(b)) if a != b => {
            return Err(Mismatch(format!("r0 differs: original {a:#x}, rewritten {b:#x}")));
        }
        (Outcome::Exit(_), Outcome::Fault(f)) => {
            return Err(Mismatch(format!("rewritten program faulted: {f:?}")));
        }
        (Outcome::Fault(f), Outcome::Exit(_)) => {
            return Err(Mismatch(format!("original faulted ({f:?}) but rewritten exited")));
        }
        _ => {}
    }
    if orig.ctx != new.ctx {
        return Err(Mismatch("ctx bytes differ".into()));
    }
    if orig.events != new.events {
        let n = orig
            .events
            .iter()
            .zip(&new.events)
            .position(|(a, b)| a != b)
            .unwrap_or(orig.events.len().min(new.events.len()));
        return Err(Mismatch(format!(
            "helper events differ at #{n}: original {:?}, rewritten {:?}",
            orig.events.get(n),
            new.events.get(n)
        )));
    }
    for (i, (&w, (&a, &b))) in orig
        .stack_written
        .iter()
        .zip(orig.stack.iter().zip(&new.stack))
        .enumerate()
    {
        if w && a != b {
            let off = i as i64 - STACK_SIZE as i64;
            return Err(Mismatch(format!("stack byte r10{off:+} differs: {a:#x} vs {b:#x}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// Register reads the verifier would reject as uninitialized ("R%d
/// !read_ok"): a must-initialized dataflow over the bytecode, starting
/// from {r1, r10}. Calls define r0 and leave r1-r5 uninitialized; helper
/// arguments are not checked (their arity is per-helper). Returns
/// `(pc, register)` pairs, sorted.
pub fn uninit_reads(prog: &[u64]) -> Vec<(usize, u8)> {
    let n = prog.len();
    let insns: Vec<Insn> = prog.iter().map(|&r| Insn::decode(r)).collect();
    // (uses, defs, kills) as register masks, and successors.
    let effect = |pc: usize| -> (u16, u16, u16, Vec<usize>) {
        let i = insns[pc];
        let bit = |r: u8| 1u16 << r;
        let class = i.code & 7;
        let op = i.code & 0xf0;
        let x = i.code & 0x08 != 0;
        let next = vec![pc + 1];
        match class {
            0x04 | 0x07 => {
                let mut u = 0;
                if op != 0xb0 {
                    u |= bit(i.dst);
                }
                if x && op != 0x80 && op != 0xd0 {
                    u |= bit(i.src);
                }
                (u, bit(i.dst), 0, next)
            }
            0x01 => (bit(i.src), bit(i.dst), 0, next),
            0x02 => (bit(i.dst), 0, 0, next),
            0x03 => {
                let mut u = bit(i.dst) | bit(i.src);
                let mut d = 0;
                if i.code & 0xe0 == 0xc0 {
                    if i.imm == 0xf1 || i.imm == 0xf0 {
                        u |= 1;
                        d |= 1;
                    } else if i.imm & 1 != 0 {
                        d |= bit(i.src);
                    }
                }
                (u, d, 0, next)
            }
            0x00 if i.code == 0x18 => (0, bit(i.dst), 0, vec![pc + 2]),
            0x00 => {
                let u = bit(6) | if i.code & 0xe0 == 0x40 { bit(i.src) } else { 0 };
                (u, 1, 0x3e, next)
            }
            _ => match op {
                0x00 if class == 0x06 => (0, 0, 0, vec![(pc as i64 + 1 + i.imm as i64) as usize]),
                0x00 => (0, 0, 0, vec![(pc as i64 + 1 + i.off as i64) as usize]),
                0x80 => (0, 1, 0x3e, next),
                0x90 => (1, 0, 0, vec![]),
                0xe0 => (0, 0, 0, vec![pc + 1, (pc as i64 + 1 + i.off as i64) as usize]),
                _ => {
                    let u = bit(i.dst) | if x { bit(i.src) } else { 0 };
                    (u, 0, 0, vec![pc + 1, (pc as i64 + 1 + i.off as i64) as usize])
                }
            },
        }
    };
    let all = 0x7ffu16;
    let mut init_in = vec![all; n];
    let mut seen = vec![false; n];
    if n == 0 {
        return Vec::new();
    }
    init_in[0] = (1 << 1) | (1 << 10);
    seen[0] = true;
    let mut work = vec![0usize];
    while let Some(pc) = work.pop() {
        let (_, d, k, succ) = effect(pc);
        let out = (init_in[pc] & !k) | d;
        for s in succ {
            if s < n {
                let new = if seen[s] { init_in[s] & out } else { out };
                if !seen[s] || new != init_in[s] {
                    seen[s] = true;
                    init_in[s] = new;
                    work.push(s);
                }
            }
        }
    }
    let mut bad = Vec::new();
    for pc in 0..n {
        if !seen[pc] {
            continue;
        }
        let (u, ..) = effect(pc);
        for r in 0..11u8 {
            if u & (1 << r) != 0 && init_in[pc] & (1 << r) == 0 {
                bad.push((pc, r));
            }
        }
    }
    bad
}
