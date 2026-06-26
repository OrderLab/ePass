//! Parseable text serialization for ePass IR.
//!
//! This is a debugging format, not a stable external ABI. It intentionally
//! serializes only semantic IR state; arena ids, users, reachable lists, and CG
//! metadata are reconstructed after parsing.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::bytecode::MAX_FUNC_ARG;
use crate::error::{Error, Result};
use crate::ir::insn::{BinOp, Cond, EndKind, InsnKind};
use crate::ir::value::{AddrValue, AluOp, ConstKind, LoadImmExtra, Value, VrType};
use crate::ir::{BbId, Function, InsnId, InsertPos};
use crate::{cfg, invalid, unsupported};

#[derive(Debug, Clone, Copy)]
pub struct DumpOptions {
    pub include_preds_succs: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self { include_preds_succs: true }
    }
}

pub fn dump_function(func: &Function) -> String {
    dump_function_with_options(func, DumpOptions::default())
}

pub fn dump_function_with_options(func: &Function, opts: DumpOptions) -> String {
    let mut names = Names::new(func);
    let mut out = String::new();
    out.push_str("; ePass IR v1\n\n");
    let order: &[BbId] = if func.reachable_bbs.is_empty() { &func.all_bbs } else { &func.reachable_bbs };
    for &bb in order {
        out.push_str(&format!("{}:", names.bb(bb)));
        if opts.include_preds_succs {
            let preds: Vec<_> = func.bb(bb).preds.iter().map(|&p| names.bb(p)).collect();
            let succs: Vec<_> = func.bb(bb).succs.iter().map(|&s| names.bb(s)).collect();
            out.push_str(&format!(" ; preds=[{}] succs=[{}]", preds.join(","), succs.join(",")));
        }
        out.push('\n');
        for &id in &func.bb(bb).insns {
            out.push_str("  ");
            out.push_str(&dump_insn(func, &mut names, id));
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

pub fn dump_function_to_file<P: AsRef<Path>>(func: &Function, path: P) -> Result<()> {
    fs::write(path.as_ref(), dump_function(func))
        .map_err(|e| Error::Internal(format!("failed to write IR dump '{}': {e}", path.as_ref().display())))
}

struct Names {
    insns: HashMap<InsnId, String>,
    bbs: HashMap<BbId, String>,
    next_insn: usize,
}

impl Names {
    fn new(func: &Function) -> Self {
        let mut bbs = HashMap::new();
        let order: &[BbId] = if func.reachable_bbs.is_empty() { &func.all_bbs } else { &func.reachable_bbs };
        for (i, &bb) in order.iter().enumerate() {
            bbs.insert(bb, format!("bb{i}"));
        }
        Self { insns: HashMap::new(), bbs, next_insn: 0 }
    }

    fn bb(&self, bb: BbId) -> String {
        self.bbs.get(&bb).cloned().unwrap_or_else(|| format!("bb?{}", bb.0))
    }

    fn insn(&mut self, func: &Function, id: InsnId) -> String {
        if id == func.sp { return "%sp".to_string(); }
        for i in 0..MAX_FUNC_ARG {
            if id == func.args[i] { return format!("%arg{i}"); }
        }
        if let Some(n) = self.insns.get(&id) { return n.clone(); }
        let name = format!("%{}", self.next_insn);
        self.next_insn += 1;
        self.insns.insert(id, name.clone());
        name
    }
}

fn dump_insn(func: &Function, names: &mut Names, id: InsnId) -> String {
    let insn = func.insn(id);
    let dst = if insn.is_void() { String::new() } else { format!("{} = ", names.insn(func, id)) };
    let val = |names: &mut Names, v: Value| dump_value(func, names, v);
    match &insn.kind {
        InsnKind::Alloc { vr_type } => format!("{dst}alloc {}", vr_name(*vr_type)),
        InsnKind::AllocArray { vr_type, num } => format!("{dst}allocarray {} x {}", vr_name(*vr_type), num),
        InsnKind::GetElemPtr => format!("{dst}getelemptr {}, {}", val(names, insn.values[0]), val(names, insn.values[1])),
        InsnKind::Store => format!("store {}, {}", val(names, insn.values[0]), val(names, insn.values[1])),
        InsnKind::Load => format!("{dst}load {}", val(names, insn.values[0])),
        InsnKind::LoadImmExtra { extra, imm64 } => format!("{dst}loadimm.{} {}", extra_name(*extra), imm64),
        InsnKind::StoreRaw { vr_type, addr } => format!("storeraw.{} {}, {}", vr_name(*vr_type), dump_addr(func, names, addr), val(names, insn.values[0])),
        InsnKind::LoadRaw { vr_type, addr } => format!("{dst}loadraw.{} {}", vr_name(*vr_type), dump_addr(func, names, addr)),
        InsnKind::Neg => format!("{dst}neg{} {}", alu_suffix(insn.alu_op), val(names, insn.values[0])),
        InsnKind::End { kind, swap_width } => format!("{dst}end.{}{} {}", match kind { EndKind::ToBe => "be", EndKind::ToLe => "le" }, swap_width, val(names, insn.values[0])),
        InsnKind::Bin { op } => format!("{dst}{}{} {}, {}", bin_name(*op), alu_suffix(insn.alu_op), val(names, insn.values[0]), val(names, insn.values[1])),
        InsnKind::Call { fid } => {
            let args: Vec<_> = insn.values.iter().map(|&v| val(names, v)).collect();
            format!("{dst}call #{}({})", fid, args.join(", "))
        }
        InsnKind::Ret => format!("ret {}", val(names, insn.values[0])),
        InsnKind::Throw => "throw".to_string(),
        InsnKind::Ja => format!("ja {}", names.bb(insn.bb1.unwrap())),
        InsnKind::CondJmp { cond } => format!("{}{} {}, {} -> {} else {}", cond_name(*cond), alu_suffix(insn.alu_op), val(names, insn.values[0]), val(names, insn.values[1]), names.bb(insn.bb2.unwrap()), names.bb(insn.bb1.unwrap())),
        InsnKind::Phi => {
            let entries: Vec<_> = insn.phi.iter().map(|p| format!("[{}, {}]", val(names, p.value), names.bb(p.bb))).collect();
            format!("{dst}phi {}", entries.join(", "))
        }
        InsnKind::Assign => format!("{dst}assign {}", val(names, insn.values[0])),
        InsnKind::Reg { reg_id } => format!("{dst}reg R{reg_id}"),
        InsnKind::FunctionArg { arg_id } => format!("{dst}funcarg {arg_id}"),
        InsnKind::Ecall => {
            let args: Vec<_> = insn.values.iter().map(|&v| val(names, v)).collect();
            format!("{dst}ecall({})", args.join(", "))
        }
    }
}

fn dump_value(func: &Function, names: &mut Names, v: Value) -> String {
    match v {
        Value::Insn(id) => names.insn(func, id),
        Value::Const { v, ty, kind: ConstKind::Plain, builtin } if builtin == crate::ir::BuiltinConst::None => {
            format!("{}:{}", v, match ty { AluOp::Alu32 => "i32", AluOp::Alu64 => "i64", AluOp::Unknown => "i?" })
        }
        Value::Const { v, ty, kind, builtin } => format!("const({},{:?},{:?},{:?})", v, ty, kind, builtin),
        Value::Undef => "undef".to_string(),
        Value::VrPos(_) | Value::FlattenDst(_) => "<cg-value>".to_string(),
    }
}

fn dump_addr(func: &Function, names: &mut Names, addr: &AddrValue) -> String {
    let suffix = match addr.offset_kind { ConstKind::Plain => "", ConstKind::RawOff => "+sp", ConstKind::RawOffRev => "-sp" };
    format!("[{}{:+}{}]", dump_value(func, names, addr.value), addr.offset, suffix)
}

pub fn load_function_from_file<P: AsRef<Path>>(path: P) -> Result<Function> {
    let text = fs::read_to_string(path.as_ref())
        .map_err(|e| Error::InvalidProgram(format!("failed to read IR file '{}': {e}", path.as_ref().display())))?;
    load_function_from_str(&text)
}

pub fn load_function_from_str(text: &str) -> Result<Function> {
    Parser::new(text).parse()
}

struct Parser<'a> {
    lines: Vec<(usize, &'a str)>,
    bb_names: HashMap<String, BbId>,
    val_names: HashMap<String, InsnId>,
    pending_vals: Vec<(InsnId, Vec<PValue>)>,
    pending_addr: Vec<(InsnId, PValue)>,
    pending_phi: Vec<(InsnId, Vec<(PValue, String)>)>,
    pending_jumps: Vec<(InsnId, Option<String>, Option<String>)>,
}

#[derive(Clone, Debug)]
enum PValue { Const(Value), Name(String), Sp, Arg(usize), Undef }

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        let lines = text.lines().enumerate().filter_map(|(i, raw)| {
            let line = raw.split(';').next().unwrap_or("").trim();
            if line.is_empty() { None } else { Some((i + 1, line)) }
        }).collect();
        Self { lines, bb_names: HashMap::new(), val_names: HashMap::new(), pending_vals: Vec::new(), pending_addr: Vec::new(), pending_phi: Vec::new(), pending_jumps: Vec::new() }
    }

    fn parse(mut self) -> Result<Function> {
        let mut func = Function::new();
        let mut first = true;
        for &(line_no, line) in &self.lines {
            if let Some(name) = line.strip_suffix(':') {
                if self.bb_names.contains_key(name) { return Err(invalid!("IR parse line {line_no}: duplicate block {name}")); }
                let bb = if first { first = false; func.entry } else { func.create_bb() };
                self.bb_names.insert(name.to_string(), bb);
            }
        }
        if self.bb_names.is_empty() { return Err(invalid!("IR parse error: no blocks")); }

        let mut cur_bb: Option<BbId> = None;
        let lines = self.lines.clone();
        for (line_no, line) in lines {
            if let Some(name) = line.strip_suffix(':') {
                cur_bb = Some(*self.bb_names.get(name).unwrap());
                continue;
            }
            let bb = cur_bb.ok_or_else(|| invalid!("IR parse line {line_no}: instruction before first block"))?;
            self.parse_insn(&mut func, bb, line_no, line)?;
        }

        self.resolve(&mut func)?;
        cfg::finalize(&mut crate::Env::new(Default::default(), Vec::new()), &mut func)?;
        Ok(func)
    }

    fn parse_insn(&mut self, func: &mut Function, bb: BbId, line_no: usize, line: &str) -> Result<()> {
        let (dst, body) = if let Some((d, b)) = line.split_once(" = ") { (Some(d.trim()), b.trim()) } else { (None, line.trim()) };
        let mut words = body.split_whitespace();
        let op = words.next().ok_or_else(|| invalid!("IR parse line {line_no}: empty instruction"))?;

        let mk = |func: &mut Function, kind| func.create_insn(bb, kind, InsertPos::Back);
        let id = match op {
            "alloc" => mk(func, InsnKind::Alloc { vr_type: parse_vr(words.next(), line_no)? }),
            "allocarray" => {
                let ty = parse_vr(words.next(), line_no)?;
                if words.next() != Some("x") { return Err(invalid!("IR parse line {line_no}: expected 'x' in allocarray")); }
                let n = words.next().ok_or_else(|| invalid!("IR parse line {line_no}: missing allocarray size"))?.parse().map_err(|_| invalid!("IR parse line {line_no}: bad allocarray size"))?;
                mk(func, InsnKind::AllocArray { vr_type: ty, num: n })
            }
            "store" => { let id = mk(func, InsnKind::Store); self.pending_vals.push((id, parse_value_list(rest_after(op, body))?)); id }
            "load" => { let id = mk(func, InsnKind::Load); self.pending_vals.push((id, parse_value_list(rest_after(op, body))?)); id }
            x if x.starts_with("loadimm.") => {
                let extra = parse_extra(&x[8..], line_no)?;
                let imm64: i64 = words.next().ok_or_else(|| invalid!("IR parse line {line_no}: missing imm64"))?.parse().map_err(|_| invalid!("IR parse line {line_no}: bad imm64"))?;
                mk(func, InsnKind::LoadImmExtra { extra, imm64 })
            }
            x if x.starts_with("loadraw.") => {
                let ty = parse_vr_name(&x[8..], line_no)?;
                let addr_s = rest_after(op, body).trim();
                let (addr, base) = parse_addr(addr_s, line_no)?;
                let id = mk(func, InsnKind::LoadRaw { vr_type: ty, addr });
                self.pending_addr.push((id, base));
                id
            }
            x if x.starts_with("storeraw.") => {
                let ty = parse_vr_name(&x[9..], line_no)?;
                let rest = rest_after(op, body);
                let (a, v) = split_top_comma(rest, line_no)?;
                let (addr, base) = parse_addr(a.trim(), line_no)?;
                let id = mk(func, InsnKind::StoreRaw { vr_type: ty, addr });
                self.pending_addr.push((id, base));
                self.pending_vals.push((id, vec![parse_pvalue(v.trim(), line_no)?]));
                id
            }
            x if parse_bin_op(x).is_some() => {
                let (op2, alu) = parse_bin_op(x).unwrap();
                let id = mk(func, InsnKind::Bin { op: op2 });
                func.insn_mut(id).alu_op = alu;
                self.pending_vals.push((id, parse_value_list(rest_after(op, body))?));
                id
            }
            x if x.starts_with("neg") => { let id = mk(func, InsnKind::Neg); func.insn_mut(id).alu_op = parse_alu_suffix(&x[3..], line_no)?; self.pending_vals.push((id, parse_value_list(rest_after(op, body))?)); id }
            x if x.starts_with("end.") => return Err(unsupported!("IR parser does not yet support {x} at line {line_no}")),
            "call" => {
                let rest = rest_after(op, body).trim();
                let hash = rest.strip_prefix('#').ok_or_else(|| invalid!("IR parse line {line_no}: call missing #fid"))?;
                let (fid_s, args_s) = hash.split_once('(').ok_or_else(|| invalid!("IR parse line {line_no}: call missing args"))?;
                let fid = fid_s.parse().map_err(|_| invalid!("IR parse line {line_no}: bad fid"))?;
                let args_s = args_s.strip_suffix(')').ok_or_else(|| invalid!("IR parse line {line_no}: call missing ')'"))?;
                let id = mk(func, InsnKind::Call { fid });
                self.pending_vals.push((id, parse_value_list(args_s)?));
                id
            }
            "ret" => { let id = mk(func, InsnKind::Ret); self.pending_vals.push((id, parse_value_list(rest_after(op, body))?)); id }
            "ja" => { let id = mk(func, InsnKind::Ja); self.pending_jumps.push((id, Some(words.next().ok_or_else(|| invalid!("IR parse line {line_no}: ja missing target"))?.to_string()), None)); id }
            "phi" => {
                let id = mk(func, InsnKind::Phi);
                self.pending_phi.push((id, parse_phi_entries(rest_after(op, body), line_no)?));
                id
            }
            "assign" => { let id = mk(func, InsnKind::Assign); self.pending_vals.push((id, parse_value_list(rest_after(op, body))?)); id }
            x if parse_cond_op(x).is_some() => {
                let (cond, alu) = parse_cond_op(x).unwrap();
                let rest = rest_after(op, body);
                let (lhs_rhs, targets) = rest.split_once(" -> ").ok_or_else(|| invalid!("IR parse line {line_no}: conditional missing ->"))?;
                let (taken, fall) = targets.split_once(" else ").ok_or_else(|| invalid!("IR parse line {line_no}: conditional missing else"))?;
                let id = mk(func, InsnKind::CondJmp { cond });
                func.insn_mut(id).alu_op = alu;
                self.pending_vals.push((id, parse_value_list(lhs_rhs)?));
                self.pending_jumps.push((id, Some(fall.trim().to_string()), Some(taken.trim().to_string())));
                id
            }
            other => return Err(unsupported!("IR parser does not support opcode '{other}' at line {line_no}")),
        };
        if let Some(dst) = dst { self.val_names.insert(dst.to_string(), id); }
        Ok(())
    }

    fn resolve(self, func: &mut Function) -> Result<()> {
        let bb_names = self.bb_names;
        let val_names = self.val_names;
        for (id, vals) in self.pending_vals {
            for pv in vals {
                let v = resolve_pvalue(func, &val_names, pv)?;
                func.add_value_operand(id, v);
            }
        }
        for (id, pv) in self.pending_addr {
            let v = resolve_pvalue(func, &val_names, pv)?;
            match &mut func.insn_mut(id).kind { InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } => addr.value = v, _ => unreachable!() }
            func.add_use(v, id);
        }
        for (id, entries) in self.pending_phi {
            for (pv, bb_name) in entries {
                let v = resolve_pvalue(func, &val_names, pv)?;
                let bb = *bb_names.get(&bb_name).ok_or_else(|| invalid!("IR parse error: unknown block {bb_name}"))?;
                func.add_phi_operand(id, v, bb);
            }
        }
        for (id, bb1, bb2) in self.pending_jumps {
            if let Some(b) = bb1 { let bb = *bb_names.get(&b).ok_or_else(|| invalid!("IR parse error: unknown block {b}"))?; func.insn_mut(id).bb1 = Some(bb); }
            if let Some(b) = bb2 { let bb = *bb_names.get(&b).ok_or_else(|| invalid!("IR parse error: unknown block {b}"))?; func.insn_mut(id).bb2 = Some(bb); }
        }
        // Establish CFG edges from terminators.
        for bb in func.all_bbs.clone() {
            if let Some(last) = func.bb(bb).last() {
                let (b1, b2) = { let insn = func.insn(last); (insn.bb1, insn.bb2) };
                if let Some(t) = b1 { func.connect(bb, t); }
                if let Some(t) = b2 { func.connect(bb, t); }
            }
        }
        Ok(())
    }
}

fn resolve_pvalue(func: &Function, val_names: &HashMap<String, InsnId>, pv: PValue) -> Result<Value> {
    Ok(match pv {
        PValue::Const(v) => v,
        PValue::Undef => Value::Undef,
        PValue::Sp => Value::Insn(func.sp),
        PValue::Arg(i) if i < MAX_FUNC_ARG => Value::Insn(func.args[i]),
        PValue::Arg(i) => return Err(invalid!("IR parse error: arg{i} out of range")),
        PValue::Name(n) => Value::Insn(*val_names.get(&n).ok_or_else(|| invalid!("IR parse error: unknown value {n}"))?),
    })
}

fn rest_after<'a>(op: &str, body: &'a str) -> &'a str { body[op.len()..].trim() }

fn split_top_comma(s: &str, line_no: usize) -> Result<(&str, &str)> {
    s.split_once(',').ok_or_else(|| invalid!("IR parse line {line_no}: expected comma"))
}

fn parse_value_list(s: &str) -> Result<Vec<PValue>> {
    let s = s.trim();
    if s.is_empty() { return Ok(Vec::new()); }
    s.split(',').map(|x| parse_pvalue(x.trim(), 0)).collect()
}

fn parse_pvalue(s: &str, line_no: usize) -> Result<PValue> {
    if s == "%sp" { return Ok(PValue::Sp); }
    if s == "undef" { return Ok(PValue::Undef); }
    if let Some(n) = s.strip_prefix("%arg") { return Ok(PValue::Arg(n.parse().map_err(|_| invalid!("IR parse line {line_no}: bad arg"))?)); }
    if s.starts_with('%') { return Ok(PValue::Name(s.to_string())); }
    if let Some((num, ty)) = s.rsplit_once(':') {
        let v: i64 = num.parse().map_err(|_| invalid!("IR parse line {line_no}: bad const"))?;
        let alu = match ty { "i32" => AluOp::Alu32, "i64" => AluOp::Alu64, _ => return Err(unsupported!("IR parse line {line_no}: unsupported const type {ty}")) };
        return Ok(PValue::Const(Value::Const { v, ty: alu, kind: ConstKind::Plain, builtin: crate::ir::BuiltinConst::None }));
    }
    Err(invalid!("IR parse line {line_no}: bad value '{s}'"))
}

fn parse_addr(s: &str, line_no: usize) -> Result<(AddrValue, PValue)> {
    let inner = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')).ok_or_else(|| invalid!("IR parse line {line_no}: bad address"))?;
    let (base_s, off_owned): (&str, String) = if let Some((b, o)) = inner.rsplit_once('+') {
        (b, o.to_string())
    } else if let Some((b, o)) = inner.rsplit_once('-') {
        (b, format!("-{o}"))
    } else {
        (inner, "0".to_string())
    };
    let offset: i16 = off_owned.parse().map_err(|_| invalid!("IR parse line {line_no}: bad address offset"))?;
    Ok((AddrValue { value: Value::Undef, offset, offset_kind: ConstKind::Plain }, parse_pvalue(base_s.trim(), line_no)?))
}

fn parse_phi_entries(s: &str, line_no: usize) -> Result<Vec<(PValue, String)>> {
    let mut out = Vec::new();
    for part in s.split("],") {
        let p = part.trim().trim_start_matches('[').trim_end_matches(']').trim();
        let (v, b) = split_top_comma(p, line_no)?;
        out.push((parse_pvalue(v.trim(), line_no)?, b.trim().to_string()));
    }
    Ok(out)
}

fn parse_vr(v: Option<&str>, line_no: usize) -> Result<VrType> { parse_vr_name(v.ok_or_else(|| invalid!("IR parse line {line_no}: missing type"))?, line_no) }
fn parse_vr_name(s: &str, line_no: usize) -> Result<VrType> { Ok(match s { "u8" => VrType::B8, "u16" => VrType::B16, "u32" => VrType::B32, "u64" => VrType::B64, _ => return Err(invalid!("IR parse line {line_no}: bad vr type {s}")) }) }
fn vr_name(t: VrType) -> &'static str { match t { VrType::B8 => "u8", VrType::B16 => "u16", VrType::B32 => "u32", VrType::B64 => "u64", VrType::Unknown => "u?" } }
fn alu_suffix(a: AluOp) -> &'static str { match a { AluOp::Alu32 => "32", AluOp::Alu64 => "64", AluOp::Unknown => "?" } }
fn parse_alu_suffix(s: &str, line_no: usize) -> Result<AluOp> { Ok(match s { "32" => AluOp::Alu32, "64" => AluOp::Alu64, _ => return Err(invalid!("IR parse line {line_no}: bad alu suffix {s}")) }) }
fn bin_name(op: BinOp) -> &'static str { match op { BinOp::Add => "add", BinOp::Sub => "sub", BinOp::Mul => "mul", BinOp::Div => "div", BinOp::Or => "or", BinOp::And => "and", BinOp::Lsh => "lsh", BinOp::Arsh => "arsh", BinOp::Rsh => "rsh", BinOp::Mod => "mod", BinOp::Xor => "xor" } }
fn parse_bin_op(s: &str) -> Option<(BinOp, AluOp)> { let (name, suf) = s.split_at(s.len().saturating_sub(2)); let alu = match suf { "32" => AluOp::Alu32, "64" => AluOp::Alu64, _ => return None }; Some((match name { "add" => BinOp::Add, "sub" => BinOp::Sub, "mul" => BinOp::Mul, "div" => BinOp::Div, "or" => BinOp::Or, "and" => BinOp::And, "lsh" => BinOp::Lsh, "arsh" => BinOp::Arsh, "rsh" => BinOp::Rsh, "mod" => BinOp::Mod, "xor" => BinOp::Xor, _ => return None }, alu)) }
fn cond_name(c: Cond) -> &'static str { match c { Cond::Eq => "jeq", Cond::Ne => "jne", Cond::Gt => "jgt", Cond::Ge => "jge", Cond::Lt => "jlt", Cond::Le => "jle", Cond::Sgt => "jsgt", Cond::Sge => "jsge", Cond::Slt => "jslt", Cond::Sle => "jsle" } }
fn parse_cond_op(s: &str) -> Option<(Cond, AluOp)> { let (name, suf) = s.split_at(s.len().saturating_sub(2)); let alu = match suf { "32" => AluOp::Alu32, "64" => AluOp::Alu64, _ => return None }; Some((match name { "jeq" => Cond::Eq, "jne" => Cond::Ne, "jgt" => Cond::Gt, "jge" => Cond::Ge, "jlt" => Cond::Lt, "jle" => Cond::Le, "jsgt" => Cond::Sgt, "jsge" => Cond::Sge, "jslt" => Cond::Slt, "jsle" => Cond::Sle, _ => return None }, alu)) }
fn extra_name(e: LoadImmExtra) -> &'static str { match e { LoadImmExtra::Imm64 => "imm64", LoadImmExtra::MapByFd => "map_by_fd", LoadImmExtra::MapValFd => "map_val_fd", LoadImmExtra::VarAddr => "var_addr", LoadImmExtra::CodeAddr => "code_addr", LoadImmExtra::MapByIdx => "map_by_idx", LoadImmExtra::MapValIdx => "map_val_idx" } }
fn parse_extra(s: &str, line_no: usize) -> Result<LoadImmExtra> { Ok(match s { "imm64" => LoadImmExtra::Imm64, "map_by_fd" => LoadImmExtra::MapByFd, "map_val_fd" => LoadImmExtra::MapValFd, "var_addr" => LoadImmExtra::VarAddr, "code_addr" => LoadImmExtra::CodeAddr, "map_by_idx" => LoadImmExtra::MapByIdx, "map_val_idx" => LoadImmExtra::MapValIdx, _ => return Err(invalid!("IR parse line {line_no}: bad loadimm kind {s}")) }) }
