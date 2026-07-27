"use client"
import { motion } from "framer-motion"
import { GlassCard } from "@/components/GlassCard"
import { fadeUpVariants } from "@/lib/animations"
import { Binary, ShieldAlert, Layers, Zap, GitBranch } from "lucide-react"

/**
 * Pickle opcode forensics emitted by scanner/pickle_forensics.py and surfaced
 * (for .pkl / .pt / .bin / .pth) at metadata.format_specific. All fields are
 * optional; the card returns null for non-pickle formats (safetensors, gguf,
 * onnx) and pre-Phase-2 cached scans.
 */
export interface PickleForensicsMeta {
  opcode_count?: number
  opcode_histogram?: Record<string, number>
  global_references?: string[]
  reduce_count?: number
  build_count?: number
  inst_count?: number
  newobj_count?: number
  ext_count?: number
  num_streams?: number
  truncated?: boolean
  pickle_protocol?: number
}

/* ── Client-side global classification (mirrors pickle_forensics.py) ───── */

const DANGEROUS = new Set<string>([
  "os.system", "os.popen", "os.execv", "os.execve", "os.spawnv", "os.spawnve", "os.startfile",
  "posix.system", "posix.popen", "posix.execv", "posix.execve", "posix.spawnv",
  "nt.system", "nt.popen", "nt.startfile", "_posixsubprocess.fork_exec",
  "subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_output",
  "subprocess.check_call", "subprocess.getoutput", "subprocess.getstatusoutput",
  "builtins.exec", "builtins.eval", "builtins.compile", "builtins.__import__",
  "builtins.getattr", "builtins.setattr", "builtins.globals", "builtins.vars", "builtins.breakpoint",
  "__builtin__.exec", "__builtin__.eval", "__builtin__.compile", "__builtin__.__import__", "__builtin__.getattr",
  "ctypes.cdll", "ctypes.CDLL", "ctypes.WinDLL", "ctypes.windll", "ctypes.PyDLL", "ctypes.LibraryLoader",
  "importlib.import_module", "importlib.__import__", "importlib.util.spec_from_file_location",
  "marshal.loads", "marshal.load", "pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load",
  "pty.spawn", "socket.socket", "runpy.run_path", "runpy._run_module_code", "codecs.decode",
  "operator.attrgetter", "operator.methodcaller", "functools.partial", "webbrowser.open",
  "timeit.timeit", "bdb.Bdb", "sys.modules",
])
const SAFE_PREFIXES = ["torch", "collections", "numpy", "argparse", "copyreg"]
const SAFE_EXACT = new Set<string>([
  "builtins.set", "builtins.frozenset", "builtins.list", "builtins.dict", "builtins.tuple",
  "builtins.bytearray", "builtins.complex", "copyreg._reconstructor",
  "__builtin__.set", "__builtin__.frozenset",
])

type Cls = "danger" | "untrusted" | "safe"
function classify(ref: string): Cls {
  if (DANGEROUS.has(ref)) return "danger"
  const mod = ref.slice(0, ref.lastIndexOf("."))
  if (SAFE_EXACT.has(ref)) return "safe"
  if (SAFE_PREFIXES.some((p) => mod === p || mod.startsWith(p + "."))) return "safe"
  return "untrusted"
}

const CLS_STYLE: Record<Cls, { color: string; bg: string; label: string }> = {
  danger: { color: "var(--danger)", bg: "var(--danger-bg)", label: "RCE gadget" },
  untrusted: { color: "var(--warn)", bg: "var(--warn-bg)", label: "untrusted" },
  safe: { color: "var(--safe)", bg: "var(--safe-bg)", label: "allow-listed" },
}

/* ── Opcode grouping for the histogram (execution opcodes highlighted) ── */
const EXEC_OPCODES = new Set(["REDUCE", "GLOBAL", "STACK_GLOBAL", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "EXT1", "EXT2", "EXT4"])

function Counter({ icon, label, value, danger }: { icon: React.ReactNode; label: string; value: number; danger?: boolean }) {
  const on = value > 0
  return (
    <div
      style={{
        background: "var(--bg-subtle)",
        border: `1px solid ${on && danger ? "var(--danger-border)" : "var(--gold-border)"}`,
        borderRadius: "var(--radius-md)",
        padding: "12px 14px",
        display: "flex",
        flexDirection: "column",
        gap: "4px",
      }}
    >
      <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "0.68rem", letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)" }}>
        {icon} {label}
      </span>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "1.35rem", fontWeight: 700, color: on ? (danger ? "var(--danger)" : "var(--gold-bright)") : "var(--text-muted)", lineHeight: 1 }}>{value}</span>
    </div>
  )
}

export function PickleForensicsCard({ meta }: { meta?: PickleForensicsMeta | null }) {
  const isPickle =
    meta &&
    (meta.opcode_count !== undefined ||
      meta.pickle_protocol !== undefined ||
      (meta.opcode_histogram && Object.keys(meta.opcode_histogram).length > 0))
  if (!isPickle) return null

  const histogram = Object.entries(meta!.opcode_histogram || {}).sort((a, b) => b[1] - a[1])
  const maxCount = histogram.length ? histogram[0][1] : 1
  const topHistogram = histogram.slice(0, 14)
  const refs = (meta!.global_references || []).map((r) => ({ ref: r, cls: classify(r) }))
  refs.sort((a, b) => {
    const order = { danger: 0, untrusted: 1, safe: 2 }
    return order[a.cls] - order[b.cls]
  })
  const dangerCount = refs.filter((r) => r.cls === "danger").length
  const untrustedCount = refs.filter((r) => r.cls === "untrusted").length
  const streams = meta!.num_streams ?? 1

  return (
    <>
      <motion.h3 variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "16px", color: "var(--text-primary)", display: "inline-flex", alignItems: "center", gap: "10px" }}>
        <Binary size={20} color="var(--gold-bright)" /> Pickle Opcode Forensics
        {meta!.pickle_protocol !== undefined && (
          <span className="tag tag-info" style={{ marginLeft: "4px" }}>protocol {meta!.pickle_protocol}</span>
        )}
      </motion.h3>

      <motion.div variants={fadeUpVariants} initial="hidden" animate="visible" style={{ marginBottom: "40px" }}>
        <GlassCard style={{ padding: "24px", display: "flex", flexDirection: "column", gap: "22px" }}>

          {/* Concatenated-stream alert — a high-signal evasion indicator */}
          {streams > 1 && (
            <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "14px 16px", background: "var(--danger-bg)", border: "1px solid var(--danger-border)", borderRadius: "var(--radius-md)", boxShadow: "var(--danger-glow)" }}>
              <GitBranch size={20} color="var(--danger)" style={{ flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 700, color: "var(--danger)" }}>{streams} concatenated pickle streams detected</div>
                <div style={{ fontSize: "0.83rem", color: "var(--text-secondary)" }}>
                  Additional pickle data follows the first STOP opcode — a known trick to hide a malicious payload behind a benign-looking first object.
                </div>
              </div>
            </div>
          )}

          {/* Execution-opcode counters */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: "12px" }}>
            <Counter icon={<Zap size={12} />} label="Total Opcodes" value={meta!.opcode_count ?? 0} />
            <Counter icon={<ShieldAlert size={12} />} label="REDUCE" value={meta!.reduce_count ?? 0} danger />
            <Counter icon={<ShieldAlert size={12} />} label="BUILD" value={meta!.build_count ?? 0} danger />
            <Counter icon={<ShieldAlert size={12} />} label="NEWOBJ" value={meta!.newobj_count ?? 0} danger />
            <Counter icon={<ShieldAlert size={12} />} label="EXT1/2/4" value={meta!.ext_count ?? 0} danger />
            <Counter icon={<Layers size={12} />} label="Streams" value={streams} danger={streams > 1} />
          </div>

          {/* Global reference list — classified */}
          {refs.length > 0 && (
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px", flexWrap: "wrap", gap: "8px" }}>
                <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                  <ShieldAlert size={14} color="var(--warn)" /> Global references ({refs.length})
                </span>
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  {dangerCount > 0 && <span style={{ color: "var(--danger)" }}>{dangerCount} dangerous</span>}
                  {dangerCount > 0 && untrustedCount > 0 && " · "}
                  {untrustedCount > 0 && <span style={{ color: "var(--warn)" }}>{untrustedCount} untrusted</span>}
                  {dangerCount === 0 && untrustedCount === 0 && "all allow-listed"}
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "260px", overflowY: "auto" }}>
                {refs.map(({ ref, cls }, i) => {
                  const s = CLS_STYLE[cls]
                  return (
                    <motion.div
                      key={`${ref}-${i}`}
                      variants={fadeUpVariants}
                      custom={Math.min(i, 8)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        gap: "12px",
                        padding: "8px 12px",
                        background: cls === "safe" ? "var(--bg-subtle)" : s.bg,
                        border: `1px solid ${cls === "safe" ? "var(--border-fine)" : s.color + "40"}`,
                        borderRadius: "var(--radius-sm)",
                      }}
                    >
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: cls === "safe" ? "var(--text-secondary)" : s.color, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {cls === "danger" && <ShieldAlert size={13} style={{ display: "inline", verticalAlign: "-2px", marginRight: "6px" }} />}
                        {ref}
                      </span>
                      <span className="tag" style={{ flexShrink: 0, background: "transparent", color: s.color, border: `1px solid ${s.color}40`, fontSize: "0.68rem" }}>
                        {s.label}
                      </span>
                    </motion.div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Opcode histogram */}
          {topHistogram.length > 0 && (
            <div>
              <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)", display: "inline-flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
                <Binary size={14} color="var(--gold-bright)" /> Opcode distribution (top {topHistogram.length})
              </span>
              <div style={{ display: "flex", flexDirection: "column", gap: "7px" }}>
                {topHistogram.map(([op, count], i) => {
                  const exec = EXEC_OPCODES.has(op)
                  const pct = (count / maxCount) * 100
                  return (
                    <div key={op} style={{ display: "grid", gridTemplateColumns: "150px 1fr 48px", alignItems: "center", gap: "12px" }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: exec ? "var(--warn)" : "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {exec && <Zap size={11} style={{ display: "inline", verticalAlign: "-1px", marginRight: "4px" }} />}
                        {op}
                      </span>
                      <div style={{ height: "10px", background: "var(--bg-base)", borderRadius: "999px", overflow: "hidden", border: "1px solid var(--border-subtle)" }}>
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.7, delay: Math.min(i * 0.03, 0.4), ease: [0.22, 1, 0.36, 1] }}
                          style={{
                            height: "100%",
                            borderRadius: "999px",
                            background: exec ? "linear-gradient(90deg,#F59E0B,#EF4444)" : "linear-gradient(90deg,#8B6914,#D4AF37)",
                          }}
                        />
                      </div>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--text-muted)", textAlign: "right" }}>{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {meta!.truncated && (
            <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontStyle: "italic" }}>
              ⚠ Opcode analysis was capped or the stream ended early — counts are a lower bound.
            </div>
          )}
        </GlassCard>
      </motion.div>
    </>
  )
}
