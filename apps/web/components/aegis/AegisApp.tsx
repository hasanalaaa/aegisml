"use client";

import { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { API_BASE_URL } from "@/lib/api";
import { BYOK_PROVIDERS, byokHeaders, sealKey, getKey, getActiveProvider, setActiveProvider, initByok } from "@/lib/byok";
import { useDashboardData, type RecentScan } from "@/hooks/useDashboardData";
import { NumberTicker } from "@/components/NumberTicker";
import { motion, AnimatePresence } from "framer-motion";
import { tabVariants, riseItem, cascadeContainer, cascadeItem } from "@/lib/animations";
import Link from "next/link";

const SUPPORTED_EXTENSIONS = [".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"];
const isSupported = (name: string) => SUPPORTED_EXTENSIONS.some((ext) => name.toLowerCase().endsWith(ext));

/* ============ i18n dictionary ============ */
const DICT = {
  en: {
    tagline: "Model Static Analysis", secureSession: "CONFIGURED SCAN ENGINE",
    heroBadge: "Local-first deployment · Static analysis",
    heroPre: "Inspect models with", heroEm: "evidence, not guarantees.",
    heroSub: "AegisML sends the selected artifact to the scan engine you configure. It inspects bytes, structure, metadata, and known patterns without executing the model. Static analysis can miss runtime-only behavior.",
    dropTitle: "Drop one model file", dropOr: "or", dropBrowse: "browse your device", dropHint: ".gguf, .safetensors, .pkl, .pickle, .pt, or .pth up to 100 GB",
    ready: "READY", oneFile: "Only one file can be scanned at a time", orUrl: "OR SCAN A HUGGING FACE FILE URL", runScan: "Run Scan",
    analyzing: "Starting scan…",
    byokTitle: "Bring Your Own Key",
    byokDesc: "Provider keys are encrypted at rest in this browser. When BYOK is enabled, the selected key is sent to the configured scan engine for that request.",
    provider: "PROVIDER", secretKey: "SECRET KEY", show: "SHOW", hide: "HIDE",
    sealBtn: "Seal Key", savedBtn: "Saved ✓",
    sealed: "Encrypted at rest in this browser",
    keySavedMsg: "Key encrypted locally. It is attached only while BYOK is enabled.",
    opsOverview: "OPERATIONS OVERVIEW", threatCommand: "Scan Activity", newScan: "New Scan",
    documentation: "DOCUMENTATION", aegisProtocol: "How AegisML Scans",
    footerRight: "STATIC ANALYSIS · NO SAFETY GUARANTEE",
    nav: { dashboard: "Dashboard", scanner: "Scanner", docs: "Docs" },
    sev: { Critical: "Critical", High: "High", Medium: "Medium", Resolved: "Resolved" },
    totalScans: "Total Scans", threatsFlagged: "Threats Flagged", avgRisk: "Avg Risk Score",
    riskDistribution: "Risk Distribution", recentScans: "Recent Scans", liveData: "LIVE",
    noScansTitle: "No scans yet", noScansBody: "Run your first scan to populate live metrics.",
    statsError: "Couldn’t load live stats", retry: "Retry", threatsLabel: "threats",
    scanFailed: "Scan failed to start", sealFailed: "Secure browser storage is unavailable", needTarget: "Add one file or a Hugging Face file URL", unsupported: "Unsupported file type",
  },
  ar: {
    tagline: "التحليل الساكن للنماذج", secureSession: "محرك الفحص المضبوط",
    heroBadge: "تشغيل محلي أولاً · تحليل ساكن",
    heroPre: "افحص النماذج بأدلة", heroEm: "لا بوعود مطلقة.",
    heroSub: "ترسل AegisML العنصر المحدد إلى محرك الفحص الذي تضبطه. يفحص البايتات والبنية والبيانات الوصفية والأنماط المعروفة من دون تشغيل النموذج. قد يفوّت التحليل الساكن سلوكاً لا يظهر إلا وقت التشغيل.",
    dropTitle: "أفلت ملف نموذج واحد", dropOr: "أو", dropBrowse: "تصفّح جهازك", dropHint: ".gguf أو .safetensors أو .pkl أو .pickle أو .pt أو .pth حتى 100 غيغابايت",
    ready: "جاهز", oneFile: "يمكن فحص ملف واحد فقط في كل مرة", orUrl: "أو افحص رابط ملف على Hugging Face", runScan: "ابدأ الفحص",
    analyzing: "جارٍ بدء الفحص…",
    byokTitle: "استخدم مفتاحك الخاص",
    byokDesc: "تُشفّر مفاتيح المزوّد عند تخزينها في هذا المتصفح. عند تفعيل الخيار، يُرسل المفتاح المحدد إلى محرك الفحص المضبوط لذلك الطلب.",
    provider: "المزوّد", secretKey: "المفتاح السري", show: "إظهار", hide: "إخفاء",
    sealBtn: "ختم المفتاح", savedBtn: "تم الحفظ ✓",
    sealed: "مشفّر عند التخزين في هذا المتصفح",
    keySavedMsg: "شُفّر المفتاح محلياً. لن يُرفق إلا أثناء تفعيل خيار المفتاح الخاص.",
    opsOverview: "نظرة عامة على العمليات", threatCommand: "نشاط الفحص", newScan: "فحص جديد",
    documentation: "التوثيق", aegisProtocol: "كيف تفحص AegisML",
    footerRight: "تحليل ساكن · لا يضمن سلامة النموذج",
    nav: { dashboard: "لوحة القيادة", scanner: "الماسح الأمني", docs: "المستندات" },
    sev: { Critical: "حرج", High: "عالٍ", Medium: "متوسط", Resolved: "تمت المعالجة" },
    totalScans: "إجمالي الفحوصات", threatsFlagged: "تهديدات موسومة", avgRisk: "متوسط درجة الخطورة",
    riskDistribution: "توزيع الخطورة", recentScans: "أحدث الفحوصات", liveData: "مباشر",
    noScansTitle: "لا توجد فحوصات بعد", noScansBody: "شغّل أول فحص لتعبئة المقاييس المباشرة.",
    statsError: "تعذّر تحميل الإحصاءات المباشرة", retry: "إعادة المحاولة", threatsLabel: "تهديدات",
    scanFailed: "فشل بدء الفحص", sealFailed: "التخزين الآمن في المتصفح غير متاح", needTarget: "أضف ملفاً واحداً أو رابط ملف على Hugging Face", unsupported: "نوع ملف غير مدعوم",
  },
} as const;

type Lang = keyof typeof DICT;

const SEV_STYLE: Record<string, string> = {
  Critical: "text-[#E88A6B] bg-[rgba(224,124,90,0.12)] border-[rgba(224,124,90,0.35)]",
  High: "text-[#E6B26B] bg-[rgba(224,168,90,0.12)] border-[rgba(224,168,90,0.35)]",
  Medium: "text-[#DFC96A] bg-[rgba(216,194,94,0.1)] border-[rgba(216,194,94,0.3)]",
  Resolved: "text-[#7BD6A2] bg-[rgba(111,207,151,0.1)] border-[rgba(111,207,151,0.3)]",
};

const RISK_TO_SEV: Record<string, string> = {
  clean: "Resolved", suspicious: "Medium", malicious: "High", critical: "Critical",
};

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

const DOC_TABS = {
  en: [
    { key: "overview", tag: "01", label: "Overview", title: "Local-first deployment",
      lead: "The web app talks to the scan engine configured by NEXT_PUBLIC_API_URL. Point it at a service on your device or at infrastructure you operate; the selected file is sent to that service for analysis.",
      points: [{ h: "One configured boundary", d: "Your deployment decides where the scan engine runs and who can reach it." }, { h: "No model execution", d: "The scanner reads file bytes and metadata without loading the submitted model for inference." }, { h: "Evidence for review", d: "Findings support triage; they do not certify that a model is safe." }] },
    { key: "byok", tag: "02", label: "BYOK", title: "Browser key storage",
      lead: "A provider key is encrypted at rest in this browser. When BYOK is enabled, the decrypted key is attached to the scan request and becomes visible to the configured scan engine for that request.",
      points: [{ h: "Encrypted at rest", d: "Ciphertext is stored locally and its non-exportable encryption key is kept in IndexedDB." }, { h: "Explicit transmission", d: "Turning BYOK off prevents the provider headers from being sent." }, { h: "Browser boundary", d: "This does not protect a key from malicious code already running on the same browser origin." }] },
    { key: "taxonomy", tag: "03", label: "Findings", title: "Rule-based evidence",
      lead: "AegisML groups matches by severity and category so reviewers can prioritize them. A match is evidence to investigate, not proof of intent or exploitability.",
      points: [{ h: "Known byte patterns", d: "Rules compare file content with signatures included in the scan engine." }, { h: "Structure checks", d: "Format-aware parsers inspect headers and metadata for unusual or unsafe structures." }, { h: "Optional AI review", d: "When configured, provider output is an additional heuristic and can be wrong." }] },
    { key: "pipeline", tag: "04", label: "Pipeline", title: "Static scan stages",
      lead: "The engine validates the file header, runs structure and pattern checks, and may request optional AI analysis. Progress events report those stages to this interface.",
      points: [{ h: "Header validation", d: "Checks whether the submitted bytes match a supported model format." }, { h: "Bounded checks", d: "Pattern, structure, and entropy checks run without executing the model." }, { h: "Report", d: "The engine returns findings, metadata, and a risk score for human review." }] },
    { key: "limits", tag: "05", label: "Limits", title: "Know the limits",
      lead: "Static analysis can miss runtime-only behavior, dynamically downloaded code, encrypted payloads, and novel patterns. A clean result is not a safety guarantee.",
      points: [{ h: "Coverage is finite", d: "Detection depends on parsers and rules available in the engine version you run." }, { h: "Runtime remains separate", d: "Test untrusted models in an isolated runtime with restricted network and filesystem access." }, { h: "Review high-impact use", d: "Combine scan evidence with provenance, deployment controls, and human review." }] },
  ],
  ar: [
    { key: "overview", tag: "01", label: "نظرة عامة", title: "تشغيل محلي أولاً",
      lead: "يتصل تطبيق الويب بمحرك الفحص المحدد في NEXT_PUBLIC_API_URL. يمكنك توجيهه إلى خدمة على جهازك أو إلى بنية تديرها أنت؛ ويُرسل الملف المحدد إلى تلك الخدمة للتحليل.",
      points: [{ h: "حدّ تشغيل واضح", d: "طريقة نشرك هي التي تحدد مكان تشغيل محرك الفحص ومن يستطيع الوصول إليه." }, { h: "دون تشغيل النموذج", d: "يقرأ الماسح بايتات الملف وبياناته الوصفية من دون تحميل النموذج المرسل للاستدلال." }, { h: "أدلة للمراجعة", d: "تساعد النتائج على الفرز، لكنها لا تصادق على سلامة النموذج." }] },
    { key: "byok", tag: "02", label: "المفتاح الخاص", title: "تخزين المفتاح في المتصفح",
      lead: "يُشفّر مفتاح المزوّد عند التخزين في هذا المتصفح. عند تفعيل الخيار، يُرفق المفتاح بعد فك تشفيره بطلب الفحص ويصبح متاحاً لمحرك الفحص المضبوط لذلك الطلب.",
      points: [{ h: "تشفير عند التخزين", d: "تُخزن النسخة المشفرة محلياً ويُحفظ مفتاح تشفير غير قابل للتصدير في IndexedDB." }, { h: "إرسال صريح", d: "إيقاف الخيار يمنع إرسال ترويسات المزوّد." }, { h: "حدود المتصفح", d: "لا يحمي ذلك المفتاح من شيفرة ضارة تعمل بالفعل ضمن نطاق المتصفح نفسه." }] },
    { key: "taxonomy", tag: "03", label: "النتائج", title: "أدلة مبنية على القواعد",
      lead: "تجمع AegisML التطابقات حسب الخطورة والفئة لتسهيل ترتيبها. التطابق دليل يستحق التحقيق، وليس إثباتاً للنية أو لقابلية الاستغلال.",
      points: [{ h: "أنماط بايتات معروفة", d: "تقارن القواعد محتوى الملف بالتواقيع المتوفرة في محرك الفحص." }, { h: "فحوصات البنية", d: "تفحص المحللات الخاصة بالصيغة الترويسات والبيانات الوصفية بحثاً عن بنى غير معتادة أو غير آمنة." }, { h: "مراجعة AI اختيارية", d: "عند ضبطها، تكون نتيجة المزوّد مؤشراً إضافياً وقد تكون خاطئة." }] },
    { key: "pipeline", tag: "04", label: "المسار", title: "مراحل الفحص الساكن",
      lead: "يتحقق المحرك من ترويسة الملف، ويجري فحوصات البنية والأنماط، وقد يطلب تحليلاً اختيارياً من مزوّد AI. تعرض الواجهة أحداث تقدم هذه المراحل.",
      points: [{ h: "التحقق من الترويسة", d: "يفحص ما إذا كانت البايتات المرسلة تطابق صيغة نموذج مدعومة." }, { h: "فحوصات محدودة الموارد", d: "تُجرى فحوصات الأنماط والبنية والإنتروبيا من دون تشغيل النموذج." }, { h: "التقرير", d: "يعيد المحرك النتائج والبيانات الوصفية ودرجة خطورة للمراجعة البشرية." }] },
    { key: "limits", tag: "05", label: "الحدود", title: "اعرف حدود الفحص",
      lead: "قد يفوّت التحليل الساكن سلوكاً لا يظهر إلا وقت التشغيل، أو شيفرة تُنزّل ديناميكياً، أو حمولات مشفرة، أو أنماطاً جديدة. النتيجة النظيفة لا تضمن السلامة.",
      points: [{ h: "التغطية محدودة", d: "يعتمد الكشف على المحللات والقواعد المتوفرة في إصدار المحرك الذي تشغله." }, { h: "التشغيل مرحلة منفصلة", d: "اختبر النماذج غير الموثوقة في بيئة معزولة ذات وصول مقيّد للشبكة ونظام الملفات." }, { h: "راجع الاستخدام عالي الأثر", d: "ادمج أدلة الفحص مع مصدر النموذج وضوابط النشر والمراجعة البشرية." }] },
  ],
} as const;

/* ============ reusable pieces ============ */

// mirrors automatically: uses logical inset-inline-start so RTL flips the knob
function Toggle({ on, onClick, label, small = false }: { on: boolean; onClick: () => void; label: string; small?: boolean }) {
  const wrap = small ? "w-[52px] h-[29px]" : "w-[58px] h-[32px]";
  const knob = small ? "w-[21px] h-[21px]" : "w-[24px] h-[24px]";
  const onStart = small ? "start-[26px]" : "start-[29px]"; // Tailwind `start-*` = inset-inline-start
  return (
    <button
      type="button"
      onClick={onClick}
      role="switch"
      aria-checked={on}
      aria-label={label}
      className={`relative flex-shrink-0 ${wrap} rounded-full border p-0 cursor-pointer transition-all duration-300 ${
        on ? "bg-gradient-to-br from-[#D8B25E] to-[#B88A38] border-[rgba(201,163,90,0.5)]"
           : "bg-[rgba(255,255,255,0.06)] border-[rgba(255,255,255,0.12)]"
      }`}
    >
      <span className={`absolute top-[3px] ${knob} rounded-full shadow-[0_2px_6px_rgba(0,0,0,0.4)] transition-all duration-300 ${
        on ? `${onStart} bg-[#1c1608]` : "start-[3px] bg-[rgba(237,234,227,0.6)]"
      }`} />
    </button>
  );
}

function SevBadge({ label, sevKey, wide = false }: { label: string; sevKey: string; wide?: boolean }) {
  return (
    <span className={`text-[10px] font-semibold px-2.5 py-1 rounded-md border whitespace-nowrap ${wide ? "min-w-[78px] text-center" : ""} ${SEV_STYLE[sevKey]}`}>
      {label}
    </span>
  );
}

function StatCard({ mono, label, value, suffix, accent }: { mono: string; label: string; value: number | null; suffix?: string; accent?: boolean }) {
  return (
    <motion.div variants={cascadeItem} whileHover={{ y: -4, boxShadow: "0 0 0 1px rgba(212,175,55,0.28), 0 12px 42px rgba(0,0,0,0.55)" }} transition={{ type: "spring", stiffness: 320, damping: 26 }} className="rounded-[18px] border border-[rgba(201,163,90,0.16)] p-6 sm:p-[26px] flex flex-col justify-between min-h-[120px]" style={{ background: "linear-gradient(180deg,rgba(18,18,20,0.7),rgba(12,12,14,0.8))" }}>
      <span className="text-[11px] font-semibold text-[rgba(237,234,227,0.6)] uppercase tracking-wide">{label}</span>
      {value === null ? (
        <div className="h-10 w-24 mt-2 rounded-md bg-[rgba(255,255,255,0.05)] animate-pulse" />
      ) : (
        <div className={`${mono} text-[38px] sm:text-[46px] font-semibold leading-none mt-2 ${accent ? "text-[#E6B26B]" : "text-[#F6E6B0]"}`}>
          <NumberTicker value={value} decimals={Number.isInteger(value) ? 0 : 1} />
          {suffix ? <span className="text-[15px] text-[rgba(237,234,227,0.6)]"> {suffix}</span> : null}
        </div>
      )}
    </motion.div>
  );
}

function EmptyState({ mono, title, body }: { mono: string; title: string; body: string }) {
  return (
    <div className="mt-6 flex flex-col items-center text-center py-8 px-4">
      <div className="w-10 h-10 rounded-full border border-[rgba(201,163,90,0.3)] flex items-center justify-center mb-3">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.6"><path d="M3 3v18h18" /><path d="M7 14l4-4 3 3 5-6" /></svg>
      </div>
      <div className="text-[14.5px] text-[#F0EBDF] font-semibold mb-1">{title}</div>
      <div className={`${mono} text-[11.5px] text-[rgba(237,234,227,0.6)] max-w-[280px]`}>{body}</div>
    </div>
  );
}

/* ============ main component ============ */

export default function AegisApp() {
  const [lang, setLang] = useState<Lang>("ar");          // default Arabic
  const [page, setPage] = useState<"scanner" | "dashboard" | "docs">("scanner");

  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<{ name: string; size: string; file: File } | null>(null);
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);

  const [byok, setByok] = useState(false);
  const [provider, setProvider] = useState("anthropic");
  const [apiKey, setApiKey] = useState("");
  const [reveal, setReveal] = useState(false);
  const [keySaved, setKeySaved] = useState(false);

  const [activeDoc, setActiveDoc] = useState("overview");

  const fileInputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  // Live dashboard data (fetched on mount; refreshable via dash.reload()).
  const dash = useDashboardData(6);

  const ar = lang === "ar";
  const t = DICT[lang];
  const dir = ar ? "rtl" : "ltr";

  // font family per language — reference next/font CSS variables (hashed
  // families won't resolve via a literal `font-['Cairo']` name).
  const baseFont = ar ? "font-[family-name:var(--font-cairo)]" : "font-[family-name:var(--font-manrope)]";
  const serifFont = ar ? "font-[family-name:var(--font-cairo)]" : "font-[family-name:var(--font-cormorant)]";
  const mono = "font-[family-name:var(--font-jetbrains)]";
  const cormorant = "font-[family-name:var(--font-cormorant)]"; // wordmark/avatar stay Cormorant in both langs

  // mirror language/direction onto <html> so UA behaviour (scrollbar side,
  // form controls, ::selection) matches. Client-only → no SSR mismatch.
  useEffect(() => {
    document.documentElement.dir = dir;
    document.documentElement.lang = lang;
  }, [dir, lang]);

  // hydrate BYOK state from encrypted storage on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      await initByok();
      if (cancelled) return;
      const active = getActiveProvider();
      setProvider(active);
      const existing = getKey(active);
      if (existing) { setApiKey(existing); setByok(true); setKeySaved(true); }
    })();
    return () => { cancelled = true; };
  }, []);

  const goTo = (p: typeof page) => setPage(p);

  const fmtSize = (b: number) =>
    b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : b < 1073741824 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1073741824).toFixed(2)} GB`;

  const selectFile = (list: FileList) => {
    if (list.length > 1) toast.info(t.oneFile);
    const selected = Array.from(list).find((candidate) => isSupported(candidate.name));
    if (!selected) {
      toast.error(t.unsupported, { description: SUPPORTED_EXTENSIONS.join(", ") });
      return;
    }
    setFile({ name: selected.name, size: fmtSize(selected.size), file: selected });
  };

  // Real scan: POST to the backend with BYOK headers, then hand off to the
  // live report route (/scan/[id]) which streams progress + real findings.
  const startScan = async () => {
    if (scanning) return;
    const targetUrl = url.trim();
    if (!file && !targetUrl) { toast.error(t.needTarget); return; }
    setScanning(true);
    try {
      const headers = byokHeaders(byok);
      let res: Response;
      if (file) {
        const fd = new FormData();
        fd.append("file", file.file);
        res = await fetch(`${API_BASE_URL}/api/v1/scan/file`, { method: "POST", headers, body: fd });
      } else {
        res = await fetch(`${API_BASE_URL}/api/v1/scan/url`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...headers },
          body: JSON.stringify({ url: targetUrl }),
        });
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({} as { detail?: string }));
        throw new Error((body as { detail?: string }).detail || `Server returned ${res.status}`);
      }
      const data = await res.json();
      if (!data.scan_id) throw new Error("Server did not return a scan ID");
      router.push(`/scan/${data.scan_id}`);
    } catch (err) {
      setScanning(false);
      toast.error(t.scanFailed, { description: err instanceof Error ? err.message : undefined });
    }
  };

  const sealCurrentKey = async () => {
    if (!apiKey.trim()) return;
    try {
      await sealKey(provider, apiKey);
      setActiveProvider(provider);
      setKeySaved(true);
    } catch {
      toast.error(t.sealFailed);
    }
  };

  const activeDocData = DOC_TABS[lang].find((d) => d.key === activeDoc) ?? DOC_TABS[lang][0];

  return (
    <div
      dir={dir}
      className={`min-h-screen text-[#EDEAE3] relative overflow-x-hidden bg-[#0B0B0C] ${baseFont}`}
      style={{
        backgroundImage: `
          radial-gradient(1200px 620px at 78% -8%, rgba(216,178,94,0.14), transparent 60%),
          radial-gradient(900px 520px at 8% 4%, rgba(216,178,94,0.06), transparent 55%),
          radial-gradient(700px 700px at 50% 120%, rgba(216,178,94,0.05), transparent 60%)`,
      }}
    >
      <style jsx global>{`
        @keyframes aegisEnter { from { opacity: .55; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes aegisGlow { 0%,100% { opacity: .5; } 50% { opacity: .9; } }
        @keyframes aegisSpin { to { transform: rotate(360deg); } }
        @keyframes aegisPulse { 0%,100% { transform: scale(1); opacity: .9; } 50% { transform: scale(1.35); opacity: .2; } }
        @keyframes aegisScan { 0% { top: 0; opacity: 0; } 10% { opacity: 1; } 90% { opacity: 1; } 100% { top: 100%; opacity: 0; } }
        @keyframes aegisPulseGlow {
          0%,100% { box-shadow: 0 6px 20px rgba(184,138,56,.32), 0 0 0 rgba(216,178,94,0); }
          50% { box-shadow: 0 8px 26px rgba(184,138,56,.5), 0 0 24px rgba(216,178,94,.38); }
        }
      `}</style>

      {/* noise overlay */}
      <div className="fixed inset-0 pointer-events-none opacity-50" style={{
        backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.035'/%3E%3C/svg%3E\")",
      }} />

      {/* ================= NAVBAR ================= */}
      <nav className="sticky top-0 z-50 flex flex-wrap sm:flex-nowrap items-center justify-between gap-2 px-4 sm:px-10 py-3 sm:py-4 bg-[rgba(11,11,12,0.72)] backdrop-blur-xl backdrop-saturate-150 border-b border-[rgba(201,163,90,0.18)]">
        <button type="button" onClick={() => goTo("scanner")} aria-label={t.nav.scanner} className="flex items-center gap-2 sm:gap-[13px] cursor-pointer min-w-0 bg-transparent border-0 p-0 text-inherit">
          <svg width="34" height="38" viewBox="0 0 34 38" fill="none">
            <path d="M17 1.5 32 8v11.5C32 29 25.5 34.5 17 36.5 8.5 34.5 2 29 2 19.5V8L17 1.5Z" stroke="url(#gg)" strokeWidth="1.4" fill="rgba(216,178,94,0.05)" />
            <path d="M17 10.5 17 26M10 18.2 17 26 24 18.2" stroke="url(#gg)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            <defs><linearGradient id="gg" x1="2" y1="2" x2="32" y2="36" gradientUnits="userSpaceOnUse"><stop stopColor="#F4E2A8" /><stop offset="0.5" stopColor="#D8B25E" /><stop offset="1" stopColor="#B88A38" /></linearGradient></defs>
          </svg>
          <div className="flex flex-col leading-none">
            {/* wordmark stays Cormorant in both languages */}
            <span className={`${cormorant} font-semibold text-[23px] tracking-wide text-[#F3EEE3]`}>Aegis<span className="text-[#D8B25E]">ML</span></span>
            <span className={`${mono} hidden sm:block text-[8.5px] tracking-[2.4px] text-[rgba(201,163,90,0.65)] mt-1 uppercase`}>{t.tagline}</span>
          </div>
        </button>

        <div className="order-3 sm:order-none w-full sm:w-auto flex items-center justify-center gap-0.5 sm:gap-1.5 overflow-x-auto pt-1 sm:pt-0 border-t sm:border-t-0 border-[rgba(201,163,90,0.12)]">
          {(Object.keys(t.nav) as (keyof typeof t.nav)[]).map((key) => {
            const active = page === key;
            return (
              <button key={key} onClick={() => goTo(key)}
                aria-pressed={active}
                className={`relative bg-transparent border-none cursor-pointer text-[13px] sm:text-sm font-semibold px-3 sm:px-4 py-2.5 transition-colors duration-300 hover:text-[#F3EEE3] ${active ? "text-[#F3EEE3]" : "text-[rgba(237,234,227,0.55)]"}`}>
                {t.nav[key]}
                {active && <motion.span layoutId="nav-underline" transition={{ type: "spring", stiffness: 420, damping: 32 }} className="absolute inset-x-4 bottom-0.5 h-[1.5px] bg-gradient-to-r from-transparent via-[#D8B25E] to-transparent" />}
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          {/* language toggle */}
          <button onClick={() => setLang(ar ? "en" : "ar")}
            className="flex items-center gap-2 px-[13px] py-[7px] border border-[rgba(201,163,90,0.28)] rounded-full bg-[rgba(216,178,94,0.05)] cursor-pointer transition-all duration-300 hover:border-[rgba(216,178,94,0.6)] hover:bg-[rgba(216,178,94,0.1)]">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.6"><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20" /></svg>
            <span className={`${mono} text-[11px] tracking-wide font-semibold text-[#F3EEE3]`}>{ar ? "EN" : "عربي"}</span>
          </button>
          <div className="hidden md:flex items-center gap-2 px-3.5 py-[7px] border border-[rgba(201,163,90,0.2)] rounded-full bg-[rgba(255,255,255,0.02)]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#6FCF97] shadow-[0_0_8px_#6FCF97]" style={{ animation: "aegisGlow 2.4s ease-in-out infinite" }} />
            <span className="text-[11.5px] text-[rgba(237,234,227,0.78)] whitespace-nowrap">{t.secureSession}</span>
          </div>
          <div className={`hidden sm:flex w-9 h-9 rounded-full border border-[rgba(201,163,90,0.3)] items-center justify-center ${cormorant} font-semibold text-[15px] text-[#D8B25E] flex-shrink-0`} style={{ background: "linear-gradient(145deg,#2a2a2c,#141416)" }}>A</div>
        </div>
      </nav>

      {/* ============ PAGES — AnimatePresence tab transitions ============ */}
      <AnimatePresence mode="wait">
      {/* ================= SCANNER ================= */}
      {page === "scanner" && (
        <motion.main key="scanner" variants={tabVariants} initial="hidden" animate="visible" exit="exit" className="max-w-[1120px] mx-auto px-4 sm:px-8 lg:px-10 pt-10 sm:pt-16 pb-24">
          <div className="text-center">
            <motion.div variants={riseItem} className="inline-flex items-center gap-2 px-4 py-[7px] border border-[rgba(201,163,90,0.28)] rounded-full bg-[rgba(216,178,94,0.05)] mb-7">
              <span className="relative flex w-1.5 h-1.5">
                <span className="absolute inline-flex h-full w-full rounded-full bg-[#D8B25E]" style={{ animation: "pulseRing 2.4s ease-out infinite" }} />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#D8B25E]" />
              </span>
              <span className="text-[11.5px] text-[#C9A35A]">{t.heroBadge}</span>
            </motion.div>
            <motion.h1 variants={riseItem} className={`${serifFont} font-semibold text-[40px] sm:text-[56px] lg:text-[70px] leading-[1.08] tracking-tight mb-5 text-[#F5F1E8]`}>
              {t.heroPre}{" "}
              <span className="italic bg-clip-text text-transparent" style={{ backgroundImage: "linear-gradient(110deg,#B88A38,#D8B25E 30%,#F6E6B0 50%,#D8B25E 70%,#B88A38)", backgroundSize: "220% 100%", animation: "shimmer 6s linear infinite" }}>{t.heroEm}</span>
            </motion.h1>
            <motion.p variants={riseItem} className="max-w-[600px] mx-auto text-base leading-[1.75] text-[rgba(237,234,227,0.55)] font-light">{t.heroSub}</motion.p>
          </div>

          {/* Scan console */}
          <motion.div variants={riseItem} className="mt-14 rounded-[22px] p-px bg-gradient-to-br from-[rgba(216,178,94,0.45)] via-[rgba(216,178,94,0.05)] to-[rgba(255,255,255,0.06)]">
            <div className="rounded-[21px] p-5 sm:p-9 backdrop-blur-3xl" style={{ background: "linear-gradient(180deg,rgba(20,20,22,0.9),rgba(13,13,15,0.94))" }}>
              {/* drop zone */}
              <div
                role="button"
                tabIndex={0}
                aria-label={`${t.dropTitle}. ${t.dropHint}`}
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    fileInputRef.current?.click();
                  }
                }}
                onDragOver={(e) => { e.preventDefault(); if (!dragOver) setDragOver(true); }}
                onDragLeave={(e) => { e.preventDefault(); setDragOver(false); }}
                onDrop={(e) => { e.preventDefault(); setDragOver(false); selectFile(e.dataTransfer.files); }}
                className="relative rounded-2xl border-[1.5px] border-dashed border-[rgba(201,163,90,0.3)] bg-[rgba(255,255,255,0.015)] px-6 py-12 text-center cursor-pointer overflow-hidden transition-all duration-300 hover:border-[rgba(216,178,94,0.6)] hover:bg-[rgba(216,178,94,0.04)]"
              >
                {dragOver && <div className="absolute inset-0 rounded-2xl border-[1.5px] border-[#D8B25E] bg-[rgba(216,178,94,0.09)] pointer-events-none shadow-[inset_0_0_40px_rgba(216,178,94,0.12)]" />}
                <div className="w-[60px] h-[60px] mx-auto mb-5 rounded-2xl border border-[rgba(201,163,90,0.3)] flex items-center justify-center" style={{ background: "linear-gradient(145deg,rgba(216,178,94,0.16),rgba(216,178,94,0.03))" }}>
                  <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 16V4M7 9l5-5 5 5" /><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" /></svg>
                </div>
                <div className={`${serifFont} text-2xl font-semibold text-[#F0EBDF] mb-1.5`}>{t.dropTitle}</div>
                <div className="text-[13.5px] text-[rgba(237,234,227,0.6)] font-light">{t.dropOr} <span className="text-[#D8B25E] border-b border-[rgba(216,178,94,0.4)]">{t.dropBrowse}</span> — {t.dropHint}</div>
                <input type="file" ref={fileInputRef} accept={SUPPORTED_EXTENSIONS.join(",")} onChange={(e) => e.target.files && selectFile(e.target.files)} className="hidden" />
              </div>

              {/* selected file */}
              {file && (
                <div className="mt-4">
                    <motion.div layout key={file.name} initial={{ opacity: 0, y: 10, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ type: "spring", stiffness: 400, damping: 30 }} className="flex items-center gap-3 px-4 py-3 rounded-xl border border-[rgba(201,163,90,0.16)] bg-[rgba(255,255,255,0.02)]">
                      <div className="w-8 h-8 rounded-lg bg-[rgba(216,178,94,0.1)] flex items-center justify-center flex-shrink-0">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.6"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></svg>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-[13.5px] text-[#EDEAE3] font-medium whitespace-nowrap overflow-hidden text-ellipsis" dir="ltr" style={{ textAlign: "start" }}>{file.name}</div>
                        <div className={`${mono} text-[10.5px] text-[rgba(237,234,227,0.6)] mt-0.5`} dir="ltr" style={{ textAlign: "start" }}>{file.size}</div>
                      </div>
                      <span className={`${mono} text-[10px] tracking-wide text-[#6FCF97] whitespace-nowrap`}>{t.ready}</span>
                    </motion.div>
                </div>
              )}

              {/* divider */}
              <div className="flex items-center gap-4 my-6">
                <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[rgba(201,163,90,0.2)] to-transparent" />
                <span className="text-[11px] text-[rgba(237,234,227,0.6)] whitespace-nowrap">{t.orUrl}</span>
                <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[rgba(201,163,90,0.2)] to-transparent" />
              </div>

              {/* URL row */}
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1 flex items-center gap-3 px-[18px] rounded-[13px] border border-[rgba(201,163,90,0.22)] bg-[rgba(255,255,255,0.02)]">
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="rgba(216,178,94,0.7)" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20" /></svg>
                  <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://huggingface.co/org/model/resolve/main/model.safetensors" dir="ltr" style={{ textAlign: "start" }}
                    aria-label={t.orUrl}
                    className={`flex-1 bg-transparent border-none outline-none text-[#EDEAE3] ${mono} text-[13px] py-[15px]`} />
                </div>
                <motion.button onClick={startScan} disabled={scanning}
                  whileHover={{ y: -2, scale: 1.02 }} whileTap={{ scale: 0.97 }} transition={{ type: "spring", stiffness: 400, damping: 28 }}
                  className="flex items-center gap-2 px-7 rounded-[13px] border-none cursor-pointer font-bold text-sm text-[#1c1608] whitespace-nowrap disabled:opacity-60 disabled:cursor-default"
                  style={{ background: "linear-gradient(145deg,#F6E6B0 0%,#D8B25E 42%,#B88A38 100%)", animation: "aegisPulseGlow 2.6s ease-in-out infinite" }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1c1608" strokeWidth="2"><path d="m21 21-4.3-4.3M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z" /></svg>
                  {t.runScan}
                </motion.button>
              </div>

              {/* starting indicator (real progress + findings render on /scan/[id]) */}
              {scanning && (
                <div className="relative mt-6 px-[22px] py-5 rounded-2xl border border-[rgba(201,163,90,0.22)] bg-[rgba(216,178,94,0.04)] flex items-center gap-2.5">
                  <span className="w-3.5 h-3.5 rounded-full border-2 border-[rgba(216,178,94,0.25)]" style={{ borderTopColor: "#D8B25E", animation: "aegisSpin 0.8s linear infinite" }} />
                  <span className="text-[13.5px] text-[#EDEAE3] font-medium">{t.analyzing}</span>
                </div>
              )}
            </div>
          </motion.div>

          {/* BYOK */}
          <motion.div variants={riseItem} className="mt-7 rounded-[20px] p-px bg-gradient-to-br from-[rgba(216,178,94,0.4)] to-[rgba(255,255,255,0.05)]">
            <div className="rounded-[19px] px-[30px] py-7 backdrop-blur-2xl" style={{ background: "linear-gradient(180deg,rgba(18,18,20,0.85),rgba(12,12,14,0.9))" }}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-5">
                <div className="flex items-start sm:items-center gap-3 sm:gap-4">
                  <div className="w-[46px] h-[46px] rounded-[13px] border border-[rgba(201,163,90,0.3)] flex items-center justify-center flex-shrink-0" style={{ background: "linear-gradient(145deg,rgba(216,178,94,0.15),rgba(216,178,94,0.03))" }}>
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.5"><path d="M7 11V7a5 5 0 0 1 10 0v4" /><rect x="4" y="11" width="16" height="10" rx="2" /><circle cx="12" cy="16" r="1.2" /></svg>
                  </div>
                  <div>
                    <div className="flex items-center gap-2.5">
                      <span className={`${serifFont} text-[22px] font-semibold text-[#F3EEE3]`}>{t.byokTitle}</span>
                      <span className={`${mono} text-[9px] tracking-wide text-[#C9A35A] border border-[rgba(201,163,90,0.35)] px-2 py-0.5 rounded-md`}>BYOK</span>
                    </div>
                    <div className="text-[13px] text-[rgba(237,234,227,0.6)] font-light mt-1">{t.byokDesc}</div>
                  </div>
                </div>
                <div className="self-end sm:self-auto"><Toggle on={byok} onClick={() => setByok((v) => !v)} label={t.byokTitle} /></div>
              </div>

              {byok && (
                <div className="mt-6 pt-6 border-t border-[rgba(201,163,90,0.16)]" style={{ animation: "aegisEnter 0.4s ease" }}>
                  <div className="grid grid-cols-1 md:grid-cols-[200px_1fr] gap-4">
                    <div>
                      <label className="block text-[11px] font-semibold text-[rgba(237,234,227,0.6)] mb-2">{t.provider}</label>
                      <div className="flex flex-col gap-1.5">
                        {BYOK_PROVIDERS.map((p) => {
                          const active = provider === p.id;
                          return (
                            <button key={p.id} onClick={() => { setProvider(p.id); setApiKey(getKey(p.id)); setKeySaved(false); }} style={{ textAlign: "start" }}
                              className={`flex items-center gap-2 px-[13px] py-2.5 rounded-[10px] cursor-pointer text-[13px] border transition-all duration-200 ${active ? "text-[#F6E6B0] border-[rgba(201,163,90,0.45)] bg-[rgba(216,178,94,0.09)]" : "text-[rgba(237,234,227,0.6)] border-[rgba(255,255,255,0.07)] bg-[rgba(255,255,255,0.02)] hover:border-[rgba(201,163,90,0.3)] hover:text-[#EDEAE3]"}`}>
                              <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${active ? "bg-[#D8B25E] shadow-[0_0_7px_rgba(216,178,94,0.8)]" : "bg-[rgba(237,234,227,0.25)]"}`} />
                              {p.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    <div>
                      <label htmlFor="aegis-byok-key" className="block text-[11px] font-semibold text-[rgba(237,234,227,0.6)] mb-2">{t.secretKey}</label>
                      <div className="flex items-center gap-2.5 px-4 rounded-[11px] border border-[rgba(201,163,90,0.26)] bg-[rgba(0,0,0,0.35)]">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.5" className="flex-shrink-0"><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                        <input id="aegis-byok-key" value={apiKey} onChange={(e) => { setApiKey(e.target.value); setKeySaved(false); }} type={reveal ? "text" : "password"} placeholder="sk-••••••••••••••••••••••••••••" dir="ltr" style={{ textAlign: "start" }}
                          className={`flex-1 bg-transparent border-none outline-none text-[#EDEAE3] ${mono} text-[13px] py-3.5 tracking-wide`} />
                        <button onClick={() => setReveal((v) => !v)} className="bg-transparent border-none cursor-pointer text-[rgba(237,234,227,0.6)] text-[11px] font-semibold transition-colors duration-200 hover:text-[#D8B25E] whitespace-nowrap">{reveal ? t.hide : t.show}</button>
                      </div>
                      <div className="flex items-center justify-between mt-3.5 gap-3">
                        <div className="flex items-center gap-2 text-[11.5px] text-[rgba(237,234,227,0.6)]">
                          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6FCF97" strokeWidth="1.7" className="flex-shrink-0"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /><path d="m9 12 2 2 4-4" /></svg>
                          <span>{t.sealed}</span>
                        </div>
                        <button onClick={sealCurrentKey} className="px-[22px] py-2.5 rounded-[11px] border-none cursor-pointer font-bold text-[13px] text-[#1c1608] transition-transform duration-200 hover:-translate-y-0.5 whitespace-nowrap" style={{ background: "linear-gradient(145deg,#F6E6B0,#D8B25E 50%,#B88A38)" }}>{keySaved ? t.savedBtn : t.sealBtn}</button>
                      </div>
                      {keySaved && (
                        <div className="mt-3 flex items-center gap-2 px-3.5 py-2.5 rounded-[10px] bg-[rgba(111,207,151,0.08)] border border-[rgba(111,207,151,0.24)]" style={{ animation: "aegisEnter 0.35s ease" }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6FCF97" strokeWidth="2" className="flex-shrink-0"><path d="M20 6 9 17l-5-5" /></svg>
                          <span className="text-[12.5px] text-[#9FE0BA]">{t.keySavedMsg}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        </motion.main>
      )}

      {/* ================= DASHBOARD ================= */}
      {page === "dashboard" && (
        <motion.main key="dashboard" variants={tabVariants} initial="hidden" animate="visible" exit="exit" className="max-w-[1180px] mx-auto px-4 sm:px-8 lg:px-10 pt-10 sm:pt-12 pb-24">
          <motion.div variants={riseItem} className="flex flex-wrap items-end justify-between gap-4 sm:gap-5 mb-8">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold text-[#C9A35A] mb-2.5">
                {t.opsOverview}
                <span className={`${mono} text-[9px] tracking-wider px-1.5 py-0.5 rounded ${dash.loading ? "text-[rgba(237,234,227,0.6)] border border-[rgba(255,255,255,0.1)]" : "text-[#7BD6A2] border border-[rgba(111,207,151,0.3)] bg-[rgba(111,207,151,0.08)]"}`}>{t.liveData}</span>
              </div>
              <h1 className={`${serifFont} font-semibold text-[32px] sm:text-[40px] lg:text-[44px] text-[#F5F1E8] tracking-tight`}>{t.threatCommand}</h1>
            </div>
            <motion.button whileHover={{ y: -2, scale: 1.03 }} whileTap={{ scale: 0.97 }} transition={{ type: "spring", stiffness: 400, damping: 28 }} onClick={() => goTo("scanner")} className="px-5 py-2.5 rounded-[11px] border-none font-bold text-[13px] text-[#1c1608] cursor-pointer whitespace-nowrap" style={{ background: "linear-gradient(145deg,#F6E6B0,#D8B25E 50%,#B88A38)", animation: "aegisPulseGlow 2.6s ease-in-out infinite" }}>{t.newScan}</motion.button>
          </motion.div>

          {dash.error && !dash.loading && (
            <div className="rounded-[16px] border border-[rgba(224,124,90,0.3)] bg-[rgba(224,124,90,0.06)] px-5 sm:px-6 py-5 flex flex-wrap items-center justify-between gap-4 mb-[18px]">
              <span className="text-[13.5px] text-[#E8B7A0]">{t.statsError} · {dash.error}</span>
              <button onClick={dash.reload} className="px-4 py-2 rounded-[10px] text-[12.5px] font-semibold text-[#1c1608] cursor-pointer" style={{ background: "linear-gradient(145deg,#F6E6B0,#D8B25E 50%,#B88A38)" }}>{t.retry}</button>
            </div>
          )}

          <motion.div variants={cascadeContainer} initial="hidden" animate="visible" className="grid grid-cols-1 sm:grid-cols-3 gap-[18px]">
            <StatCard mono={mono} label={t.totalScans} value={dash.loading ? null : (dash.stats?.total ?? 0)} />
            <StatCard mono={mono} label={t.threatsFlagged} value={dash.loading ? null : ((dash.stats?.suspicious ?? 0) + (dash.stats?.malicious ?? 0) + (dash.stats?.critical ?? 0))} accent />
            <StatCard mono={mono} label={t.avgRisk} value={dash.loading ? null : (dash.stats?.avg_risk_score ?? 0)} suffix="/100" />
          </motion.div>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.4fr] gap-[18px] mt-[18px]">
            <div className="rounded-[18px] border border-[rgba(201,163,90,0.16)] px-6 sm:px-7 py-[26px]" style={{ background: "linear-gradient(180deg,rgba(18,18,20,0.7),rgba(12,12,14,0.8))" }}>
              <span className={`${serifFont} text-[20px] sm:text-[22px] font-semibold text-[#F3EEE3]`}>{t.riskDistribution}</span>
              {dash.loading ? (
                <div className="mt-6 flex flex-col gap-3">{[0, 1, 2, 3].map((i) => (<div key={i} className="h-9 rounded-lg bg-[rgba(255,255,255,0.03)] animate-pulse" />))}</div>
              ) : (dash.stats?.total ?? 0) === 0 ? (
                <EmptyState mono={mono} title={t.noScansTitle} body={t.noScansBody} />
              ) : (
                <div className="mt-6 flex flex-col gap-3.5">
                  {(["clean", "suspicious", "malicious", "critical"] as const).map((k) => {
                    const sev = RISK_TO_SEV[k];
                    const count = (dash.stats?.[k] ?? 0) as number;
                    const total = dash.stats?.total || 1;
                    const pct = Math.round((count / total) * 100);
                    const barColor = sev === "Critical" ? "#E88A6B" : sev === "High" ? "#E6B26B" : sev === "Medium" ? "#DFC96A" : "#7BD6A2";
                    return (
                      <div key={k}>
                        <div className="flex items-center justify-between mb-1.5">
                          <SevBadge label={t.sev[sev as keyof typeof t.sev]} sevKey={sev} />
                          <span className={`${mono} text-[12px] text-[rgba(237,234,227,0.6)]`} dir="ltr">{count} · {pct}%</span>
                        </div>
                        <div className="h-2 rounded-full bg-[rgba(255,255,255,0.05)] overflow-hidden">
                          <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ type: "spring", stiffness: 60, damping: 20, delay: 0.15 }} className="h-full rounded-full" style={{ background: barColor, boxShadow: `0 0 12px ${barColor}66` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="rounded-[18px] border border-[rgba(201,163,90,0.16)] px-6 sm:px-7 py-[26px]" style={{ background: "linear-gradient(180deg,rgba(18,18,20,0.7),rgba(12,12,14,0.8))" }}>
              <div className="flex items-center justify-between mb-5">
                <span className={`${serifFont} text-[20px] sm:text-[22px] font-semibold text-[#F3EEE3]`}>{t.recentScans}</span>
              </div>
              {dash.loading ? (
                <div className="flex flex-col gap-2">{[0, 1, 2, 3].map((i) => (<div key={i} className="h-[52px] rounded-lg bg-[rgba(255,255,255,0.03)] animate-pulse" />))}</div>
              ) : dash.recent.length === 0 ? (
                <EmptyState mono={mono} title={t.noScansTitle} body={t.noScansBody} />
              ) : (
                <motion.div variants={cascadeContainer} initial="hidden" animate="visible" className="flex flex-col">
                  {dash.recent.map((sc: RecentScan) => {
                    const sev = RISK_TO_SEV[sc.risk_level] ?? "Medium";
                    return (
                      <motion.div key={sc.scan_id} variants={cascadeItem}>
                      <Link href={`/scan/${sc.scan_id}`} className="flex items-center gap-3 sm:gap-4 px-1 py-[13px] rounded-lg border-b border-[rgba(255,255,255,0.05)] transition-colors duration-200 hover:bg-[rgba(216,178,94,0.04)] no-underline">
                        <SevBadge label={t.sev[sev as keyof typeof t.sev]} sevKey={sev} wide />
                        <div className="flex-1 min-w-0">
                          <div className="text-[13.5px] text-[#EDEAE3] font-medium truncate" dir="ltr" style={{ textAlign: "start" }}>{sc.filename || sc.scan_id}</div>
                          <div className={`${mono} text-[10.5px] text-[rgba(237,234,227,0.6)] mt-0.5`} dir="ltr">{sc.threats_count} {t.threatsLabel} · {sc.risk_score}/100</div>
                        </div>
                        <span className="text-[11px] text-[rgba(237,234,227,0.6)] flex-shrink-0 whitespace-nowrap" dir="ltr">{timeAgo(sc.created_at)}</span>
                      </Link>
                      </motion.div>
                    );
                  })}
                </motion.div>
              )}
            </div>
          </div>
        </motion.main>
      )}

      {/* ================= DOCS ================= */}
      {page === "docs" && (
        <motion.main key="docs" variants={tabVariants} initial="hidden" animate="visible" exit="exit" className="max-w-[1080px] mx-auto px-4 sm:px-8 lg:px-10 pt-12 pb-24">
          <div className="text-xs font-semibold text-[#C9A35A] mb-2.5">{t.documentation}</div>
          <h1 className={`${serifFont} font-semibold text-[32px] sm:text-[44px] text-[#F5F1E8] tracking-tight mb-[34px]`}>{t.aegisProtocol}</h1>
          <div className="grid grid-cols-1 md:grid-cols-[230px_1fr] gap-6 md:gap-9 items-start">
            <div className="flex flex-col gap-1 md:sticky md:top-[100px]">
              {DOC_TABS[lang].map((d) => {
                const active = activeDoc === d.key;
                return (
                  <div key={d.key} onClick={() => setActiveDoc(d.key)}
                    className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-[10px] text-[13.5px] cursor-pointer border-s-2 transition-all duration-200 ${active ? "text-[#F6E6B0] bg-[rgba(216,178,94,0.08)] border-[#D8B25E] font-semibold" : "text-[rgba(237,234,227,0.6)] border-transparent hover:text-[#EDEAE3] hover:bg-[rgba(255,255,255,0.02)]"}`}>
                    <span className={`${mono} text-[10px] ${active ? "text-[rgba(216,178,94,0.7)]" : "text-[rgba(237,234,227,0.6)]"}`}>{d.tag}</span>
                    {d.label}
                  </div>
                );
              })}
            </div>
            <AnimatePresence mode="wait">
            <motion.div key={activeDoc} initial={{ opacity: 0, y: 14, filter: "blur(6px)" }} animate={{ opacity: 1, y: 0, filter: "blur(0px)" }} exit={{ opacity: 0, y: -10, filter: "blur(4px)" }} transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }} className="flex flex-col gap-[22px]">
              <div className="rounded-2xl border border-[rgba(201,163,90,0.18)] px-8 py-[30px]" style={{ background: "linear-gradient(180deg,rgba(216,178,94,0.06),rgba(255,255,255,0.01))" }}>
                <div className="flex items-center gap-3 mb-3.5">
                  <span className={`${mono} text-[11px] text-[#C9A35A] border border-[rgba(201,163,90,0.35)] rounded-md px-2 py-0.5`}>{activeDocData.tag}</span>
                  <span className={`${serifFont} text-[28px] font-semibold text-[#F3EEE3]`}>{activeDocData.title}</span>
                </div>
                <p className="text-[15px] leading-[1.85] text-[rgba(237,234,227,0.62)] font-light">{activeDocData.lead}</p>
              </div>
              <motion.div variants={cascadeContainer} initial="hidden" animate="visible" className="flex flex-col gap-3">
                {activeDocData.points.map((pt, i) => (
                  <motion.div variants={cascadeItem} key={i} className="flex gap-4 rounded-2xl border border-[rgba(201,163,90,0.12)] px-6 py-5 bg-[rgba(255,255,255,0.02)] transition-all duration-300 hover:border-[rgba(216,178,94,0.3)] hover:-translate-y-0.5">
                    <div className="flex-shrink-0 w-[34px] h-[34px] rounded-[9px] bg-[rgba(216,178,94,0.1)] border border-[rgba(201,163,90,0.28)] flex items-center justify-center">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#D8B25E" strokeWidth="1.7"><path d="M20 6 9 17l-5-5" /></svg>
                    </div>
                    <div>
                      <div className="text-[15px] text-[#F0EBDF] font-semibold mb-1.5">{pt.h}</div>
                      <div className="text-[13.5px] leading-[1.75] text-[rgba(237,234,227,0.55)] font-light">{pt.d}</div>
                    </div>
                  </motion.div>
                ))}
              </motion.div>
            </motion.div>
            </AnimatePresence>
          </div>
        </motion.main>
      )}

      </AnimatePresence>

      <footer className="border-t border-[rgba(201,163,90,0.1)] px-4 sm:px-10 py-[26px] flex flex-wrap items-center justify-between gap-3 sm:gap-5">
        <span className={`${mono} text-[10.5px] tracking-wide text-[rgba(237,234,227,0.6)]`} dir="ltr">AEGISML · OPEN SOURCE · SELF-HOSTABLE</span>
        <span className="text-[11px] text-[rgba(237,234,227,0.6)] whitespace-nowrap">{t.footerRight}</span>
      </footer>
    </div>
  );
}
