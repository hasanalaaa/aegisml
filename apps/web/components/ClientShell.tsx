"use client";

import { createContext, useContext, useState, useMemo } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export type Language = "en" | "ar";

export const copy = {
  en: {
    direction: "ltr",
    nav: ["Dashboard", "API Docs", "Threats", "GitHub"],
    startScan: "Get API Key",
    eyebrow: "AI MODEL SECURITY · PRE-RUNTIME SCANNING",
    headline: "Scan AI Models Before They Harm You",
    subhead: "Detect backdoors, trojans & malicious code in AI models before running them in production.",
    consoleKicker: "Scanner Console",
    consoleTitle: "Preflight model scanner",
    consoleMeta: "Sandboxed static analysis · no execution required",
    liveSurface: "Live Surface",
    uploadTab: "Upload Model File",
    urlTab: "HuggingFace URL",
    uploadTitle: "Secure data ingestion port",
    uploadBody: "Drop a model artifact into an isolated scan lane. AegisML validates structure, signatures, tensors, and suspicious payload traces before runtime.",
    formats: ".gguf · .safetensors · .pt",
    urlLabel: "Model repository URL",
    urlPlaceholder: "https://huggingface.co/org/model",
    urlHint: "Paste a public or authenticated repository path for preflight inspection.",
    scanIdle: "Scan Now",
    scanActive: "Scanning model surface",
    scanComplete: "Scan queued securely",
    stats: [
      { value: "6", label: "Formats Supported", detail: "Coverage across model weights, checkpoints, and tensor-safe containers." },
      { value: "14+", label: "Threat Patterns", detail: "Backdoors, trojans, poisoned loaders, and malicious execution traces." },
      { value: "AGPL-3.0", label: "Open Source", detail: "Auditable scanner logic for teams that need trust before deployment." }
    ],
    footer: { rights: "© 2026 AegisML. All security interfaces sandboxed.", status: "System Status: Operational", cert: "AGPL-3.0 Compliant" },
    modalTitle: "Developer API Key",
    modalClose: "Close"
  },
  ar: {
    direction: "rtl",
    nav: ["لوحة التحكم", "وثائق API", "التهديدات", "GitHub"],
    startScan: "مفتاح API",
    eyebrow: "أمن نماذج الذكاء الاصطناعي · فحص قبل التشغيل",
    headline: "افحص نماذج الذكاء الاصطناعي قبل أن تضرّك",
    subhead: "اكشف الأبواب الخلفية وأحصنة طروادة والشيفرات الخبيثة داخل نماذج الذكاء الاصطناعي قبل تشغيلها في الإنتاج.",
    consoleKicker: "وحدة الفحص",
    consoleTitle: "فحص النموذج قبل التشغيل",
    consoleMeta: "تحليل ثابت داخل عزل آمن · من دون تنفيذ النموذج",
    liveSurface: "سطح نشط",
    uploadTab: "رفع ملف النموذج",
    urlTab: "رابط HuggingFace",
    uploadTitle: "منفذ إدخال بيانات آمن",
    uploadBody: "اسحب ملف النموذج إلى مسار فحص معزول. يتحقق AegisML من البنية والتواقيع والتنسورات وآثار الحمولة المشبوهة قبل التشغيل.",
    formats: ".gguf · .safetensors · .pt",
    urlLabel: "رابط مستودع النموذج",
    urlPlaceholder: "https://huggingface.co/org/model",
    urlHint: "ألصق رابط مستودع عام أو مصرح به لفحصه قبل الإنتاج.",
    scanIdle: "افحص الآن",
    scanActive: "جار فحص سطح النموذج",
    scanComplete: "تمت جدولة الفحص بأمان",
    stats: [
      { value: "6", label: "صيغ مدعومة", detail: "تغطية لأوزان النماذج ونقاط الحفظ وحاويات التنسور الآمنة." },
      { value: "14+", label: "أنماط تهديد", detail: "أبواب خلفية، تروجانات، محملات ملوثة، وآثار تنفيذ خبيثة." },
      { value: "AGPL-3.0", label: "مفتوح المصدر", detail: "منطق فحص قابل للتدقيق للفرق التي تحتاج الثقة قبل النشر." }
    ],
    footer: { rights: "© 2026 AegisML. جميع واجهات الفحص معزولة بأمان.", status: "حالة النظام: يعمل بكفاءة", cert: "متوافق مع مرخصة AGPL-3.0" },
    modalTitle: "مفتاح المطور (API)",
    modalClose: "إغلاق"
  }
} as const;

export const LanguageContext = createContext<{ language: Language; setLanguage: (l: Language) => void }>({
  language: "ar",
  setLanguage: () => {},
});

export function useLanguage() {
  return useContext(LanguageContext);
}

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function GeometricMark() {
  return (
    <div className="relative h-9 w-9 overflow-hidden rounded-xl border border-white/10 bg-black/40 shadow-xl backdrop-blur-xl transition-all duration-300 hover:border-white/20">
      <div className="absolute inset-2 rotate-45 border border-white/20" />
      <div className="absolute left-1/2 top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-white shadow-md shadow-white/50" />
    </div>
  );
}

import { ScanProvider } from "../context/ScanContext";
import dynamic from "next/dynamic";

const HeroScene = dynamic(() => import("../components/HeroScene"), { ssr: false });

const NAV_ROUTES = ["/dashboard", "/api-docs", "/threats", "https://github.com"];

export function ClientShell({ children }: { children: React.ReactNode }) {
  const [language, setLanguage] = useState<Language>("ar");
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  
  const pathname = usePathname();
  const t = useMemo(() => copy[language], [language]);

  const handleCopyKey = () => {
    navigator.clipboard.writeText("aegis_live_9x8f_terminal_mock_key");
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <LanguageContext.Provider value={{ language, setLanguage }}>
      <ScanProvider>
        <HeroScene />
        <section
          key={language}
          lang={language}
          dir={t.direction}
          className="relative isolate flex flex-col justify-between min-h-screen overflow-hidden bg-transparent px-4 pb-8 pt-5 font-sans text-slate-200 sm:px-6 lg:px-8 z-10 transition-all duration-500 ease-out opacity-100"
        >
          <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-b from-black/20 via-transparent to-black/80" />

          {/* HEADER */}
          <header className="mx-auto flex w-full max-w-7xl items-center justify-between rounded-2xl border border-white/5 bg-black/40 px-4 py-3 shadow-2xl backdrop-blur-3xl sm:px-5">
            <Link href="/" className="flex items-center gap-3 transition-opacity hover:opacity-80" aria-label="AegisML home">
              <GeometricMark />
              <span className="text-white text-lg font-bold tracking-tight">
                AegisML
              </span>
            </Link>

            <nav className="hidden items-center gap-4 md:flex" aria-label="Primary navigation">
              {t.nav.map((item, idx) => {
                const route = NAV_ROUTES[idx];
                const isExternal = route.startsWith("http");
                const isActive = pathname === route || (pathname && route !== "/" && pathname.includes(route));
                
                const linkClasses = cx(
                  "text-xs font-medium px-3 py-1.5 rounded-lg transition-all duration-300",
                  isActive 
                    ? "text-amber-100 bg-white/10 shadow-sm border border-amber-100/10" 
                    : "text-slate-500 hover:text-slate-300 border border-transparent"
                );

                if (isExternal) {
                  return (
                    <a key={item} href={route} target="_blank" rel="noopener noreferrer" className={linkClasses}>
                      {item}
                    </a>
                  );
                }

                return (
                  <Link key={item} href={route} className={linkClasses}>
                    {item}
                  </Link>
                );
              })}
            </nav>

            <div className="flex items-center gap-2 sm:gap-3">
              <div className="flex rounded-full border border-white/5 bg-white/[0.03] p-0.5 backdrop-blur-xl">
                {(["ar", "en"] as const).map((item) => (
                  <button
                    key={item}
                    type="button"
                    onClick={() => setLanguage(item)}
                    aria-pressed={language === item}
                    className={cx(
                      "rounded-full px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest transition-all duration-300 ease-out",
                      language === item
                        ? "bg-white/10 text-white shadow-md"
                        : "text-slate-500 hover:text-slate-300",
                    )}
                  >
                    {item}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={() => setIsAuthModalOpen(true)}
                className="hidden rounded-xl border border-white/10 bg-white text-black px-4 py-2.5 text-[11px] font-bold uppercase tracking-widest shadow-sm transition-all duration-300 ease-out hover:bg-slate-200 active:scale-95 sm:inline-flex"
              >
                {t.startScan}
              </button>
            </div>
          </header>

          {children}

          {/* FOOTER */}
          <footer className="mx-auto mt-16 w-full max-w-4xl border-t border-white/5 bg-black/10 px-2 pt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between text-[11px] text-slate-500">
            <div>{t.footer.rights}</div>
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5 text-slate-400">
                <span className="h-1 w-1 rounded-full bg-emerald-500 animate-pulse" />
                {t.footer.status}
              </span>
              <span className="text-slate-400 font-mono text-[10px] border border-white/5 bg-white/[0.01] rounded px-1.5 py-0.5">
                {t.footer.cert}
              </span>
            </div>
          </footer>
        </section>

        {/* DEVELOPER API KEY MODAL */}
        {isAuthModalOpen && (
          <div 
            dir={t.direction}
            className="fixed inset-0 z-50 flex items-center justify-center bg-[#030305]/80 backdrop-blur-md animate-fade-in"
          >
            <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl shadow-2xl p-6 w-full max-w-sm flex flex-col gap-4">
              <h2 className="text-sm font-semibold text-white tracking-tight">{t.modalTitle}</h2>
              
              <div className="relative group rounded-xl border border-white/10 bg-black overflow-hidden shadow-inner">
                <div className="flex items-center justify-between px-3 py-2 border-b border-white/5 bg-white/[0.02]">
                  <span className="text-[10px] font-mono text-slate-500">API_KEY</span>
                  <button onClick={handleCopyKey} className="text-[10px] uppercase font-bold tracking-widest text-slate-500 hover:text-white transition-colors">
                    {copiedKey ? "Copied!" : "Copy"}
                  </button>
                </div>
                <div className="p-4 overflow-x-auto">
                  <code className="text-xs font-mono text-emerald-400">aegis_live_9x8f_terminal_mock_key</code>
                </div>
              </div>

              <div className="mt-4 flex justify-end">
                <button 
                  onClick={() => setIsAuthModalOpen(false)}
                  className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold uppercase tracking-widest text-white hover:bg-white/10 transition-colors"
                >
                  {t.modalClose}
                </button>
              </div>
            </div>
          </div>
        )}

      </ScanProvider>
    </LanguageContext.Provider>
  );
}
