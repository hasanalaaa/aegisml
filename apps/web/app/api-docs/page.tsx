"use client";

import { useState } from "react";
import { useLanguage } from "../../components/ClientShell";

const cxUtil = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(" ");

const docsCopy = {
  en: {
    title: "API Documentation",
    subtitle: "Integrate AegisML preflight static analysis directly into your CI/CD pipelines.",
    menu: ["Authentication", "Scan Endpoint", "Rate Limits"],
    sections: {
      auth: {
        title: "Authentication",
        desc: "All requests must include your API key in the Authorization header. Do not expose this key in client-side code.",
        code: `Authorization: Bearer aegis_live_x89f...`
      },
      scan: {
        title: "Scan Endpoint",
        desc: "Submit a HuggingFace repository URL or a direct model artifact for sandboxed static analysis.",
        method: "POST",
        route: "/v1/scan",
        code: `import requests\n\nurl = "https://api.aegisml.com/v1/scan"\nheaders = {"Authorization": "Bearer YOUR_API_KEY"}\ndata = {\n    "target": "mistralai/Mistral-7B-v0.1",\n    "type": "url",\n    "deep_check": True\n}\n\nresponse = requests.post(url, json=data, headers=headers)\nprint(response.json())`
      },
      limits: {
        title: "Rate Limits",
        desc: "The standard tier allows up to 100 model scans per hour. For enterprise limits, contact support."
      }
    }
  },
  ar: {
    title: "وثائق واجهة برمجة التطبيقات (API)",
    subtitle: "قم بدمج التحليل الثابت من AegisML مباشرة في مسارات CI/CD الخاصة بك.",
    menu: ["المصادقة (Authentication)", "نقطة الفحص (Scan Endpoint)", "حدود الاستخدام (Rate Limits)"],
    sections: {
      auth: {
        title: "المصادقة (Authentication)",
        desc: "يجب أن تتضمن جميع الطلبات مفتاح الـ API الخاص بك في ترويسة Authorization. تجنب كشف هذا المفتاح في أكواد الواجهة الأمامية.",
        code: `Authorization: Bearer aegis_live_x89f...`
      },
      scan: {
        title: "نقطة الفحص (Scan Endpoint)",
        desc: "أرسل رابط مستودع HuggingFace أو ملف نموذج مباشر لإجراء تحليل ثابت داخل بيئة معزولة.",
        method: "POST",
        route: "/v1/scan",
        code: `import requests\n\nurl = "https://api.aegisml.com/v1/scan"\nheaders = {"Authorization": "Bearer YOUR_API_KEY"}\ndata = {\n    "target": "mistralai/Mistral-7B-v0.1",\n    "type": "url",\n    "deep_check": True\n}\n\nresponse = requests.post(url, json=data, headers=headers)\nprint(response.json())`
      },
      limits: {
        title: "حدود الاستخدام (Rate Limits)",
        desc: "تسمح الباقة القياسية بإجراء ما يصل إلى 100 فحص نماذج في الساعة. للحصول على حدود المؤسسات، يرجى التواصل مع الدعم."
      }
    }
  }
};

export default function ApiDocsPage() {
  const { language } = useLanguage();
  const [activeSection, setActiveSection] = useState(0);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  
  const t = docsCopy[language];
  const isRtl = language === "ar";

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(code);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  return (
    <main className="mx-auto w-full max-w-7xl px-4 pb-16 pt-32 sm:px-6 lg:px-8 animate-fade-in" dir={isRtl ? "rtl" : "ltr"}>
      
      {/* PAGE HEADER */}
      <section className="border-b border-white/5 pb-8 mb-8">
        <h1 className="text-3xl font-medium text-white tracking-tight">{t.title}</h1>
        <p className="mt-2 text-sm leading-relaxed text-slate-400 max-w-2xl">{t.subtitle}</p>
      </section>

      <div className="flex flex-col md:flex-row gap-10">
        {/* SIDEBAR NAVIGATION */}
        <aside className="md:w-64 flex-shrink-0">
          <div className="sticky top-32 flex flex-col gap-1 border-l border-white/5 pl-4" dir={isRtl ? "rtl" : "ltr"}>
            {t.menu.map((item, idx) => (
              <button
                key={item}
                onClick={() => setActiveSection(idx)}
                className={cxUtil(
                  "text-xs font-semibold uppercase tracking-widest text-start px-3 py-2.5 rounded-lg transition-all duration-300",
                  activeSection === idx 
                    ? "bg-white/10 text-white shadow-sm" 
                    : "text-slate-500 hover:text-slate-300 hover:bg-white/[0.02]"
                )}
              >
                {item}
              </button>
            ))}
          </div>
        </aside>

        {/* MAIN DOCUMENTATION CONTENT */}
        <section className="flex-1 max-w-3xl space-y-12">
          
          {/* AUTHENTICATION SECTION */}
          <div className={cxUtil("transition-all duration-500", activeSection !== 0 && "hidden")}>
            <h2 className="text-xl font-medium text-white tracking-tight mb-3">{t.sections.auth.title}</h2>
            <p className="text-sm text-slate-400 leading-relaxed mb-6">{t.sections.auth.desc}</p>
            
            <div className="relative group rounded-xl border border-white/10 bg-[#0a0a0a] overflow-hidden shadow-2xl">
              <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 bg-white/[0.02]">
                <span className="text-[10px] font-mono text-slate-500">HTTP Header</span>
                <button onClick={() => handleCopy(t.sections.auth.code)} className="text-[10px] uppercase font-bold tracking-widest text-slate-500 hover:text-white transition-colors">
                  {copiedCode === t.sections.auth.code ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="p-5 overflow-x-auto">
                <code className="text-xs font-mono text-emerald-400 whitespace-pre">{t.sections.auth.code}</code>
              </div>
            </div>
          </div>

          {/* SCAN ENDPOINT SECTION */}
          <div className={cxUtil("transition-all duration-500", activeSection !== 1 && "hidden")}>
            <div className="flex items-center gap-3 mb-3">
              <h2 className="text-xl font-medium text-white tracking-tight">{t.sections.scan.title}</h2>
              <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-[10px] font-mono font-bold text-cyan-400">
                {t.sections.scan.method}
              </span>
            </div>
            
            <div className="flex items-center gap-2 mb-6 text-xs font-mono text-slate-300 bg-white/[0.02] border border-white/5 rounded-lg px-3 py-2 w-fit">
              <span className="text-slate-500">https://api.aegisml.com</span>
              <span className="text-white font-bold">{t.sections.scan.route}</span>
            </div>

            <p className="text-sm text-slate-400 leading-relaxed mb-6">{t.sections.scan.desc}</p>
            
            <div className="relative group rounded-xl border border-white/10 bg-[#0a0a0a] overflow-hidden shadow-2xl">
              <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 bg-white/[0.02]">
                <span className="text-[10px] font-mono text-slate-500">Python (Requests)</span>
                <button onClick={() => handleCopy(t.sections.scan.code)} className="text-[10px] uppercase font-bold tracking-widest text-slate-500 hover:text-white transition-colors">
                  {copiedCode === t.sections.scan.code ? "Copied!" : "Copy"}
                </button>
              </div>
              <div className="p-5 overflow-x-auto">
                <code className="text-xs font-mono text-slate-300 whitespace-pre leading-relaxed">
                  {t.sections.scan.code}
                </code>
              </div>
            </div>
          </div>

          {/* RATE LIMITS SECTION */}
          <div className={cxUtil("transition-all duration-500", activeSection !== 2 && "hidden")}>
            <h2 className="text-xl font-medium text-white tracking-tight mb-3">{t.sections.limits.title}</h2>
            <p className="text-sm text-slate-400 leading-relaxed">{t.sections.limits.desc}</p>
          </div>

        </section>
      </div>
    </main>
  );
}
