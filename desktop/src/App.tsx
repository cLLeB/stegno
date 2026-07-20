import { useEffect, useState } from "react";
import { listMethods, type MethodInfo } from "./api";
import { HideTab } from "./tabs/HideTab";
import { RevealTab } from "./tabs/RevealTab";
import { ShareTab } from "./tabs/ShareTab";
import { SplitTab } from "./tabs/SplitTab";
import { KeysTab } from "./tabs/KeysTab";
import { InspectTab } from "./tabs/InspectTab";
import { LabTab } from "./tabs/LabTab";
import { CleanTab } from "./tabs/CleanTab";

/* ---------- theme ---------- */
function useTheme(): () => void {
  const [theme, setTheme] = useState<string>(() => localStorage.getItem("stegno-theme") || "auto");
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
  }, [theme]);
  return () => {
    const t = document.documentElement.getAttribute("data-theme");
    const effective = t || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = effective === "dark" ? "light" : "dark";
    localStorage.setItem("stegno-theme", next);
    setTheme(next);
  };
}

type Tab = "hide" | "reveal" | "share" | "split" | "keys" | "inspect" | "lab" | "clean";

const TABS: { id: Tab; label: string }[] = [
  { id: "hide", label: "🖼️ Hide" },
  { id: "reveal", label: "🔑 Reveal" },
  { id: "share", label: "👥 Share" },
  { id: "split", label: "🧩 Split" },
  { id: "keys", label: "🔐 Keys" },
  { id: "inspect", label: "🔍 Inspect" },
  { id: "lab", label: "🧪 Lab" },
  { id: "clean", label: "🧼 Clean" },
];

export default function App() {
  const toggleTheme = useTheme();
  const [tab, setTab] = useState<Tab>("hide");
  const [methods, setMethods] = useState<MethodInfo[]>([]);
  const themeIcon = () =>
    (document.documentElement.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark"
      ? "☀️"
      : "🌙";

  useEffect(() => {
    listMethods().then(setMethods).catch(() => {});
  }, []);

  return (
    <>
      <div className="hero">
        <div className="hero-inner">
          <div className="badge">🔒</div>
          <div>
            <h1>Stegno</h1>
            <p>Hide encrypted messages inside ordinary photos, text &amp; files.</p>
          </div>
          <div className="hero-actions">
            <button className="theme-toggle" onClick={toggleTheme} title="Switch theme">{themeIcon()}</button>
            <span className="offline">On-device</span>
          </div>
        </div>
      </div>
      <main>
        <nav className="tabs">
          {TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        {tab === "hide" && <HideTab methods={methods} />}
        {tab === "reveal" && <RevealTab />}
        {tab === "share" && <ShareTab />}
        {tab === "split" && <SplitTab methods={methods} />}
        {tab === "keys" && <KeysTab />}
        {tab === "inspect" && <InspectTab />}
        {tab === "lab" && <LabTab methods={methods} />}
        {tab === "clean" && <CleanTab />}
      </main>
      <footer>Runs entirely on your device — no uploads, no servers. · {methods.length} methods</footer>
    </>
  );
}
