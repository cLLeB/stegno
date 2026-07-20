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

type Panel = "hide" | "reveal" | "share" | "split" | "keys" | "inspect" | "lab" | "clean";
type Group = "hide" | "reveal" | "analyze";

interface GroupDef {
  id: Group;
  label: string;
  subs: { id: Panel; label: string }[];
}
const GROUPS: GroupDef[] = [
  { id: "hide", label: "🔒 Hide", subs: [
    { id: "hide", label: "🖼️ One photo" }, { id: "share", label: "👥 Recipients" },
    { id: "split", label: "🧩 Split photos" }, { id: "keys", label: "🔐 Key-shares" }] },
  { id: "reveal", label: "🔑 Reveal", subs: [{ id: "reveal", label: "🔑 Reveal" }] },
  { id: "analyze", label: "🔬 Analyze", subs: [
    { id: "inspect", label: "🔍 Inspect" }, { id: "lab", label: "🧪 Lab" }, { id: "clean", label: "🧼 Clean" }] },
];

export default function App() {
  const toggleTheme = useTheme();
  const [group, setGroup] = useState<Group>("hide");
  const [panel, setPanel] = useState<Panel>("hide");
  const [methods, setMethods] = useState<MethodInfo[]>([]);
  const themeIcon = () =>
    (document.documentElement.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark"
      ? "☀️"
      : "🌙";

  useEffect(() => {
    listMethods().then(setMethods).catch(() => {});
  }, []);

  function selectGroup(g: GroupDef) {
    setGroup(g.id);
    setPanel(g.subs[0].id);
  }
  const activeGroup = GROUPS.find((g) => g.id === group)!;

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="topbar-row">
            <span className="brand">Stegno</span>
            <button className="theme-toggle" onClick={toggleTheme} title="Switch theme">{themeIcon()}</button>
          </div>
          <nav className="tabs">
            {GROUPS.map((g) => (
              <button key={g.id} className={group === g.id ? "active" : ""} onClick={() => selectGroup(g)}>{g.label}</button>
            ))}
          </nav>
          {activeGroup.subs.length > 1 && (
            <nav className="subtabs">
              {activeGroup.subs.map((s) => (
                <button key={s.id} className={panel === s.id ? "active" : ""} onClick={() => setPanel(s.id)}>{s.label}</button>
              ))}
            </nav>
          )}
        </div>
      </header>
      <main>
        {panel === "hide" && <HideTab methods={methods} />}
        {panel === "reveal" && <RevealTab />}
        {panel === "share" && <ShareTab />}
        {panel === "split" && <SplitTab methods={methods} />}
        {panel === "keys" && <KeysTab />}
        {panel === "inspect" && <InspectTab />}
        {panel === "lab" && <LabTab methods={methods} />}
        {panel === "clean" && <CleanTab />}
      </main>
      <footer>Runs on your device. No uploads. · {methods.length} methods</footer>
    </>
  );
}
