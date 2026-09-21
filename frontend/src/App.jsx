import { useState, useEffect, Component } from 'react';
import {
  ShieldCheck,
  Activity,
  Play,
  Pause,
  SkipForward,
  RotateCcw,
  LayoutDashboard,
  Radio,
  Crosshair,
  Cpu,
  Layers,
  FileText,
  UploadCloud,
  CheckCircle2,
  AlertTriangle,
  Server,
  PanelLeftClose,
  PanelLeftOpen,
  Wifi,
  ExternalLink,
  Sparkles
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  BarChart,
  Bar
} from 'recharts';
import { downloadExcelReport, downloadPDFReport } from './reportDownloader';

const SHAP_EXPLANATIONS = {
  "Flow Pkts/s": "Extremely high packet rates indicate volumetric flooding (e.g., DoS/DDoS) intended to exhaust server resources.",
  "Fwd Pkts/s": "High forward packet rates suggest a rapid automated script or flood originating from the attacker.",
  "Bwd Pkts/s": "High backward packet rates can indicate a reflection attack or massive automated server responses.",
  "Tot Fwd Pkts": "Anomalous total forward packets often point to sustained data transfers, tunneling, or brute-force attempts.",
  "Tot Bwd Pkts": "Anomalous total backward packets suggest heavy server responses, common in data exfiltration or reflection DoS.",
  "Flow Duration": "Unusual flow durations point toward 'low-and-slow' attacks (like Slowloris) or persistent C2 beaconing connections.",
  "Flow IAT Mean": "Irregular inter-arrival times typically indicate automated command-and-control (C2) beaconing or slow-rate brute forcing.",
  "Flow IAT Max": "Large gaps between packets are characteristic of persistent stealthy connections keeping sessions alive.",
  "Fwd IAT Mean": "Anomalies in forward packet timing suggest automated attacker tools rather than natural human traffic.",
  "Fwd Pkt Len Max": "Unusually large forward payloads can indicate forced buffer overflows, SQL injection payloads, or exploit deliveries.",
  "Bwd Pkt Len Max": "Massive backward payloads strongly suggest unauthorized data exfiltration or database dumping from the server.",
  "Pkt Len Mean": "An abnormal average packet length often reveals tunneling protocols or abnormal data payloads hidden in standard ports.",
  "Pkt Len Var": "High packet length variance indicates highly irregular payloads, common in multi-stage exploits.",
  "Init Fwd Win Byts": "Anomalous initial forward TCP window sizes often suggest stealth SYN scanning or custom exploit scripts bypassing standard OS networking stacks.",
  "Init_Win_bytes_forward": "Anomalous initial forward TCP window sizes often suggest stealth SYN scanning or custom exploit scripts bypassing standard OS networking stacks.",
  "Init Bwd Win Byts": "Irregular backward window sizes can reveal customized reverse-shells or anomalous server configurations.",
  "SYN Flag Cnt": "Spikes in SYN flags are the primary indicator of TCP SYN floods or aggressive port scanning (Reconnaissance).",
  "ACK Flag Cnt": "High ACK flag counts can indicate ACK floods or attempts to bypass stateless firewalls.",
  "PSH Flag Cnt": "Frequent PSH (Push) flags often indicate interactive attacker sessions (like reverse shells) forcing immediate data processing.",
  "RST Flag Cnt": "Spikes in RST flags suggest aggressive connection termination, often seen in port scanning or application-layer DoS.",
  "Dst Port": "Targeting non-standard or administrative destination ports (e.g., 445, 3389, 22) usually indicates Lateral Movement or Credential Access attempts.",
  "Protocol": "Anomalous protocol usage (e.g., unexpected UDP or ICMP traffic) can indicate covert channels or network mapping.",
  "meta_log_flow_count": "A massive spike in total concurrent flows is the most reliable indicator of a distributed denial of service (DDoS) or aggressive subnet sweep.",
  "meta_unique_protocols": "A sudden variety of protocols in a single window suggests comprehensive network mapping and reconnaissance.",
  "meta_high_port_ratio": "A high ratio of ephemeral high ports indicates large-scale automated scripting, botnet activity, or massive outbound request flooding."
};

function getShapExplanation(featureName) {
  if (!featureName) return "No anomalous features detected in this window.";
  let baseFeature = featureName;
  if (baseFeature.startsWith("mean_")) baseFeature = baseFeature.substring(5);
  else if (baseFeature.startsWith("max_")) baseFeature = baseFeature.substring(4);
  else if (baseFeature.startsWith("min_")) baseFeature = baseFeature.substring(4);
  else if (baseFeature.startsWith("std_")) baseFeature = baseFeature.substring(4);

  const explanation = SHAP_EXPLANATIONS[baseFeature];
  if (explanation) {
    if (featureName.startsWith("max_")) return `(Peak Spike) ${explanation}`;
    if (featureName.startsWith("mean_")) return `(Sustained Average) ${explanation}`;
    if (featureName.startsWith("std_")) return `(High Volatility) ${explanation}`;
    return explanation;
  }
  return "Anomalous deviations detected in this network telemetry feature.";
}

const THREAT_VECTORS = [
  { id: "VEC-1", name: "DoS Volumetric Saturation", actor: "Slowloris / GoldenEye", target: "10.0.0.5:80", severity: "CRITICAL", prob: "99%", recommendation: "Enforce dynamic SYN-cookies & rate-limit TCP connections per IP" },
  { id: "VEC-2", name: "SMB Named Pipe Injection", actor: "Lateral Movement", target: "10.0.0.5:445", severity: "HIGH", prob: "86%", recommendation: "Enforce SMB packet signing & block RPC inter-VLAN" },
  { id: "VEC-3", name: "Stealth SYN Port Sweep", actor: "Reconnaissance", target: "Class C Subnet", severity: "MEDIUM", prob: "64%", recommendation: "Deploy dynamic rate-limiting on gateway edge" }
];

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 rounded-2xl bg-red-950/40 border border-red-800/50 backdrop-blur-2xl shadow-xl m-4">
          <h2 className="text-lg font-semibold text-red-400 mb-2 flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2" />
            Rendering Error in this View
          </h2>
          <p className="text-sm text-red-300 font-mono">
            {this.state.error?.toString()}
          </p>
          <button
            className="mt-4 px-4 py-2 bg-red-900/50 hover:bg-red-800/50 text-red-200 text-sm font-semibold rounded-lg transition"
            onClick={() => this.setState({ hasError: false })}
          >
            Try Again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  const [activeTab, setActiveTab] = useState('World Model');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [scenarios, setScenarios] = useState([]);
  const [currentScenarioId, setCurrentScenarioId] = useState(() => sessionStorage.getItem('isLiveTracking') === 'true' ? 'live' : 'scenario_recon_to_lateral');
  const [step, setStep] = useState(0);
  const [data, setData] = useState(null);
  const [uploadedResult, setUploadedResult] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [isLiveTracking, setIsLiveTracking] = useState(() => sessionStorage.getItem('isLiveTracking') === 'true');

  useEffect(() => {
    sessionStorage.setItem('isLiveTracking', isLiveTracking);
  }, [isLiveTracking]);
  const [isUploading, setIsUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [liveDetectionLog, setLiveDetectionLog] = useState([]);

  

  // 1. Fetch available scenarios
  const fetchScenarios = () => {
    fetch('http://127.0.0.1:8000/api/scenarios')
      .then(res => res.json())
      .then(list => setScenarios(list))
      .catch(err => console.error("Error fetching scenarios:", err));
  };

  useEffect(() => {
    fetchScenarios();
  }, []);

    // 2. Fetch current step data (Mock/Historical)
  useEffect(() => {
    if (!currentScenarioId || isLiveTracking) return;
    fetch(`http://127.0.0.1:8000/api/scenario/${currentScenarioId}/step/${step}`)
      .then(res => {
        if (!res.ok) throw new Error("Step fetch failed");
        return res.json();
      })
      .then(resData => setData(resData))
      .catch(err => console.error("Error loading scenario step:", err));
  }, [currentScenarioId, step, isLiveTracking]);

  // 3. Playback Loop (Mock/Historical)
  useEffect(() => {
    let interval = null;
    if (isPlaying && !isLiveTracking && data && data.total_steps) {
      interval = setInterval(() => {
        setStep(prev => (prev + 1 < data.total_steps ? prev + 1 : 0));
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [isPlaying, isLiveTracking, data]);

  // Live Tracking Polling & Reconstruction
  useEffect(() => {
    let interval = null;
    if (isLiveTracking) {
      const pollLive = async () => {
        try {
          const resScenarios = await fetch('http://127.0.0.1:8000/api/scenarios');
          if (!resScenarios.ok) throw new Error("Scenarios fetch failed");
          const list = await resScenarios.json();
          setScenarios(list);
          
          if (list.some(s => s.id === 'live')) {
            const res0 = await fetch('http://127.0.0.1:8000/api/scenario/live/step/0');
            if (!res0.ok) throw new Error("Live step 0 failed");
            const d0 = await res0.json();
            
            if (d0.total_steps && d0.total_steps > 0) {
              const totalSteps = d0.total_steps;
              
              // 1. Fetch latest data for World Model
              let dLatest = null;
              const resLatest = await fetch(`http://127.0.0.1:8000/api/scenario/live/step/${totalSteps - 1}`);
              if (resLatest.ok) {
                 dLatest = await resLatest.json();
              }

              // DIAGNOSTIC LOGGING
              console.log(`[Diagnostic] Endpoint requested: /api/scenario/live/step/${totalSteps - 1}`);
              console.log(`[Diagnostic] warmup_count: ${dLatest?.metadata?.warmup_count}`);
              console.log(`[Diagnostic] total_windows: ${dLatest?.metadata?.total_windows}`);
              console.log(`[Diagnostic] current_window timestamp: ${dLatest?.current_window?.timestamp}`);
              console.log(`[Diagnostic] inference_active/live status: ${dLatest?.metadata?.telemetry_status}`);
              console.log(`[Diagnostic] number of windows returned: total_steps=${totalSteps}`);
              
              // 2. Reconstruct Live Monitor History
              setLiveDetectionLog(prev => {
                const missingIndices = [];
                for (let i = 0; i < totalSteps; i++) {
                  // We can't use step_index to check existence because backend resets it to 0-4
                  // We just fetch all windows and merge by timestamp.
                  missingIndices.push(i);
                }
                
                if (missingIndices.length > 0) {
                   Promise.all(missingIndices.map(i => 
                     fetch(`http://127.0.0.1:8000/api/scenario/live/step/${i}`).then(r => r.json())
                   )).then(results => {
                     const fetchedWindows = results.map(r => r.current_window).filter(Boolean);
                     setLiveDetectionLog(current => {
                       const combined = [...current, ...fetchedWindows];
                       if (dLatest && dLatest.current_window) combined.push(dLatest.current_window);
                       const unique = new Map();
                       combined.forEach(w => unique.set(w.timestamp, w));
                       const sortedLog = Array.from(unique.values()).sort((a, b) => a.timestamp.localeCompare(b.timestamp)).slice(-16);
                       
                       // UPDATE WORLD MODEL STATE WITH TRUE CHRONOLOGICAL DATA
                       setData(prevData => ({
                         ...(prevData || dLatest),
                         metadata: dLatest.metadata,
                         current_window: sortedLog[sortedLog.length - 1],
                         total_steps: sortedLog.length
                       }));
                       setStep(sortedLog.length - 1);
                       
                       return sortedLog;
                     });
                   }).catch(err => console.error("History fetch error:", err));
                   return prev; // return previous state while async fetch completes
                }
                
                // If no missing historical indices, just upsert the latest mutating window
                if (!dLatest || !dLatest.current_window) return prev;
                const combined = [...prev, dLatest.current_window];
                const unique = new Map();
                combined.forEach(w => unique.set(w.timestamp, w));
                const sortedLog = Array.from(unique.values()).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
                
                setData(prevData => ({
                   ...(prevData || dLatest),
                   metadata: dLatest.metadata,
                   current_window: sortedLog[sortedLog.length - 1],
                   total_steps: sortedLog.length
                }));
                setStep(sortedLog.length - 1);
                
                return sortedLog;
              });
            } else {
              setData(d0); // Pass metadata through but current_window is null
              setLiveDetectionLog([]);
            }
          } else {
            setData(null);
          }
        } catch (err) {
          console.error("Live Polling Error:", err);
        }
      };
      
      pollLive(); // initial
      interval = setInterval(pollLive, 2000);
    }
    return () => clearInterval(interval);
  }, [isLiveTracking]);

  // 4. Handle Upload
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFile(file.name);
    setIsUploading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/upload-csv", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const errorDetail = await res.json();
        throw new Error(errorDetail.detail || "Upload error");
      }
      const resData = await res.json();

      setUploadedResult(resData);
      setCurrentScenarioId(resData.scenario_id);
      setStep(0);
      fetchScenarios(); // Refresh scenario dropdown
    } catch (err) {
      console.error("Upload error:", err);
      alert(`CSV Ingestion Error: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  if (!data || (!isLiveTracking && !data.current_window)) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-[#070b0a] text-emerald-400 font-mono">
        <div className="flex items-center space-x-3 p-6 rounded-2xl bg-white/[0.03] border border-white/10 shadow-2xl backdrop-blur-2xl">
          <Activity className="animate-spin w-5 h-5 text-emerald-400" />
          <span className="text-sm font-medium tracking-wide">CONNECTING TO CYBER WORLD MODEL ENGINE...</span>
        </div>
      </div>
    );
  }

  const currentWindow = data.current_window || null;
  const currentRisk = currentWindow?.current_risk || 0;
  const trajectoryData = Array.isArray(currentWindow?.trajectory) ? currentWindow.trajectory : [];
  const shapFeatures = Array.isArray(currentWindow?.shap_features) ? currentWindow.shap_features : [];

  // Trajectory Plot Data
  // Prepare Live Monitor Table Data
  let tableData = null;
  if (isLiveTracking) {
    if (liveDetectionLog.length > 0) {
      tableData = liveDetectionLog.map(w => ({
        timestamp: w.timestamp,
        attack_prob: w.current_risk,
        is_attack: w.current_risk >= 0.5,
        status_label: w.current_stage,
        is_warmup: w.is_warmup || false
      }));
    } else {
      tableData = []; // Triggers "Waiting for live telemetry..."
    }
  } else if (uploadedResult?.detection_log) {
    tableData = uploadedResult.detection_log.map(r => ({
      timestamp: r.timestamp,
      attack_prob: r.attack_prob,
      is_attack: r.is_attack,
      status_label: r.is_attack ? "Flagged" : "Nominal"
    }));
  }

  const trajectoryPlot = currentWindow ? [
    { timeKey: 'T_0 (Observed)', probability: currentRisk },
    ...trajectoryData.map((item) => ({
      timeKey: item.step_ahead || "+1min",
      probability: item.prob || 0
    }))
  ] : [];

  // Dynamic stages built from live PyTorch lookaheads
  const dynamicStages = currentWindow ? [
    { label: "Observed Window", stage: currentWindow.current_stage || "Normal Operation", prob: currentRisk, active: true },
    ...trajectoryData.map((item) => ({
      label: `Lookahead ${item.step_ahead}`,
      stage: item.stage || "Evaluating...",
      prob: item.prob,
      active: false
    }))
  ] : [];

  // Dynamic Attack Detection for Theme Switching
  const isAttack = Boolean(
    currentWindow && (
      currentRisk >= 0.5 ||
      currentWindow.is_attack === true ||
      (currentWindow.current_stage &&
        !["Normal Operation", "Nominal", "Nominal / Benign", "Collecting Context..."].includes(currentWindow.current_stage) &&
        (currentRisk >= 0.3 || currentWindow.current_stage.includes("(T") || currentWindow.current_stage.includes("TA")))
    )
  );

  // Theme Configuration (Green for Nominal / Red for Attack)
  const theme = isAttack
    ? {
        isAttack: true,
        bgMain: "bg-[#0d0607]",
        bgSidebar: "bg-[#14080a]/60 border-red-900/30",
        bgHeader: "bg-[#14090b]/60 border-red-900/30",
        glowTop: "bg-red-700/25",
        glowBottom: "bg-rose-950/40",
        selection: "selection:bg-red-800 selection:text-white",

        // Text & Accents
        primaryText: "text-red-400",
        primaryTextLight: "text-red-300",
        primaryTextDark: "text-red-500",
        primaryBg: "bg-red-950/70",
        primaryBgHover: "hover:bg-red-900/60",
        primaryBorder: "border-red-700/50",
        primaryShadow: "shadow-red-950/50",

        // Badges
        badgeBg: "bg-red-950/80 border-red-700/60 text-red-200 shadow-lg shadow-red-950/80",
        badgePing: "bg-red-500",
        badgeText: "🚨 ATTACK DETECTED",

        // Icon badge
        iconBadge: "bg-red-900/50 border-red-500/50 shadow-red-950/70 text-red-300 animate-pulse",
        subTitle: "text-red-400 font-mono font-semibold tracking-tight animate-pulse",
        subTitleText: "CRITICAL THREAT",

        // Buttons
        btnPrimary: "bg-red-800/90 hover:bg-red-700 text-white shadow-lg shadow-red-950/70 border border-red-600/50",
        btnLiveActive: "bg-red-600/80 hover:bg-red-500/80 text-white border-red-400 shadow-[0_0_15px_rgba(239,68,68,0.5)]",
        btnLiveInactive: "bg-red-950/40 hover:bg-red-900/60 border-red-800/50 text-red-300",

        // Chart
        chartStroke: "#ef4444",
        chartDot: "#ef4444",

        // Banner & Accents
        bannerGradient: "from-red-950/40 via-slate-900/40 to-slate-900/30 border-red-500/40",
        dotAccent: "bg-red-400",
        selectFocus: "focus:border-red-500",
        exportBtn: "bg-red-600/20 text-red-400 border border-red-500/30 hover:bg-red-600/30",
        benchmarkRow: "bg-red-950/30 text-red-300",
      }
    : {
        isAttack: false,
        bgMain: "bg-[#070b0a]",
        bgSidebar: "bg-[#0c1310]/50 border-white/10",
        bgHeader: "bg-[#080d0b]/40 border-white/10",
        glowTop: "bg-emerald-800/20",
        glowBottom: "bg-[#5a321e]/20",
        selection: "selection:bg-emerald-800 selection:text-white",

        // Text & Accents
        primaryText: "text-emerald-400",
        primaryTextLight: "text-emerald-300",
        primaryTextDark: "text-emerald-500",
        primaryBg: "bg-emerald-950/70",
        primaryBgHover: "hover:bg-emerald-900/60",
        primaryBorder: "border-emerald-700/50",
        primaryShadow: "shadow-emerald-950/50",

        // Badges
        badgeBg: "bg-emerald-950/60 border-emerald-800/40 text-emerald-300",
        badgePing: "bg-emerald-400",
        badgeText: "LIVE INFERENCE ACTIVE",

        // Icon badge
        iconBadge: "bg-emerald-800/40 border-emerald-500/40 shadow-emerald-950/60 text-emerald-300",
        subTitle: "text-emerald-400 font-mono font-medium tracking-tight",
        subTitleText: "WORLD MODEL",

        // Buttons
        btnPrimary: "bg-emerald-800/80 hover:bg-emerald-700 text-white shadow-lg shadow-emerald-950/60 border border-emerald-600/40",
        btnLiveActive: "bg-emerald-600/80 hover:bg-emerald-500/80 text-white border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.5)]",
        btnLiveInactive: "bg-emerald-950/40 hover:bg-emerald-900/60 border-emerald-800/50 text-emerald-300",

        // Chart
        chartStroke: "#10b981",
        chartDot: "#10b981",

        // Banner & Accents
        bannerGradient: "from-emerald-950/30 via-slate-900/40 to-slate-900/30 border-emerald-500/30",
        dotAccent: "bg-emerald-400",
        selectFocus: "focus:border-emerald-500",
        exportBtn: "bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/30",
        benchmarkRow: "bg-emerald-950/30 text-emerald-300",
      };

  const navItems = [
    { id: 'World Model', icon: Cpu },
    { id: 'Overview', icon: LayoutDashboard },
    { id: 'Live Monitor', icon: Radio },
    { id: 'Attacks', icon: Crosshair },
    { id: 'MITRE', icon: Layers },
    { id: 'Reports', icon: FileText }
  ];

  return (
    <div className={`flex h-screen w-screen ${theme.bgMain} text-slate-200 font-sans overflow-hidden ${theme.selection} transition-colors duration-700`}>

      {/* Top Attack Glow Line */}
      {isAttack && (
        <div className="fixed top-0 inset-x-0 h-1 bg-gradient-to-r from-red-600 via-rose-500 to-red-600 z-50 animate-pulse shadow-[0_0_15px_rgba(239,68,68,0.8)]" />
      )}

      {/* Background Animated Glows */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden transition-all duration-1000 ease-out">
        <div className={`absolute w-[600px] h-[600px] ${theme.glowTop} top-[-5%] left-[20%] rounded-full blur-[140px] animate-pulse transition-colors duration-1000`} />
        <div className={`absolute w-[500px] h-[500px] ${theme.glowBottom} bottom-[-10%] right-[15%] rounded-full blur-[140px] transition-colors duration-1000`} />
      </div>

      {/* Collapsible Sidebar */}
      <aside className={`relative z-20 border-r ${theme.bgSidebar} backdrop-blur-2xl transition-all duration-500 ease-in-out flex flex-col justify-between ${sidebarOpen ? 'w-64' : 'w-20'
        }`}>
        <div>
          <div className={`p-4 border-b border-white/10 flex ${sidebarOpen ? 'items-center justify-between' : 'flex-col items-center space-y-4'}`}>
            <div className={`flex items-center ${sidebarOpen ? 'space-x-3 overflow-hidden' : 'justify-center'}`}>
              <div className={`min-w-[32px] w-8 h-8 rounded-xl ${theme.iconBadge} border flex items-center justify-center backdrop-blur-md transition-colors duration-500`}>
                <ShieldCheck className="w-5 h-5" />
              </div>
              {sidebarOpen && (
                <div className="truncate">
                  <div className="font-bold text-sm tracking-wide text-slate-100 font-sans">SENTINEL AI</div>
                  <div className={theme.subTitle}>{theme.subTitleText}</div>
                </div>
              )}
            </div>
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 hover:text-slate-200 transition border border-white/5 flex-shrink-0"
            >
              {sidebarOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />}
            </button>
          </div>

          <div className="p-3 space-y-1.5">
            {sidebarOpen && <div className="text-[11px] font-sans font-medium uppercase tracking-wider text-slate-500 px-3 py-1">Views</div>}
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  title={!sidebarOpen ? item.id : ''}
                  className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-[13px] font-medium transition-all duration-200 font-sans ${isActive
                      ? `${theme.primaryBg} ${theme.primaryTextLight} border ${theme.primaryBorder} shadow-lg ${theme.primaryShadow} backdrop-blur-md`
                      : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
                    } ${!sidebarOpen ? 'justify-center px-0' : ''}`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? theme.primaryText : 'text-slate-400'}`} />
                  {sidebarOpen && <span>{item.id}</span>}
                </button>
              );
            })}
          </div>
        </div>

        {sidebarOpen ? (
          <div className={`p-3.5 m-3 rounded-xl bg-white/[0.03] border ${isAttack ? 'border-red-900/40 bg-red-950/20' : 'border-white/10'} backdrop-blur-xl shadow-lg transition-colors duration-500`}>
            <div className="flex items-center space-x-2 text-[11px] font-sans font-medium text-slate-400 mb-1">
              <Server className={`w-3.5 h-3.5 ${theme.primaryText}`} />
              <span>PROTECTED CII NODE</span>
            </div>
            <div className={`text-[12px] font-mono font-semibold ${theme.primaryTextLight} truncate`}>
              {data.metadata?.target_asset || "192.168.1.50"}
            </div>
            <div className="text-[11px] text-slate-400 font-sans mt-0.5">SCADA Power Gateway</div>
          </div>
        ) : (
          <div className="p-3 mb-3 flex justify-center">
            <Server className={`w-4 h-4 ${theme.primaryText}`} />
          </div>
        )}
      </aside>

      {/* Main Viewport */}
      <main className="flex-1 relative z-10 flex flex-col overflow-y-auto">
        <header className={`h-16 border-b ${theme.bgHeader} px-8 flex items-center justify-between backdrop-blur-2xl transition-colors duration-500`}>
          <div className="flex items-center space-x-3 text-xs font-sans">
            <span className="text-slate-500 font-medium">WORKSPACE //</span>
            <span className={`${theme.primaryText} font-semibold uppercase tracking-wider`}>{activeTab}</span>

            {/* Scenario Dropdown Selector */}
            <div className="relative ml-4">
              <select
                value={currentScenarioId}
                onChange={(e) => {
                  const val = e.target.value;
                  setCurrentScenarioId(val);
                  setStep(0);
                  setData(null);
                  if (val === 'live') {
                    setIsLiveTracking(true);
                    setIsPlaying(false);
                    setLiveDetectionLog([]);
                  } else {
                    setIsLiveTracking(false);
                  }
                }}
                className={`bg-white/[0.04] border border-white/10 text-slate-200 text-xs rounded-lg px-2.5 py-1 font-mono focus:outline-none ${theme.selectFocus}`}
              >
                {scenarios.map((s) => (
                  <option key={s.id} value={s.id} className="bg-[#0c1310] text-slate-200">
                    {s.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center space-x-6 text-xs">
            {isLiveTracking && (!currentWindow || currentWindow.is_warmup || data.total_steps === 0) ? (
              <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-amber-950/60 border border-amber-800/40 text-amber-300 text-[11px] font-mono font-medium backdrop-blur-md">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                <span>{data.metadata?.telemetry_status === 'WARMING_UP' ? `WARMING UP (${data.metadata?.warmup_count || 0}/5)` : 'WAITING FOR TELEMETRY'}</span>
              </div>
            ) : (
              <div className={`flex items-center space-x-1.5 px-3 py-1 rounded-full ${theme.badgeBg} text-[11px] font-mono font-medium backdrop-blur-md transition-colors duration-500`}>
                <span className={`w-1.5 h-1.5 rounded-full ${theme.badgePing} animate-ping`}></span>
                <span>{theme.badgeText}</span>
              </div>
            )}
            <div className="text-slate-500 font-sans">TELEMETRY TIME: <span className="text-slate-300 font-mono ml-1">{currentWindow?.timestamp ? `${currentWindow.timestamp} IST` : '--'}</span></div>
            <div className="text-slate-500 font-sans">CURRENT TIME: <span className="text-slate-300 font-mono ml-1">
              {new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false })} IST
            </span></div>
            {isLiveTracking && (
              <div className="text-slate-500 font-sans">STATUS: <span className={`font-mono ml-1 ${data.metadata?.telemetry_status === 'LIVE' ? theme.primaryText : 'text-amber-400'}`}>
                {data.metadata?.telemetry_status || (currentWindow ? 'LIVE' : 'WARMING_UP')}
                {data.metadata?.telemetry_lag_seconds !== undefined && ` (${data.metadata.telemetry_lag_seconds}s lag)`}
              </span></div>
            )}
          </div>
        </header>

        <div className="p-8 space-y-6">
          <ErrorBoundary>
          {/* VIEW: WORLD MODEL */}
          {activeTab === 'World Model' && (
            <>
              {/* Metric Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-white/[0.03] border border-white/10 p-4 rounded-2xl backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium text-slate-400 tracking-wider">FLOW THROUGHPUT</div>
                  <div className="text-3xl font-semibold font-mono text-slate-100 mt-1">{currentWindow?.flow_count ?? (data.metadata?.rows_ingested || 0)} <span className="text-sm font-normal text-slate-400">/min</span></div>
                  <div className={`text-[11px] ${theme.primaryText} font-sans mt-1`}>{currentWindow ? "Aggregated Window" : "Live Stream Ingest"}</div>
                </div>

                <div className="bg-white/[0.03] border border-white/10 p-4 rounded-2xl backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium text-slate-400 tracking-wider">CAUSAL DIVERGENCE</div>
                  <div className="text-xl font-semibold font-sans text-amber-300 mt-2">
                    {!currentWindow || currentWindow.is_warmup ? (data.metadata?.telemetry_status === 'WARMING_UP' ? "Collecting Context" : "Awaiting Data") : currentRisk > 0.6 ? "Critical Anomaly" : currentRisk > 0.3 ? "Elevated Drift" : "Nominal Physics"}
                  </div>
                  <div className="text-[11px] text-amber-400/80 font-sans mt-1">Latent State Transition</div>
                </div>

                <div className="bg-white/[0.03] border border-white/10 p-4 rounded-2xl backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium text-slate-400 tracking-wider">PROJECTED MITRE TACTIC</div>
                  <div className="text-sm font-semibold font-sans text-red-300 mt-2.5 truncate">
                    {currentWindow?.current_stage || (data.metadata?.telemetry_status === 'WARMING_UP' ? "Warming Up (States < 6)" : "Nominal / Benign")}
                  </div>
                  <div className="text-[11px] text-red-400 font-sans mt-1">PyTorch 3-Head Classifier</div>
                </div>

                <div className="bg-white/[0.03] border border-white/10 p-4 rounded-2xl backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium text-slate-400 tracking-wider">ATTACK PROBABILITY</div>
                  <div className="text-3xl font-semibold font-mono text-[#e59866] mt-1">
                    {!currentWindow || currentWindow.is_warmup ? "---%" : `${(currentRisk * 100).toFixed(1)}%`}
                  </div>
                  <div className="text-[11px] text-slate-400 font-sans mt-1">Horizon k=5 Rollout</div>
                </div>
              </div>

              {/* Simulation Toolbar */}
              <div className="flex justify-between items-center bg-white/[0.03] border border-white/10 px-5 py-3 rounded-2xl backdrop-blur-2xl shadow-lg">
                <div className="flex items-center space-x-3">
                  <button
                    onClick={() => setIsPlaying(!isPlaying)}
                    className={`flex items-center space-x-2 px-4 py-2 ${theme.btnPrimary} rounded-xl text-xs font-semibold tracking-wide transition backdrop-blur-md`}
                  >
                    {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{isPlaying ? 'PAUSE TRAJECTORY' : 'SIMULATE FORWARD ROLLOUT'}</span>
                  </button>
                  <button
                    onClick={() => setStep(prev => Math.min(prev + 1, Math.max(0, (data.total_steps || 1) - 1)))}
                    disabled={step >= (data.total_steps || 1) - 1 || data.total_steps === 0}
                    className="p-2 bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-30 border border-white/10 rounded-xl text-slate-300 transition"
                  >
                    <SkipForward className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setStep(0)}
                    disabled={data.total_steps === 0}
                    className="p-2 bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-30 border border-white/10 rounded-xl text-slate-300 transition"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="flex items-center space-x-4">
                  <button
                    onClick={() => {
                      const willBeLive = !isLiveTracking;
                      setIsLiveTracking(willBeLive);
                      setIsPlaying(false);
                      setData(null);
                      setLiveDetectionLog([]);
                      if (willBeLive) {
                        setCurrentScenarioId('live');
                      } else {
                        if (scenarios.length > 0) {
                          setCurrentScenarioId(scenarios[0].id);
                          setStep(0);
                        }
                      }
                    }}
                    className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl border text-xs transition backdrop-blur-md font-mono ${isLiveTracking ? theme.btnLiveActive : theme.btnLiveInactive}`}
                  >
                    <Activity className={`w-3.5 h-3.5 ${isLiveTracking ? 'text-white' : theme.primaryText} animate-pulse`} />
                    <span>{isLiveTracking ? 'LIVE TRACKING ACTIVE' : 'TRACK LIVE TRAFFIC'}</span>
                  </button>
                  <label className="cursor-pointer flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-white/[0.03] hover:bg-white/[0.07] border border-white/10 text-xs text-slate-300 transition backdrop-blur-md font-mono">
                    <UploadCloud className={`w-3.5 h-3.5 ${theme.primaryText}`} />
                    <span>{isUploading ? "COMPUTING INFERENCE..." : selectedFile ? selectedFile : "INGEST RAW PCAP / CSV"}</span>
                    <input type="file" className="hidden" accept=".pcap,.csv" onChange={handleFileUpload} />
                  </label>
                  <div className="text-xs font-sans text-slate-400">
                    WINDOW: <span className={`${theme.primaryText} font-semibold font-mono`}>{data.total_steps > 0 ? step + 1 : 0}</span> / <span className="font-mono">{data.total_steps || 0}</span>
                  </div>
                </div>
              </div>

              {/* Trajectory Plot + SHAP */}
              {!currentWindow || currentWindow.is_warmup ? (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-2 bg-white/[0.03] border border-white/10 p-8 rounded-2xl backdrop-blur-2xl shadow-xl flex flex-col items-center justify-center min-h-[260px] text-center font-mono">
                    <Activity className="animate-spin w-6 h-6 text-emerald-400 mb-3" />
                    <div className="text-emerald-400 text-sm font-semibold mb-1">
                      {data.metadata?.telemetry_status === 'WARMING_UP' ? `WARMING UP (${data.metadata?.warmup_count || 0}/5)` : 'WAITING FOR LIVE TELEMETRY'}
                    </div>
                    <p className="text-slate-400 text-xs font-sans max-w-md">
                      The PyTorch LSTM World Model requires 5 completed 1-minute historical windows before generating forward simulation trajectories (+1min to +5min).
                    </p>
                  </div>
                  <div className="bg-white/[0.03] border border-white/10 p-8 rounded-2xl backdrop-blur-2xl shadow-xl flex flex-col items-center justify-center min-h-[260px] text-center font-mono text-slate-400 text-xs">
                    <Layers className="w-6 h-6 text-slate-500 mb-2" />
                    <span>SHAP gradient attribution will compute once the first live inference window completes.</span>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-2 bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                    <div className="flex justify-between items-center mb-4">
                      <div>
                        <h2 className="text-[15px] font-semibold text-slate-100">Forward Simulation Trajectory P(S_t+k | S_t)</h2>
                        <p className="text-[12px] text-slate-400">Autoregressive forward rollout from LSTM hidden states</p>
                      </div>
                      <div className={`text-[11px] font-mono font-medium px-3 py-1 rounded-lg ${theme.primaryBg} border ${theme.primaryBorder} ${theme.primaryTextLight}`}>
                        LOOKAHEAD: +5min
                      </div>
                    </div>

                    <div className="h-60 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={trajectoryPlot}>
                          <XAxis dataKey="timeKey" stroke="#64748b" tick={{ fontSize: 11 }} />
                          <YAxis domain={[0, 1]} stroke="#64748b" tick={{ fontSize: 11 }} tickFormatter={(val) => `${(val * 100).toFixed(0)}%`} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: 'rgba(12, 19, 16, 0.85)',
                              backdropFilter: 'blur(16px)',
                              borderColor: 'rgba(255, 255, 255, 0.15)',
                              borderRadius: '12px',
                              color: '#f8fafc'
                            }}
                            formatter={(val) => [`${(Number(val) * 100).toFixed(2)}%`, 'Attack Probability']}
                          />
                          <ReferenceLine x="T_0 (Observed)" stroke="#e59866" strokeDasharray="3 3" />
                          <Line type="monotone" dataKey="probability" stroke={theme.chartStroke} strokeWidth={2.5} dot={{ r: 4, fill: theme.chartDot }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl flex flex-col">
                    <div>
                      <h2 className="text-[15px] font-semibold text-slate-100 mb-1">Explainability (SHAP / Gradient Weights)</h2>
                      <p className="text-[12px] text-slate-400 mb-4">Input saliency gradients w.r.t attack head</p>
                    </div>
                    <div className="flex-1 min-h-[160px] w-full mb-5">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={shapFeatures} layout="vertical">
                          <XAxis type="number" domain={[0, 1]} stroke="#64748b" tick={{ fontSize: 11 }} />
                          <YAxis dataKey="feature" type="category" width={140} stroke="#64748b" tick={{ fontSize: 10 }} />
                          <Tooltip
                            cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                            contentStyle={{
                              backgroundColor: 'rgba(12, 19, 16, 0.9)',
                              backdropFilter: 'blur(20px)',
                              border: '1px solid rgba(255, 255, 255, 0.2)',
                              borderRadius: '12px',
                              boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
                            }}
                            formatter={(val) => [`${(Number(val) * 100).toFixed(1)}%`, 'Attribution Weight']}
                          />
                          <Bar dataKey="importance" fill="#d97736" radius={[0, 4, 4, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>

                    {/* TEXT EXPLANATION BOX */}
                    <div className={`mt-auto p-4 rounded-xl shadow-inner border ${currentRisk >= 0.5 ? 'bg-amber-950/20 border-amber-900/40' : 'bg-white/[0.02] border-white/5'}`}>
                      <div className={`flex items-center space-x-2 mb-1.5 ${currentRisk >= 0.5 ? 'text-amber-500' : 'text-slate-500'}`}>
                        <Layers className="w-4 h-4" />
                        <span className="text-xs font-mono font-semibold uppercase tracking-wider">
                          {currentRisk >= 0.5 ? `PRIMARY INSIGHT: ${shapFeatures[0]?.feature || "None"}` : `NOMINAL VARIANCE: ${shapFeatures[0]?.feature || "None"}`}
                        </span>
                      </div>
                      <p className={`text-[13px] font-sans leading-relaxed ${currentRisk >= 0.5 ? 'text-slate-300' : 'text-slate-500'}`}>
                        {currentRisk >= 0.5
                          ? getShapExplanation(shapFeatures[0]?.feature)
                          : `Traffic is currently benign. While this feature had the highest mathematical variance in this window, it did not exceed thresholds for adversarial behavior.`
                        }
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Real Model MITRE ATT&CK Stages */}
              <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                <h2 className="text-[15px] font-semibold text-slate-100 mb-3">Model-Inferred MITRE ATT&CK Stages (Horizon Rollout)</h2>
                {currentWindow ? (
                  <div className="grid grid-cols-2 md:grid-cols-6 gap-2.5">
                    {dynamicStages.map((stg, idx) => (
                      <div
                        key={idx}
                        className={`p-3 rounded-xl border transition-all duration-300 backdrop-blur-xl text-center ${stg.active
                            ? (isAttack
                                ? 'bg-red-950/90 border-red-500 text-red-200 font-semibold shadow-lg shadow-red-950/80 scale-105'
                                : 'bg-emerald-950/80 border-emerald-400 text-emerald-200 font-semibold shadow-lg shadow-emerald-950/80 scale-105')
                            : 'bg-white/[0.02] border-white/5 text-slate-400'
                          }`}
                      >
                        <div className="text-[10px] uppercase font-mono font-medium tracking-wider text-slate-400 mb-1">{stg.label}</div>
                        <div className="text-[12px] leading-snug font-sans font-medium text-slate-200 truncate">{stg.stage}</div>
                        <div className={`text-[10px] font-mono ${theme.primaryText} mt-1`}>P: {(stg.prob * 100).toFixed(1)}%</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="py-6 text-center text-slate-500 font-mono text-xs">
                    Awaiting live prediction window to compute autoregressive forward stages (+1min ... +5min).
                  </div>
                )}
              </div>
            </>
          )}

          {/* VIEW: LIVE MONITOR */}
          {activeTab === 'Live Monitor' && (
            <div className="p-6 rounded-2xl bg-white/[0.03] border border-white/10 backdrop-blur-2xl shadow-xl space-y-4">
              <div className="flex justify-between items-center">
                <div>
                  <h2 className="text-[15px] font-semibold text-slate-100">Live Traffic Ingestion & Anomaly Monitor</h2>
                  <p className="text-[12px] text-slate-400">1-Minute Window Inference from PyTorch LSTM World Model</p>
                </div>
                {isLiveTracking ? (
                  <div className={`flex items-center space-x-2 text-[11px] font-mono ${theme.primaryText} ${theme.primaryBg} border ${theme.primaryBorder} px-3 py-1.5 rounded-lg`}>
                    <Wifi className="w-3.5 h-3.5 animate-pulse" />
                    <span>LIVE TRACKING: {tableData?.filter(r => r.is_attack).length || 0} / {tableData?.length || 0} ANOMALIES</span>
                  </div>
                ) : uploadedResult?.detection_summary && (
                  <div className={`flex items-center space-x-2 text-[11px] font-mono ${theme.primaryText} ${theme.primaryBg} border ${theme.primaryBorder} px-3 py-1.5 rounded-lg`}>
                    <Wifi className="w-3.5 h-3.5 animate-pulse" />
                    <span>DETECTED {uploadedResult.detection_summary.anomalous_windows_detected} / {uploadedResult.detection_summary.total_windows_evaluated} ANOMALIES</span>
                  </div>
                )}
              </div>

              {/* Status Banner */}
              {isLiveTracking && tableData && tableData.length > 0 ? (
                tableData.some(r => r.is_attack) ? (
                  <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-800/50 flex items-center space-x-3 text-red-300 text-xs font-mono">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span>🚨 LIVE ATTACK DETECTED</span>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-800/50 flex items-center space-x-3 text-emerald-300 text-xs font-mono">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>✓ LIVE TRAFFIC NOMINAL</span>
                  </div>
                )
              ) : uploadedResult?.detection_summary ? (
                uploadedResult.detection_summary.anomalous_windows_detected > 0 ? (
                  <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-800/50 flex items-center space-x-3 text-red-300 text-xs font-mono">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span>🚨 {uploadedResult.detection_summary.verdict} (Threshold: {uploadedResult.detection_summary.model_threshold})</span>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-800/50 flex items-center space-x-3 text-emerald-300 text-xs font-mono">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>✓ {uploadedResult.detection_summary.verdict}</span>
                  </div>
                )
              ) : null}

              {/* Detection Log Table */}
              <div className="overflow-x-auto mt-4">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-white/10 text-slate-400 uppercase tracking-wider text-[11px]">
                      <th className="py-2.5 px-3">WINDOW TIME</th>
                      <th className="py-2.5 px-3">P(ATTACK)</th>
                      <th className="py-2.5 px-3">IS ATTACK</th>
                      <th className="py-2.5 px-3">STATUS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {tableData && tableData.length > 0 ? (
                      tableData.map((row, idx) => (
                        <tr key={idx} className="hover:bg-white/[0.03] transition">
                          <td className="py-2.5 px-3 text-slate-300">{row.timestamp} IST</td>
                          <td className="py-2.5 px-3 text-amber-300 font-semibold">
                            {row.attack_prob != null ? row.attack_prob.toFixed(4) : "---"}
                          </td>
                          <td className="py-2.5 px-3">
                            {row.is_warmup ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-800">
                                N/A
                              </span>
                            ) : (
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${row.is_attack ? 'bg-red-950/80 text-red-300 border border-red-800' : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'}`}>
                                {row.is_attack ? "True" : "False"}
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3">
                            {row.is_warmup ? (
                              <span className="text-slate-400 flex items-center space-x-1">
                                <Activity className="w-3 h-3 inline mr-1 animate-pulse" />
                                {row.status_label}
                              </span>
                            ) : row.is_attack ? (
                              <span className="text-red-400 font-semibold flex items-center space-x-1">
                                <AlertTriangle className="w-3 h-3 inline mr-1" />
                                {row.status_label}
                              </span>
                            ) : (
                              <span className="text-emerald-400 flex items-center space-x-1">
                                <CheckCircle2 className="w-3 h-3 inline mr-1" />
                                {row.status_label}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-slate-500">
                          {isLiveTracking ? "Waiting for live telemetry..." : 'Upload a test CSV via "INGEST RAW PCAP / CSV" to stream real detection logs.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* VIEW: OVERVIEW */}
          {activeTab === 'Overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-3 gap-6">
                <div className="p-6 rounded-2xl bg-white/[0.03] border border-white/10 backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium uppercase tracking-wider text-slate-400 mb-1">NETWORK HEALTH INDEX</div>
                  <div className={`text-3xl font-semibold font-mono ${uploadedResult?.detection_summary?.anomalous_windows_detected > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {uploadedResult?.detection_summary ?
                      ((1 - (uploadedResult.detection_summary.anomalous_windows_detected / uploadedResult.detection_summary.total_windows_evaluated)) * 100).toFixed(1) + '%'
                      : '100%'}
                  </div>
                  <p className="text-[13px] text-slate-400 mt-2">Nominal baseline across processed traffic sequences.</p>
                </div>
                <div className="p-6 rounded-2xl bg-white/[0.03] border border-white/10 backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium uppercase tracking-wider text-slate-400 mb-1">PROACTIVE DEFENSE BUFFER</div>
                  <div className={`text-3xl font-semibold font-mono ${theme.primaryTextLight}`}>+{trajectoryData.length || 5} min</div>
                  <p className="text-[13px] text-slate-400 mt-2">Forward horizon lookahead before compromise cascades.</p>
                </div>
                <div className="p-6 rounded-2xl bg-white/[0.03] border border-white/10 backdrop-blur-2xl shadow-xl">
                  <div className="text-[11px] font-sans font-medium uppercase tracking-wider text-slate-400 mb-1">CURRENT POSTURE / ISOLATION READINESS</div>
                  <div className={`text-3xl font-semibold font-sans ${currentRisk >= 0.5 ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {currentRisk >= 0.5 ? 'Engaged / Armed' : 'Monitoring / Ready'}
                  </div>
                  <p className="text-[13px] text-slate-400 mt-2">Autonomous micro-segmentation readiness.</p>
                </div>
              </div>
            </div>
          )}

          {/* VIEW: ATTACKS */}
          {activeTab === 'Attacks' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100 font-sans">Correlated Infiltration Pathways & Mitigations</h2>
                  <p className="text-[13px] text-slate-400 font-sans">Proactive containment strategies generated from World Model rollouts</p>
                </div>
                <div className="text-[11px] font-mono font-medium text-rose-400 bg-rose-950/60 border border-rose-800/40 px-3 py-1 rounded-lg">
                  ACTION REQUIRED
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4">
                <h3 className={`text-sm font-semibold ${theme.primaryText} mb-2 mt-2`}>Live Dynamic Detection</h3>
                {currentRisk >= 0.5 ? (
                  <div className="p-5 rounded-2xl bg-white/[0.03] border border-red-500/30 backdrop-blur-2xl shadow-xl flex justify-between items-center">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-3">
                        <span className="text-xs font-mono font-semibold text-red-400">VEC-{step}</span>
                        <span className="text-[14px] font-semibold text-slate-100 font-sans">{currentWindow?.current_stage || "Unknown Threat"}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/60 border border-red-800/50 text-red-300">{currentRisk > 0.8 ? "CRITICAL" : "HIGH"}</span>
                      </div>
                      <div className="text-[13px] text-slate-400 font-sans">
                        Target Asset: <span className="font-mono text-slate-300">{data.metadata?.target_asset || "Network Gateway"}</span> ➔ Risk Probability: <span className="font-mono text-red-300">{(currentRisk * 100).toFixed(1)}%</span>
                      </div>
                      <div className="text-[12px] text-emerald-300/90 font-sans pt-1">
                        Recommended Defense: <span className="font-medium text-emerald-300">Quarantine subnet and analyze {shapFeatures[0]?.feature || "anomalous traffic"} spike</span>
                      </div>
                    </div>
                    <button className="px-4 py-2 rounded-xl bg-red-900/60 hover:bg-red-800 text-white font-sans font-medium text-xs border border-red-500/40 shadow-lg shadow-red-950/50 transition">
                      ENFORCE ACL BLOCK
                    </button>
                  </div>
                ) : (
                  <div className="p-10 text-center rounded-2xl bg-white/[0.02] border border-white/5 backdrop-blur-2xl">
                    <CheckCircle2 className="w-10 h-10 text-emerald-500/50 mx-auto mb-3" />
                    <h3 className="text-slate-300 font-sans font-medium text-sm mb-1">No Active Threats Detected</h3>
                    <p className="text-slate-500 text-xs font-sans">The world model predicts nominal behavior for the current time window.</p>
                  </div>
                )}

                <h3 className={`text-sm font-semibold ${theme.primaryText} mb-2 mt-6`}>Reference Threat Library (Static Policies)</h3>
                {THREAT_VECTORS.map((vec) => (
                  <div key={vec.id} className="p-5 rounded-2xl bg-white/[0.03] border border-white/10 backdrop-blur-2xl shadow-xl flex justify-between items-center">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-3">
                        <span className="text-xs font-mono font-semibold text-red-400">{vec.id}</span>
                        <span className="text-[14px] font-semibold text-slate-100 font-sans">{vec.name}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/60 border border-red-800/50 text-red-300">{vec.severity}</span>
                      </div>
                      <div className="text-[13px] text-slate-400 font-sans">
                        Actor Signature: <span className="font-mono text-slate-300">{vec.actor}</span> ➔ Target: <span className="font-mono text-slate-300">{vec.target}</span>
                      </div>
                      <div className="text-[12px] text-emerald-300/90 font-sans pt-1">
                        Recommended Defense: <span className="font-medium text-emerald-300">{vec.recommendation}</span>
                      </div>
                    </div>
                    <button className={`px-4 py-2 rounded-xl ${theme.btnPrimary} font-sans font-medium text-xs transition`}>
                      ENFORCE ACL
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* VIEW: MITRE */}
          {activeTab === 'MITRE' && (
            <div className="space-y-6">
              {/* LIVE RAG ANALYSIS CARD */}
              <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2.5 rounded-xl ${isAttack ? 'bg-red-500/10 border border-red-500/20 text-red-400' : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'}`}>
                      <Sparkles className="w-5 h-5" />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-slate-100 font-sans">
                        Live MITRE ATT&CK RAG Analysis
                      </h2>
                      <p className="text-[13px] text-slate-400 font-sans">
                        Semantic retrieval & evidence-grounded technique mapping from observed network dynamics
                      </p>
                    </div>
                  </div>
                  {currentWindow?.rag?.technique_id && (
                    <span className={`px-3 py-1 rounded-full text-xs font-mono font-medium border ${
                      (currentWindow.rag.confidence >= 0.75)
                        ? (isAttack ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30')
                        : (currentWindow.rag.confidence >= 0.5)
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : 'bg-red-500/10 text-red-400 border-red-500/30'
                    }`}>
                      Confidence: {(currentWindow.rag.confidence * 100).toFixed(1)}% ({
                        currentWindow.rag.confidence >= 0.75 ? 'HIGH' : currentWindow.rag.confidence >= 0.5 ? 'MEDIUM' : 'LOW'
                      })
                    </span>
                  )}
                </div>

                {currentWindow?.rag?.technique_id ? (
                  <div className="space-y-4">
                    {/* Primary Matched Technique Banner */}
                    <div className={`p-5 rounded-xl bg-gradient-to-r ${theme.bannerGradient}`}>
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                        <div className="flex items-center space-x-3">
                          <span className={`font-mono text-base font-bold ${isAttack ? 'text-red-400 bg-red-500/10 border-red-500/30' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'} px-2.5 py-1 rounded border`}>
                            {currentWindow.rag.technique_id}
                          </span>
                          <span className="text-base font-semibold text-slate-100 font-sans">
                            {currentWindow.rag.technique_name}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono text-slate-300 bg-white/5 px-2.5 py-1 rounded border border-white/10">
                            Tactic: <strong className={theme.primaryTextLight}>{currentWindow.rag.tactic}</strong>
                          </span>
                          {currentWindow.rag.mitre_url && (
                            <a
                              href={currentWindow.rag.mitre_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={`flex items-center space-x-1 text-xs font-mono ${isAttack ? 'text-red-400 hover:text-red-300 bg-red-500/10 border-red-500/20' : 'text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 border-emerald-500/20'} px-2.5 py-1 rounded border transition`}
                            >
                              <span>ATT&CK Doc</span>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </div>
                      </div>

                      {currentWindow.rag.mitre_description && (
                        <p className="text-[13px] text-slate-300 font-sans leading-relaxed mt-2 line-clamp-3">
                          {currentWindow.rag.mitre_description}
                        </p>
                      )}
                    </div>

                    {/* Reasoning & Evidence */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* Reason */}
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                        <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center space-x-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${theme.dotAccent}`}></span>
                          <span>Inference Rationale</span>
                        </div>
                        <p className="text-[13px] text-slate-300 font-sans leading-relaxed">
                          {currentWindow.rag.reason}
                        </p>
                      </div>

                      {/* Evidence & Attributed Features */}
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                        <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center space-x-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${theme.dotAccent}`}></span>
                          <span>Attributed Flow Evidence</span>
                        </div>
                        {currentWindow.rag.evidence && currentWindow.rag.evidence.length > 0 ? (
                          <div className="space-y-1.5">
                            {currentWindow.rag.evidence.map((ev, i) => (
                              <div key={i} className="flex items-center justify-between text-xs font-mono py-1 px-2 rounded bg-white/[0.02] border border-white/5">
                                <span className="text-slate-300 truncate max-w-[70%]">{ev.feature}</span>
                                <span className={`${theme.primaryText} font-semibold`}>{ev.importance}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-slate-500 italic">No feature attribution data recorded.</p>
                        )}
                      </div>
                    </div>

                    {/* Scoring Decomposition */}
                    {currentWindow.rag.scores && (
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                        <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-3">
                          Score Decomposition (Transparent Ranking)
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[11px] text-slate-400 font-sans">Semantic Match</div>
                            <div className="text-sm font-mono font-bold text-slate-200 mt-1">
                              {(currentWindow.rag.scores.semantic_score * 100).toFixed(1)}%
                            </div>
                          </div>
                          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[11px] text-slate-400 font-sans">Tactic Alignment</div>
                            <div className="text-sm font-mono font-bold text-slate-200 mt-1">
                              {(currentWindow.rag.scores.tactic_score * 100).toFixed(1)}%
                            </div>
                          </div>
                          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[11px] text-slate-400 font-sans">Evidence Grounding</div>
                            <div className="text-sm font-mono font-bold text-slate-200 mt-1">
                              {(currentWindow.rag.scores.evidence_score * 100).toFixed(1)}%
                            </div>
                          </div>
                          <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[11px] text-slate-400 font-sans">Combined Retrieval</div>
                            <div className={`text-sm font-mono font-bold ${theme.primaryText} mt-1`}>
                              {(currentWindow.rag.scores.final_retrieval_score * 100).toFixed(1)}%
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Limitations & Confidence Bounds */}
                    {currentWindow.rag.limitations && (
                      <div className="p-3 rounded-xl bg-amber-500/5 border border-amber-500/20 text-amber-300 text-[12px] font-sans flex items-start space-x-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                        <span><strong>Limitations & Ambiguity:</strong> {currentWindow.rag.limitations}</span>
                      </div>
                    )}

                    {/* Alternative Candidates */}
                    {currentWindow.rag.candidates && currentWindow.rag.candidates.length > 0 && (
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                        <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-2">
                          Alternative Technique Candidates
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                          {currentWindow.rag.candidates.map((cand, idx) => (
                            <div key={idx} className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5 flex items-center justify-between">
                              <div>
                                <span className="font-mono font-semibold text-slate-200 mr-2">{cand.technique_id}</span>
                                <span className="text-slate-400 font-sans">{cand.technique_name}</span>
                              </div>
                              <span className="font-mono text-emerald-400/80 text-[11px] ml-2 shrink-0">
                                {(cand.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-8 rounded-xl bg-white/[0.02] border border-white/10 text-center">
                    <ShieldCheck className="w-10 h-10 text-emerald-500/50 mx-auto mb-3" />
                    <div className="text-emerald-400 font-mono font-semibold text-sm mb-2">
                      {currentRisk < 0.5 ? "BENIGN NETWORK TRAFFIC" : "NO TECHNIQUE MATCH"}
                    </div>
                    <p className="text-slate-400 text-[13px] font-sans max-w-lg mx-auto">
                      {currentWindow?.rag?.reason || "Autonomous RAG retrieval active. Evaluates and maps threat vectors whenever network risk exceeds operational threshold."}
                    </p>
                  </div>
                )}
              </div>

              {/* TACTIC MATRIX ALIGNMENT */}
              <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                <h2 className="text-lg font-semibold text-slate-100 font-sans mb-1">MITRE ATT&CK Matrix Alignment (Live Inferred)</h2>
                <p className="text-[13px] text-slate-400 font-sans mb-6">Autonomous mapping of predicted latent network states to enterprise tactics based on current trajectory.</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  {currentRisk < 0.5 && !dynamicStages.some(stg => stg.prob >= 0.5) ? (
                    <div className="col-span-3 p-10 rounded-xl bg-white/[0.02] border border-white/10 text-center">
                      <ShieldCheck className="w-10 h-10 text-emerald-500/50 mx-auto mb-3" />
                      <div className="text-emerald-400 font-mono font-semibold text-sm mb-2">NOMINAL OPERATION</div>
                      <p className="text-slate-400 text-[13px] font-sans">No adversarial MITRE ATT&CK tactics detected in the current or forecasted latent states.</p>
                    </div>
                  ) : (
                    [...new Map(dynamicStages.filter(stg => stg.prob >= 0.5 && stg.stage !== "Benign" && stg.stage !== "Normal Operation").map(item => [item.stage, item])).values()].map((stg, idx) => (
                      <div key={idx} className="p-4 rounded-xl bg-white/[0.02] border border-red-500/30">
                        <div className="text-red-400 font-mono font-semibold text-xs mb-2 uppercase">{stg.stage}</div>
                        <p className="text-slate-400 text-[13px] font-sans leading-relaxed">
                          The tactical classifier has aligned the network physics for <b>{stg.label}</b> to this specific threat vector with {(stg.prob * 100).toFixed(1)}% confidence.
                        </p>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                <h2 className="text-lg font-semibold text-slate-100 font-sans mb-1">Common Monitored Tactics (Reference)</h2>
                <p className="text-[13px] text-slate-400 font-sans mb-6">Static knowledge base for typical industrial environment threats.</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-emerald-400 font-mono font-semibold text-xs mb-2">TA0006 - CREDENTIAL ACCESS</div>
                    <p className="text-slate-400 text-[13px] font-sans leading-relaxed">Repeated authentication flow attempts over standard remote management ports.</p>
                  </div>
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-amber-400 font-mono font-semibold text-xs mb-2">TA0040 - DOS / DDOS IMPACT</div>
                    <p className="text-slate-400 text-[13px] font-sans leading-relaxed">High volumetric saturation and anomalous packet length distribution collapses.</p>
                  </div>
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-red-400 font-mono font-semibold text-xs mb-2">TA0008 - LATERAL MOVEMENT</div>
                    <p className="text-slate-400 text-[13px] font-sans leading-relaxed">Subnet pivot attempts using named pipes and remote administrative shares.</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* VIEW: REPORTS */}
          {activeTab === 'Reports' && (
            <div className="space-y-6">
              <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <h2 className="text-lg font-semibold text-slate-100 font-sans mb-1">Live Session Ingestion Report</h2>
                    <p className="text-[13px] text-slate-400 font-sans">Real-time inference statistics for the currently tracked network traffic.</p>
                  </div>
                  <div className="flex space-x-3">
                    <button 
                      onClick={() => downloadExcelReport({
                        totalWindows: uploadedResult?.detection_summary?.total_windows_evaluated || data.total_steps || 0,
                        anomalousWindows: uploadedResult?.detection_summary?.anomalous_windows_detected || 0,
                        flowThroughput: currentWindow?.flow_count || 0,
                        peakRisk: (currentRisk * 100).toFixed(2) + '%',
                        sessionId: currentScenarioId
                      })}
                      className={`px-4 py-2 ${theme.exportBtn} rounded-lg text-xs font-semibold transition-colors flex items-center`}
                    >
                      Export CSV
                    </button>
                    <button 
                      onClick={() => downloadPDFReport({
                        totalWindows: uploadedResult?.detection_summary?.total_windows_evaluated || data.total_steps || 0,
                        anomalousWindows: uploadedResult?.detection_summary?.anomalous_windows_detected || 0,
                        flowThroughput: currentWindow?.flow_count || 0,
                        peakRisk: (currentRisk * 100).toFixed(2) + '%',
                        sessionId: currentScenarioId
                      })}
                      className={`px-4 py-2 ${theme.exportBtn} rounded-lg text-xs font-semibold transition-colors flex items-center`}
                    >
                      Export PDF
                    </button>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-slate-400 font-sans font-medium uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4">METRIC</th>
                        <th className="py-3 px-4">VALUE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-xs">
                      <tr>
                        <td className="py-3 px-4 text-slate-300 font-sans">Total Time Windows Evaluated</td>
                        <td className="py-3 px-4 text-slate-400">{uploadedResult?.detection_summary?.total_windows_evaluated || data.total_steps} windows (1 min each)</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-300 font-sans">Anomalous Windows Detected</td>
                        <td className={`py-3 px-4 ${uploadedResult?.detection_summary?.anomalous_windows_detected > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                          {uploadedResult?.detection_summary?.anomalous_windows_detected || 0}
                        </td>
                      </tr>
                      <tr className="bg-white/[0.02]">
                        <td className="py-3 px-4 text-slate-300 font-sans">Current Flow Throughput</td>
                        <td className="py-3 px-4 text-slate-400">{currentWindow?.flow_count || 0} flows/min</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-300 font-sans">Latest Peak Risk Probability</td>
                        <td className={`py-3 px-4 ${(currentRisk * 100) > 50 ? 'text-red-400 font-bold' : 'text-slate-400'}`}>{(currentRisk * 100).toFixed(2)}%</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-300 font-sans">Active Session ID</td>
                        <td className="py-3 px-4 text-slate-400 truncate max-w-xs">{currentScenarioId}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="bg-white/[0.03] border border-white/10 p-6 rounded-2xl backdrop-blur-2xl shadow-xl">
                <h2 className="text-lg font-semibold text-slate-100 font-sans mb-1">Empirical Benchmark: World Model vs Static ML</h2>
                <p className="text-[13px] text-slate-400 font-sans mb-6">Validation across multi-stage kill chains in CIC-IDS2018</p>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-slate-400 font-sans font-medium uppercase tracking-wider text-[11px]">
                        <th className="py-3 px-4">DETECTION ENGINE</th>
                        <th className="py-3 px-4">LEAD-TIME ADVANTAGE</th>
                        <th className="py-3 px-4">F1-SCORE</th>
                        <th className="py-3 px-4">FALSE POSITIVE RATE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-xs">
                      <tr>
                        <td className="py-3 px-4 text-slate-300 font-sans">Logistic Regression Baseline</td>
                        <td className="py-3 px-4 text-slate-400">0.0s (Alerts during exploit)</td>
                        <td className="py-3 px-4 text-slate-400">0.0208</td>
                        <td className="py-3 px-4 text-red-400/80">5.24%</td>
                      </tr>
                      <tr className={`${theme.benchmarkRow} font-semibold transition-colors duration-500`}>
                        <td className="py-3 px-4 flex items-center space-x-2 font-sans">
                          <CheckCircle2 className={`w-3.5 h-3.5 ${theme.primaryText}`} />
                          <span>Latent World Model (Trained)</span>
                        </td>
                        <td className={`py-3 px-4 ${theme.primaryText}`}>+5.0 min (Forward Horizon)</td>
                        <td className="py-3 px-4">0.5837</td>
                        <td className={`py-3 px-4 ${theme.primaryText}`}>2.47%</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
          </ErrorBoundary>
        </div>
      </main>
    </div>
  );
}