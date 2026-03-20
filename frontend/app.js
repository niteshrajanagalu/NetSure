import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import htm from "htm";

const html = htm.bind(React.createElement);

const SCAN_ENDPOINT =
  window.location.origin === "http://127.0.0.1:8000"
    ? "http://127.0.0.1:8000/scan"
    : "/scan";

const SCAN_PAYLOAD = {
  cidr: "192.168.1.0/24",
};

const PAGE_TITLE = "NetSure — Network Risk Check";
const SUPPORT_PHONE = "+919799791789";
const SUPPORT_PHONE_LABEL = "+91 9799791789";
const SUPPORT_WHATSAPP_LINK = "https://wa.me/919799791789";
const SUPPORT_EMAIL = "netsure.support@gmail.com";

const RISK_DISPLAY = {
  HIGH: {
    label: "HIGH RISK",
    className: "risk-high",
    headline: "Your network is exposed right now",
    summary: "We observed this behavior on your network during the scan",
  },
  MEDIUM: {
    label: "MEDIUM RISK",
    className: "risk-medium",
    headline: "Your network has some weak points",
    summary: "We found signals that may need attention",
  },
  LOW: {
    label: "LOW RISK",
    className: "risk-low",
    headline: "Your network has some weak points",
    summary: "We found signals that may need attention",
  },
  SAFE: {
    label: "SAFE",
    className: "risk-safe",
    headline: "Your network looks secure — for now",
    summary: "We didn’t find any immediate threats in the areas we checked",
  },
};

function getStatusKey(status) {
  const normalized = String(status || "").toUpperCase();

  if (normalized.includes("HIGH")) {
    return "HIGH";
  }
  if (normalized.includes("MEDIUM")) {
    return "MEDIUM";
  }
  if (normalized.includes("LOW")) {
    return "LOW";
  }
  return "SAFE";
}

function formatPorts(ports) {
  if (!Array.isArray(ports) || ports.length === 0) {
    return "None listed";
  }

  return ports.join(", ");
}

function firstPort(ports) {
  if (!Array.isArray(ports) || ports.length === 0) {
    return null;
  }

  return ports[0];
}

function buildExposureView(scanResult) {
  const exposure = scanResult?.internet_exposure || {};
  const primaryFinding = exposure?.exposed_devices?.[0] || {};
  const exposureLevel = String(exposure?.level || "NONE").toUpperCase();

  if (!exposure?.has_exposure) {
    return null;
  }

  const deviceLabel = primaryFinding?.device_type
    ? `${primaryFinding.device_type}${primaryFinding.device_ip ? ` (${primaryFinding.device_ip})` : ""}`
    : primaryFinding?.device_ip || "A device on your network";

  return {
    level: exposureLevel === "NONE" ? "POSSIBLE" : exposureLevel,
    device: deviceLabel || "A device on your network",
    message:
      primaryFinding?.message ||
      exposure?.summary ||
      "We found signs that a device may be reachable from outside your network.",
    emphasisClass:
      exposureLevel === "CONFIRMED" || exposureLevel === "LIKELY"
        ? "exposure-high"
        : "exposure-medium",
    upnpEnabled: Boolean(exposure?.upnp?.enabled),
  };
}

function buildFindings(scanResult) {
  const devices = scanResult?.details?.devices || [];

  return devices.slice(0, 4).map((device) => ({
    id: device.ip,
    ip: device.ip,
    ports: formatPorts(device.ports),
    primaryPort: firstPort(device.ports),
    services:
      Array.isArray(device.services) && device.services.length > 0
        ? device.services.join(", ")
        : "No named services",
    primaryService:
      Array.isArray(device.services) && device.services.length > 0
        ? device.services[0]
        : null,
    exposure: device.exposure || "LOW",
    issue:
      device?.primary_issue?.title ||
      device?.issues?.[0]?.title ||
      "Network behavior observed",
    behavior: firstPort(device.ports)
      ? `${device.ip} responded on port ${firstPort(device.ports)}`
      : `${device.ip} responded during the scan`,
    concreteSignal:
      firstPort(device.ports) === 80
        ? "Port 80 responded without encryption"
        : firstPort(device.ports) === 23
          ? "Port 23 responded for remote access"
          : firstPort(device.ports) === 554
            ? "Port 554 responded for camera or stream access"
            : firstPort(device.ports) === 443
              ? "Port 443 responded over HTTPS"
              : firstPort(device.ports)
                ? `Port ${firstPort(device.ports)} responded during the scan`
                : "Device responded during the scan",
  }));
}

function buildObservedSignals(scanResult, exposureView, findings) {
  const signals = [];
  const firstFinding = findings[0];

  if (firstFinding?.ports && firstFinding.ports !== "None listed") {
    const leadPort = firstFinding.ports.split(",")[0]?.trim();
    if (leadPort) {
      signals.push(`${firstFinding.ip} responded on port ${leadPort}`);
    }
  }

  if (exposureView?.upnpEnabled) {
    signals.push("UPnP is enabled and can expose devices externally");
  }

  if (firstFinding?.services && firstFinding.services !== "No named services") {
    const firstService = firstFinding.services.split(",")[0]?.trim().toUpperCase();
    if (firstService) {
      signals.push(`${firstService} service was active`);
    }
  }

  if (exposureView?.level && exposureView.level !== "NONE") {
    signals.push(`Internet exposure level ${exposureView.level}`);
  }

  return signals.slice(0, 4);
}

function buildFixSteps(scanResult, findings, exposureView, statusKey) {
  const firstFinding = findings[0];
  const steps = [];

  if (statusKey === "SAFE") {
    return [
      "Keep this network setup unchanged unless you review the security impact first.",
      "Run this check again after device, software, or router setting changes.",
      "Use alerts so you know if anything becomes exposed later.",
    ];
  }

  if (firstFinding?.ip) {
    steps.push(`Log into the device or router at ${firstFinding.ip}.`);
  } else {
    steps.push("Log into your router or the device linked to this finding.");
  }

  if (scanResult?.fix_now?.action) {
    steps.push(scanResult.fix_now.action);
  }

  if (exposureView?.upnpEnabled) {
    steps.push("Disable UPnP so devices cannot quietly open outside access.");
  }

  if (firstFinding?.ports && firstFinding.ports !== "None listed") {
    steps.push(`Close any ports you do not need, especially ${firstFinding.ports}.`);
  }

  steps.push("Run the check again to confirm the exposure is gone.");
  return steps.slice(0, 4);
}

function buildSuccessView(scanResult) {
  const statusKey = getStatusKey(scanResult?.answer?.status);
  const meta = RISK_DISPLAY[statusKey];
  const exposureView = buildExposureView(scanResult);
  const findings = buildFindings(scanResult);
  const observedSignals = buildObservedSignals(scanResult, exposureView, findings);
  const impactPoints =
    statusKey === "HIGH"
      ? [
          "Router login accessible without encryption",
          "Credentials may be intercepted",
        ]
      : statusKey === "SAFE"
        ? [
            "No immediate outside access was detected during this scan",
            "Keep monitoring in case devices or router settings change",
          ]
        : [
            "Weak points were found that deserve attention",
            "Address them now to reduce the chance of outside access",
          ];

  return {
    statusKey,
    badge: meta,
    headline: meta.headline,
    summary: meta.summary,
    impact:
      scanResult?.impact ||
      "We found activity that deserves review so this network stays protected.",
    timeEstimate:
      statusKey === "HIGH" ? "5 minutes" : scanResult?.fix_now?.time || "15 minutes",
    findings,
    exposureView,
    observedSignals,
    impactPoints,
    steps: buildFixSteps(scanResult, findings, exposureView, statusKey),
  };
}

function formatRelativeScanTime(scanCompletedAt, nowMs) {
  const elapsedSeconds = Math.max(
    0,
    Math.floor((nowMs - scanCompletedAt) / 1000)
  );

  if (elapsedSeconds < 10) {
    return "just now";
  }
  if (elapsedSeconds < 60) {
    return `${elapsedSeconds} seconds ago`;
  }

  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  if (elapsedMinutes < 60) {
    return `${elapsedMinutes} minute${elapsedMinutes === 1 ? "" : "s"} ago`;
  }

  const elapsedHours = Math.floor(elapsedMinutes / 60);
  return `${elapsedHours} hour${elapsedHours === 1 ? "" : "s"} ago`;
}

function getHeaderMetadata(phase, scanCompletedAt, nowMs) {
  if (phase === "loading") {
    return "Scanning…";
  }

  if (phase === "error") {
    return "Last scan: failed";
  }

  if (phase === "success" && scanCompletedAt) {
    return `Last scan: ${formatRelativeScanTime(scanCompletedAt, nowMs)}`;
  }

  return "Local network";
}

function TopBar({ metadata }) {
  return html`
    <header className="top-bar">
      <div className="top-bar__left">NetSure</div>
      <div className="top-bar__center">Network Risk Check</div>
      <div className="top-bar__right">${metadata}</div>
    </header>
  `;
}

function ContactActions() {
  return html`
    <div className="contact-actions">
      <a
        className="secondary-button contact-link contact-link--whatsapp"
        href=${`${SUPPORT_WHATSAPP_LINK}?text=I%20need%20help%20with%20my%20NetSure%20network%20risk%20check`}
        target="_blank"
        rel="noreferrer"
      >
        WhatsApp
      </a>
      <a
        className="secondary-button contact-link contact-link--call"
        href=${`tel:${SUPPORT_PHONE}`}
      >
        Call Now
      </a>
      <a
        className="secondary-button contact-link contact-link--email"
        href=${`mailto:${SUPPORT_EMAIL}`}
      >
        Email Support
      </a>
    </div>
  `;
}

function InitialView({ onScan }) {
  return html`
    <section className="hero-panel hero-panel--landing">
      <div className="hero-copy">
        <p className="eyebrow">Network Security Check</p>
        <h1>Can someone access your network right now?</h1>
        <p className="support-copy">
          A quick check to see if your WiFi is exposing anything it shouldn’t.
        </p>
        <button className="primary-button hero-button" onClick=${onScan}>
          Check My Network
        </button>
      </div>
    </section>
  `;
}

function LoadingView() {
  return html`
    <section className="hero-panel">
      <div className="loader-row">
        <div className="loader" aria-hidden="true"></div>
        <div className="loader-copy">
          <p className="eyebrow">Running Check</p>
          <h1>Checking your network exposure...</h1>
          <p className="support-copy">This takes a few seconds</p>
        </div>
      </div>
    </section>
  `;
}

function ErrorView({ onRetry }) {
  return html`
    <section className="hero-panel">
      <p className="eyebrow">Network Risk Check</p>
      <h1>We couldn’t complete the check automatically</h1>
      <p className="support-copy">Scan could not complete. Please try again.</p>
      <div className="contact-card">
        <div className="action-stack">
          <button className="primary-button hero-button" onClick=${onRetry}>
            Try Again
          </button>
          <p className="assist-line">
            Need help? We can walk through the check with you right away.
          </p>
          <${ContactActions} />
        </div>
      </div>
    </section>
  `;
}

function ResultView({ view }) {
  return html`
    <section className="results-grid">
      <div className=${`panel panel-findings ${view.badge.className}-panel`}>
        <div className="result-intro">
          <div className="panel-head">
            <span className=${`status-badge ${view.badge.className}`}>
              ${view.badge.label}
            </span>
          </div>

          <h1 className="result-headline">${view.headline}</h1>
          <p className="confidence-tag">${view.summary}</p>
          <p className="proof-line">
            This result is based on a real scan of your network — not a
            simulation.
          </p>
        </div>

        <div className="section-card">
          <p className="section-label">What this means</p>
          <div className="impact-lines">
            ${view.impactPoints.map(
              (point) => html`<p className="section-copy impact-line">${point}</p>`
            )}
          </div>
        </div>

        <div className="section-card">
          <p className="section-label">Findings</p>
          <div className="finding-list">
            ${view.findings.length > 0
              ? view.findings.map(
                  (finding) => html`
                    <article className="finding-item">
                      <div className="finding-top">
                        <strong>${finding.ip}</strong>
                        <span className="finding-chip">${finding.exposure}</span>
                      </div>
                      <p className="finding-copy">
                        <span>Ports:</span> ${finding.ports}
                      </p>
                      <p className="finding-copy">
                        <span>Key issue:</span> ${finding.concreteSignal}
                      </p>
                    </article>
                  `
                )
              : html`
                  <p className="section-copy">
                    We did not receive device-level findings from this scan.
                  </p>
                `}
          </div>
        </div>

        ${view.exposureView
          ? html`
              <div className=${`section-card exposure-card ${view.exposureView.emphasisClass}`}>
                <p className="section-label">Internet Exposure Detected</p>
                <div className="exposure-grid">
                  <div className="exposure-meta">
                    <span className="detail-label">Exposure level</span>
                    <strong>${view.exposureView.level}</strong>
                  </div>
                  <div className="exposure-meta">
                    <span className="detail-label">Exposed device</span>
                    <strong>${view.exposureView.device}</strong>
                  </div>
                </div>
                <p className="section-copy">${view.exposureView.message}</p>
              </div>
            `
          : null}

        <div className="section-card">
          <p className="section-label">What we saw on your network</p>
          <ul className="signal-list">
            ${view.observedSignals.length > 0
              ? view.observedSignals.map((signal) => html`<li>${signal}</li>`)
              : html`<li>Direct device activity was confirmed during the scan</li>`}
          </ul>
        </div>
      </div>

      <aside className=${`panel panel-actions ${view.badge.className}-panel`}>
        <div className="action-card">
          <p className="section-label">${`How to fix this (takes ~${view.timeEstimate})`}</p>
          <ol className="steps-list">
            ${view.steps.map((step) => html`<li>${step}</li>`)}
          </ol>
        </div>

        <div className="panel-divider" aria-hidden="true"></div>

        <div className="contact-card contact-card--balanced">
          <div className="assist-copy">
            <p className="assist-title">Need help fixing this?</p>
            <p className="assist-line">
              I can secure your network remotely in ~20 minutes.
            </p>
          </div>
          <${ContactActions} />
        </div>
      </aside>
    </section>
  `;
}

function App() {
  const [phase, setPhase] = useState("initial");
  const [result, setResult] = useState(null);
  const [scanCompletedAt, setScanCompletedAt] = useState(null);
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    document.title = PAGE_TITLE;
  }, []);

  useEffect(() => {
    if (phase !== "success" || !scanCompletedAt) {
      return undefined;
    }

    const intervalId = window.setInterval(() => {
      setNowMs(Date.now());
    }, 5000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [phase, scanCompletedAt]);

  async function runScan() {
    setPhase("loading");

    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => {
      controller.abort();
    }, 15000);

    try {
      const response = await fetch(SCAN_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(SCAN_PAYLOAD),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error("Scan unavailable");
      }

      const payload = await response.json();
      setScanCompletedAt(Date.now());
      setNowMs(Date.now());
      setResult(payload);
      setPhase("success");
    } catch (error) {
      setResult(null);
      setPhase("error");
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  const successView =
    phase === "success" && result ? buildSuccessView(result) : null;
  const headerMetadata = getHeaderMetadata(phase, scanCompletedAt, nowMs);

  return html`
    <main className="page-shell">
      <div className="page-frame">
        <${TopBar} metadata=${headerMetadata} />

        ${phase === "initial" ? html`<${InitialView} onScan=${runScan} />` : null}
        ${phase === "loading" ? html`<${LoadingView} />` : null}
        ${phase === "error" ? html`<${ErrorView} onRetry=${runScan} />` : null}
        ${phase === "success" && successView
          ? html`<${ResultView} view=${successView} />`
          : null}
      </div>
    </main>
  `;
}

createRoot(document.getElementById("root")).render(html`<${App} />`);
