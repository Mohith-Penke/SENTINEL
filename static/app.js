/* =========================================================
   SENTINEL — COMPLETE APPLICATION JAVASCRIPT
========================================================= */

"use strict";

/* =========================================================
   HELPERS
========================================================= */

const $ = (id) => document.getElementById(id);

const sleep = (ms) =>
    new Promise(resolve => setTimeout(resolve, ms));

function show(el) {
    if (el) el.classList.remove("hidden");
}

function hide(el) {
    if (el) el.classList.add("hidden");
}

function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
}

function setButtonLoading(button, loading, text = "LOADING...") {
    if (!button) return;

    if (loading) {
        if (!button.dataset.originalText) {
            button.dataset.originalText = button.textContent;
        }

        button.disabled = true;
        button.classList.add("loading");
        button.textContent = text;
    } else {
        button.disabled = false;
        button.classList.remove("loading");

        if (button.dataset.originalText) {
            button.textContent = button.dataset.originalText;
        }
    }
}

/* =========================================================
   TOAST
========================================================= */

function showToast(message, icon = "!") {

    let toast = $("sentinel-toast");

    if (!toast) {

        toast = document.createElement("div");
        toast.id = "sentinel-toast";

        toast.innerHTML = `
            <span class="toast-icon"></span>
            <span class="toast-message"></span>
        `;

        document.body.appendChild(toast);
    }

    const iconEl = toast.querySelector(".toast-icon");
    const messageEl = toast.querySelector(".toast-message");

    if (iconEl) iconEl.textContent = icon;
    if (messageEl) messageEl.textContent = message;

    toast.classList.add("show");

    clearTimeout(window.__sentinelToastTimer);

    window.__sentinelToastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 3200);
}

/* =========================================================
   SAFE HTML
========================================================= */

function escapeHTML(value) {

    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* =========================================================
   API HELPER
========================================================= */

async function postJSON(url, data, timeoutMs = 30000) {

    const controller = new AbortController();

    const timer = setTimeout(() => {
        controller.abort();
    }, timeoutMs);

    try {

        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data),
            signal: controller.signal
        });

        let result;

        try {
            result = await response.json();
        } catch {
            throw new Error("Invalid server response.");
        }

        if (!response.ok) {
            throw new Error(
                result.error ||
                result.message ||
                "Request failed."
            );
        }

        return result;

    } catch (error) {

        if (error.name === "AbortError") {
            throw new Error(
                "Request timed out. Please try again."
            );
        }

        throw error;

    } finally {

        clearTimeout(timer);
    }
}

/* =========================================================
   RISK HELPERS
========================================================= */

function normalizeRiskLevel(level) {

    const value = String(level || "")
        .trim()
        .toUpperCase();

    if (value === "HIGH") return "HIGH";
    if (value === "MEDIUM") return "MEDIUM";
    if (value === "LOW") return "LOW";

    return "UNKNOWN";
}

function getRiskClass(level) {

    const normalized = normalizeRiskLevel(level);

    if (normalized === "HIGH") {
        return "risk-high";
    }

    if (normalized === "MEDIUM") {
        return "risk-medium";
    }

    if (normalized === "LOW") {
        return "risk-low";
    }

    return "risk-unknown";
}

/* =========================================================
   SSL DISPLAY
========================================================= */

function renderSSLDetails(ssl) {

    if (!ssl || typeof ssl !== "object") {
        return `
            <div class="security-check-result">
                SSL check unavailable.
            </div>
        `;
    }

    const valid = ssl.valid === true;
    const https = ssl.https === true;

    const statusClass =
        valid ? "security-safe" : "security-danger";

    const statusText =
        valid
            ? "✓ Certificate valid"
            : "✕ Certificate invalid";

    const rows = [];

    rows.push(`
        <div class="security-detail-row">
            <span>HTTPS</span>
            <strong>${https ? "Enabled" : "Not enabled"}</strong>
        </div>
    `);

    rows.push(`
        <div class="security-detail-row">
            <span>Certificate</span>
            <strong class="${statusClass}">
                ${statusText}
            </strong>
        </div>
    `);

    if (typeof ssl.hostname_match !== "undefined") {

        rows.push(`
            <div class="security-detail-row">
                <span>Hostname match</span>
                <strong>
                    ${ssl.hostname_match ? "Yes" : "No"}
                </strong>
            </div>
        `);
    }

    if (typeof ssl.trusted !== "undefined") {

        rows.push(`
            <div class="security-detail-row">
                <span>Trusted</span>
                <strong>
                    ${ssl.trusted ? "Yes" : "No"}
                </strong>
            </div>
        `);
    }

    if (ssl.issuer) {

        rows.push(`
            <div class="security-detail-row">
                <span>Issuer</span>
                <strong>
                    ${escapeHTML(ssl.issuer)}
                </strong>
            </div>
        `);
    }

    if (ssl.valid_from) {

        rows.push(`
            <div class="security-detail-row">
                <span>Valid from</span>
                <strong>
                    ${escapeHTML(ssl.valid_from)}
                </strong>
            </div>
        `);
    }

    if (ssl.expires_at) {

        rows.push(`
            <div class="security-detail-row">
                <span>Valid until</span>
                <strong>
                    ${escapeHTML(ssl.expires_at)}
                </strong>
            </div>
        `);
    }

    if (
        typeof ssl.days_remaining !== "undefined" &&
        ssl.days_remaining !== null
    ) {

        rows.push(`
            <div class="security-detail-row">
                <span>Days remaining</span>
                <strong>
                    ${escapeHTML(ssl.days_remaining)}
                </strong>
            </div>
        `);
    }

    if (ssl.tls_version) {

        rows.push(`
            <div class="security-detail-row">
                <span>TLS</span>
                <strong>
                    ${escapeHTML(ssl.tls_version)}
                </strong>
            </div>
        `);
    }

    if (ssl.cipher) {

        rows.push(`
            <div class="security-detail-row">
                <span>Cipher</span>
                <strong>
                    ${escapeHTML(ssl.cipher)}
                </strong>
            </div>
        `);
    }

    if (ssl.error) {

        rows.push(`
            <div class="security-detail-row security-error">
                <span>Details</span>
                <strong>
                    ${escapeHTML(ssl.error)}
                </strong>
            </div>
        `);
    }

    return `
        <div class="ssl-security-card">
            <div class="ssl-status ${statusClass}">
                ${statusText}
            </div>

            <div class="security-detail-list">
                ${rows.join("")}
            </div>
        </div>
    `;
}

/* =========================================================
   VISUAL SIMILARITY DISPLAY
========================================================= */

function renderVisualSimilarity(visual) {

    if (!visual || typeof visual !== "object") {

        return `
            <div class="security-check-result">
                Visual similarity check unavailable.
            </div>
        `;
    }

    const checked = visual.checked === true;

    if (!checked) {

        return `
            <div class="visual-security-card">
                <div class="visual-status">
                    Not checked
                </div>

                <div class="visual-reason">
                    ${escapeHTML(
                        visual.reason ||
                        "No comparable legitimate reference was available."
                    )}
                </div>
            </div>
        `;
    }

    const similarity =
        Number(visual.similarity_percent ?? 0);

    const cloning =
        visual.cloning_indicator === true;

    const statusClass =
        cloning
            ? "security-danger"
            : "security-safe";

    const statusText =
        cloning
            ? "⚠ Possible visual cloning detected"
            : "✓ No strong visual cloning detected";

    return `
        <div class="visual-security-card">

            <div class="visual-status ${statusClass}">
                ${statusText}
            </div>

            <div class="visual-score">
                <span>Visual similarity</span>
                <strong>
                    ${escapeHTML(similarity)}%
                </strong>
            </div>

            ${
                visual.reference_brand
                    ? `
                        <div class="security-detail-row">
                            <span>Reference</span>
                            <strong>
                                ${escapeHTML(
                                    visual.reference_brand
                                )}
                            </strong>
                        </div>
                    `
                    : ""
            }

            ${
                visual.reason
                    ? `
                        <div class="visual-reason">
                            ${escapeHTML(visual.reason)}
                        </div>
                    `
                    : ""
            }

        </div>
    `;
}

/* =========================================================
   RISK RESULT RENDERER
========================================================= */

function renderRiskResult(prefix, result) {

    if (!result) {
        showToast("No scan result received.", "!");
        return;
    }

    const container =
        $(`${prefix}-result`);

    if (!container) {
        console.warn(
            `SENTINEL: ${prefix}-result element not found.`
        );
        return;
    }

    const score =
        Number(result.score ?? result.risk_score ?? 0);

    const level =
        normalizeRiskLevel(result.level);

    const riskClass =
        getRiskClass(level);

    const summary =
        result.summary ||
        result.message ||
        "Analysis completed.";

    const reasons =
        Array.isArray(result.reasons)
            ? result.reasons
            : [];

    const actions =
        Array.isArray(result.actions)
            ? result.actions
            : [];

    let html = `
        <div class="risk-result-card ${riskClass}">

            <div class="risk-result-header">

                <div>
                    <div class="risk-result-label">
                        RISK LEVEL
                    </div>

                    <div class="risk-result-level">
                        ${escapeHTML(level)}
                    </div>
                </div>

                <div class="risk-score">
                    <span>Score</span>
                    <strong>
                        ${escapeHTML(score)}/100
                    </strong>
                </div>

            </div>

            <div class="risk-meter">
                <div
                    class="risk-meter-fill"
                    style="width:${Math.max(
                        0,
                        Math.min(100, score)
                    )}%"
                ></div>
            </div>

            <div class="risk-summary">
                ${escapeHTML(summary)}
            </div>
    `;

    if (reasons.length) {

        html += `
            <div class="risk-section">
                <h4>Why SENTINEL flagged it</h4>

                <ul class="risk-list">
                    ${reasons.map(reason => `
                        <li>
                            ${escapeHTML(reason)}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (actions.length) {

        html += `
            <div class="risk-section">
                <h4>Recommended actions</h4>

                <ul class="risk-list action-list">
                    ${actions.map(action => `
                        <li>
                            ${escapeHTML(action)}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    /*
       =====================================================
       ROUND-2 SECURITY CHECKS
       SSL + VISUAL SIMILARITY
       =====================================================
    */

    if (prefix === "website") {

        const ssl =
            result.ssl_check || {};

        const visual =
            result.visual_similarity || {};

        html += `
            <div class="security-checks-result">

                <div class="security-check-item">

                    <p>
                        🔒 SSL / Certificate Security
                    </p>

                    <div
                        id="website-ssl-status"
                        class="security-check-result"
                    >
                        ${renderSSLDetails(ssl)}
                    </div>

                </div>

                <div class="security-check-item">

                    <p>
                        👁️ Visual Similarity / Clone Detection
                    </p>

                    <div
                        id="website-visual-status"
                        class="security-check-result"
                    >
                        ${renderVisualSimilarity(visual)}
                    </div>

                </div>

            </div>
        `;
    }

    html += `
        </div>
    `;

    container.innerHTML = html;

    show(container);

    try {
        container.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });
    } catch {
        // Ignore unsupported scroll behavior.
    }
}

/* =========================================================
   WEBSITE SCANNER
========================================================= */

async function scanWebsite() {

    const input = $("website-url");
    const button = $("scan-website-btn");
    const progress = $("website-progress");

    if (!input || !button) return;

    const url = input.value.trim();

    if (!url) {
        showToast("Enter a website URL first.", "!");
        input.focus();
        return;
    }

    hide($("website-result"));
    show(progress);

    setButtonLoading(
        button,
        true,
        "ANALYZING..."
    );

    const fill =
        $("website-progress-fill");

    const percent =
        $("website-progress-percent");

    try {

        const steps = [
            ["Checking URL structure...", 20],
            ["Checking suspicious indicators...", 40],
            ["Checking SSL certificate...", 60],
            ["Analyzing visual similarity...", 82],
            ["Generating risk report...", 100]
        ];

        for (const [stage, value] of steps) {

            setText(
                "website-stages",
                stage
            );

            if (fill) {
                fill.style.width =
                    `${value}%`;
            }

            if (percent) {
                percent.textContent =
                    `${value}%`;
            }

            await sleep(180);
        }

        const result =
            await postJSON(
                "/scan",
                { url: url },
                30000
            );

        if (!result) {
            throw new Error(
                "No result received from server."
            );
        }

        renderRiskResult(
            "website",
            result
        );

        showToast(
            `Website analysis complete: ${
                result.level || "UNKNOWN"
            }`,
            result.level === "LOW"
                ? "✓"
                : "!"
        );

    } catch (error) {

        console.error(
            "SENTINEL website scan error:",
            error
        );

        showToast(
            error.message ||
            "Website scan failed.",
            "!"
        );

    } finally {

        setButtonLoading(
            button,
            false
        );

        hide(progress);
    }
}

$("scan-website-btn")?.addEventListener(
    "click",
    scanWebsite
);

$("website-url")?.addEventListener(
    "keydown",
    event => {

        if (event.key === "Enter") {

            event.preventDefault();

            scanWebsite();
        }
    }
);
