/* =========================================================
   SENTINEL — COMPLETE APPLICATION JAVASCRIPT
   FULL REPLACEMENT VERSION
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

    if (
        value === "HIGH" ||
        value === "CRITICAL"
    ) {
        return "HIGH";
    }

    if (
        value === "MEDIUM" ||
        value === "MEDIUM-TO-HIGH" ||
        value === "MEDIUM_TO_HIGH" ||
        value === "MEDIUM HIGH"
    ) {
        return "MEDIUM";
    }

    if (value === "LOW") {
        return "LOW";
    }

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
   DANGER SOUND
========================================================= */

let sentinelAudioContext = null;

function playDangerSound() {
    try {
        const AudioContext =
            window.AudioContext ||
            window.webkitAudioContext;

        if (!AudioContext) return;

        if (!sentinelAudioContext) {
            sentinelAudioContext = new AudioContext();
        }

        const ctx = sentinelAudioContext;

        if (ctx.state === "suspended") {
            ctx.resume().catch(() => {});
        }

        const oscillator = ctx.createOscillator();
        const gain = ctx.createGain();

        oscillator.type = "sawtooth";
        oscillator.frequency.setValueAtTime(
            440,
            ctx.currentTime
        );

        oscillator.frequency.exponentialRampToValueAtTime(
            180,
            ctx.currentTime + 0.45
        );

        gain.gain.setValueAtTime(
            0.0001,
            ctx.currentTime
        );

        gain.gain.exponentialRampToValueAtTime(
            0.12,
            ctx.currentTime + 0.03
        );

        gain.gain.exponentialRampToValueAtTime(
            0.0001,
            ctx.currentTime + 0.5
        );

        oscillator.connect(gain);
        gain.connect(ctx.destination);

        oscillator.start();
        oscillator.stop(ctx.currentTime + 0.5);

    } catch (error) {
        console.warn(
            "SENTINEL danger sound unavailable:",
            error
        );
    }
}

function playSuccessSound() {
    try {
        const AudioContext =
            window.AudioContext ||
            window.webkitAudioContext;

        if (!AudioContext) return;

        if (!sentinelAudioContext) {
            sentinelAudioContext = new AudioContext();
        }

        const ctx = sentinelAudioContext;

        if (ctx.state === "suspended") {
            ctx.resume().catch(() => {});
        }

        const oscillator = ctx.createOscillator();
        const gain = ctx.createGain();

        oscillator.type = "sine";

        oscillator.frequency.setValueAtTime(
            520,
            ctx.currentTime
        );

        oscillator.frequency.exponentialRampToValueAtTime(
            760,
            ctx.currentTime + 0.16
        );

        gain.gain.setValueAtTime(
            0.0001,
            ctx.currentTime
        );

        gain.gain.exponentialRampToValueAtTime(
            0.08,
            ctx.currentTime + 0.02
        );

        gain.gain.exponentialRampToValueAtTime(
            0.0001,
            ctx.currentTime + 0.22
        );

        oscillator.connect(gain);
        gain.connect(ctx.destination);

        oscillator.start();
        oscillator.stop(ctx.currentTime + 0.22);

    } catch (error) {
        console.warn(
            "SENTINEL success sound unavailable:",
            error
        );
    }
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
        valid
            ? "security-safe"
            : "security-danger";

    const statusText =
        valid
            ? "✓ Certificate valid"
            : "✕ Certificate invalid";

    const rows = [];

    rows.push(`
        <div class="security-detail-row">
            <span>HTTPS</span>
            <strong>
                ${https ? "Enabled" : "Not enabled"}
            </strong>
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
        showToast(
            "No scan result received.",
            "!"
        );

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
        Number(
            result.score ??
            result.risk_score ??
            0
        );

    const safeScore =
        Math.max(
            0,
            Math.min(
                100,
                Number.isFinite(score)
                    ? score
                    : 0
            )
        );

    const level =
        normalizeRiskLevel(
            result.level ||
            result.risk_level ||
            result.risk
        );

    const riskClass =
        getRiskClass(level);

    const summary =
        result.summary ||
        result.message ||
        result.description ||
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
                        ${escapeHTML(safeScore)}/100
                    </strong>
                </div>

            </div>

            <div class="risk-meter">
                <div
                    class="risk-meter-fill"
                    style="width:${safeScore}%"
                ></div>
            </div>

            <div class="risk-summary">
                ${escapeHTML(summary)}
            </div>
    `;

    if (reasons.length) {
        html += `
            <div class="risk-section">

                <h4>
                    Why SENTINEL flagged it
                </h4>

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

                <h4>
                    Recommended actions
                </h4>

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

    /* =====================================================
       ROUND-2 SECURITY CHECKS
       SSL + VISUAL SIMILARITY
    ===================================================== */

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

    if (level === "HIGH") {
        playDangerSound();
    } else if (level === "LOW") {
        playSuccessSound();
    }

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
    const input =
        $("website-url");

    const button =
        $("scan-website-btn");

    const progress =
        $("website-progress");

    if (!input || !button) return;

    const url =
        input.value.trim();

    if (!url) {
        showToast(
            "Enter a website URL first.",
            "!"
        );

        input.focus();

        return;
    }

    hide(
        $("website-result")
    );

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
            [
                "Checking URL structure...",
                20
            ],
            [
                "Checking suspicious indicators...",
                40
            ],
            [
                "Checking SSL certificate...",
                60
            ],
            [
                "Analyzing visual similarity...",
                82
            ],
            [
                "Generating risk report...",
                100
            ]
        ];

        for (
            const [stage, value]
            of steps
        ) {
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
                {
                    url: url
                },
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

        const normalized =
            normalizeRiskLevel(
                result.level ||
                result.risk_level
            );

        showToast(
            `Website analysis complete: ${
                result.level || "UNKNOWN"
            }`,
            normalized === "LOW"
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

/* =========================================================
   MESSAGE SCANNER
========================================================= */

async function scanMessage() {
    const input =
        $("message-input") ||
        $("message-text");

    const button =
        $("scan-message-btn");

    const resultBox =
        $("message-result");

    if (!input || !button) return;

    const message =
        input.value.trim();

    if (!message) {
        showToast(
            "Enter a message first.",
            "!"
        );

        input.focus();

        return;
    }

    hide(resultBox);

    setButtonLoading(
        button,
        true,
        "ANALYZING..."
    );

    try {
        const result =
            await postJSON(
                "/scan-message",
                {
                    message: message
                },
                20000
            );

        if (!result) {
            throw new Error(
                "No result received from server."
            );
        }

        renderRiskResult(
            "message",
            result
        );

        const normalized =
            normalizeRiskLevel(
                result.level ||
                result.risk_level
            );

        showToast(
            `Message analysis complete: ${
                result.level || "UNKNOWN"
            }`,
            normalized === "LOW"
                ? "✓"
                : "!"
        );

    } catch (error) {
        console.error(
            "SENTINEL message scan error:",
            error
        );

        showToast(
            error.message ||
            "Message scan failed.",
            "!"
        );

    } finally {
        setButtonLoading(
            button,
            false
        );
    }
}

$("scan-message-btn")?.addEventListener(
    "click",
    scanMessage
);

/* =========================================================
   SOCIAL PROFILE ANALYZER
========================================================= */

async function analyzeSocialProfile() {
    const input =
        $("social-profile-url");

    const button =
        $("analyze-social-btn");

    const progress =
        $("social-progress");

    if (!input || !button) return;

    const url =
        input.value.trim();

    if (!url) {
        showToast(
            "Enter a social profile URL first.",
            "!"
        );

        input.focus();

        return;
    }

    hide(
        $("social-result")
    );

    show(progress);

    setButtonLoading(
        button,
        true,
        "ANALYZING..."
    );

    try {
        const steps = [
            [
                "Validating profile URL...",
                25
            ],
            [
                "Processing screenshot...",
                50
            ],
            [
                "Analyzing profile indicators...",
                75
            ],
            [
                "Generating risk report...",
                100
            ]
        ];

        const fill =
            $("social-progress-fill");

        const percent =
            $("social-progress-percent");

        for (
            const [stage, value]
            of steps
        ) {
            setText(
                "social-stages",
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

            await sleep(220);
        }

        const result =
            await postJSON(
                "/analyze-social",
                {
                    url: url
                },
                30000
            );

        if (!result) {
            throw new Error(
                "No result received from server."
            );
        }

        renderRiskResult(
            "social",
            result
        );

        showToast(
            `Social analysis complete: ${
                result.level || "UNKNOWN"
            }`,
            normalizeRiskLevel(
                result.level
            ) === "LOW"
                ? "✓"
                : "!"
        );

    } catch (error) {
        console.error(
            "SENTINEL social analysis error:",
            error
        );

        showToast(
            error.message ||
            "Social profile analysis failed.",
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

$("analyze-social-btn")?.addEventListener(
    "click",
    analyzeSocialProfile
);

$("social-profile-url")?.addEventListener(
    "keydown",
    event => {
        if (event.key === "Enter") {
            event.preventDefault();
            analyzeSocialProfile();
        }
    }
);

/* =========================================================
   SOCIAL SCREENSHOT ANALYZER
========================================================= */

async function analyzeSocialScreenshot() {
    const fileInput =
        $("social-screenshot");

    const button =
        $("social-screenshot-btn");

    if (!fileInput || !button) return;

    const file =
        fileInput.files?.[0];

    if (!file) {
        showToast(
            "Select a screenshot first.",
            "!"
        );

        return;
    }

    setButtonLoading(
        button,
        true,
        "PROCESSING..."
    );

    try {
        const formData =
            new FormData();

        formData.append(
            "screenshot",
            file
        );

        const response =
            await fetch(
                "/analyze-social-screenshot",
                {
                    method: "POST",
                    body: formData
                }
            );

        let result;

        try {
            result =
                await response.json();
        } catch {
            throw new Error(
                "Invalid server response."
            );
        }

        if (!response.ok) {
            throw new Error(
                result.error ||
                result.message ||
                "Screenshot analysis failed."
            );
        }

        renderRiskResult(
            "social",
            result
        );

        showToast(
            "Screenshot analysis complete.",
            normalizeRiskLevel(
                result.level
            ) === "LOW"
                ? "✓"
                : "!"
        );

    } catch (error) {
        console.error(
            "SENTINEL screenshot error:",
            error
        );

        showToast(
            error.message ||
            "Screenshot analysis failed.",
            "!"
        );

    } finally {
        setButtonLoading(
            button,
            false
        );
    }
}

/* =========================================================
   FILE INPUT PREVIEW
========================================================= */

$("social-screenshot")?.addEventListener(
    "change",
    event => {
        const file =
            event.target.files?.[0];

        if (!file) return;

        const allowed = [
            "image/png",
            "image/jpeg",
            "image/webp"
        ];

        if (
            file.type &&
            !allowed.includes(file.type)
        ) {
            showToast(
                "Please select a PNG, JPG or WEBP image.",
                "!"
            );

            event.target.value = "";

            return;
        }

        const maxSize =
            10 * 1024 * 1024;

        if (file.size > maxSize) {
            showToast(
                "Image is too large. Maximum size is 10 MB.",
                "!"
            );

            event.target.value = "";

            return;
        }

        showToast(
            `Screenshot selected: ${file.name}`,
            "✓"
        );
    }
);

$("social-screenshot-btn")?.addEventListener(
    "click",
    analyzeSocialScreenshot
);

/* =========================================================
   SAMPLE URL BUTTONS
========================================================= */

function fillWebsiteURL(url) {
    const input =
        $("website-url");

    if (!input) return;

    input.value = url;

    input.focus();

    showToast(
        "Sample URL loaded.",
        "✓"
    );
}

document
    .querySelectorAll(
        "[data-sample-url]"
    )
    .forEach(button => {
        button.addEventListener(
            "click",
            () => {
                fillWebsiteURL(
                    button.dataset.sampleUrl
                );
            }
        );
    });

/* =========================================================
   COPY RESULT
========================================================= */

function copyText(text) {
    if (!text) return;

    if (
        navigator.clipboard &&
        navigator.clipboard.writeText
    ) {
        navigator.clipboard
            .writeText(text)
            .then(() => {
                showToast(
                    "Copied to clipboard.",
                    "✓"
                );
            })
            .catch(() => {
                showToast(
                    "Unable to copy.",
                    "!"
                );
            });

        return;
    }

    const textarea =
        document.createElement("textarea");

    textarea.value = text;

    textarea.style.position =
        "fixed";

    textarea.style.opacity =
        "0";

    document.body.appendChild(
        textarea
    );

    textarea.select();

    try {
        document.execCommand("copy");

        showToast(
            "Copied to clipboard.",
            "✓"
        );

    } catch {
        showToast(
            "Unable to copy.",
            "!"
        );
    }

    textarea.remove();
}

document
    .querySelectorAll(
        "[data-copy]"
    )
    .forEach(button => {
        button.addEventListener(
            "click",
            () => {
                copyText(
                    button.dataset.copy
                );
            }
        );
    });

/* =========================================================
   NAVIGATION
========================================================= */

document
    .querySelectorAll(
        "[data-section]"
    )
    .forEach(link => {
        link.addEventListener(
            "click",
            event => {
                const targetId =
                    link.dataset.section;

                const target =
                    $(targetId);

                if (!target) return;

                event.preventDefault();

                target.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });
            }
        );
    });

/* =========================================================
   MOBILE MENU
========================================================= */

const menuButton =
    $("menu-toggle");

const mobileMenu =
    $("mobile-menu");

menuButton?.addEventListener(
    "click",
    () => {
        if (!mobileMenu) return;

        mobileMenu.classList.toggle(
            "open"
        );

        menuButton.classList.toggle(
            "active"
        );
    }
);

document
    .querySelectorAll(
        "#mobile-menu a"
    )
    .forEach(link => {
        link.addEventListener(
            "click",
            () => {
                mobileMenu?.classList.remove(
                    "open"
                );

                menuButton?.classList.remove(
                    "active"
                );
            }
        );
    });

/* =========================================================
   CYBER GAME / QUIZ
========================================================= */

let quizQuestions = [];
let currentQuizIndex = 0;
let quizScore = 0;
let quizAnswered = false;

async function loadQuiz() {
    try {
        const response =
            await fetch(
                "/quiz",
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {
            throw new Error(
                "Quiz unavailable."
            );
        }

        const data =
            await response.json();

        if (Array.isArray(data)) {
            quizQuestions = data;
        } else if (
            Array.isArray(data.questions)
        ) {
            quizQuestions =
                data.questions;
        } else {
            quizQuestions = [];
        }

        currentQuizIndex = 0;
        quizScore = 0;
        quizAnswered = false;

        renderQuiz();

    } catch (error) {
        console.error(
            "SENTINEL quiz error:",
            error
        );

        showToast(
            "Cyber game is currently unavailable.",
            "!"
        );
    }
}

function renderQuiz() {
    const questionBox =
        $("quiz-question");

    const optionsBox =
        $("quiz-options");

    const scoreBox =
        $("quiz-score");

    if (
        !questionBox ||
        !optionsBox
    ) {
        return;
    }

    if (!quizQuestions.length) {
        questionBox.textContent =
            "No quiz questions available.";

        optionsBox.innerHTML = "";

        return;
    }

    if (
        currentQuizIndex >=
        quizQuestions.length
    ) {
        questionBox.textContent =
            "Quiz complete!";

        optionsBox.innerHTML = `
            <div class="quiz-final-score">
                Final score:
                <strong>
                    ${quizScore}
                </strong>
                /
                ${quizQuestions.length}
            </div>
        `;

        if (scoreBox) {
            scoreBox.textContent =
                quizScore;
        }

        return;
    }

    const question =
        quizQuestions[
            currentQuizIndex
        ];

    quizAnswered = false;

    questionBox.textContent =
        question.question ||
        question.text ||
        "Question";

    const options =
        Array.isArray(question.options)
            ? question.options
            : [];

    optionsBox.innerHTML =
        options.map(
            (option, index) => `
                <button
                    type="button"
                    class="quiz-option"
                    data-quiz-index="${index}"
                >
                    ${escapeHTML(option)}
                </button>
            `
        ).join("");

    optionsBox
        .querySelectorAll(
            ".quiz-option"
        )
        .forEach(button => {
            button.addEventListener(
                "click",
                () => {
                    answerQuiz(
                        Number(
                            button.dataset.quizIndex
                        )
                    );
                }
            );
        });

    if (scoreBox) {
        scoreBox.textContent =
            quizScore;
    }
}

function answerQuiz(index) {
    if (quizAnswered) return;

    const question =
        quizQuestions[
            currentQuizIndex
        ];

    if (!question) return;

    quizAnswered = true;

    let correct =
        question.correct_answer ??
        question.correct ??
        question.answer;

    if (
        typeof correct === "string" &&
        !/^\d+$/.test(correct)
    ) {
        const options =
            Array.isArray(question.options)
                ? question.options
                : [];

        const found =
            options.findIndex(
                option =>
                    String(option)
                        .trim()
                        .toLowerCase() ===
                    correct
                        .trim()
                        .toLowerCase()
            );

        correct = found;
    }

    correct =
        Number(correct);

    const optionButtons =
        document.querySelectorAll(
            ".quiz-option"
        );

    optionButtons.forEach(
        button => {
            button.disabled = true;
        }
    );

    if (index === correct) {
        quizScore++;

        const selected =
            document.querySelector(
                `[data-quiz-index="${index}"]`
            );

        selected?.classList.add(
            "correct"
        );

        playSuccessSound();

        showToast(
            "Correct! Good cyber awareness.",
            "✓"
        );

    } else {
        const selected =
            document.querySelector(
                `[data-quiz-index="${index}"]`
            );

        selected?.classList.add(
            "wrong"
        );

        const correctButton =
            document.querySelector(
                `[data-quiz-index="${correct}"]`
            );

        correctButton?.classList.add(
            "correct"
        );

        playDangerSound();

        showToast(
            "Wrong answer. Stay alert online!",
            "!"
        );
    }

    const scoreBox =
        $("quiz-score");

    if (scoreBox) {
        scoreBox.textContent =
            quizScore;
    }

    setTimeout(
        () => {
            currentQuizIndex++;
            renderQuiz();
        },
        900
    );
}

$("start-quiz-btn")?.addEventListener(
    "click",
    loadQuiz
);

$("quiz-start")?.addEventListener(
    "click",
    loadQuiz
);

/* =========================================================
   CYBER AI COPILOT
========================================================= */

function getAIElements() {
    return {
        input:
            $("ai-input") ||
            $("chat-input"),

        button:
            $("ai-send-btn") ||
            $("send-ai-btn"),

        messages:
            $("ai-chat-messages") ||
            $("chat-messages")
    };
}

async function sendAIMessage() {
    const {
        input,
        button,
        messages
    } = getAIElements();

    if (!input) return;

    const message =
        input.value.trim();

    if (!message) {
        input.focus();
        return;
    }

    if (button) {
        setButtonLoading(
            button,
            true,
            "THINKING..."
        );
    }

    appendAIMessage(
        messages,
        message,
        "user"
    );

    input.value = "";

    try {
        /*
         * Primary SENTINEL AI endpoint.
         */
        const result =
            await postJSON(
                "/api/ai-chat",
                {
                    message: message
                },
                20000
            );

        const reply =
            result?.reply ||
            result?.response ||
            result?.message ||
            result?.answer;

        if (!reply) {
            throw new Error(
                "AI returned an empty response."
            );
        }

        appendAIMessage(
            messages,
            reply,
            "ai"
        );

    } catch (error) {
        console.error(
            "SENTINEL AI error:",
            error
        );

        /*
         * Do not break the AI popup if the backend
         * endpoint is unavailable.
         */
        appendAIMessage(
            messages,
            "Cyber AI is temporarily unavailable. Please try again.",
            "ai"
        );

    } finally {
        if (button) {
            setButtonLoading(
                button,
                false
            );
        }
    }
}

function appendAIMessage(
    container,
    text,
    type
) {
    if (!container) return;

    const message =
        document.createElement("div");

    message.className =
        `ai-message ${type}`;

    message.textContent =
        String(text ?? "");

    container.appendChild(
        message
    );

    container.scrollTop =
        container.scrollHeight;
}

/* =========================================================
   AI SEND BUTTONS
========================================================= */

$("ai-send-btn")?.addEventListener(
    "click",
    sendAIMessage
);

$("send-ai-btn")?.addEventListener(
    "click",
    sendAIMessage
);

$("ai-input")?.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Enter" &&
            !event.shiftKey
        ) {
            event.preventDefault();
            sendAIMessage();
        }
    }
);

$("chat-input")?.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Enter" &&
            !event.shiftKey
        ) {
            event.preventDefault();
            sendAIMessage();
        }
    }
);

/* =========================================================
   AI BALL / CHAT POPUP
========================================================= */

const aiBall =
    $("ai-ball");

const aiPopup =
    $("ai-chat-popup");

function toggleAIChat() {
    if (!aiPopup) return;

    const isOpen =
        aiPopup.classList.contains("open") ||
        aiPopup.classList.contains("show");

    if (isOpen) {
        aiPopup.classList.remove(
            "open",
            "show"
        );

        return;
    }

    aiPopup.classList.add(
        "open",
        "show"
    );

    const input =
        $("ai-input") ||
        $("chat-input");

    setTimeout(
        () => input?.focus(),
        100
    );
}

aiBall?.addEventListener(
    "click",
    toggleAIChat
);

$("ai-close")?.addEventListener(
    "click",
    () => {
        aiPopup?.classList.remove(
            "open",
            "show"
        );
    }
);

$("close-ai-chat")?.addEventListener(
    "click",
    () => {
        aiPopup?.classList.remove(
            "open",
            "show"
        );
    }
);

/* =========================================================
   AWARENESS SEARCH
========================================================= */

function filterAwareness() {
    const input =
        $("awareness-search");

    if (!input) return;

    const query =
        input.value
            .trim()
            .toLowerCase();

    const cards =
        document.querySelectorAll(
            "[data-awareness]"
        );

    cards.forEach(card => {
        const text =
            card.textContent
                .toLowerCase();

        card.style.display =
            !query ||
            text.includes(query)
                ? ""
                : "none";
    });
}

$("awareness-search")?.addEventListener(
    "input",
    filterAwareness
);

/* =========================================================
   DASHBOARD COUNTERS
========================================================= */

function animateCounter(
    element,
    target
) {
    if (!element) return;

    const numericTarget =
        Number(target) || 0;

    const duration =
        900;

    const startTime =
        performance.now();

    function update(now) {
        const progress =
            Math.min(
                1,
                (now - startTime) /
                duration
            );

        const eased =
            1 -
            Math.pow(
                1 - progress,
                3
            );

        const value =
            Math.round(
                numericTarget * eased
            );

        element.textContent =
            value.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(
                update
            );
        }
    }

    requestAnimationFrame(
        update
    );
}

function updateDashboard(data) {
    if (!data) return;

    const scans =
        data.scans ??
        data.total_scans;

    const threats =
        data.threats ??
        data.threats_detected;

    const safe =
        data.safe ??
        data.safe_scans;

    if (scans !== undefined) {
        animateCounter(
            $("dashboard-scans"),
            scans
        );
    }

    if (threats !== undefined) {
        animateCounter(
            $("dashboard-threats"),
            threats
        );
    }

    if (safe !== undefined) {
        animateCounter(
            $("dashboard-safe"),
            safe
        );
    }
}

/* =========================================================
   DASHBOARD LOAD
========================================================= */

async function loadDashboard() {
    try {
        const response =
            await fetch(
                "/dashboard",
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {
            return;
        }

        const data =
            await response.json();

        updateDashboard(
            data
        );

    } catch (error) {
        console.warn(
            "Dashboard data unavailable:",
            error
        );
    }
}

/* =========================================================
   SYSTEM STATUS
========================================================= */

async function checkSystemStatus() {
    const status =
        $("system-status");

    if (!status) return;

    try {
        const response =
            await fetch(
                "/health",
                {
                    method: "GET",
                    cache: "no-store"
                }
            );

        if (response.ok) {
            status.textContent =
                "SYSTEM ONLINE";

            status.classList.add(
                "online"
            );

            status.classList.remove(
                "offline"
            );

        } else {
            throw new Error(
                "Health check failed"
            );
        }

    } catch {
        status.textContent =
            "SYSTEM OFFLINE";

        status.classList.add(
            "offline"
        );

        status.classList.remove(
            "online"
        );
    }
}

/* =========================================================
   NATIONAL CYBER CRIME HELPLINE
========================================================= */

function callCyberCrimeHelpline() {
    window.location.href =
        "tel:1930";
}

$("cyber-crime-call")?.addEventListener(
    "click",
    callCyberCrimeHelpline
);

$("call-cyber-crime")?.addEventListener(
    "click",
    callCyberCrimeHelpline
);

/* =========================================================
   EXTERNAL LINK SAFETY
========================================================= */

document
    .querySelectorAll(
        'a[target="_blank"]'
    )
    .forEach(link => {
        const rel =
            link.getAttribute("rel") ||
            "";

        if (
            !rel.includes("noopener")
        ) {
            link.setAttribute(
                "rel",
                `${rel} noopener noreferrer`
                    .trim()
            );
        }
    });

/* =========================================================
   SCROLL REVEAL
========================================================= */

function initRevealAnimations() {
    const elements =
        document.querySelectorAll(
            ".reveal, [data-reveal]"
        );

    if (!elements.length) return;

    if (
        !("IntersectionObserver" in window)
    ) {
        elements.forEach(
            element => {
                element.classList.add(
                    "visible"
                );
            }
        );

        return;
    }

    const observer =
        new IntersectionObserver(
            entries => {
                entries.forEach(
                    entry => {
                        if (
                            entry.isIntersecting
                        ) {
                            entry.target.classList.add(
                                "visible"
                            );

                            observer.unobserve(
                                entry.target
                            );
                        }
                    }
                );
            },
            {
                threshold: 0.12
            }
        );

    elements.forEach(
        element =>
            observer.observe(element)
    );
}

/* =========================================================
   ACTIVE NAVIGATION
========================================================= */

function initActiveNavigation() {
    const sections =
        document.querySelectorAll(
            "section[id]"
        );

    const links =
        document.querySelectorAll(
            'a[href^="#"]'
        );

    if (
        !sections.length ||
        !links.length
    ) {
        return;
    }

    if (
        !("IntersectionObserver" in window)
    ) {
        return;
    }

    const observer =
        new IntersectionObserver(
            entries => {
                entries.forEach(
                    entry => {
                        if (
                            !entry.isIntersecting
                        ) {
                            return;
                        }

                        const id =
                            entry.target.id;

                        links.forEach(
                            link => {
                                const active =
                                    link.getAttribute(
                                        "href"
                                    ) ===
                                    `#${id}`;

                                link.classList.toggle(
                                    "active",
                                    active
                                );
                            }
                        );
                    }
                );
            },
            {
                rootMargin:
                    "-35% 0px -55% 0px"
            }
        );

    sections.forEach(
        section =>
            observer.observe(section)
    );
}

/* =========================================================
   BACK TO TOP
========================================================= */

function initBackToTop() {
    const button =
        $("back-to-top");

    if (!button) return;

    window.addEventListener(
        "scroll",
        () => {
            button.classList.toggle(
                "show",
                window.scrollY > 500
            );
        },
        {
            passive: true
        }
    );

    button.addEventListener(
        "click",
        () => {
            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });
        }
    );
}

/* =========================================================
   PAGE INITIALIZATION
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {
        console.log(
            "SENTINEL frontend initialized."
        );

        initRevealAnimations();

        initActiveNavigation();

        initBackToTop();

        checkSystemStatus();

        loadDashboard();

        const websiteProgress =
            $("website-progress");

        if (websiteProgress) {
            hide(websiteProgress);
        }

        const socialProgress =
            $("social-progress");

        if (socialProgress) {
            hide(socialProgress);
        }
    }
);

/* =========================================================
   GLOBAL ERROR HANDLING
========================================================= */

window.addEventListener(
    "error",
    event => {
        console.error(
            "SENTINEL frontend error:",
            event.error ||
            event.message
        );
    }
);

window.addEventListener(
    "unhandledrejection",
    event => {
        console.error(
            "SENTINEL unhandled promise rejection:",
            event.reason
        );
    }
);

/* =========================================================
   SENTINEL READY
========================================================= */

window.SENTINEL = {
    version: "2.1",

    scanWebsite,
    scanMessage,

    analyzeSocialProfile,
    analyzeSocialScreenshot,

    sendAIMessage,

    loadDashboard,
    checkSystemStatus,

    playDangerSound,
    playSuccessSound
};

console.log(
    "🛡️ SENTINEL security system ready."
);
