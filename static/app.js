// SENTINEL - Frontend JavaScript

"use strict";

/* =========================
   HELPERS
========================= */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const show = (el) => {
    if (el) el.classList.remove("hidden");
};

const hide = (el) => {
    if (el) el.classList.add("hidden");
};

const setText = (selector, value) => {
    const el = typeof selector === "string" ? $(selector) : selector;
    if (el) el.textContent = value ?? "";
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const escapeHTML = (text) => {
    if (text === null || text === undefined) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

function showToast(message, type = "info") {
    const toast = $("#toast");
    const toastMessage = $("#toast-message");
    const toastIcon = $("#toast-icon");

    if (!toast) return;

    const icons = {
        success: "✓",
        error: "!",
        warning: "⚠",
        info: "i"
    };

    if (toastIcon) toastIcon.textContent = icons[type] || "i";
    if (toastMessage) toastMessage.textContent = message;

    toast.classList.remove("hidden", "success", "error", "warning", "info");
    toast.classList.add(type);

    clearTimeout(window.__toastTimer);

    window.__toastTimer = setTimeout(() => {
        toast.classList.add("hidden");
    }, 3500);
}

async function postJSON(url, data) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    let result;

    try {
        result = await response.json();
    } catch {
        throw new Error("Server returned an invalid response.");
    }

    if (!response.ok) {
        throw new Error(result.error || "Something went wrong.");
    }

    return result;
}

function setButtonLoading(button, loading, loadingText = "Scanning...") {
    if (!button) return;

    if (loading) {
        if (!button.dataset.originalText) {
            button.dataset.originalText = button.innerHTML;
        }

        button.disabled = true;
        button.innerHTML = `<span class="btn-spinner"></span>${loadingText}`;
    } else {
        button.disabled = false;

        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
        }
    }
}


/* =========================
   NAVIGATION
========================= */

function openSection(target) {
    if (!target) return;

    const sections = $$(".page-section");

    sections.forEach(section => {
        section.classList.remove("active");
    });

    const targetSection = document.getElementById(target);

    if (targetSection) {
        targetSection.classList.add("active");
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }

    $$("[data-target]").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.target === target
        );
    });
}

$$("[data-target]").forEach(button => {
    button.addEventListener("click", () => {
        openSection(button.dataset.target);
    });
});


/* =========================
   DASHBOARD
========================= */

const dashboard = {
    websiteScans: 0,
    highRisk: 0,
    critical: 0,
    messages: 0,
    social: 0,
    bestScore: 0
};

function loadDashboard() {
    const saved = localStorage.getItem("sentinelDashboard");

    if (saved) {
        try {
            Object.assign(dashboard, JSON.parse(saved));
        } catch {
            console.warn("Dashboard data reset.");
        }
    }

    updateDashboard();
}

function saveDashboard() {
    localStorage.setItem(
        "sentinelDashboard",
        JSON.stringify(dashboard)
    );

    updateDashboard();
}

function updateDashboard() {
    setText("#dash-website-scans", dashboard.websiteScans);
    setText("#dash-high-risk", dashboard.highRisk);
    setText("#dash-critical", dashboard.critical);
    setText("#dash-messages", dashboard.messages);
    setText("#dash-social", dashboard.social);
    setText("#dash-best-score", dashboard.bestScore);

    const total =
        dashboard.websiteScans +
        dashboard.messages +
        dashboard.social;

    setText("#dash-total", total);

    let level = "Beginner";

    if (dashboard.bestScore >= 400) {
        level = "SENTINEL Elite";
    } else if (dashboard.bestScore >= 300) {
        level = "Cyber Defender";
    } else if (dashboard.bestScore >= 200) {
        level = "Cyber Smart";
    } else if (dashboard.bestScore >= 100) {
        level = "Aware";
    }

    setText("#dash-level", level);
}


/* =========================
   WEBSITE SCANNER
========================= */

const websiteStages = [
    "Connecting to target",
    "Checking HTTPS security",
    "Inspecting domain structure",
    "Detecting suspicious patterns",
    "Analyzing phishing indicators",
    "Running fraud risk engine",
    "Generating security report"
];

async function runWebsiteStages() {
    const container = $("#website-stages");
    const progress = $("#website-progress-fill");
    const percent = $("#website-progress-percent");

    if (!container) return;

    container.innerHTML = websiteStages
        .map((stage, index) => `
            <div class="scan-stage" data-stage="${index}">
                <span class="stage-icon">○</span>
                <span>${escapeHTML(stage)}</span>
            </div>
        `)
        .join("");

    for (let i = 0; i < websiteStages.length; i++) {
        const stage = container.querySelector(
            `[data-stage="${i}"]`
        );

        if (stage) {
            stage.classList.add("active");

            const icon = stage.querySelector(".stage-icon");

            if (icon) icon.textContent = "◉";
        }

        const value = Math.round(
            ((i + 1) / websiteStages.length) * 100
        );

        if (progress) {
            progress.style.width = `${value}%`;
        }

        setText("#website-progress-percent", `${value}%`);

        await sleep(350);

        if (stage) {
            stage.classList.remove("active");
            stage.classList.add("complete");

            const icon = stage.querySelector(".stage-icon");

            if (icon) icon.textContent = "✓";
        }
    }
}

function riskClass(level) {
    return String(level || "Unknown")
        .toLowerCase()
        .replace(/\s+/g, "-");
}

function renderReasons(selector, reasons) {
    const container = $(selector);

    if (!container) return;

    const items = Array.isArray(reasons) ? reasons : [];

    if (!items.length) {
        container.innerHTML =
            `<li>No major suspicious indicators detected.</li>`;
        return;
    }

    container.innerHTML = items
        .map(item => `<li>${escapeHTML(item)}</li>`)
        .join("");
}

function renderActions(selector, actions) {
    const container = $(selector);

    if (!container) return;

    const items = Array.isArray(actions) ? actions : [];

    if (!items.length) {
        container.innerHTML =
            `<li>Continue using normal security precautions.</li>`;
        return;
    }

    container.innerHTML = items
        .map(item => `<li>${escapeHTML(item)}</li>`)
        .join("");
}

function renderRiskResult(prefix, data) {
    const score = Number(data.score || 0);
    const level = data.level || "Unknown";
    const summary = data.summary || "Analysis completed.";

    setText(`#${prefix}-score`, score);
    setText(`#${prefix}-level`, level);
    setText(`#${prefix}-summary`, summary);

    const meter = $(`#${prefix}-meter-fill`);

    if (meter) {
        meter.style.width = `${Math.min(100, Math.max(0, score))}%`;
    }

    const levelElement = $(`#${prefix}-level`);

    if (levelElement) {
        levelElement.className = `risk-level ${riskClass(level)}`;
    }

    renderReasons(`#${prefix}-reasons`, data.reasons);
    renderActions(`#${prefix}-actions`, data.actions);
}

async function scanWebsite() {
    const input = $("#website-url");
    const button = $("#scan-website-btn");
    const result = $("#website-result");

    if (!input) return;

    const url = input.value.trim();

    if (!url) {
        showToast("Enter a website URL first.", "warning");
        input.focus();
        return;
    }

    setButtonLoading(button, true, "Scanning...");
    hide(result);

    try {
        show($("#website-stages"));
        show($("#website-progress"));

        await runWebsiteStages();

        const data = await postJSON("/scan", {
            url: url
        });

        renderRiskResult("website", data);

        dashboard.websiteScans++;

        if (Number(data.score || 0) >= 70) {
            dashboard.highRisk++;
        }

        if (Number(data.score || 0) >= 90) {
            dashboard.critical++;
        }

        saveDashboard();

        show(result);

        showToast(
            `Scan complete — ${data.level || "Unknown"} risk`,
            Number(data.score || 0) >= 70 ? "warning" : "success"
        );
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        setButtonLoading(button, false);
    }
}

$("#scan-website-btn")?.addEventListener(
    "click",
    scanWebsite
);

$("#website-url")?.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        scanWebsite();
    }
});


/* =========================
   DEMO URLS
========================= */

$$("[data-demo-url]").forEach(button => {
    button.addEventListener("click", () => {
        const url = button.dataset.demoUrl;

        const input = $("#website-url");

        if (input && url) {
            input.value = url;
            input.focus();

            showToast(
                "Demo URL loaded. Click Scan Website.",
                "info"
            );
        }
    });
});


/* =========================
   MESSAGE SCANNER
========================= */

const messageStages = [
    "Reading message language & intent",
    "Detecting scam patterns",
    "Checking urgency & fear tactics",
    "Checking OTP / KYC requests",
    "Checking UPI & payment requests",
    "Inspecting suspicious links",
    "Checking impersonation signals",
    "Calculating fraud risk"
];

async function runMessageStages() {
    const container = $("#message-stages");
    const progress = $("#message-progress-fill");

    if (!container) return;

    container.innerHTML = messageStages
        .map((stage, index) => `
            <div class="scan-stage" data-stage="${index}">
                <span class="stage-icon">○</span>
                <span>${escapeHTML(stage)}</span>
            </div>
        `)
        .join("");

    for (let i = 0; i < messageStages.length; i++) {
        const stage = container.querySelector(
            `[data-stage="${i}"]`
        );

        if (stage) {
            stage.classList.add("active");

            const icon = stage.querySelector(".stage-icon");

            if (icon) icon.textContent = "◉";
        }

        const value = Math.round(
            ((i + 1) / messageStages.length) * 100
        );

        if (progress) {
            progress.style.width = `${value}%`;
        }

        setText("#message-progress-percent", `${value}%`);

        await sleep(300);

        if (stage) {
            stage.classList.remove("active");
            stage.classList.add("complete");

            const icon = stage.querySelector(".stage-icon");

            if (icon) icon.textContent = "✓";
        }
    }
}

async function scanMessage() {
    const input = $("#message-text");
    const button = $("#scan-message-btn");
    const result = $("#message-result");

    if (!input) return;

    const message = input.value.trim();

    if (!message) {
        showToast("Paste a message first.", "warning");
        input.focus();
        return;
    }

    if (message.length < 5) {
        showToast("Please enter a little more text.", "warning");
        return;
    }

    setButtonLoading(button, true, "Analyzing...");
    hide(result);

    try {
        show($("#message-stages"));
        show($("#message-progress"));

        await runMessageStages();

        const data = await postJSON("/scan-message", {
            message: message
        });

        renderRiskResult("message", data);

        dashboard.messages++;
        saveDashboard();

        show(result);

        showToast(
            `Message analysis complete — ${data.level || "Unknown"} risk`,
            Number(data.score || 0) >= 70
                ? "warning"
                : "success"
        );
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        setButtonLoading(button, false);
    }
}

$("#scan-message-btn")?.addEventListener(
    "click",
    scanMessage
);

$("#clear-message-btn")?.addEventListener(
    "click",
    () => {
        const input = $("#message-text");

        if (input) input.value = "";

        hide($("#message-result"));
        hide($("#message-stages"));
        hide($("#message-progress"));

        showToast("Message cleared.", "info");
    }
);

$("#message-demo-btn")?.addEventListener(
    "click",
    () => {
        const input = $("#message-text");

        if (!input) return;

        input.value =
            "URGENT! Your bank KYC has expired. Verify immediately or your account will be blocked. Click http://secure-bank-update.example and enter OTP to continue.";

        input.focus();

        showToast(
            "Demo scam message loaded.",
            "warning"
        );
    }
);


/* =========================
   SOCIAL PROFILE ANALYZER
========================= */

let selectedPlatform = "Instagram";

$$(".platform-tab").forEach(tab => {
    tab.addEventListener("click", () => {
        $$(".platform-tab").forEach(item => {
            item.classList.remove("active");
        });

        tab.classList.add("active");

        selectedPlatform =
            tab.dataset.platform ||
            tab.textContent.trim() ||
            "Instagram";
    });
});

async function analyzeSocialProfile() {
    const button = $("#analyze-social-btn");
    const result = $("#social-result");

    const username = $("#social-username")?.value.trim() || "";
    const name = $("#social-name")?.value.trim() || "";
    const bio = $("#social-bio")?.value.trim() || "";
    const followers = $("#social-followers")?.value.trim() || "";
    const following = $("#social-following")?.value.trim() || "";
    const profileUrl = $("#social-url")?.value.trim() || "";

    if (!username && !name && !bio && !profileUrl) {
        showToast(
            "Enter at least one profile detail.",
            "warning"
        );
        return;
    }

    setButtonLoading(
        button,
        true,
        "Analyzing..."
    );

    hide(result);

    try {
        const data = await postJSON("/scan-profile", {
            platform: selectedPlatform,
            username,
            name,
            bio,
            followers,
            following,
            url: profileUrl
        });

        renderRiskResult("social", data);

        dashboard.social++;
        saveDashboard();

        show(result);

        showToast(
            "Profile indicator analysis completed.",
            "success"
        );
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        setButtonLoading(button, false);
    }
}

$("#analyze-social-btn")?.addEventListener(
    "click",
    analyzeSocialProfile
);


/* =========================
   SCREENSHOT ANALYZER
========================= */

const screenshotInput = $("#screenshot-input");

screenshotInput?.addEventListener(
    "change",
    () => {
        const file = screenshotInput.files?.[0];

        if (!file) {
            setText("#selected-file", "No file selected");
            return;
        }

        setText(
            "#selected-file",
            `${file.name} (${Math.round(file.size / 1024)} KB)`
        );

        if (file.size > 5 * 1024 * 1024) {
            showToast(
                "Screenshot must be smaller than 5 MB.",
                "warning"
            );

            screenshotInput.value = "";
            setText("#selected-file", "No file selected");
        }
    }
);

$("#screenshot-form")?.addEventListener(
    "submit",
    async event => {
        event.preventDefault();

        const file = screenshotInput?.files?.[0];

        if (!file) {
            showToast(
                "Choose a screenshot first.",
                "warning"
            );
            return;
        }

        if (file.size > 5 * 1024 * 1024) {
            showToast(
                "Screenshot must be smaller than 5 MB.",
                "warning"
            );
            return;
        }

        const button = $("#analyze-screenshot-btn");

        setButtonLoading(
            button,
            true,
            "Analyzing..."
        );

        try {
            const formData = new FormData();

            formData.append("screenshot", file);

            const response = await fetch(
                "/analyze-screenshot",
                {
                    method: "POST",
                    body: formData
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Screenshot analysis failed."
                );
            }

            setText(
                "#screenshot-summary",
                data.summary ||
                "Indicator-based screenshot analysis completed."
            );

            const indicators =
                $("#screenshot-indicators");

            if (indicators) {
                const items =
                    Array.isArray(data.indicators)
                        ? data.indicators
                        : [];

                indicators.innerHTML = items.length
                    ? items.map(item =>
                        `<li>${escapeHTML(item)}</li>`
                    ).join("")
                    : `<li>No obvious indicators detected.</li>`;
            }

            show($("#screenshot-result"));

            showToast(
                "Screenshot analysis completed.",
                "success"
            );
        } catch (error) {
            showToast(error.message, "error");
        } finally {
            setButtonLoading(button, false);
        }
    }
);


/* =========================
   CYBER FRAUD GAME
========================= */

const QUESTION_BANK = [
    {
        q: "You receive a message saying your bank account will be blocked today unless you verify a link. What should you do?",
        options: [
            "Click immediately",
            "Share OTP",
            "Open the official bank app directly",
            "Forward it to friends"
        ],
        answer: 2,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "Someone claiming to be customer support asks for your UPI PIN. What is the safest response?",
        options: [
            "Give it if they know your name",
            "Never share the UPI PIN",
            "Send half of the PIN",
            "Ask them to call later"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "A website uses a familiar brand logo but its domain has many strange words. What should you check?",
        options: [
            "Logo quality only",
            "Domain name carefully",
            "Number of animations",
            "Background color"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "You receive an OTP you did not request. What should you do?",
        options: [
            "Share it with support",
            "Ignore it and investigate account activity",
            "Reply with the OTP",
            "Post it online"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "A friend suddenly asks for money through a new UPI ID. What is safest?",
        options: [
            "Send immediately",
            "Verify through another trusted channel",
            "Ask for their OTP",
            "Send a small amount first"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "A job recruiter asks you to pay a registration fee before an interview. What is this a warning sign of?",
        options: [
            "Normal hiring",
            "Possible job scam",
            "Guaranteed employment",
            "Government verification"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "Which information should never be shared with an unknown person?",
        options: [
            "Favorite movie",
            "OTP",
            "Public username",
            "Favorite color"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "A message says you won a lottery you never entered. What should you suspect?",
        options: [
            "Guaranteed prize",
            "Possible scam",
            "Bank refund",
            "Normal notification"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "What does HTTPS mainly indicate?",
        options: [
            "The website is guaranteed legitimate",
            "The connection is encrypted",
            "The website cannot be hacked",
            "The owner is verified"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },
    {
        q: "A stranger sends you a shortened URL and asks you to log in. What should you do?",
        options: [
            "Click without checking",
            "Avoid it and verify the destination",
            "Enter only your username",
            "Share it publicly"
        ],
        answer: 1,
        difficulty: "Easy",
        points: 10
    },

    {
        q: "An attacker says they are from your bank and creates urgency to make you reveal account details. Which technique is being used?",
        options: [
            "Social engineering",
            "Compression",
            "Encryption",
            "Caching"
        ],
        answer: 0,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "A fake login page copies the design of a popular service. What is its main goal?",
        options: [
            "Improve performance",
            "Steal credentials",
            "Increase battery life",
            "Update the browser"
        ],
        answer: 1,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "You receive an email attachment from an unknown sender. What is safest?",
        options: [
            "Open it immediately",
            "Verify sender before opening",
            "Forward it",
            "Disable antivirus"
        ],
        answer: 1,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "A website URL contains an @ symbol before the real domain. Why can this be suspicious?",
        options: [
            "It always improves security",
            "It can disguise the actual destination",
            "It makes the site faster",
            "It confirms ownership"
        ],
        answer: 1,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "Someone asks you to install remote-control software to receive a refund. What should you do?",
        options: [
            "Install it",
            "Give them full access",
            "Refuse and contact the company independently",
            "Disable device security"
        ],
        answer: 2,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "A social-media profile has copied photos, very new activity, and asks for money. What should you do?",
        options: [
            "Send money",
            "Verify identity independently",
            "Give your OTP",
            "Share your password"
        ],
        answer: 1,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "Why should you avoid reusing the same password across important accounts?",
        options: [
            "It slows the internet",
            "One breach can expose multiple accounts",
            "It prevents updates",
            "It removes 2FA"
        ],
        answer: 1,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "What is a strong sign of phishing?",
        options: [
            "Unexpected urgency and a login link",
            "Normal greeting",
            "Company logo alone",
            "Email signature alone"
        ],
        answer: 0,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "A caller knows some public information about you and uses it to gain trust. What is happening?",
        options: [
            "Social engineering",
            "Software compilation",
            "Data compression",
            "Screen mirroring"
        ],
        answer: 0,
        difficulty: "Medium",
        points: 20
    },
    {
        q: "A payment request says you must scan a QR code to receive money. What should you remember?",
        options: [
            "Scanning always receives money",
            "UPI PIN is generally used when sending money",
            "QR codes are always safe",
            "Anyone requesting payment is trusted"
        ],
        answer: 1,
        difficulty: "Medium",
        points: 20
    },

    {
        q: "A domain uses a punycode-style name that visually resembles a trusted brand. What attack can this facilitate?",
        options: [
            "Homograph impersonation",
            "Battery optimization",
            "Video compression",
            "Database backup"
        ],
        answer: 0,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "An attacker sends a realistic voice recording pretending to be a family member asking for urgent money. What should you do?",
        options: [
            "Trust the voice immediately",
            "Verify using a separate known contact method",
            "Send money first",
            "Share your OTP"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "A company website is HTTPS but has a suspicious domain and unusual payment instructions. What does HTTPS NOT prove?",
        options: [
            "The connection is encrypted",
            "The site is legitimate",
            "Traffic is protected in transit",
            "The browser can establish TLS"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "An attacker uses information from your public social profile to make a convincing scam message. What is this?",
        options: [
            "Reconnaissance for social engineering",
            "Normal personalization",
            "Software patching",
            "Firewall configuration"
        ],
        answer: 0,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "You clicked a suspicious link but did not enter credentials. What is a sensible next step?",
        options: [
            "Ignore everything",
            "Close it and run security checks/update software",
            "Share the link",
            "Disable antivirus"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "Your email password was exposed in a breach. What should you prioritize?",
        options: [
            "Reuse the password elsewhere",
            "Change it and enable 2FA",
            "Post it for warning",
            "Ignore the breach"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "A scammer asks you to transfer money to a 'safe account' to protect your funds. What is this?",
        options: [
            "Standard bank procedure",
            "Common impersonation scam tactic",
            "Required UPI security",
            "Normal KYC"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "A suspicious app requests SMS, accessibility, contacts and screen-control permissions without a clear reason. What should you do?",
        options: [
            "Grant everything",
            "Review legitimacy and avoid unnecessary permissions",
            "Disable lock screen",
            "Share OTP"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "A social-media account sends you a login code and asks you to forward it to them. What is the likely goal?",
        options: [
            "Account takeover",
            "Profile optimization",
            "Password recovery for you",
            "Verification of your device"
        ],
        answer: 0,
        difficulty: "Hard",
        points: 30
    },
    {
        q: "A fake support number appears in a search result and asks you to install remote-access software. What is the safest approach?",
        options: [
            "Use the number",
            "Use contact details from the official website/app",
            "Give them your PIN",
            "Install the software"
        ],
        answer: 1,
        difficulty: "Hard",
        points: 30
    },

    {
        q: "You discover that someone may have taken over your social account. What should you do first?",
        options: [
            "Send them money",
            "Secure the account using official recovery methods",
            "Delete all evidence",
            "Share your new password"
        ],
        answer: 1,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "A deepfake video appears to show a trusted person requesting an emergency transfer. What is the strongest verification?",
        options: [
            "Video quality",
            "Independent communication through a known channel",
            "Their profile picture",
            "The number of followers"
        ],
        answer: 1,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "A website has HTTPS, a familiar logo, a copied privacy policy and a newly registered-looking domain. What should influence your decision most?",
        options: [
            "Logo",
            "Overall trust signals including domain and context",
            "Animation quality",
            "HTTPS alone"
        ],
        answer: 1,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "An attacker combines leaked credentials, SIM-related tricks and social engineering to access an account. What is this best described as?",
        options: [
            "Multi-stage attack",
            "Normal login",
            "Browser caching",
            "File compression"
        ],
        answer: 0,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "After accidentally sending money to a scammer, what should you do?",
        options: [
            "Wait several days",
            "Immediately contact your bank/payment provider and report the fraud",
            "Send more money",
            "Delete transaction records"
        ],
        answer: 1,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "An attacker creates a convincing fake employee profile using a real person's public details. What risk is most relevant?",
        options: [
            "Identity impersonation",
            "Battery drain only",
            "Normal networking",
            "Browser update"
        ],
        answer: 0,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "A suspicious login page asks for your password and 2FA code on the same page. What should you consider?",
        options: [
            "It is automatically safe",
            "It may be attempting credential and session theft",
            "2FA makes phishing impossible",
            "The logo proves legitimacy"
        ],
        answer: 1,
        difficulty: "Expert",
        points: 50
    },
    {
        q: "An investment group promises guaranteed returns and pressures you to deposit cryptocurrency quickly. What is the strongest warning sign?",
        options: [
            "Guaranteed returns and pressure",
            "Professional logo",
            "Group chat",
            "Charts"
        ],
        answer: 0,
        difficulty: "Expert",
        points: 50
    }
];


/* Create additional unique scenario variations
   so the game has 100+ questions. */

const extraTopics = [
    ["parcel delivery", "customs payment", "unexpected delivery fee"],
    ["electricity bill", "service disconnection", "urgent payment link"],
    ["tax refund", "government impersonation", "bank details"],
    ["college scholarship", "application fee", "fake portal"],
    ["internship offer", "security deposit", "remote job"],
    ["Instagram verification", "blue tick", "payment request"],
    ["Facebook account warning", "copyright complaint", "login link"],
    ["X/Twitter verification", "account suspension", "credential request"],
    ["gaming reward", "free skins", "login page"],
    ["crypto giveaway", "wallet connection", "private key"],
    ["bank cashback", "refund link", "OTP request"],
    ["credit-card reward", "KYC update", "payment link"],
    ["SIM replacement", "identity verification", "OTP"],
    ["Wi-Fi support", "remote access", "password request"],
    ["antivirus alert", "fake support", "remote software"],
    ["browser warning", "fake update", "malware"],
    ["cloud storage", "account suspension", "login link"],
    ["email storage", "mailbox full", "credential link"],
    ["student loan", "processing fee", "bank details"],
    ["exam result", "verification fee", "fake website"],
    ["travel ticket", "refund scam", "payment request"],
    ["hotel booking", "discount offer", "card details"],
    ["food delivery", "refund link", "UPI request"],
    ["online shopping", "prize coupon", "payment page"],
    ["friend request", "fake profile", "money request"],
    ["romance profile", "emergency request", "money transfer"],
    ["charity appeal", "fake donation", "QR payment"],
    ["job interview", "identity verification", "document upload"],
    ["company HR", "salary account update", "login link"]
];

extraTopics.forEach((topic, index) => {
    const [context, trigger, request] = topic;

    QUESTION_BANK.push({
        q: `You receive an unexpected ${context} message mentioning ${trigger} and asking for ${request}. What is the safest response?`,
        options: [
            "Act immediately because the message sounds urgent",
            "Verify the claim using the official website or app",
            "Share OTP to prove identity",
            "Forward the message to everyone"
        ],
        answer: 1,
        difficulty: index % 4 === 0
            ? "Easy"
            : index % 4 === 1
                ? "Medium"
                : index % 4 === 2
                    ? "Hard"
                    : "Expert",
        points: index % 4 === 0
            ? 10
            : index % 4 === 1
                ? 20
                : index % 4 === 2
                    ? 30
                    : 50
    });
});

for (let i = 0; i < 45; i++) {
    const scenarios = [
        "unexpected password reset",
        "urgent account verification",
        "fake customer support",
        "suspicious cashback",
        "unknown investment opportunity",
        "fake scholarship",
        "unexpected KYC request",
        "social-media warning",
        "fake delivery notification",
        "unknown QR payment"
    ];

    const scenario =
        scenarios[i % scenarios.length];

    QUESTION_BANK.push({
        q: `Scenario ${i + 1}: You receive an ${scenario} message with a link and pressure to act quickly. Which security principle should guide your decision?`,
        options: [
            "Trust urgency",
            "Verify independently before acting",
            "Share credentials to confirm identity",
            "Disable security controls"
        ],
        answer: 1,
        difficulty: i % 4 === 0
            ? "Easy"
            : i % 4 === 1
                ? "Medium"
                : i % 4 === 2
                    ? "Hard"
                    : "Expert",
        points: i % 4 === 0
            ? 10
            : i % 4 === 1
                ? 20
                : i % 4 === 2
                    ? 30
                    : 50
    });
}

setText(
    "#question-bank-count",
    `${QUESTION_BANK.length}+`
);


/* Game state */

let gameQuestions = [];
let gameIndex = 0;
let gameScore = 0;
let gameStreak = 0;
let gameBestStreak = 0;
let gameCorrect = 0;
let gameWrong = 0;
let gameStartTime = 0;
let currentQuestionAnswered = false;
let mistakes = [];

function shuffle(array) {
    const copy = [...array];

    for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));

        [copy[i], copy[j]] =
            [copy[j], copy[i]];
    }

    return copy;
}

function startGame() {
    gameQuestions =
        shuffle(QUESTION_BANK).slice(0, 15);

    gameIndex = 0;
    gameScore = 0;
    gameStreak = 0;
    gameBestStreak = 0;
    gameCorrect = 0;
    gameWrong = 0;
    mistakes = [];
    currentQuestionAnswered = false;

    hide($("#game-start"));
    hide($("#game-over"));
    show($("#game-play"));

    updateGameStats();
    renderQuestion();
}

function renderQuestion() {
    const question = gameQuestions[gameIndex];

    if (!question) {
        endGame();
        return;
    }

    currentQuestionAnswered = false;
    gameStartTime = Date.now();

    setText(
        "#question-number",
        `Question ${gameIndex + 1} / ${gameQuestions.length}`
    );

    setText(
        "#question-text",
        question.q
    );

    setText(
        "#question-difficulty",
        question.difficulty
    );

    const optionsContainer =
        $("#question-options");

    if (!optionsContainer) return;

    optionsContainer.innerHTML = "";

    question.options.forEach((option, index) => {
        const button =
            document.createElement("button");

        button.className = "game-option";
        button.innerHTML = `
            <span class="option-letter">
                ${String.fromCharCode(65 + index)}
            </span>
            <span>${escapeHTML(option)}</span>
        `;

        button.addEventListener(
            "click",
            () => answerQuestion(index)
        );

        optionsContainer.appendChild(button);
    });

    const progress =
        ((gameIndex) / gameQuestions.length) * 100;

    const gameProgress = $("#game-progress");

    if (gameProgress) {
        gameProgress.style.width =
            `${progress}%`;
    }

    setText(
        "#game-score",
        gameScore
    );

    setText(
        "#game-streak",
        gameStreak
    );

    setText(
        "#game-correct",
        gameCorrect
    );

    setText(
        "#game-wrong",
        gameWrong
    );

    const feedback =
        $("#answer-feedback");

    if (feedback) {
        feedback.className =
            "answer-feedback hidden";

        feedback.textContent = "";
    }
}

function answerQuestion(selectedIndex) {
    if (currentQuestionAnswered) return;

    currentQuestionAnswered = true;

    const question =
        gameQuestions[gameIndex];

    const buttons =
        $$("#question-options .game-option");

    buttons.forEach(button => {
        button.disabled = true;
    });

    const correct =
        selectedIndex === question.answer;

    const elapsed =
        Date.now() - gameStartTime;

    if (correct) {
        gameCorrect++;
        gameStreak++;

        gameBestStreak =
            Math.max(
                gameBestStreak,
                gameStreak
            );

        let earned = question.points;

        if (elapsed < 5000) {
            earned += 5;
        }

        if (gameStreak >= 3) {
            earned += Math.min(
                20,
                gameStreak * 2
            );
        }

        gameScore += earned;

        buttons[selectedIndex]?.classList.add(
            "correct"
        );

        showAnswerFeedback(
            `Correct! +${earned} points`,
            "success"
        );

        showToast(
            `Correct! +${earned}`,
            "success"
        );
    } else {
        gameWrong++;
        gameStreak = 0;

        buttons[selectedIndex]?.classList.add(
            "wrong"
        );

        buttons[question.answer]?.classList.add(
            "correct"
        );

        mistakes.push({
            question: question.q,
            selected: question.options[selectedIndex],
            correct: question.options[question.answer]
        });

        showAnswerFeedback(
            `Not quite. Correct answer: ${question.options[question.answer]}`,
            "error"
        );

        showToast(
            "Incorrect — learn from this one!",
            "error"
        );
    }

    updateGameStats();

    setTimeout(() => {
        gameIndex++;

        if (gameIndex >= gameQuestions.length) {
            endGame();
        } else {
            renderQuestion();
        }
    }, 1100);
}

function showAnswerFeedback(message, type) {
    const feedback =
        $("#answer-feedback");

    if (!feedback) return;

    feedback.textContent = message;
    feedback.className =
        `answer-feedback ${type}`;
}

function updateGameStats() {
    setText("#game-score", gameScore);
    setText("#game-streak", gameStreak);
    setText("#game-correct", gameCorrect);
    setText("#game-wrong", gameWrong);
}

function getGameLevel(score) {
    if (score >= 400) return "SENTINEL Elite";
    if (score >= 300) return "Cyber Defender";
    if (score >= 200) return "Cyber Smart";
    if (score >= 100) return "Aware";
    return "Beginner";
}

function endGame() {
    hide($("#game-play"));
    show($("#game-over"));

    const accuracy =
        gameQuestions.length
            ? Math.round(
                (gameCorrect /
                    gameQuestions.length) *
                100
            )
            : 0;

    setText("#final-score", gameScore);

    setText(
        "#final-level",
        getGameLevel(gameScore)
    );

    setText(
        "#final-correct",
        gameCorrect
    );

    setText(
        "#final-wrong",
        gameWrong
    );

    setText(
        "#final-streak",
        gameBestStreak
    );

    setText(
        "#final-accuracy",
        `${accuracy}%`
    );

    const review =
        $("#mistake-review");

    if (review) {
        if (!mistakes.length) {
            review.innerHTML =
                `<p>Perfect run! No mistakes to review. 🛡️</p>`;
        } else {
            review.innerHTML =
                mistakes.map((mistake, index) => `
                    <div class="mistake-item">
                        <strong>${index + 1}. ${escapeHTML(mistake.question)}</strong>
                        <p>Your answer: ${escapeHTML(mistake.selected)}</p>
                        <p>Correct answer: ${escapeHTML(mistake.correct)}</p>
                    </div>
                `).join("");
        }
    }

    const oldBest =
        Number(
            localStorage.getItem(
                "sentinelGameBest"
            ) || 0
        );

    if (gameScore > oldBest) {
        localStorage.setItem(
            "sentinelGameBest",
            gameScore
        );

        dashboard.bestScore =
            Math.max(
                dashboard.bestScore,
                gameScore
            );

        saveDashboard();

        showToast(
            "New personal best! 🏆",
            "success"
        );
    }

    updateDashboard();
}

$("#start-game-btn")?.addEventListener(
    "click",
    startGame
);

$("#restart-game-btn")?.addEventListener(
    "click",
    startGame
);


/* =========================
   AI CHAT
========================= */

function addChatMessage(message, type = "ai") {
    const container = $("#chat-messages");

    if (!container) return;

    const bubble =
        document.createElement("div");

    bubble.className =
        `chat-message ${type}`;

    bubble.innerHTML =
        `<div class="chat-bubble">${escapeHTML(message)}</div>`;

    container.appendChild(bubble);

    container.scrollTop =
        container.scrollHeight;
}

function showChatTyping(showTyping) {
    const typing =
        $("#chat-typing");

    if (!typing) return;

    typing.classList.toggle(
        "hidden",
        !showTyping
    );
}

function toggleChat() {
    const chat = $("#ai-chat");

    if (!chat) return;

    chat.classList.toggle("hidden");

    if (!chat.classList.contains("hidden")) {
        $("#chat-input")?.focus();
    }
}

$("#ai-ball")?.addEventListener(
    "click",
    toggleChat
);

$("#chat-close")?.addEventListener(
    "click",
    () => {
        hide($("#ai-chat"));
    }
);

$("#chat-minimize")?.addEventListener(
    "click",
    () => {
        hide($("#ai-chat"));
    }
);

async function sendChatMessage() {
    const input = $("#chat-input");
    const message = input?.value.trim();

    if (!message) return;

    addChatMessage(
        message,
        "user"
    );

    input.value = "";

    showChatTyping(true);

    try {
        const data = await postJSON(
            "/chat",
            {
                message: message
            }
        );

        await sleep(450);

        addChatMessage(
            data.response ||
            data.message ||
            "I couldn't process that right now.",
            "ai"
        );
    } catch (error) {
        addChatMessage(
            "I couldn't connect to the security assistant right now. Please try again.",
            "ai"
        );
    } finally {
        showChatTyping(false);
    }
}

$("#chat-send")?.addEventListener(
    "click",
    sendChatMessage
);

$("#chat-input")?.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Enter" &&
            !event.shiftKey
        ) {
            event.preventDefault();
            sendChatMessage();
        }
    }
);


/* =========================
   KEYBOARD SHORTCUT
========================= */

document.addEventListener(
    "keydown",
    event => {
        if (
            (event.ctrlKey || event.metaKey) &&
            event.key.toLowerCase() === "k"
        ) {
            event.preventDefault();

            const input =
                $("#website-url");

            if (input) {
                openSection("scanner");
                input.focus();
            }
        }

        if (event.key === "Escape") {
            hide($("#ai-chat"));
        }
    }
);


/* =========================
   INITIALIZATION
========================= */

function initializeSentinel() {
    loadDashboard();

    const activeSection =
        $(".page-section.active");

    if (!activeSection) {
        const home =
            $("#home");

        if (home) {
            home.classList.add("active");
        }
    }

    const best =
        Number(
            localStorage.getItem(
                "sentinelGameBest"
            ) || 0
        );

    if (best > dashboard.bestScore) {
        dashboard.bestScore = best;
        saveDashboard();
    }

    setText(
        "#question-bank-count",
        `${QUESTION_BANK.length}+`
    );

    console.log(
        `SENTINEL initialized with ${QUESTION_BANK.length} cyber-fraud scenarios.`
    );
}

document.addEventListener(
    "DOMContentLoaded",
    initializeSentinel
);
