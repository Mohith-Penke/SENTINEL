/* =========================================================
   SENTINEL — CYBER INTELLIGENCE FRONTEND
========================================================= */

"use strict";

/* =========================================================
   HELPERS
========================================================= */

const $ = (id) => document.getElementById(id);

const $$ = (selector) =>
    Array.from(document.querySelectorAll(selector));

const escapeHTML = (value) => {
    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
};

const sleep = (ms) =>
    new Promise(resolve => setTimeout(resolve, ms));

function show(element) {
    if (element) element.classList.remove("hidden");
}

function hide(element) {
    if (element) element.classList.add("hidden");
}

function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = value ?? "";
}

function showToast(message, icon = "✓") {

    setText("toast-message", message);
    setText("toast-icon", icon);

    const toast = $("toast");

    if (!toast) return;

    toast.classList.add("show");

    clearTimeout(window.sentinelToastTimer);

    window.sentinelToastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 2800);
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
        throw new Error(
            result.error ||
            result.message ||
            "Request failed."
        );
    }

    return result;
}

function setButtonLoading(button, loading, loadingText = "PROCESSING...") {

    if (!button) return;

    if (loading) {

        button.dataset.originalText = button.innerHTML;
        button.disabled = true;
        button.innerHTML = `⏳ ${loadingText}`;

    } else {

        button.disabled = false;

        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
        }
    }
}

/* =========================================================
   NAVIGATION
========================================================= */

function navigateTo(target) {

    const pages = $$(".page");

    pages.forEach(page => {
        page.classList.remove("active");
    });

    const page = $(target);

    if (page) {
        page.classList.add("active");
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }
}

$$("[data-target]").forEach(button => {

    button.addEventListener("click", () => {

        const target = button.dataset.target;

        if (target) {
            navigateTo(target);
        }
    });
});


/* =========================================================
   RISK CLASSIFICATION
========================================================= */

function getRiskInfo(score) {

    score = Number(score) || 0;

    if (score <= 29) {
        return {
            level: "LOW RISK",
            className: "low",
            emoji: "🟢"
        };
    }

    if (score <= 49) {
        return {
            level: "MEDIUM RISK",
            className: "medium",
            emoji: "🟡"
        };
    }

    if (score <= 69) {
        return {
            level: "MEDIUM → HIGH RISK",
            className: "medium-high",
            emoji: "🟠"
        };
    }

    if (score <= 89) {
        return {
            level: "HIGH RISK",
            className: "high",
            emoji: "🔴"
        };
    }

    return {
        level: "CRITICAL RISK",
        className: "critical",
        emoji: "🚨"
    };
}


/* =========================================================
   DANGER SOUND
========================================================= */

function playDangerSound() {

    try {

        const AudioContext =
            window.AudioContext ||
            window.webkitAudioContext;

        if (!AudioContext) return;

        const audioContext = new AudioContext();

        const now = audioContext.currentTime;

        const oscillator1 =
            audioContext.createOscillator();

        const oscillator2 =
            audioContext.createOscillator();

        const gain =
            audioContext.createGain();

        oscillator1.type = "sawtooth";
        oscillator2.type = "square";

        oscillator1.frequency.setValueAtTime(
            880,
            now
        );

        oscillator1.frequency.exponentialRampToValueAtTime(
            440,
            now + 0.25
        );

        oscillator2.frequency.setValueAtTime(
            660,
            now
        );

        oscillator2.frequency.exponentialRampToValueAtTime(
            330,
            now + 0.25
        );

        gain.gain.setValueAtTime(
            0.0001,
            now
        );

        gain.gain.exponentialRampToValueAtTime(
            0.18,
            now + 0.02
        );

        gain.gain.exponentialRampToValueAtTime(
            0.0001,
            now + 0.55
        );

        oscillator1.connect(gain);
        oscillator2.connect(gain);

        gain.connect(audioContext.destination);

        oscillator1.start(now);
        oscillator2.start(now);

        oscillator1.stop(now + 0.55);
        oscillator2.stop(now + 0.55);

        setTimeout(() => {
            audioContext.close().catch(() => {});
        }, 800);

    } catch (error) {

        console.warn(
            "Danger sound could not play:",
            error
        );
    }
}


/* =========================================================
   DANGER VISUAL
========================================================= */

function triggerDangerMode() {

    document.body.classList.add("danger-mode");

    showToast(
        "🚨 HIGH-RISK THREAT DETECTED",
        "🚨"
    );

    setTimeout(() => {
        document.body.classList.remove("danger-mode");
    }, 3500);
}


/* =========================================================
   DASHBOARD STORAGE
========================================================= */

const defaultStats = {
    websiteScans: 0,
    highRisk: 0,
    critical: 0,
    messages: 0,
    social: 0,
    bestScore: 0,
    total: 0
};

function getStats() {

    try {

        return {
            ...defaultStats,
            ...JSON.parse(
                localStorage.getItem("sentinelStats") || "{}"
            )
        };

    } catch {

        return {
            ...defaultStats
        };
    }
}

function saveStats(stats) {

    localStorage.setItem(
        "sentinelStats",
        JSON.stringify(stats)
    );
}

function updateDashboard() {

    const stats = getStats();

    setText(
        "dash-website-scans",
        stats.websiteScans
    );

    setText(
        "dash-high-risk",
        stats.highRisk
    );

    setText(
        "dash-critical",
        stats.critical
    );

    setText(
        "dash-messages",
        stats.messages
    );

    setText(
        "dash-social",
        stats.social
    );

    setText(
        "dash-best-score",
        stats.bestScore
    );

    setText(
        "dash-total",
        stats.total
    );

    let level = "BEGINNER";

    if (stats.total >= 25) {
        level = "DEFENDER";
    }

    if (stats.total >= 50) {
        level = "CYBER SCOUT";
    }

    if (stats.total >= 100) {
        level = "CYBER GUARDIAN";
    }

    setText(
        "dash-level",
        level
    );
}

function recordScan(type, score) {

    const stats = getStats();

    stats.total++;

    if (type === "website") {
        stats.websiteScans++;
    }

    if (type === "message") {
        stats.messages++;
    }

    if (type === "social") {
        stats.social++;
    }

    if (score >= 70) {
        stats.highRisk++;
    }

    if (score >= 90) {
        stats.critical++;
    }

    saveStats(stats);

    updateDashboard();
}


/* =========================================================
   RISK RESULT RENDERER
========================================================= */

function renderRiskResult(prefix, data) {

    const score = Math.max(
        0,
        Math.min(
            100,
            Number(data.score) || 0
        )
    );

    const info = getRiskInfo(score);

    setText(
        `${prefix}-score`,
        score
    );

    setText(
        `${prefix}-level`,
        info.level
    );

    setText(
        `${prefix}-summary`,
        data.summary ||
        `${info.emoji} SENTINEL classified this as ${info.level}.`
    );

    const meter =
        $(`${prefix}-meter-fill`);

    if (meter) {
        meter.style.width = `${score}%`;
    }

    const reasons =
        $(`${prefix}-reasons`);

    if (reasons) {

        reasons.innerHTML = "";

        const list =
            Array.isArray(data.reasons)
                ? data.reasons
                : [];

        if (!list.length) {

            const li =
                document.createElement("li");

            li.textContent =
                "No major suspicious indicators were detected.";

            reasons.appendChild(li);

        } else {

            list.forEach(reason => {

                const li =
                    document.createElement("li");

                li.textContent = reason;

                reasons.appendChild(li);
            });
        }
    }

    const actions =
        $(`${prefix}-actions`);

    if (actions) {

        actions.innerHTML = "";

        const list =
            Array.isArray(data.actions)
                ? data.actions
                : [];

        if (!list.length) {

            const li =
                document.createElement("li");

            li.textContent =
                score >= 70
                    ? "Do not enter passwords, OTPs or payment information."
                    : "Verify the information before taking action.";

            actions.appendChild(li);

        } else {

            list.forEach(action => {

                const li =
                    document.createElement("li");

                li.textContent = action;

                actions.appendChild(li);
            });
        }
    }

    const result =
        $(`${prefix}-result`);

    show(result);

    if (
        prefix === "website" &&
        score >= 70 &&
        (
            info.level.includes("HIGH") ||
            info.level.includes("CRITICAL")
        )
    ) {

        playDangerSound();
        triggerDangerMode();
    }
}


/* =========================================================
   WEBSITE SCANNER
========================================================= */

async function scanWebsite() {

    const input = $("website-url");
    const button = $("scan-website-btn");

    if (!input || !button) return;

    const url =
        input.value.trim();

    if (!url) {

        showToast(
            "Enter a website URL first.",
            "⚠️"
        );

        input.focus();

        return;
    }

    const progress =
        $("website-progress");

    const result =
        $("website-result");

    show(progress);
    hide(result);

    setButtonLoading(
        button,
        true,
        "SCANNING..."
    );

    const fill =
        $("website-progress-fill");

    const stages = [
        [15, "Connecting to target..."],
        [30, "Inspecting URL structure..."],
        [48, "Checking suspicious patterns..."],
        [66, "Analyzing domain indicators..."],
        [82, "Calculating threat score..."],
        [95, "Generating security recommendation..."]
    ];

    try {

        for (const [percent, message] of stages) {

            setText(
                "website-stages",
                message
            );

            setText(
                "website-progress-percent",
                `${percent}%`
            );

            if (fill) {
                fill.style.width =
                    `${percent}%`;
            }

            await sleep(180);
        }

        const data =
            await postJSON(
                "/scan",
                { url }
            );

        if (fill) {
            fill.style.width = "100%";
        }

        setText(
            "website-progress-percent",
            "100%"
        );

        renderRiskResult(
            "website",
            data
        );

        recordScan(
            "website",
            Number(data.score) || 0
        );

        showToast(
            "Website analysis complete.",
            "✓"
        );

    } catch (error) {

        showToast(
            error.message ||
            "Website scan failed.",
            "❌"
        );

    } finally {

        setButtonLoading(
            button,
            false
        );
    }
}

$("scan-website-btn")
    ?.addEventListener(
        "click",
        scanWebsite
    );

$("website-url")
    ?.addEventListener(
        "keydown",
        event => {

            if (event.key === "Enter") {
                scanWebsite();
            }
        }
    );


/* =========================================================
   MESSAGE SCANNER
========================================================= */

async function scanMessage() {

    const input =
        $("message-text");

    const button =
        $("scan-message-btn");

    if (!input || !button) return;

    const message =
        input.value.trim();

    if (!message) {

        showToast(
            "Paste a suspicious message first.",
            "⚠️"
        );

        input.focus();

        return;
    }

    const progress =
        $("message-progress");

    const result =
        $("message-result");

    show(progress);
    hide(result);

    setButtonLoading(
        button,
        true,
        "ANALYZING..."
    );

    const fill =
        $("message-progress-fill");

    const stages = [
        [20, "Reading message..."],
        [40, "Detecting scam language..."],
        [60, "Checking payment indicators..."],
        [78, "Checking links and urgency..."],
        [94, "Calculating risk..."]
    ];

    try {

        for (const [percent, stage] of stages) {

            setText(
                "message-stages",
                stage
            );

            setText(
                "message-progress-percent",
                `${percent}%`
            );

            if (fill) {
                fill.style.width =
                    `${percent}%`;
            }

            await sleep(180);
        }

        const data =
            await postJSON(
                "/scan-message",
                { message }
            );

        if (fill) {
            fill.style.width = "100%";
        }

        renderRiskResult(
            "message",
            data
        );

        recordScan(
            "message",
            Number(data.score) || 0
        );

        showToast(
            "Message analysis complete.",
            "✓"
        );

    } catch (error) {

        showToast(
            error.message ||
            "Message analysis failed.",
            "❌"
        );

    } finally {

        setButtonLoading(
            button,
            false
        );
    }
}

$("scan-message-btn")
    ?.addEventListener(
        "click",
        scanMessage
    );


/* =========================================================
   MESSAGE DEMO
========================================================= */

$("message-demo-btn")
    ?.addEventListener(
        "click",
        () => {

            const message =
                "URGENT! Your bank KYC has expired. Click https://bit.ly/verify-now immediately to update your account or it will be blocked. Share the OTP with our verification agent.";

            setText(
                "message-text",
                message
            );

            const textarea =
                $("message-text");

            if (textarea) {
                textarea.value = message;
            }

            showToast(
                "Demo scam message loaded.",
                "🧪"
            );
        }
    );


/* =========================================================
   CLEAR MESSAGE
========================================================= */

$("clear-message-btn")
    ?.addEventListener(
        "click",
        () => {

            const input =
                $("message-text");

            if (input) {
                input.value = "";
            }

            hide(
                $("message-result")
            );

            showToast(
                "Message cleared.",
                "✓"
            );
        }
    );


/* =========================================================
   SCREENSHOT FILE
========================================================= */

$("screenshot-input")
    ?.addEventListener(
        "change",
        event => {

            const file =
                event.target.files?.[0];

            const display =
                $("selected-file");

            if (!file) {

                if (display) {
                    display.textContent = "";
                }

                return;
            }

            if (file.size > 5 * 1024 * 1024) {

                showToast(
                    "Screenshot must be smaller than 5 MB.",
                    "⚠️"
                );

                event.target.value = "";

                if (display) {
                    display.textContent = "";
                }

                return;
            }

            if (!file.type.startsWith("image/")) {

                showToast(
                    "Please select an image file.",
                    "⚠️"
                );

                event.target.value = "";

                return;
            }

            if (display) {

                display.textContent =
                    `✓ ${file.name}`;
            }
        }
    );


/* =========================================================
   SCREENSHOT ANALYZER
========================================================= */

$("screenshot-form")
    ?.addEventListener(
        "submit",
        async event => {

            event.preventDefault();

            const input =
                $("screenshot-input");

            const button =
                $("analyze-screenshot-btn");

            const file =
                input?.files?.[0];

            if (!file) {

                showToast(
                    "Upload a profile screenshot first.",
                    "⚠️"
                );

                return;
            }

            setButtonLoading(
                button,
                true,
                "ANALYZING..."
            );

            const formData =
                new FormData();

            formData.append(
                "screenshot",
                file
            );

            try {

                const response =
                    await fetch(
                        "/analyze-screenshot",
                        {
                            method: "POST",
                            body: formData
                        }
                    );

                const data =
                    await response.json();

                if (!response.ok) {
                    throw new Error(
                        data.error ||
                        "Screenshot analysis failed."
                    );
                }

                const score =
                    Number(data.score) || 0;

                const info =
                    getRiskInfo(score);

                setText(
                    "screenshot-score",
                    score
                );

                setText(
                    "screenshot-level",
                    info.level
                );

                setText(
                    "screenshot-summary",
                    data.summary ||
                    "Screenshot analysis completed."
                );

                const indicators =
                    $("screenshot-indicators");

                if (indicators) {

                    indicators.innerHTML = "";

                    const list =
                        Array.isArray(data.indicators)
                            ? data.indicators
                            : [];

                    list.forEach(item => {

                        const li =
                            document.createElement("li");

                        li.textContent = item;

                        indicators.appendChild(li);
                    });
                }

                const actions =
                    $("screenshot-actions");

                if (actions) {

                    actions.innerHTML = "";

                    const list =
                        Array.isArray(data.actions)
                            ? data.actions
                            : [
                                "Verify the account independently.",
                                "Do not send money or OTPs.",
                                "Do not open suspicious links."
                            ];

                    list.forEach(item => {

                        const li =
                            document.createElement("li");

                        li.textContent = item;

                        actions.appendChild(li);
                    });
                }

                show(
                    $("screenshot-result")
                );

                recordScan(
                    "social",
                    score
                );

                if (score >= 70) {

                    playDangerSound();
                    triggerDangerMode();
                }

                showToast(
                    "Screenshot analysis complete.",
                    "✓"
                );

            } catch (error) {

                showToast(
                    error.message ||
                    "Screenshot analysis failed.",
                    "❌"
                );

            } finally {

                setButtonLoading(
                    button,
                    false
                );
            }
        }
    );


/* =========================================================
   AI CHAT
========================================================= */

const aiBall =
    $("ai-ball");

const aiChat =
    $("ai-chat");

const aiPopup =
    $("ai-chat-popup");

const aiPopupClose =
    $("ai-popup-close");

const chatClose =
    $("chat-close");

const chatMinimize =
    $("chat-minimize");

const chatInput =
    $("chat-input");

const chatSend =
    $("chat-send");

const chatMessages =
    $("chat-messages");

const chatTyping =
    $("chat-typing");


function openAIChat() {

    if (!aiChat) return;

    aiChat.classList.add("open");

    if (aiPopup) {
        aiPopup.style.display = "none";
    }

    if (chatInput) {
        setTimeout(
            () => chatInput.focus(),
            150
        );
    }
}

function closeAIChat() {

    if (aiChat) {
        aiChat.classList.remove("open");
    }
}

function addChatMessage(
    message,
    type = "bot"
) {

    if (!chatMessages) return;

    const wrapper =
        document.createElement("div");

    wrapper.className =
        `chat-message ${type}`;

    const avatar =
        document.createElement("div");

    avatar.className = "avatar";

    avatar.textContent =
        type === "user"
            ? "👤"
            : "🛡️";

    const bubble =
        document.createElement("div");

    bubble.className = "message";

    const title =
        document.createElement("strong");

    title.textContent =
        type === "user"
            ? "YOU"
            : "SENTINEL AI";

    const text =
        document.createElement("p");

    text.textContent = message;

    bubble.appendChild(title);
    bubble.appendChild(text);

    wrapper.appendChild(avatar);
    wrapper.appendChild(bubble);

    chatMessages.appendChild(wrapper);

    chatMessages.scrollTop =
        chatMessages.scrollHeight;
}


async function sendChatMessage() {

    if (!chatInput) return;

    const message =
        chatInput.value.trim();

    if (!message) return;

    addChatMessage(
        message,
        "user"
    );

    chatInput.value = "";

    show(chatTyping);

    try {

        const response =
            await postJSON(
                "/chat",
                {
                    message
                }
            );

        hide(chatTyping);

        addChatMessage(
            response.reply ||
            response.message ||
            "I couldn't generate a response right now."
        );

    } catch (error) {

        hide(chatTyping);

        addChatMessage(
            "I couldn't connect to the Cyber AI service right now. You can still use the website and message scanners."
        );

        console.error(
            "AI chat error:",
            error
        );
    }
}

aiBall?.addEventListener(
    "click",
    openAIChat
);

aiPopup?.addEventListener(
    "click",
    event => {

        if (
            event.target !== aiPopupClose
        ) {
            openAIChat();
        }
    }
);

aiPopupClose?.addEventListener(
    "click",
    event => {

        event.stopPropagation();

        if (aiPopup) {
            aiPopup.style.display = "none";
        }
    }
);

chatClose?.addEventListener(
    "click",
    closeAIChat
);

chatMinimize?.addEventListener(
    "click",
    closeAIChat
);

chatSend?.addEventListener(
    "click",
    sendChatMessage
);

chatInput?.addEventListener(
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


/* =========================================================
   AI POPUP AUTO HIDE
========================================================= */

setTimeout(() => {

    if (aiPopup) {
        aiPopup.style.display = "none";
    }

}, 6500);


/* =========================================================
   KEYBOARD SHORTCUT
========================================================= */

document.addEventListener(
    "keydown",
    event => {

        if (
            (event.ctrlKey || event.metaKey) &&
            event.key.toLowerCase() === "k"
        ) {

            event.preventDefault();

            openAIChat();
        }

        if (
            event.key === "Escape" &&
            aiChat?.classList.contains("open")
        ) {

            closeAIChat();
        }
    }
);


/* =========================================================
   GAME
========================================================= */

const QUESTION_BANK = [

    {
        q: "You receive an SMS saying your bank account will be blocked unless you click a link. What should you do?",
        options: [
            "Click immediately",
            "Share OTP",
            "Verify through the official bank app/site",
            "Reply with your account number"
        ],
        answer: 2,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "Someone asks for your UPI PIN to send money to you. What is correct?",
        options: [
            "Give the PIN",
            "UPI PIN is not required to receive money",
            "Send OTP instead",
            "Give ATM PIN"
        ],
        answer: 1,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "A job recruiter asks you to pay a registration fee before an interview. What is the strongest warning sign?",
        options: [
            "Professional email",
            "Video interview",
            "Upfront payment demand",
            "Job description"
        ],
        answer: 2,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "Which URL is most suspicious?",
        options: [
            "https://www.google.com",
            "https://bank.example.com",
            "http://secure-bank-login.example.xyz",
            "https://www.microsoft.com"
        ],
        answer: 2,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "What is phishing?",
        options: [
            "A backup technique",
            "A social engineering attack to steal information",
            "A firewall",
            "A password manager"
        ],
        answer: 1,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "A caller claims to be from a bank and asks for your OTP. What should you do?",
        options: [
            "Share it",
            "Read half of it",
            "Refuse and contact the bank independently",
            "Send it by SMS"
        ],
        answer: 2,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "Which is the safest way to verify a suspicious link?",
        options: [
            "Click it and inspect later",
            "Search for the official website independently",
            "Ask the sender for another link",
            "Disable antivirus"
        ],
        answer: 1,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "What does 2FA provide?",
        options: [
            "Two usernames",
            "An additional authentication layer",
            "Two bank accounts",
            "Automatic antivirus"
        ],
        answer: 1,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "A social media profile copies a celebrity's name and asks followers for money. What should you suspect?",
        options: [
            "Official promotion",
            "Impersonation scam",
            "Normal giveaway",
            "Verified banking account"
        ],
        answer: 1,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "You accidentally transferred money to a scammer in India. What should you do first?",
        options: [
            "Wait one week",
            "Send more money",
            "Report immediately through 1930",
            "Delete all evidence"
        ],
        answer: 2,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "Which password is strongest?",
        options: [
            "mohit123",
            "password123",
            "A long unique password/passphrase",
            "12345678"
        ],
        answer: 2,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "What should you do with an unknown APK sent through WhatsApp?",
        options: [
            "Install it",
            "Forward it",
            "Avoid installing it",
            "Disable Play Protect"
        ],
        answer: 2,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "An investment platform promises guaranteed huge returns with no risk. What is this?",
        options: [
            "Normal banking",
            "Potential investment scam",
            "Government guarantee",
            "Password reset"
        ],
        answer: 1,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "Why can urgency be a phishing warning sign?",
        options: [
            "Attackers use pressure to prevent careful verification",
            "Urgent messages are always legitimate",
            "Banks always use urgency",
            "It improves encryption"
        ],
        answer: 0,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "What should you do if a website asks for your OTP unexpectedly?",
        options: [
            "Enter it",
            "Share it with support",
            "Stop and verify the website",
            "Send a screenshot"
        ],
        answer: 2,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "What is social engineering?",
        options: [
            "Manipulating people into revealing information or taking unsafe actions",
            "Building social networks",
            "Encrypting files",
            "Updating software"
        ],
        answer: 0,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "A fake courier message says you must pay ₹25 immediately to release a parcel. What should you do?",
        options: [
            "Pay immediately",
            "Verify through the courier's official website",
            "Share card details",
            "Give OTP"
        ],
        answer: 1,
        difficulty: "MEDIUM",
        points: 20
    },

    {
        q: "What is credential phishing mainly trying to steal?",
        options: [
            "Wallpaper",
            "Login information",
            "Screen brightness",
            "Battery power"
        ],
        answer: 1,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "Which practice improves account security?",
        options: [
            "Reuse passwords",
            "Enable 2FA",
            "Share recovery codes",
            "Use public passwords"
        ],
        answer: 1,
        difficulty: "EASY",
        points: 10
    },

    {
        q: "A caller says they are police and threatens arrest unless you transfer money. What should you suspect?",
        options: [
            "Routine verification",
            "Possible impersonation/extortion scam",
            "Normal banking process",
            "Password reset"
        ],
        answer: 1,
        difficulty: "HARD",
        points: 30
    }

];


/* Generate additional safe variations */
const variationTemplates = [

    "You receive a suspicious message asking you to verify your account urgently. What is the safest response?",
    "A stranger requests an OTP claiming it is required for verification. What should you do?",
    "A website uses a very unusual domain and asks for banking credentials. What should you do?",
    "A social media account promises guaranteed investment returns. What is the safest approach?",
    "Someone asks you to install an unknown application to receive a refund. What should you do?",
    "A message claims you won a prize but asks for a processing fee. What should you suspect?",
    "A caller asks for your card PIN while pretending to be customer support. What should you do?",
    "A shortened URL arrives from an unknown person. What should you do before opening it?",
    "A recruiter asks for money before offering a job. What is the warning sign?",
    "A suspicious account copies a friend's profile photo and asks for money. What should you do?"
];

variationTemplates.forEach(
    (question, index) => {

        QUESTION_BANK.push({

            q: question,

            options: [
                "Act immediately",
                "Share sensitive information",
                "Verify independently before acting",
                "Send payment"
            ],

            answer: 2,

            difficulty:
                index % 3 === 0
                    ? "EASY"
                    : index % 3 === 1
                        ? "MEDIUM"
                        : "HARD",

            points:
                index % 3 === 0
                    ? 10
                    : index % 3 === 1
                        ? 20
                        : 30
        });
    }
);


/* Add generated awareness questions */
const generatedTopics = [
    "OTP",
    "UPI",
    "passwords",
    "phishing links",
    "fake jobs",
    "fake investments",
    "social impersonation",
    "malware",
    "fake courier messages",
    "account takeover",
    "email phishing",
    "QR scams",
    "bank impersonation",
    "fake customer support",
    "romance scams"
];

generatedTopics.forEach(
    (topic, index) => {

        QUESTION_BANK.push({

            q:
                `Which action is safest when dealing with a suspicious ${topic} situation?`,

            options: [
                "Trust it immediately",
                "Share OTP/PIN",
                "Verify through an independent trusted source",
                "Send money"
            ],

            answer: 2,

            difficulty:
                index % 4 === 0
                    ? "EASY"
                    : index % 4 === 1
                        ? "MEDIUM"
                        : index % 4 === 2
                            ? "HARD"
                            : "EXPERT",

            points:
                index % 4 === 0
                    ? 10
                    : index % 4 === 1
                        ? 20
                        : index % 4 === 2
                            ? 30
                            : 50
        });
    }
);


let gameQuestions = [];
let currentQuestion = 0;
let gameScore = 0;
let gameStreak = 0;
let bestStreak = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
let mistakes = [];
let questionStartTime = 0;


function shuffle(array) {

    const copy = [...array];

    for (
        let i = copy.length - 1;
        i > 0;
        i--
    ) {

        const j =
            Math.floor(
                Math.random() * (i + 1)
            );

        [
            copy[i],
            copy[j]
        ] = [
            copy[j],
            copy[i]
        ];
    }

    return copy;
}


function startGame() {

    gameQuestions =
        shuffle(QUESTION_BANK)
            .slice(0, 15);

    currentQuestion = 0;
    gameScore = 0;
    gameStreak = 0;
    bestStreak = 0;
    correctAnswers = 0;
    wrongAnswers = 0;
    mistakes = [];

    hide($("game-start"));
    hide($("game-over"));

    show($("game-play"));

    updateGameStats();

    loadQuestion();
}


function loadQuestion() {

    const question =
        gameQuestions[currentQuestion];

    if (!question) {

        endGame();

        return;
    }

    setText(
        "question-number",
        `${currentQuestion + 1}/15`
    );

    setText(
        "question-text",
        question.q
    );

    setText(
        "question-difficulty",
        question.difficulty
    );

    const progress =
        $("game-progress");

    if (progress) {

        progress.style.width =
            `${(currentQuestion / 15) * 100}%`;
    }

    const options =
        $("question-options");

    if (!options) return;

    options.innerHTML = "";

    question.options.forEach(
        (option, index) => {

            const button =
                document.createElement("button");

            button.textContent =
                option;

            button.addEventListener(
                "click",
                () => answerQuestion(index)
            );

            options.appendChild(button);
        }
    );

    setText(
        "answer-feedback",
        ""
    );

    questionStartTime =
        Date.now();
}


function answerQuestion(selected) {

    const question =
        gameQuestions[currentQuestion];

    if (!question) return;

    const buttons =
        $$("#question-options button");

    buttons.forEach(
        button => {
            button.disabled = true;
        }
    );

    const elapsed =
        (Date.now() - questionStartTime) / 1000;

    const correct =
        selected === question.answer;

    if (correct) {

        correctAnswers++;

        gameStreak++;

        bestStreak =
            Math.max(
                bestStreak,
                gameStreak
            );

        let points =
            question.points;

        if (elapsed < 5) {
            points += 5;
        }

        if (gameStreak >= 3) {
            points += 5;
        }

        gameScore += points;

        setText(
            "answer-feedback",
            `✓ Correct! +${points} points`
        );

    } else {

        wrongAnswers++;

        gameStreak = 0;

        mistakes.push({
            question: question.q,
            correct:
                question.options[
                    question.answer
                ],
            selected:
                question.options[selected]
        });

        setText(
            "answer-feedback",
            `✕ Incorrect. Correct answer: ${question.options[question.answer]}`
        );
    }

    updateGameStats();

    setTimeout(
        () => {

            currentQuestion++;

            loadQuestion();

        },
        900
    );
}


function updateGameStats() {

    setText(
        "game-score",
        gameScore
    );

    setText(
        "game-streak",
        gameStreak
    );

    setText(
        "game-correct",
        correctAnswers
    );

    setText(
        "game-wrong",
        wrongAnswers
    );

    setText(
        "game-best-streak",
        bestStreak
    );
}


function endGame() {

    hide($("game-play"));
    show($("game-over"));

    const accuracy =
        Math.round(
            (correctAnswers / 15) * 100
        );

    let level =
        "BEGINNER";

    if (accuracy >= 60) {
        level = "CYBER LEARNER";
    }

    if (accuracy >= 75) {
        level = "CYBER DEFENDER";
    }

    if (accuracy >= 90) {
        level = "CYBER GUARDIAN";
    }

    setText(
        "final-score",
        gameScore
    );

    setText(
        "final-level",
        level
    );

    setText(
        "final-correct",
        correctAnswers
    );

    setText(
        "final-wrong",
        wrongAnswers
    );

    setText(
        "final-streak",
        bestStreak
    );

    setText(
        "final-accuracy",
        `${accuracy}%`
    );

    const mistakeReview =
        $("mistake-review");

    if (mistakeReview) {

        mistakeReview.innerHTML = "";

        if (!mistakes.length) {

            mistakeReview.innerHTML =
                "<strong>🎯 Perfect run! No mistakes.</strong>";

        } else {

            const title =
                document.createElement("h3");

            title.textContent =
                "🧠 Mistake Review";

            mistakeReview.appendChild(title);

            mistakes.forEach(
                mistake => {

                    const item =
                        document.createElement("div");

                    item.style.marginTop =
                        "12px";

                    item.innerHTML = `
                        <strong>${escapeHTML(mistake.question)}</strong>
                        <br>
                        <span>Correct: ${escapeHTML(mistake.correct)}</span>
                    `;

                    mistakeReview.appendChild(item);
                }
            );
        }
    }

    const stats =
        getStats();

    if (gameScore > stats.bestScore) {

        stats.bestScore =
            gameScore;

        saveStats(stats);
    }

    updateDashboard();
}


$("start-game-btn")
    ?.addEventListener(
        "click",
        startGame
    );

$("restart-game-btn")
    ?.addEventListener(
        "click",
        startGame
    );

setText(
    "question-bank-count",
    `${QUESTION_BANK.length}+`
);


/* =========================================================
   INITIALIZATION
========================================================= */

updateDashboard();

console.log(
    `%cSENTINEL CYBER INTELLIGENCE%c\nSystem initialized.`,
    "color:#35d9ff;font-size:20px;font-weight:bold;",
    "color:#8ea3bd;"
);
