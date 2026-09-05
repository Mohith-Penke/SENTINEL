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
    if (el) el.textContent = value ?? "";
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showToast(message, icon = "✓") {
    const toast = $("toast");
    if (!toast) return;

    setText("toast-message", message);
    setText("toast-icon", icon);

    toast.classList.add("show");

    clearTimeout(window.__toastTimer);

    window.__toastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
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
        throw new Error("Invalid server response.");
    }

    if (!response.ok) {
        throw new Error(result.error || "Request failed.");
    }

    return result;
}

function setButtonLoading(button, loading, text) {
    if (!button) return;

    if (loading) {
        button.dataset.originalText = button.textContent;
        button.disabled = true;
        button.textContent = text || "SCANNING...";
    } else {
        button.disabled = false;
        button.textContent =
            button.dataset.originalText || text || "SCAN";
    }
}


/* =========================================================
   NAVIGATION
========================================================= */

function openPage(pageId) {
    const pages = document.querySelectorAll(".page");

    pages.forEach(page => {
        page.classList.remove("active");
    });

    const target = $(pageId);

    if (target) {
        target.classList.add("active");
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }
}

document.querySelectorAll("[data-target]").forEach(button => {

    button.addEventListener("click", () => {

        const target = button.dataset.target;

        if (target) {
            openPage(target);
        }

    });

});


/* =========================================================
   RISK RESULT
========================================================= */

function renderRiskResult(prefix, result) {

    if (!result) return;

    const score = Number(result.score || 0);
    const level = result.level || "LOW";

    setText(`${prefix}-score`, score);
    setText(`${prefix}-level`, level);
    setText(`${prefix}-summary`, result.summary || "");

    const reasons = $( `${prefix}-reasons` );
    const actions = $( `${prefix}-actions` );

    if (reasons) {
        reasons.innerHTML = "";

        (result.reasons || []).forEach(reason => {

            const li = document.createElement("li");
            li.textContent = reason;
            reasons.appendChild(li);

        });
    }

    if (actions) {
        actions.innerHTML = "";

        (result.actions || []).forEach(action => {

            const li = document.createElement("li");
            li.textContent = action;
            actions.appendChild(li);

        });
    }

    const meter = $(`${prefix}-meter-fill`);

    if (meter) {
        meter.style.width = `${score}%`;
    }

    show($(`${prefix}-result`));

    updateStats(prefix, result);

    if (level === "HIGH" || level === "CRITICAL") {
        triggerDangerMode();
    }

}


/* =========================================================
   DASHBOARD STORAGE
========================================================= */

const DEFAULT_STATS = {
    websiteScans: 0,
    highRisk: 0,
    critical: 0,
    messageScans: 0,
    socialScans: 0,
    bestScore: 0,
    total: 0,
    level: "BEGINNER"
};

function getStats() {

    try {
        const saved = localStorage.getItem("sentinelStats");

        if (!saved) {
            return { ...DEFAULT_STATS };
        }

        return {
            ...DEFAULT_STATS,
            ...JSON.parse(saved)
        };

    } catch {
        return { ...DEFAULT_STATS };
    }
}

function saveStats(stats) {
    localStorage.setItem(
        "sentinelStats",
        JSON.stringify(stats)
    );
}

function updateStats(prefix, result) {

    const stats = getStats();

    stats.total++;

    const level = result.level;

    if (level === "HIGH") {
        stats.highRisk++;
    }

    if (level === "CRITICAL") {
        stats.critical++;
    }

    if (prefix === "website") {
        stats.websiteScans++;
    }

    if (prefix === "message") {
        stats.messageScans++;
    }

    if (prefix === "screenshot") {
        stats.socialScans++;
    }

    saveStats(stats);

    renderDashboard();
}

function renderDashboard() {

    const stats = getStats();

    setText("dash-website-scans", stats.websiteScans);
    setText("dash-high-risk", stats.highRisk);
    setText("dash-critical", stats.critical);
    setText("dash-messages", stats.messageScans);
    setText("dash-social", stats.socialScans);
    setText("dash-best-score", stats.bestScore);
    setText("dash-total", stats.total);
    setText("dash-level", stats.level);
}


/* =========================================================
   DANGER MODE
========================================================= */

function triggerDangerMode() {

    document.body.classList.add("danger-mode");

    clearTimeout(window.__dangerTimer);

    window.__dangerTimer = setTimeout(() => {
        document.body.classList.remove("danger-mode");
    }, 1800);
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

    setButtonLoading(button, true, "ANALYZING...");

    const fill = $("website-progress-fill");
    const percent = $("website-progress-percent");
    const stages = $("website-stages");

    try {

        const steps = [
            ["Checking URL structure...", 25],
            ["Checking suspicious indicators...", 50],
            ["Analyzing domain patterns...", 75],
            ["Generating risk report...", 100]
        ];

        for (const [stage, value] of steps) {

            setText("website-stages", stage);

            if (fill) {
                fill.style.width = `${value}%`;
            }

            if (percent) {
                percent.textContent = `${value}%`;
            }

            await sleep(180);
        }

        const result = await postJSON("/scan", {
            url: url
        });

        renderRiskResult("website", result);

        showToast(
            `Website analysis complete: ${result.level}`,
            result.level === "LOW" ? "✓" : "!"
        );

    } catch (error) {

        showToast(error.message || "Website scan failed.", "!");

    } finally {

        setButtonLoading(button, false);
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

    const input = $("message-text");
    const button = $("scan-message-btn");
    const progress = $("message-progress");

    if (!input || !button) return;

    const message = input.value.trim();

    if (!message) {
        showToast("Paste a message first.", "!");
        input.focus();
        return;
    }

    hide($("message-result"));
    show(progress);

    setButtonLoading(button, true, "ANALYZING...");

    const fill = $("message-progress-fill");

    try {

        const steps = [
            ["Reading message patterns...", 25],
            ["Checking scam indicators...", 50],
            ["Checking urgency and payment signals...", 75],
            ["Generating risk report...", 100]
        ];

        for (const [stage, value] of steps) {

            setText("message-stages", stage);

            if (fill) {
                fill.style.width = `${value}%`;
            }

            setText(
                "message-progress-percent",
                `${value}%`
            );

            await sleep(180);
        }

        const result = await postJSON(
            "/scan-message",
            { message: message }
        );

        renderRiskResult("message", result);

        showToast(
            `Message analysis complete: ${result.level}`,
            result.level === "LOW" ? "✓" : "!"
        );

    } catch (error) {

        showToast(
            error.message || "Message scan failed.",
            "!"
        );

    } finally {

        setButtonLoading(button, false);
        hide(progress);

    }
}

$("scan-message-btn")?.addEventListener(
    "click",
    scanMessage
);


/* =========================================================
   MESSAGE DEMO
========================================================= */

$("message-demo-btn")?.addEventListener(
    "click",
    () => {

        const demo =
            "URGENT! Your bank account will be blocked today. " +
            "Verify your KYC immediately using this link " +
            "https://bit.ly/verify-account and share your OTP.";

        setText("message-text", demo);

        showToast(
            "Demo scam message loaded.",
            "!"
        );
    }
);


/* =========================================================
   CLEAR MESSAGE
========================================================= */

$("clear-message-btn")?.addEventListener(
    "click",
    () => {

        const input = $("message-text");

        if (input) {
            input.value = "";
        }

        hide($("message-result"));

        showToast(
            "Message cleared.",
            "✓"
        );
    }
);


/* =========================================================
   SOCIAL SCREENSHOT
========================================================= */

const screenshotInput = $("screenshot-input");

screenshotInput?.addEventListener(
    "change",
    () => {

        const file = screenshotInput.files?.[0];

        if (!file) {
            setText(
                "selected-file",
                "No file selected"
            );
            return;
        }

        setText(
            "selected-file",
            file.name
        );
    }
);


$("screenshot-form")?.addEventListener(
    "submit",
    async event => {

        event.preventDefault();

        const file = screenshotInput?.files?.[0];

        if (!file) {
            showToast(
                "Select a screenshot first.",
                "!"
            );
            return;
        }

        if (!file.type.startsWith("image/")) {
            showToast(
                "Please select an image file.",
                "!"
            );
            return;
        }

        const button = $("analyze-screenshot-btn");

        setButtonLoading(
            button,
            true,
            "ANALYZING..."
        );

        try {

            const formData = new FormData();

            formData.append(
                "screenshot",
                file
            );

            const response = await fetch(
                "/analyze-screenshot",
                {
                    method: "POST",
                    body: formData
                }
            );

            const result = await response.json();

            if (!response.ok) {
                throw new Error(
                    result.error ||
                    "Screenshot analysis failed."
                );
            }

            setText(
                "screenshot-score",
                result.score
            );

            setText(
                "screenshot-level",
                result.level
            );

            setText(
                "screenshot-summary",
                result.summary
            );

            const indicators =
                $("screenshot-indicators");

            if (indicators) {

                indicators.innerHTML = "";

                (result.reasons || []).forEach(
                    reason => {

                        const li =
                            document.createElement("li");

                        li.textContent = reason;

                        indicators.appendChild(li);
                    }
                );
            }

            const actions =
                $("screenshot-actions");

            if (actions) {

                actions.innerHTML = "";

                (result.actions || []).forEach(
                    action => {

                        const li =
                            document.createElement("li");

                        li.textContent = action;

                        actions.appendChild(li);
                    }
                );
            }

            show($("screenshot-result"));

            updateStats(
                "screenshot",
                result
            );

            if (
                result.level === "HIGH" ||
                result.level === "CRITICAL"
            ) {
                triggerDangerMode();
            }

            showToast(
                `Screenshot analysis complete: ${result.level}`,
                "✓"
            );

        } catch (error) {

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
);


/* =========================================================
   AI CHAT
========================================================= */

function addChatMessage(
    text,
    sender = "ai"
) {

    const container = $("chat-messages");

    if (!container) return;

    const wrapper =
        document.createElement("div");

    wrapper.className =
        `chat-message ${sender === "user" ? "user" : ""}`;

    const avatar =
        document.createElement("div");

    avatar.className = "avatar";

    avatar.textContent =
        sender === "user" ? "U" : "✦";

    const message =
        document.createElement("div");

    message.className = "message";

    const title =
        document.createElement("strong");

    title.textContent =
        sender === "user"
            ? "YOU"
            : "SENTINEL AI";

    const paragraph =
        document.createElement("p");

    paragraph.textContent = text;

    message.appendChild(title);
    message.appendChild(paragraph);

    wrapper.appendChild(avatar);
    wrapper.appendChild(message);

    container.appendChild(wrapper);

    container.scrollTop =
        container.scrollHeight;
}


async function sendChatMessage() {

    const input = $("chat-input");
    const button = $("chat-send");

    if (!input) return;

    const message =
        input.value.trim();

    if (!message) return;

    addChatMessage(
        message,
        "user"
    );

    input.value = "";

    show($("chat-typing"));

    if (button) {
        button.disabled = true;
    }

    try {

        const result = await postJSON(
            "/chat",
            {
                message: message
            }
        );

        await sleep(250);

        addChatMessage(
            result.response ||
            "I could not generate a response.",
            "ai"
        );

    } catch (error) {

        addChatMessage(
            "Sorry, I could not connect to Cyber AI.",
            "ai"
        );

    } finally {

        hide($("chat-typing"));

        if (button) {
            button.disabled = false;
        }

        input.focus();
    }
}


$("chat-send")?.addEventListener(
    "click",
    sendChatMessage
);


$("chat-input")?.addEventListener(
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
   AI BALL
========================================================= */

const aiBall = $("ai-ball");
const aiChat = $("ai-chat");
const aiPopup = $("ai-chat-popup");

function openAIChat() {

    if (!aiChat) return;

    aiChat.classList.add("open");

    if (aiPopup) {
        hide(aiPopup);
    }

    setTimeout(() => {
        $("chat-input")?.focus();
    }, 100);
}

function closeAIChat() {

    if (!aiChat) return;

    aiChat.classList.remove("open");
}

aiBall?.addEventListener(
    "click",
    openAIChat
);

$("ai-popup-close")?.addEventListener(
    "click",
    () => {
        hide(aiPopup);
    }
);

$("chat-close")?.addEventListener(
    "click",
    closeAIChat
);

$("chat-minimize")?.addEventListener(
    "click",
    closeAIChat
);


/* =========================================================
   KEYBOARD ESCAPE
========================================================= */

document.addEventListener(
    "keydown",
    event => {

        if (event.key === "Escape") {
            closeAIChat();
        }

    }
);


/* =========================================================
   CYBER GAME
========================================================= */

const QUESTIONS = [

    {
        q: "You receive an unexpected OTP request from someone claiming to be bank support. What should you do?",
        options: [
            "Share the OTP",
            "Ignore and never share the OTP",
            "Send your PIN too",
            "Forward the message"
        ],
        answer: 1,
        difficulty: "EASY"
    },

    {
        q: "Which is the safest website address?",
        options: [
            "http://bank-login-free.com",
            "https://bank.example.com",
            "http://secure-bank-login.xyz",
            "https://bank-login-verify-free.com"
        ],
        answer: 1,
        difficulty: "EASY"
    },

    {
        q: "A stranger asks you to pay a registration fee for a guaranteed job. What is the best response?",
        options: [
            "Pay immediately",
            "Send your OTP",
            "Verify the employer independently",
            "Send your bank password"
        ],
        answer: 2,
        difficulty: "EASY"
    },

    {
        q: "What does phishing mainly attempt to steal?",
        options: [
            "Screen brightness",
            "Credentials and sensitive information",
            "Battery power",
            "Computer wallpaper"
        ],
        answer: 1,
        difficulty: "EASY"
    },

    {
        q: "What should you do before clicking an unexpected link?",
        options: [
            "Click quickly",
            "Check the destination and domain",
            "Forward it",
            "Disable antivirus"
        ],
        answer: 1,
        difficulty: "EASY"
    },

    {
        q: "Which password is strongest?",
        options: [
            "mohith123",
            "password",
            "MyName2009",
            "A unique long password with mixed characters"
        ],
        answer: 3,
        difficulty: "MEDIUM"
    },

    {
        q: "Someone says your account will be blocked unless you act in five minutes. This is an example of:",
        options: [
            "Urgency tactic",
            "Normal support",
            "Software update",
            "Backup"
        ],
        answer: 0,
        difficulty: "EASY"
    },

    {
        q: "What should you do if you receive a suspicious bank message?",
        options: [
            "Use the link in the message",
            "Reply with OTP",
            "Contact the bank using its official channel",
            "Send your card number"
        ],
        answer: 2,
        difficulty: "MEDIUM"
    },

    {
        q: "What is two-factor authentication designed to provide?",
        options: [
            "Extra security verification",
            "Faster internet",
            "More storage",
            "Free Wi-Fi"
        ],
        answer: 0,
        difficulty: "EASY"
    },

    {
        q: "A social media profile promises to double your money quickly. What should you suspect?",
        options: [
            "Guaranteed investment opportunity",
            "Possible scam",
            "Normal banking",
            "Software update"
        ],
        answer: 1,
        difficulty: "MEDIUM"
    },

    {
        q: "Why should you avoid shortened links from unknown senders?",
        options: [
            "They always contain viruses",
            "They can hide the real destination",
            "They improve security",
            "They are official links"
        ],
        answer: 1,
        difficulty: "MEDIUM"
    },

    {
        q: "Which information should never be shared casually?",
        options: [
            "Favorite color",
            "OTP and password",
            "Favorite movie",
            "Public username"
        ],
        answer: 1,
        difficulty: "EASY"
    },

    {
        q: "You receive a prize notification for a contest you never entered. What should you do?",
        options: [
            "Pay the processing fee",
            "Share bank details",
            "Treat it as suspicious",
            "Send OTP"
        ],
        answer: 2,
        difficulty: "EASY"
    },

    {
        q: "What is a common sign of a fake website?",
        options: [
            "Correct official domain",
            "Suspicious spelling in the domain",
            "Normal HTTPS",
            "Official contact information"
        ],
        answer: 1,
        difficulty: "MEDIUM"
    },

    {
        q: "What should you do with a suspicious attachment?",
        options: [
            "Open it immediately",
            "Verify the sender before opening",
            "Forward it to everyone",
            "Disable security software"
        ],
        answer: 1,
        difficulty: "MEDIUM"
    },

    {
        q: "Which action is safest on public Wi-Fi?",
        options: [
            "Access sensitive accounts without protection",
            "Share passwords",
            "Avoid sensitive transactions when possible",
            "Disable all security"
        ],
        answer: 2,
        difficulty: "MEDIUM"
    },

    {
        q: "A caller claiming to be police demands an immediate payment to avoid arrest. What is this likely to be?",
        options: [
            "Normal procedure",
            "Possible impersonation scam",
            "Software update",
            "Bank verification"
        ],
        answer: 1,
        difficulty: "HARD"
    },

    {
        q: "What is social engineering?",
        options: [
            "Manipulating people into revealing information",
            "Building a social media page",
            "Installing a printer",
            "Changing a password"
        ],
        answer: 0,
        difficulty: "MEDIUM"
    },

    {
        q: "If your account may have been compromised, what should you do first?",
        options: [
            "Ignore it",
            "Change the password and secure the account",
            "Share the password",
            "Delete all evidence"
        ],
        answer: 1,
        difficulty: "MEDIUM"
    },

    {
        q: "What is the safest way to verify an organization contacting you?",
        options: [
            "Use the link they sent",
            "Call a number from the message",
            "Find the official website independently",
            "Ask another unknown person"
        ],
        answer: 2,
        difficulty: "HARD"
    }

];


let gameState = {
    questions: [],
    index: 0,
    score: 0,
    streak: 0,
    bestStreak: 0,
    correct: 0,
    wrong: 0,
    mistakes: []
};


function shuffle(array) {

    const copy = [...array];

    for (
        let i = copy.length - 1;
        i > 0;
        i--
    ) {

        const j =
            Math.floor(Math.random() * (i + 1));

        [copy[i], copy[j]] =
            [copy[j], copy[i]];
    }

    return copy;
}


function startGame() {

    gameState = {
        questions: shuffle(QUESTIONS),
        index: 0,
        score: 0,
        streak: 0,
        bestStreak: 0,
        correct: 0,
        wrong: 0,
        mistakes: []
    };

    setText(
        "question-bank-count",
        QUESTIONS.length
    );

    hide($("game-start"));
    hide($("game-over"));
    show($("game-play"));

    updateGameStats();

    showQuestion();
}


function showQuestion() {

    const question =
        gameState.questions[
            gameState.index
        ];

    if (!question) {
        endGame();
        return;
    }

    setText(
        "question-number",
        `Question ${gameState.index + 1} / ${gameState.questions.length}`
    );

    setText(
        "question-text",
        question.q
    );

    setText(
        "question-difficulty",
        question.difficulty
    );

    setText(
        "answer-feedback",
        ""
    );

    const progress =
        ((gameState.index) /
        gameState.questions.length) * 100;

    const progressBar =
        $("game-progress");

    if (progressBar) {
        progressBar.style.width =
            `${progress}%`;
    }

    const options =
        $("question-options");

    if (!options) return;

    options.innerHTML = "";

    question.options.forEach(
        (option, index) => {

            const button =
                document.createElement("button");

            button.type = "button";

            button.textContent =
                `${String.fromCharCode(65 + index)}. ${option}`;

            button.addEventListener(
                "click",
                () => answerQuestion(index)
            );

            options.appendChild(button);
        }
    );
}


function answerQuestion(selected) {

    const question =
        gameState.questions[
            gameState.index
        ];

    if (!question) return;

    const buttons =
        document.querySelectorAll(
            "#question-options button"
        );

    buttons.forEach(
        button => {
            button.disabled = true;
        }
    );

    const correct =
        selected === question.answer;

    if (correct) {

        gameState.correct++;

        gameState.streak++;

        gameState.bestStreak =
            Math.max(
                gameState.bestStreak,
                gameState.streak
            );

        const points =
            100 +
            (gameState.streak - 1) * 25;

        gameState.score += points;

        setText(
            "answer-feedback",
            `✓ Correct! +${points} points`
        );

    } else {

        gameState.wrong++;

        gameState.streak = 0;

        gameState.mistakes.push({
            question: question.q,
            selected:
                question.options[selected],
            correct:
                question.options[question.answer]
        });

        setText(
            "answer-feedback",
            `✗ Incorrect. Correct answer: ${question.options[question.answer]}`
        );
    }

    updateGameStats();

    setTimeout(
        () => {

            gameState.index++;

            showQuestion();

        },
        900
    );
}


function updateGameStats() {

    setText(
        "game-score",
        gameState.score
    );

    setText(
        "game-streak",
        gameState.streak
    );

    setText(
        "game-correct",
        gameState.correct
    );

    setText(
        "game-wrong",
        gameState.wrong
    );

    setText(
        "game-best-streak",
        gameState.bestStreak
    );
}


function endGame() {

    hide($("game-play"));
    show($("game-over"));

    const total =
        gameState.correct +
        gameState.wrong;

    const accuracy =
        total > 0
            ? Math.round(
                gameState.correct /
                total * 100
            )
            : 0;

    let level = "BEGINNER";

    if (accuracy >= 90) {
        level = "CYBER EXPERT";
    } else if (accuracy >= 75) {
        level = "ADVANCED";
    } else if (accuracy >= 55) {
        level = "INTERMEDIATE";
    }

    setText(
        "final-score",
        gameState.score
    );

    setText(
        "final-level",
        level
    );

    setText(
        "final-correct",
        gameState.correct
    );

    setText(
        "final-wrong",
        gameState.wrong
    );

    setText(
        "final-streak",
        gameState.bestStreak
    );

    setText(
        "final-accuracy",
        `${accuracy}%`
    );

    const mistakes =
        $("mistake-review");

    if (mistakes) {

        if (gameState.mistakes.length) {

            mistakes.innerHTML =
                "<h3>Mistake Review</h3>";

            gameState.mistakes.forEach(
                mistake => {

                    const item =
                        document.createElement("div");

                    item.style.marginBottom = "15px";

                    item.innerHTML = `
                        <strong>${escapeHTML(mistake.question)}</strong>
                        <p style="margin-top:5px;">
                            Your answer:
                            ${escapeHTML(mistake.selected)}
                        </p>
                        <p>
                            Correct:
                            ${escapeHTML(mistake.correct)}
                        </p>
                    `;

                    mistakes.appendChild(item);
                }
            );

            show(mistakes);

        } else {

            hide(mistakes);
        }
    }

    const stats = getStats();

    stats.bestScore =
        Math.max(
            stats.bestScore,
            gameState.score
        );

    stats.level = level;

    saveStats(stats);

    renderDashboard();

    const progress =
        $("game-progress");

    if (progress) {
        progress.style.width = "100%";
    }
}


$("start-game-btn")?.addEventListener(
    "click",
    startGame
);


$("restart-game-btn")?.addEventListener(
    "click",
    startGame
);


/* =========================================================
   INITIALIZATION
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        renderDashboard();

        setText(
            "question-bank-count",
            QUESTIONS.length
        );

        hide($("game-play"));
        hide($("game-over"));

        const pages =
            document.querySelectorAll(".page");

        pages.forEach(page => {

            if (page.id === "home") {
                page.classList.add("active");
            }
        });

    }
);
