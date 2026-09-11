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

    try {

        const steps = [
            ["Checking URL structure...", 25],
            ["Checking suspicious indicators...", 50],
            ["Checking SSL certificate...", 65],
            ["Analyzing visual similarity...", 85],
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

        if (!result) {
            throw new Error("No result received from server.");
        }

        renderRiskResult("website", result);

        showToast(
            `Website analysis complete: ${result.level || "UNKNOWN"}`,
            result.level === "LOW" ? "✓" : "!"
        );

    } catch (error) {

        console.error("SENTINEL website scan error:", error);

        showToast(
            error.message || "Website scan failed.",
            "!"
        );

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
