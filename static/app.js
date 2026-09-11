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

    const reasons = $(`${prefix}-reasons`);
    const actions = $(`${prefix}-actions`);

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


    /* =====================================================
       WEBSITE SECURITY CHECKS
       Existing UI/features remain untouched.
    ===================================================== */

    if (prefix === "website") {

        const ssl = result.ssl_check || {};
        const visual = result.visual_similarity || {};

        const sslStatus = $("website-ssl-status");
        const visualStatus = $("website-visual-status");


        /* =================================================
           SSL / CERTIFICATE RESULT
        ================================================= */

        if (sslStatus) {

            let sslHTML = "";

            if (!ssl.checked) {

                sslHTML = `
                    <strong>NOT CHECKED</strong>
                    ${ssl.error
                        ? `<br><small>${escapeHTML(ssl.error)}</small>`
                        : ""}
                `;

            } else {

                const statusClass =
                    ssl.valid
                        ? "VALID"
                        : "INVALID";

                sslHTML = `
                    <div class="ssl-result-details">

                        <strong>
                            ${ssl.valid
                                ? "VALID ✓"
                                : "INVALID ✗"}
                        </strong>

                        <br>

                        <small>
                            HTTPS:
                            ${ssl.https
                                ? "SECURE ✓"
                                : "NOT SECURE ✗"}
                        </small>

                        <br>

                        <small>
                            Hostname:
                            ${ssl.hostname_match
                                ? "MATCHED ✓"
                                : "MISMATCH ✗"}
                        </small>

                        <br>

                        <small>
                            Trust:
                            ${ssl.trusted
                                ? "TRUSTED ✓"
                                : "NOT TRUSTED ✗"}
                        </small>

                        ${
                            ssl.issuer
                                ? `
                                    <br>
                                    <small>
                                        Issuer:
                                        ${escapeHTML(
                                            ssl.issuer
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                        ${
                            ssl.valid_from
                                ? `
                                    <br>
                                    <small>
                                        Valid From:
                                        ${escapeHTML(
                                            ssl.valid_from
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                        ${
                            ssl.valid_until
                                ? `
                                    <br>
                                    <small>
                                        Valid Until:
                                        ${escapeHTML(
                                            ssl.valid_until
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                        ${
                            ssl.days_remaining !== null &&
                            ssl.days_remaining !== undefined
                                ? `
                                    <br>
                                    <small>
                                        Days Remaining:
                                        ${escapeHTML(
                                            ssl.days_remaining
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                        ${
                            ssl.tls_version
                                ? `
                                    <br>
                                    <small>
                                        TLS:
                                        ${escapeHTML(
                                            ssl.tls_version
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                        ${
                            ssl.cipher
                                ? `
                                    <br>
                                    <small>
                                        Cipher:
                                        ${escapeHTML(
                                            ssl.cipher
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                        ${
                            ssl.error
                                ? `
                                    <br>
                                    <small>
                                        ⚠️
                                        ${escapeHTML(
                                            ssl.error
                                        )}
                                    </small>
                                  `
                                : ""
                        }

                    </div>
                `;
            }

            sslStatus.innerHTML = sslHTML;
        }


        /* =================================================
           VISUAL SIMILARITY RESULT
        ================================================= */

        if (visualStatus) {

            if (visual.checked) {

                const similarity =
                    Number(
                        visual.similarity_percent
                    );

                if (Number.isFinite(similarity)) {

                    if (visual.cloning_indicator) {

                        visualStatus.innerHTML = `
                            <strong>
                                ${similarity.toFixed(1)}%
                                similarity ⚠
                            </strong>
                            <br>
                            <small>
                                POSSIBLE VISUAL CLONING
                            </small>
                            ${
                                visual.reference_brand
                                    ? `
                                        <br>
                                        <small>
                                            Reference:
                                            ${escapeHTML(
                                                visual.reference_brand
                                            )}
                                        </small>
                                      `
                                    : ""
                            }
                        `;

                    } else {

                        visualStatus.innerHTML = `
                            <strong>
                                ${similarity.toFixed(1)}%
                                similarity ✓
                            </strong>
                            <br>
                            <small>
                                No strong visual cloning match
                            </small>
                            ${
                                visual.reference_brand
                                    ? `
                                        <br>
                                        <small>
                                            Reference:
                                            ${escapeHTML(
                                                visual.reference_brand
                                            )}
                                        </small>
                                      `
                                    : ""
                            }
                        `;
                    }

                } else {

                    visualStatus.innerHTML = `
                        <strong>CHECKED</strong>
                        ${
                            visual.reason
                                ? `
                                    <br>
                                    <small>
                                        ${escapeHTML(
                                            visual.reason
                                        )}
                                    </small>
                                  `
                                : ""
                        }
                    `;
                }

            } else {

                visualStatus.innerHTML = `
                    <strong>NOT CHECKED</strong>
                    ${
                        visual.reason
                            ? `
                                <br>
                                <small>
                                    ${escapeHTML(
                                        visual.reason
                                    )}
                                </small>
                              `
                            : ""
                    }
                `;
            }
        }
    }


    /* =====================================================
       SHOW RESULT
    ===================================================== */

    show($(`${prefix}-result`));

    updateStats(prefix, result);


    /* =====================================================
       DANGER MODE
    ===================================================== */

    if (
        level === "HIGH" ||
        level === "CRITICAL"
    ) {
        triggerDangerMode();
    }
}
