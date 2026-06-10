/**
 * Password Security Analyzer — dashboard logic.
 *
 * Debounces input, POSTs the password to /api/analyze over the same
 * origin, and renders the JSON report. All DOM insertion of
 * server-supplied strings uses textContent (never innerHTML) to rule
 * out XSS via crafted analysis output.
 */
(function () {
    "use strict";

    const DEBOUNCE_MS = 350;

    const input = document.getElementById("password-input");
    const toggleBtn = document.getElementById("toggle-visibility");
    const visibilityIcon = document.getElementById("visibility-icon");
    const breachToggle = document.getElementById("breach-toggle");
    const errorBox = document.getElementById("error-message");
    const results = document.getElementById("results");

    const strengthBar = document.getElementById("strength-bar");
    const strengthLabel = document.getElementById("strength-label");
    const strengthProgress = document.getElementById("strength-progress");

    const TIER_CLASSES = [
        "tier-very-weak", "tier-weak", "tier-moderate", "tier-strong", "tier-very-strong",
    ];

    function tierClass(label) {
        return "tier-" + label.toLowerCase().replace(/\s+/g, "-");
    }

    let debounceTimer = null;
    let inflight = null;

    input.addEventListener("input", scheduleAnalysis);
    breachToggle.addEventListener("change", scheduleAnalysis);

    toggleBtn.addEventListener("click", function () {
        const showing = input.type === "text";
        input.type = showing ? "password" : "text";
        visibilityIcon.className = showing ? "bi bi-eye" : "bi bi-eye-slash";
        input.focus();
    });

    function scheduleAnalysis() {
        clearTimeout(debounceTimer);
        const password = input.value;
        if (!password) {
            resetUI();
            return;
        }
        debounceTimer = setTimeout(function () { analyze(password); }, DEBOUNCE_MS);
    }

    async function analyze(password) {
        // Abort any in-flight request so stale responses can't win the race.
        if (inflight) inflight.abort();
        inflight = new AbortController();

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    password: password,
                    check_breach: breachToggle.checked,
                }),
                signal: inflight.signal,
            });
            const data = await response.json();
            if (!response.ok) {
                showError(data.error || "Analysis failed.");
                return;
            }
            hideError();
            render(data);
        } catch (err) {
            if (err.name !== "AbortError") {
                showError("Could not reach the analysis service.");
            }
        }
    }

    function render(data) {
        results.classList.remove("d-none");

        // --- strength meter ---
        const score = data.score.score;
        const label = data.score.label;
        strengthBar.style.width = score + "%";
        strengthProgress.setAttribute("aria-valuenow", String(score));
        TIER_CLASSES.forEach(function (c) {
            strengthBar.classList.remove(c);
            strengthLabel.classList.remove(c);
        });
        const tier = tierClass(label);
        strengthBar.classList.add(tier);
        strengthLabel.classList.add("tier-label", tier);
        strengthLabel.textContent = label + " (" + score + "/100)";

        // --- entropy card ---
        document.getElementById("entropy-bits").textContent = data.entropy.bits;
        const categoryBadge = document.getElementById("entropy-category");
        categoryBadge.textContent = data.entropy.category;
        categoryBadge.className = "badge mb-3 text-bg-" + badgeColor(data.entropy.category);

        document.querySelectorAll("#charset-list li").forEach(function (li) {
            const present = data.entropy.character_classes[li.dataset.class];
            li.classList.toggle("present", Boolean(present));
        });

        // --- crack time card ---
        document.getElementById("crack-time").textContent = data.crack_time.display;
        document.getElementById("crack-model").textContent =
            "Model: " + data.crack_time.attack_model + " (" +
            Number(data.crack_time.guesses_per_second).toExponential(0) + " guesses/sec)";

        renderBreach(data.breach);
        renderRecommendations(data.recommendations);
        renderPatterns(data.patterns);
    }

    function renderBreach(breach) {
        const box = document.getElementById("breach-status");
        box.textContent = "";
        const icon = document.createElement("i");
        const text = document.createElement("span");
        if (!breach.checked) {
            icon.className = "bi bi-question-circle text-secondary me-1";
            text.textContent = breach.error
                ? "Check failed: " + breach.error
                : "Breach check skipped.";
        } else if (breach.breached) {
            icon.className = "bi bi-exclamation-triangle-fill text-danger me-1";
            text.textContent =
                "Found in breaches " + breach.count.toLocaleString() + " times — do not use this password.";
            text.className = "text-danger fw-semibold";
        } else {
            icon.className = "bi bi-check-circle-fill text-success me-1";
            text.textContent = "Not found in known breach databases.";
        }
        box.append(icon, text);
    }

    function renderRecommendations(recs) {
        const list = document.getElementById("recommendations");
        list.textContent = "";
        recs.forEach(function (rec) {
            const li = document.createElement("li");
            const badge = document.createElement("span");
            badge.className = "badge me-2 text-bg-" + severityColor(rec.severity);
            badge.textContent = rec.severity;
            const span = document.createElement("span");
            span.textContent = rec.message;
            li.append(badge, span);
            list.appendChild(li);
        });
    }

    function renderPatterns(patterns) {
        const container = document.getElementById("pattern-findings");
        container.textContent = "";
        const findings = [
            ["Common password", patterns.is_common_password ? ["yes — found in top lists"] : [], true],
            ["Dictionary words", patterns.dictionary_words, false],
            ["Repeated patterns", patterns.repeated_patterns, false],
            ["Sequential patterns", patterns.sequential_patterns, false],
        ];
        findings.forEach(function (entry) {
            const title = entry[0];
            const items = entry[1];
            const col = document.createElement("div");
            col.className = "col-sm-6 col-lg-3";
            const heading = document.createElement("div");
            heading.className = "fw-semibold mb-1";
            const icon = document.createElement("i");
            icon.className = items.length
                ? "bi bi-x-circle-fill text-danger me-1"
                : "bi bi-check-circle-fill text-success me-1";
            heading.append(icon, document.createTextNode(title));
            const detail = document.createElement("div");
            detail.className = "text-secondary";
            detail.textContent = items.length ? items.join(", ") : "none detected";
            col.append(heading, detail);
            container.appendChild(col);
        });
    }

    function badgeColor(category) {
        switch (category) {
            case "Very Weak": return "danger";
            case "Weak": return "danger";
            case "Moderate": return "warning";
            case "Strong": return "success";
            case "Very Strong": return "success";
            default: return "secondary";
        }
    }

    function severityColor(severity) {
        switch (severity) {
            case "critical": return "danger";
            case "warning": return "warning";
            case "success": return "success";
            default: return "info";
        }
    }

    function showError(message) {
        errorBox.textContent = message;
        errorBox.classList.remove("d-none");
    }

    function hideError() {
        errorBox.classList.add("d-none");
    }

    function resetUI() {
        clearTimeout(debounceTimer);
        if (inflight) inflight.abort();
        results.classList.add("d-none");
        strengthBar.style.width = "0%";
        strengthLabel.textContent = "—";
        TIER_CLASSES.forEach(function (c) {
            strengthBar.classList.remove(c);
            strengthLabel.classList.remove(c);
        });
        hideError();
    }
})();
