"use strict";
// Scan History only: local table filtering and an explicit archive confirmation.
document.addEventListener("DOMContentLoaded", function () {
    const search = document.getElementById("scanHistorySearch");
    const rows = Array.from(document.querySelectorAll("[data-history-row]"));
    const count = document.getElementById("scanHistoryCount");
    const empty = document.getElementById("scanHistoryNoMatches");
    if (search) {
        search.addEventListener("input", function () {
            const query = search.value.trim().toLowerCase();
            let visible = 0;
            rows.forEach(function (row) {
                const show = row.textContent.toLowerCase().includes(query);
                row.hidden = !show;
                if (show) visible += 1;
            });
            if (count) count.textContent = String(visible) + " of " + rows.length + " scan(s)";
            if (empty) empty.hidden = visible !== 0;
        });
    }
    document.querySelectorAll(".history-archive-form").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            const id = form.getAttribute("data-analysis-id") || "this scan";
            const message = "Move " + id + " and its saved report to local Trash?\n\n" +
                "Its findings, review and verification snapshot will leave Scan History. " +
                "You can recover the files manually from the .trash folder.";
            if (!window.confirm(message)) event.preventDefault();
        });
    });
});
