document.addEventListener(
    "DOMContentLoaded",
    function () {

        // ========================================================
        // CURRENT FINDING ID
        // ========================================================

        function getFindingIdFromUrl() {

            const parts =
                window.location.pathname
                    .split("/")
                    .filter(Boolean);


            if (
                parts.length >= 2 &&
                parts[0] === "findings"
            ) {

                return parts[1];
            }


            return null;
        }


        const findingId =
            getFindingIdFromUrl();


        // Findings overview has no finding-specific controls.
        if (!findingId) {

            console.log(
                "Findings overview loaded."
            );

            return;
        }


        // ========================================================
        // ELEMENTS
        // ========================================================

        const runVerificationButton =
            document.getElementById(
                "runVerificationButton"
            );

        const verificationMessage =
            document.getElementById(
                "verificationMessage"
            );

        const finalSeverity =
            document.getElementById(
                "finalSeverity"
            );

        const reviewerCwe =
            document.getElementById(
                "reviewerCwe"
            );

        const reviewComment =
            document.getElementById(
                "reviewComment"
            );

        const reviewSaveStatus =
            document.getElementById(
                "reviewSaveStatus"
            );

        const rejectButton =
            document.getElementById(
                "rejectButton"
            );

        const reviewButton =
            document.getElementById(
                "reviewButton"
            );

        const acceptButton =
            document.getElementById(
                "acceptButton"
            );


        // ========================================================
        // GENERAL JSON REQUEST
        // ========================================================

        async function postJson(
            url,
            payload = {}
        ) {

            const response =
                await fetch(
                    url,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                payload
                            )
                    }
                );


            let data = {};


            try {

                data =
                    await response.json();

            }
            catch (error) {

                data = {
                    ok: false,
                    error:
                        "The server returned an invalid response."
                };
            }


            if (!response.ok) {

                throw new Error(
                    data.error
                    || `Request failed (${response.status})`
                );
            }


            return data;
        }


        // ========================================================
        // RUN VERIFICATION
        // ========================================================

        if (runVerificationButton) {

            runVerificationButton.addEventListener(
                "click",
                async function () {

                    const originalText =
                        runVerificationButton.textContent;


                    runVerificationButton.disabled =
                        true;


                    runVerificationButton.textContent =
                        "Running Verification...";


                    if (verificationMessage) {

                        verificationMessage.textContent =
                            "Connecting to the local DVWA lab and collecting runtime evidence...";
                    }


                    try {

                        const result =
                            await postJson(
                                `/findings/${findingId}/verify`
                            );


                        if (verificationMessage) {

                            verificationMessage.textContent =
                                `Verification complete: ${result.evidence_gate_result}`;
                        }


                        console.log(
                            "Verification result:",
                            result
                        );


                        // Reload so Flask renders the real evidence
                        // collected during this verification run.
                        window.location.reload();

                    }
                    catch (error) {

                        console.error(
                            "Verification failed:",
                            error
                        );


                        if (verificationMessage) {

                            verificationMessage.textContent =
                                `Verification failed: ${error.message}`;
                        }


                        runVerificationButton.disabled =
                            false;


                        runVerificationButton.textContent =
                            originalText;
                    }

                }
            );
        }


        // ========================================================
        // SAVE REVIEW FIELD TO FLASK
        // ========================================================

        let saveStatusTimer = null;


        function showSaveStatus(
            message
        ) {

            if (!reviewSaveStatus) {
                return;
            }


            reviewSaveStatus.textContent =
                message;


            if (saveStatusTimer) {

                clearTimeout(
                    saveStatusTimer
                );
            }


            saveStatusTimer =
                setTimeout(
                    function () {

                        reviewSaveStatus.textContent =
                            "";

                    },
                    2200
                );
        }


        async function saveReviewField(
            field,
            value
        ) {

            try {

                const result =
                    await postJson(
                        `/findings/${findingId}/review`,
                        {
                            field: field,
                            value: value
                        }
                    );


                console.log(
                    "Review field saved:",
                    result
                );


                showSaveStatus(
                    "Saved"
                );


                return true;

            }
            catch (error) {

                console.error(
                    "Unable to save review field:",
                    error
                );


                showSaveStatus(
                    `Save failed: ${error.message}`
                );


                return false;
            }
        }


        // ========================================================
        // FINAL SEVERITY
        // ========================================================

        if (finalSeverity) {

            finalSeverity.addEventListener(
                "change",
                function () {

                    saveReviewField(
                        "final_severity",
                        finalSeverity.value
                    );

                }
            );
        }


        // ========================================================
        // REVIEWER CWE
        //
        // Save when leaving the field so we do not send one request
        // for every single typed character.
        // ========================================================

        if (reviewerCwe) {

            reviewerCwe.addEventListener(
                "change",
                function () {

                    saveReviewField(
                        "reviewer_cwe",
                        reviewerCwe.value.trim()
                    );

                }
            );
        }


        // ========================================================
        // REVIEWER COMMENT
        // ========================================================

        if (reviewComment) {

            reviewComment.addEventListener(
                "change",
                function () {

                    saveReviewField(
                        "reviewer_comment",
                        reviewComment.value.trim()
                    );

                }
            );
        }


        // ========================================================
        // HUMAN DECISION
        // ========================================================

        async function recordHumanDecision(
            decision
        ) {

            const saved =
                await saveReviewField(
                    "human_decision",
                    decision
                );


            if (saved) {

                // Reload to update timeline, badge and recorded
                // decision using server-side state.
                window.location.reload();
            }
        }


        if (rejectButton) {

            rejectButton.addEventListener(
                "click",
                function () {

                    if (rejectButton.disabled) {
                        return;
                    }


                    recordHumanDecision(
                        "REJECTED"
                    );
                }
            );
        }


        if (reviewButton) {

            reviewButton.addEventListener(
                "click",
                function () {

                    if (reviewButton.disabled) {
                        return;
                    }


                    recordHumanDecision(
                        "NEEDS_FURTHER_REVIEW"
                    );
                }
            );
        }


        if (acceptButton) {

            acceptButton.addEventListener(
                "click",
                function () {

                    if (acceptButton.disabled) {
                        return;
                    }


                    recordHumanDecision(
                        "ACCEPTED"
                    );
                }
            );
        }


        console.log(
            `Finding Details loaded: ${findingId}`
        );

    }
);