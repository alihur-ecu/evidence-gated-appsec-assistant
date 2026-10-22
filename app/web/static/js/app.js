document.addEventListener(
    "DOMContentLoaded",
    function () {


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


        const analysisLaunch =
            document.getElementById(
                "analysisLaunch"
            );


        if (analysisLaunch) {

            const modeCards =
                Array.from(
                    document.querySelectorAll(
                        "[data-analysis-mode]"
                    )
                );


            const configPanel =
                document.getElementById(
                    "analysisConfigPanel"
                );


            const staticConfig =
                document.getElementById(
                    "staticConfig"
                );


            const dynamicConfig =
                document.getElementById(
                    "dynamicConfig"
                );


            const configPanelTitle =
                document.getElementById(
                    "configPanelTitle"
                );


            const configPanelDescription =
                document.getElementById(
                    "configPanelDescription"
                );


            const changeModeButton =
                document.getElementById(
                    "changeModeButton"
                );


            const startAnalysisButton =
                document.getElementById(
                    "startAnalysisButton"
                );


            const validationContainer =
                document.querySelector(
                    ".config-validation"
                );


            const validationMessage =
                document.getElementById(
                    "analysisValidationMessage"
                );


            const analysisProgressPanel = document.getElementById("analysisProgressPanel");
            const analysisProgressStage = document.getElementById("analysisProgressStage");
            const analysisProgressPercent = document.getElementById("analysisProgressPercent");
            const analysisProgressTrack = document.getElementById("analysisProgressTrack");
            const analysisProgressFill = document.getElementById("analysisProgressFill");
            const analysisProgressMessage = document.getElementById("analysisProgressMessage");
            const analysisProgressCounter = document.getElementById("analysisProgressCounter");

            function renderAnalysisProgress(state) {
                if (!analysisProgressPanel) return;
                analysisProgressPanel.hidden = false;
                const value = Math.max(0, Math.min(100, Number(state.progress || 0)));
                if (analysisProgressStage) analysisProgressStage.textContent = state.stage_label || "Analysis in progress";
                if (analysisProgressPercent) analysisProgressPercent.textContent = `${value}%`;
                if (analysisProgressFill) analysisProgressFill.style.width = `${value}%`;
                if (analysisProgressTrack) analysisProgressTrack.setAttribute("aria-valuenow", String(value));
                if (analysisProgressMessage) analysisProgressMessage.textContent = state.message || "Analysis in progress...";
                if (analysisProgressCounter) {
                    const total = Number(state.llm_total || 0);
                    const completed = Number(state.llm_completed || 0);
                    analysisProgressCounter.textContent = total > 0 ? `${completed} / ${total} LLM items completed` : "";
                }
            }

            async function waitForAnalysisJob(jobId) {
               
                let consecutiveNetworkFailures = 0;
                const maxNetworkFailures = 5;
                while (true) {
                    let statusResponse;
                    try {
                        statusResponse = await fetch(
                            `/analysis/jobs/${encodeURIComponent(jobId)}`,
                            { cache: "no-store" }
                        );
                    } catch (error) {
                        consecutiveNetworkFailures += 1;
                        if (consecutiveNetworkFailures >= maxNetworkFailures) {
                            throw new Error(
                                "Connection to the analysis server was lost. " +
                                "Check the Flask console for a restart or crash; " +
                                "the analysis result cannot be confirmed."
                            );
                        }
                        if (analysisProgressMessage) {
                            analysisProgressMessage.textContent =
                                `Connection interrupted; retrying (${consecutiveNetworkFailures}/${maxNetworkFailures})...`;
                        }
                        await new Promise(resolve => window.setTimeout(resolve, 1500));
                        continue;
                    }
                    consecutiveNetworkFailures = 0;
                    if (!statusResponse.ok) {
                        if (statusResponse.status === 404) {
                            throw new Error(
                                "The analysis job is no longer available on the server. " +
                                "The Flask process may have restarted; check its console."
                            );
                        }
                        throw new Error(`Unable to read analysis progress (HTTP ${statusResponse.status}).`);
                    }
                    let state;
                    try {
                        state = await statusResponse.json();
                    } catch (error) {
                        throw new Error("The analysis server returned an invalid progress response.");
                    }
                    if (!state.ok) throw new Error(state.error || "Unable to read analysis progress.");
                    renderAnalysisProgress(state);
                    if (state.status === "COMPLETED") return state;
                    if (state.status === "FAILED") throw new Error(state.error || state.message || "Analysis failed.");
                    await new Promise(resolve => window.setTimeout(resolve, 700));
                }
            }

            const staticSourceFile =
                document.getElementById(
                    "staticSourceFile"
                );


            const staticFileName =
                document.getElementById(
                    "staticFileName"
                );


            const staticDropZone =
                document.getElementById(
                    "staticDropZone"
                );


            const selectedSourceCard =
                document.getElementById(
                    "selectedSourceCard"
                );


            const selectedSourceName =
                document.getElementById(
                    "selectedSourceName"
                );


            const selectedSourceDescription =
                document.getElementById(
                    "selectedSourceDescription"
                );


            const selectedApplicationName =
                document.getElementById(
                    "selectedApplicationName"
                );


            const selectedFileType =
                document.getElementById(
                    "selectedFileType"
                );


            const selectedFileExtension =
                document.getElementById(
                    "selectedFileExtension"
                );


            const selectedContextSource =
                document.getElementById(
                    "selectedContextSource"
                );


            const staticAuthorised =
                document.getElementById(
                    "staticAuthorised"
                );

            const llmProvider =
                document.querySelector(
                    '[name="llm_provider"]'
                );

            const llmApiKeyField =
                document.getElementById("llmApiKeyField");

            const llmApiKey =
                document.getElementById("llmApiKey");


            const dynamicTargetUrl =
                document.getElementById(
                    "dynamicTargetUrl"
                );


            const dynamicScope =
                document.getElementById(
                    "dynamicScope"
                );


            const dynamicAuthorised =
                document.getElementById(
                    "dynamicAuthorised"
                );


            const dynamicAuthCards =
                Array.from(
                    document.querySelectorAll(
                        "[data-auth-mode]"
                    )
                );


            const authenticationFields =
                document.getElementById(
                    "authenticationFields"
                );


            const dynamicUsername =
                document.getElementById(
                    "dynamicUsername"
                );


            const dynamicPassword =
                document.getElementById(
                    "dynamicPassword"
                );


            let selectedMode = null;
            let selectedAuthenticationMode = "NONE";


            const supportedStaticExtensions = {
                ".zip": {
                    type: "ZIP archive",
                    context: "Project archive"
                },
                ".py": {
                    type: "Python source file",
                    context: "Single source file"
                },
                ".php": {
                    type: "PHP source file",
                    context: "Single source file"
                },
                ".js": {
                    type: "JavaScript source file",
                    context: "Single source file"
                },
                ".ts": {
                    type: "TypeScript source file",
                    context: "Single source file"
                },
                ".html": {
                    type: "HTML source file",
                    context: "Single source file"
                },
                ".htm": {
                    type: "HTML source file",
                    context: "Single source file"
                },
                ".jsx": {
                    type: "JSX source file",
                    context: "Single source file"
                },
                ".tsx": {
                    type: "TSX source file",
                    context: "Single source file"
                },
                ".java": {
                    type: "Java source file",
                    context: "Single source file"
                },
                ".cs": {
                    type: "C# source file",
                    context: "Single source file"
                },
                ".go": {
                    type: "Go source file",
                    context: "Single source file"
                },
                ".rb": {
                    type: "Ruby source file",
                    context: "Single source file"
                },
                ".c": {
                    type: "C source file",
                    context: "Single source file"
                },
                ".cpp": {
                    type: "C++ source file",
                    context: "Single source file"
                },
                ".vue": {
                    type: "Vue source file",
                    context: "Single source file"
                },
                ".txt": {
                    type: "Text source file",
                    context: "Single source file"
                }
            };


            function getStaticFileInfo(
                file
            ) {

                if (!file || !file.name) {

                    return null;

                }


                const fileName =
                    file.name.trim();


                const dotIndex =
                    fileName.lastIndexOf(".");


                const extension =
                    dotIndex >= 0
                    ? fileName
                        .slice(dotIndex)
                        .toLowerCase()
                    : "";


                const definition =
                    supportedStaticExtensions[
                        extension
                    ];


                if (!definition) {

                    return null;

                }


                const applicationName =
                    dotIndex > 0
                    ? fileName
                        .slice(0, dotIndex)
                    : fileName;


                return {
                    fileName: fileName,
                    extension: extension,
                    applicationName: applicationName,
                    type: definition.type,
                    context: definition.context
                };

            }


            function clearStaticSourceSummary() {

                if (selectedApplicationName) {

                    selectedApplicationName.value =
                        "";

                }


                if (selectedSourceCard) {

                    selectedSourceCard.hidden =
                        true;

                }


                if (staticDropZone) {

                    staticDropZone.classList.remove(
                        "file-selected"
                    );

                }

            }


            function renderStaticSourceSummary(
                fileInfo
            ) {

                if (!fileInfo) {

                    clearStaticSourceSummary();
                    return;

                }


                if (selectedSourceName) {

                    selectedSourceName.textContent =
                        fileInfo.fileName;

                }


                if (selectedSourceDescription) {

                    selectedSourceDescription.textContent =
                        `${fileInfo.type} · ${fileInfo.extension.toUpperCase()}`;

                }


                if (selectedApplicationName) {

                    selectedApplicationName.value =
                        fileInfo.applicationName;

                }


                if (selectedFileType) {

                    selectedFileType.textContent =
                        fileInfo.type;

                }


                if (selectedFileExtension) {

                    selectedFileExtension.textContent =
                        fileInfo.extension;

                }


                if (selectedContextSource) {

                    selectedContextSource.textContent =
                        fileInfo.context;

                }


                if (selectedSourceCard) {

                    selectedSourceCard.hidden =
                        false;

                }


                if (staticDropZone) {

                    staticDropZone.classList.add(
                        "file-selected"
                    );

                }

            }


            function isValidUrl(
                value
            ) {

                try {

                    const url =
                        new URL(
                            value
                        );


                    return (
                        url.protocol === "http:"
                        || url.protocol === "https:"
                    );

                }
                catch (error) {

                    return false;

                }

            }

            function updateValidation() {

                if (llmApiKeyField) {
                    llmApiKeyField.hidden =
                        !llmProvider || !["openai", "gemini"].includes(llmProvider.value);
                }

                let ready = false;

                let message =
                    "Complete all required fields to continue.";


                if (selectedMode === "static") {

                    const file =
                        staticSourceFile
                        && staticSourceFile.files
                        ? staticSourceFile.files[0]
                        : null;


                    const fileInfo =
                        getStaticFileInfo(
                            file
                        );


                    const applicationName =
                        selectedApplicationName
                        ? selectedApplicationName.value.trim()
                        : "";


                    const authorised =
                        Boolean(
                            staticAuthorised
                            && staticAuthorised.checked
                        );


                    ready =
                        Boolean(
                            file
                            && fileInfo
                            && applicationName
                            && llmProvider
                            && ["openai", "gemini", "lmstudio"].includes(llmProvider.value)
                            && authorised
                        );


                    if (!file) {

                        message =
                            "Select an authorised source file or project archive.";

                    }
                    else if (!fileInfo) {

                        message =
                            "This file type is not supported by the current frontend mock.";

                    }
                    else if (!applicationName) {

                        message =
                            "Enter an application name before continuing.";

                    }
                    else if (
                        !llmProvider
                        || !["openai", "gemini", "lmstudio"].includes(llmProvider.value)
                    ) {

                        message =
                            "Choose an LLM provider: OpenAI, Gemini, or LM Studio.";

                    }
                    else if (!authorised) {

                        message =
                            "Confirm authorisation before continuing.";

                    }
                    else {

                        message =
                            "Static analysis configuration is complete.";

                    }

                }



                if (selectedMode === "dynamic") {

                    const targetUrl =
                        dynamicTargetUrl
                        ? dynamicTargetUrl.value.trim()
                        : "";

                    const scope =
                        dynamicScope
                        ? dynamicScope.value.trim()
                        : "";

                    const authorised =
                        Boolean(
                            dynamicAuthorised
                            && dynamicAuthorised.checked
                        );

                    const requiresCredentials =
                        selectedAuthenticationMode === "FORM";

                    const username =
                        dynamicUsername
                        ? dynamicUsername.value.trim()
                        : "";

                    const password =
                        dynamicPassword
                        ? dynamicPassword.value
                        : "";

                    ready =
                        Boolean(
                            targetUrl
                            && isValidUrl(targetUrl)
                            && scope
                            && authorised
                            && (
                                !requiresCredentials
                                || (username && password)
                            )
                        );

                    if (!targetUrl) {
                        message = "Enter the authorised target URL.";
                    }
                    else if (!isValidUrl(targetUrl)) {
                        message = "Enter a valid HTTP or HTTPS target URL.";
                    }
                    else if (!scope) {
                        message = "Define the analysis scope.";
                    }
                    else if (requiresCredentials && !username) {
                        message = "Enter the authorised username or email.";
                    }
                    else if (requiresCredentials && !password) {
                        message = "Enter the authorised account password.";
                    }
                    else if (!authorised) {
                        message = "Confirm authorisation before continuing.";
                    }
                    else if (requiresCredentials) {
                        message = "Authenticated dynamic analysis configuration is complete.";
                    }
                    else {
                        message = "Unauthenticated dynamic analysis configuration is complete.";
                    }

                }



                if (startAnalysisButton) {

                    startAnalysisButton.disabled =
                        !ready;

                }



                if (validationMessage) {

                    validationMessage.textContent =
                        message;

                }


                if (validationContainer) {

                    validationContainer.classList.toggle(
                        "ready",
                        ready
                    );

                }

            }



            function selectMode(
                mode
            ) {

                selectedMode =
                    mode;


                modeCards.forEach(
                    function (card) {

                        const isSelected =
                            card.dataset.analysisMode
                            === mode;


                        card.classList.toggle(
                            "selected",
                            isSelected
                        );


                        card.classList.toggle(
                            "dimmed",
                            !isSelected
                        );


                        card.setAttribute(
                            "aria-pressed",
                            isSelected
                            ? "true"
                            : "false"
                        );


                        const status =
                            card.querySelector(
                                "[data-mode-status]"
                            );


                        if (status) {

                            status.textContent =
                                isSelected
                                ? "SELECTED"
                                : "SELECT";

                        }

                    }
                );


               

                if (configPanel) {

                    configPanel.hidden =
                        false;

                }


               

                if (staticConfig) {

                    staticConfig.hidden =
                        mode !== "static";

                }


                if (dynamicConfig) {

                    dynamicConfig.hidden =
                        mode !== "dynamic";

                }


               

                if (configPanelTitle) {

                    configPanelTitle.textContent =
                        mode === "static"
                        ? "Configure Static Analysis"
                        : "Configure Dynamic Analysis";

                }


                if (configPanelDescription) {

                    configPanelDescription.textContent =
                        mode === "static"
                        ? "Provide an authorised source file or project archive. File details are identified automatically."
                        : "Provide the authorised running target and define the scope.";

                }


                updateValidation();


                window.requestAnimationFrame(
                    function () {

                        configPanel.scrollIntoView(
                            {
                                behavior: "smooth",
                                block: "nearest"
                            }
                        );

                    }
                );

            }


            function selectAuthenticationMode(mode) {

                selectedAuthenticationMode =
                    mode === "FORM" ? "FORM" : "NONE";

                dynamicAuthCards.forEach(
                    function (card) {

                        const isSelected =
                            card.dataset.authMode === selectedAuthenticationMode;

                        card.classList.toggle("selected", isSelected);
                        card.setAttribute(
                            "aria-pressed",
                            isSelected ? "true" : "false"
                        );

                        const status =
                            card.querySelector("[data-auth-status]");

                        if (status) {
                            status.textContent = isSelected ? "SELECTED" : "SELECT";
                        }
                    }
                );

                if (authenticationFields) {
                    authenticationFields.hidden =
                        selectedAuthenticationMode !== "FORM";
                }

                if (selectedAuthenticationMode === "NONE") {
                    if (dynamicUsername) {
                        dynamicUsername.value = "";
                    }
                    if (dynamicPassword) {
                        dynamicPassword.value = "";
                    }
                }

                updateValidation();
            }


            function clearSelection() {

                selectedMode =
                    null;


                modeCards.forEach(
                    function (card) {

                        card.classList.remove(
                            "selected",
                            "dimmed"
                        );


                        card.setAttribute(
                            "aria-pressed",
                            "false"
                        );


                        const status =
                            card.querySelector(
                                "[data-mode-status]"
                            );


                        if (status) {

                            status.textContent =
                                "SELECT";

                        }

                    }
                );


                if (configPanel) {

                    configPanel.hidden =
                        true;

                }


                if (staticConfig) {

                    staticConfig.hidden =
                        true;

                }


                if (dynamicConfig) {

                    dynamicConfig.hidden =
                        true;

                }


                updateValidation();

            }


            modeCards.forEach(
                function (card) {

                    card.addEventListener(
                        "click",
                        function (event) {

                            if (
                                event.target.closest(
                                    "input, button, label, a"
                                )
                            ) {

                                return;

                            }


                            selectMode(
                                card.dataset.analysisMode
                            );

                        }
                    );


                    card.addEventListener(
                        "keydown",
                        function (event) {

                            if (
                                event.key === "Enter"
                                || event.key === " "
                            ) {

                                event.preventDefault();


                                selectMode(
                                    card.dataset.analysisMode
                                );

                            }

                        }
                    );

                }
            );



            dynamicAuthCards.forEach(
                function (card) {
                    card.addEventListener(
                        "click",
                        function () {
                            selectAuthenticationMode(card.dataset.authMode);
                        }
                    );
                }
            );



            if (changeModeButton) {

                changeModeButton.addEventListener(
                    "click",
                    clearSelection
                );

            }



            [
                selectedApplicationName,
                staticAuthorised,
                llmProvider,
                llmApiKey,
                dynamicTargetUrl,
                dynamicScope,
                dynamicAuthorised,
                dynamicUsername,
                dynamicPassword
            ].forEach(
                function (element) {

                    if (!element) {

                        return;

                    }


                    element.addEventListener(
                        "input",
                        updateValidation
                    );


                    element.addEventListener(
                        "change",
                        updateValidation
                    );

                }
            );



            if (staticSourceFile) {

                staticSourceFile.addEventListener(
                    "change",
                    function () {

                        const file =
                            staticSourceFile.files
                            && staticSourceFile.files[0]
                            ? staticSourceFile.files[0]
                            : null;


                        if (!file) {

                            if (staticFileName) {

                                staticFileName.textContent =
                                    "ZIP, PY, PHP, JS, TS, HTML, JAVA, TXT and other supported source files.";

                            }


                            clearStaticSourceSummary();
                            updateValidation();
                            return;

                        }


                        const fileInfo =
                            getStaticFileInfo(
                                file
                            );


                        if (!fileInfo) {

                            staticSourceFile.value =
                                "";


                            if (staticFileName) {

                                staticFileName.textContent =
                                    "Unsupported file type. Choose a supported source file or ZIP archive.";

                            }


                            clearStaticSourceSummary();
                            updateValidation();
                            return;

                        }


                        if (staticFileName) {

                            staticFileName.textContent =
                                fileInfo.fileName;

                        }


                        renderStaticSourceSummary(
                            fileInfo
                        );


                        updateValidation();

                    }
                );

            }



            if (
                staticDropZone
                && staticSourceFile
            ) {

                [
                    "dragenter",
                    "dragover"
                ].forEach(
                    function (eventName) {

                        staticDropZone.addEventListener(
                            eventName,
                            function (event) {

                                event.preventDefault();


                                staticDropZone.classList.add(
                                    "drag-over"
                                );

                            }
                        );

                    }
                );


                [
                    "dragleave",
                    "drop"
                ].forEach(
                    function (eventName) {

                        staticDropZone.addEventListener(
                            eventName,
                            function (event) {

                                event.preventDefault();


                                staticDropZone.classList.remove(
                                    "drag-over"
                                );

                            }
                        );

                    }
                );


                staticDropZone.addEventListener(
                    "drop",
                    function (event) {

                        const files =
                            event.dataTransfer.files;


                        if (!files.length) {

                            return;

                        }


                        const file =
                            files[0];


                        const fileInfo =
                            getStaticFileInfo(
                                file
                            );


                        if (!fileInfo) {

                            if (staticFileName) {

                                staticFileName.textContent =
                                    "Unsupported file type. Choose a supported source file or ZIP archive.";

                            }


                            clearStaticSourceSummary();
                            updateValidation();
                            return;

                        }


                        const transfer =
                            new DataTransfer();


                        transfer.items.add(
                            file
                        );


                        staticSourceFile.files =
                            transfer.files;


                        staticSourceFile.dispatchEvent(
                            new Event(
                                "change",
                                {
                                    bubbles: true
                                }
                            )
                        );

                    }
                );

            }



            if (startAnalysisButton) {

                startAnalysisButton.addEventListener(
                    "click",
                    async function () {

                        updateValidation();

                        if (
                            startAnalysisButton.disabled
                            || !selectedMode
                        ) {
                            return;
                        }

                        const originalText =
                            startAnalysisButton.textContent;

                        startAnalysisButton.disabled = true;
                        startAnalysisButton.textContent =
                            "Starting Analysis...";

                        try {

                            let response;

                            if (selectedMode === "static") {

                                const file =
                                    staticSourceFile
                                    && staticSourceFile.files
                                    ? staticSourceFile.files[0]
                                    : null;

                                const applicationName =
                                    selectedApplicationName
                                    ? selectedApplicationName.value.trim()
                                    : "";

                                if (!file || !applicationName) {
                                    updateValidation();
                                    startAnalysisButton.textContent =
                                        originalText;
                                    return;
                                }

                                if (validationMessage) {
                                    validationMessage.textContent =
                                        "Uploading the authorised source to the configured analysis provider...";
                                }

                                const formData =
                                    new FormData();

                                formData.append(
                                    "source_file",
                                    file
                                );

                                formData.append(
                                    "application_name",
                                    applicationName
                                );

                                formData.append(
                                    "authorised",
                                    staticAuthorised
                                    && staticAuthorised.checked
                                    ? "true"
                                    : "false"
                                );

                                formData.append(
                                    "llm_provider",
                                    llmProvider
                                    ? llmProvider.value
                                    : ""
                                );

                                if (llmApiKey && llmApiKey.value.trim()) {
                                    formData.append("llm_api_key", llmApiKey.value.trim());
                                }

                                response = await fetch(
                                    "/analysis/static/job",
                                    {
                                        method: "POST",
                                        body: formData
                                    }
                                );

                            }
                            else if (selectedMode === "dynamic") {

                                const targetUrl =
                                    dynamicTargetUrl
                                    ? dynamicTargetUrl.value.trim()
                                    : "";

                                const analysisScope =
                                    dynamicScope
                                    ? dynamicScope.value.trim()
                                    : "";

                                const authenticationMode =
                                    selectedAuthenticationMode;

                                const username =
                                    dynamicUsername
                                    ? dynamicUsername.value.trim()
                                    : "";

                                const password =
                                    dynamicPassword
                                    ? dynamicPassword.value
                                    : "";

                                if (
                                    !targetUrl
                                    || !analysisScope
                                    || !dynamicAuthorised
                                    || !dynamicAuthorised.checked
                                    || (
                                        authenticationMode === "FORM"
                                        && (!username || !password)
                                    )
                                ) {
                                    updateValidation();
                                    startAnalysisButton.textContent =
                                        originalText;
                                    return;
                                }

                                if (validationMessage) {
                                    validationMessage.innerHTML =
                                        '<span class="analysis-progress-spinner" aria-hidden="true"></span>' +
                                        '<span> Analysis in progress — validating target, discovering runtime surface, building context and requesting LLM proposals...</span>';
                                }

                                const formData =
                                    new FormData();

                                formData.append(
                                    "target_url",
                                    targetUrl
                                );

                                formData.append(
                                    "application_name",
                                    targetUrl
                                );

                                formData.append(
                                    "analysis_scope",
                                    analysisScope
                                );

                                formData.append(
                                    "authentication_mode",
                                    authenticationMode
                                );

                                if (authenticationMode === "FORM") {
                                    formData.append("username", username);
                                    formData.append("password", password);
                                }

                                formData.append(
                                    "authorised",
                                    "true"
                                );

                                formData.append("llm_provider", llmProvider ? llmProvider.value : "");
                                if (llmApiKey && llmApiKey.value.trim()) {
                                    formData.append("llm_api_key", llmApiKey.value.trim());
                                }

                                response = await fetch(
                                    "/analysis/dynamic/job",
                                    {
                                        method: "POST",
                                        body: formData
                                    }
                                );

                            }
                            else {
                                throw new Error(
                                    "Unknown analysis mode."
                                );
                            }

                            let result = {};

                            try {
                                result =
                                    await response.json();
                            }
                            catch (error) {
                                result = {
                                    ok: false,
                                    error:
                                        "The server returned an invalid response."
                                };
                            }

                            if (response.ok && result.ok && result.job_id) {
                                renderAnalysisProgress({ progress: 3, stage_label: "Analysis queued", message: "Analysis accepted. Waiting for the first real stage..." });
                                result = await waitForAnalysisJob(result.job_id);
                            }

                            if (
                                !response.ok
                                || !result.ok
                            ) {
                                throw new Error(
                                    result.error
                                    || `Request failed (${response.status})`
                                );
                            }

                            if (validationMessage) {

                                const analysisLabel =
                                    result.analysis_type
                                    || selectedMode.toUpperCase();

                                validationMessage.textContent =
                                    `${analysisLabel} analysis prepared by ${result.provider}. Opening ${result.finding_count} proposed finding(s)...`;
                            }

                            window.location.href =
                                result.redirect_url;
                        }
                        catch (error) {

                            console.error(
                                "Unable to start analysis:",
                                error
                            );

                            if (validationMessage) {
                                validationMessage.textContent =
                                    `Unable to start analysis: ${error.message}`;
                            }

                            startAnalysisButton.disabled =
                                false;

                            startAnalysisButton.textContent =
                                originalText;
                        }
                    }
                );
            }


            selectAuthenticationMode("NONE");
            clearSelection();

        }


        if (!findingId) {

            console.log(
                "Application page loaded."
            );

            return;

        }



        const runVerificationButton =
            document.getElementById(
                "runVerificationButton"
            );


        const verificationMessage =
            document.getElementById(
                "verificationMessage"
            );

        const verificationTargetUrl =
            document.getElementById(
                "verificationTargetUrl"
            );


        const finalSeverity =
            document.getElementById(
                "finalSeverity"
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



        const findingWorkflow =
            document.getElementById("findingWorkflow");

        if (findingWorkflow) {

            const workflowStages =
                Array.from(
                    findingWorkflow.querySelectorAll(
                        "[data-workflow-stage]"
                    )
                );

            const verificationComplete =
                findingWorkflow.dataset.verificationComplete === "true";

            const humanDecision =
                (findingWorkflow.dataset.humanDecision || "").trim();

            let currentWorkflowStage =
                verificationComplete ? 3 : 1;

            function renderWorkflowStage(stageNumber) {

                currentWorkflowStage = stageNumber;

                workflowStages.forEach(function (stage) {
                    const number = Number(stage.dataset.workflowStage);
                    stage.classList.toggle(
                        "is-current",
                        number === currentWorkflowStage
                    );
                    stage.setAttribute(
                        "aria-current",
                        number === currentWorkflowStage ? "step" : "false"
                    );
                });

            }

            function canOpenWorkflowStage(stageNumber) {

                if (stageNumber === 1) {
                    return true;
                }

                if (stageNumber === 2) {
                    return true;
                }

                if (stageNumber === 3) {
                    return verificationComplete;
                }

                if (stageNumber === 4) {
                    return Boolean(humanDecision) && false;
                }

                return false;

            }

            function stageName(stageNumber) {
                const names = {
                    1: "LLM Proposal",
                    2: "Verification",
                    3: "Human Review",
                    4: "Report"
                };
                return names[stageNumber] || "previous stage";
            }

            function confirmPreviousStage(stageNumber) {

                return window.confirm(
                    `View ${stageName(stageNumber)}?\n\n` +
                    "You are returning to a previous workflow stage. " +
                    "Existing verification evidence and human-review data will be preserved."
                );

            }

            function openWorkflowStage(stage) {

                const stageNumber =
                    Number(stage.dataset.workflowStage);

                if (!canOpenWorkflowStage(stageNumber)) {
                    return;
                }

                if (stageNumber < currentWorkflowStage) {
                    if (!confirmPreviousStage(stageNumber)) {
                        return;
                    }
                }

                renderWorkflowStage(stageNumber);

                const targetId = stage.dataset.workflowTarget;
                const target = targetId
                    ? document.getElementById(targetId)
                    : null;

                if (target) {
                    target.scrollIntoView({
                        behavior: "smooth",
                        block: "start"
                    });
                }

            }

            workflowStages.forEach(function (stage) {

                stage.addEventListener("click", function () {
                    openWorkflowStage(stage);
                });

            });

            renderWorkflowStage(currentWorkflowStage);

        }


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


        if (runVerificationButton) {

            runVerificationButton.addEventListener(
                "click",
                async function () {

                    const originalText =
                        runVerificationButton.textContent;


                    runVerificationButton.disabled =
                        true;


                    runVerificationButton.textContent =
                        "Collecting Oracle Evidence...";


                    if (verificationMessage) {

                        verificationMessage.textContent =
                            "The Oracle is checking this proposal and collecting independent evidence...";

                    }


                    try {

                        const result =
                            await postJson(
                                `/findings/${findingId}/verify`,
                                {}
                            );


                        if (verificationMessage) {

                            verificationMessage.textContent =
                                `Verification complete: ${result.evidence_gate_result}`;

                        }


                        console.log(
                            "Verification result:",
                            result
                        );


                        // Reload so Flask renders the evidence
                        // collected during this run.
                        window.location.reload();

                    }
                    catch (error) {

                        console.error(
                            "Verification failed:",
                            error
                        );


                        if (verificationMessage) {

                            verificationMessage.textContent =
                                `Oracle evidence could not be collected: ${error.message}`;

                        }


                        runVerificationButton.disabled =
                            false;


                        runVerificationButton.textContent =
                            originalText;

                    }

                }
            );

        }



        let saveStatusTimer =
            null;


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


        async function recordHumanDecision(
            decision
        ) {

            const saved =
                await saveReviewField(
                    "human_decision",
                    decision
                );


            if (saved) {

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
