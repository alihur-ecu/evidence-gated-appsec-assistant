# Python Module Reference — generated from the uploaded final code

Generated from `Evidence-Gated AppSec Finding Assistant.zip` (22 October 2026) using Python AST; source locations are relative to project root. Functions and methods listed below are *definitions found in source*, not evidence of runtime execution.

See [Architecture](ARCHITECTURE.md) and [Oracle Rules](ORACLE_RULE_CATALOGUE.md) for workflow semantics.

## `app/analysis/analysis_service.py`

| Line | Kind | Definition |
|---:|---|---|
| 27 | function | `run_static_analysis` |

## `app/analysis/finding_adapter.py`

| Line | Kind | Definition |
|---:|---|---|
| 133 | function | `_clean_optional_string` |
| 143 | function | `_normalise_key` |
| 158 | function | `_normalise_finding_type` |
| 202 | function | `_normalise_scan_type` |
| 230 | function | `_normalise_line_number` |
| 242 | function | `_normalise_confidence` |
| 254 | function | `adapt_analysis_result` |

## `app/analysis/finding_presentation.py`

| Line | Kind | Definition |
|---:|---|---|
| 35 | function | `effective_cwe` |
| 46 | function | `proposed_family` |
| 58 | function | `finding_label` |
| 70 | function | `proposal_quality_notes` |

## `app/analysis/proposal_aggregator.py`

| Line | Kind | Definition |
|---:|---|---|
| 12 | class | `AggregationResult` |
| 20 | method | `AggregationResult.to_dict` |
| 31 | function | `_clean_string` |
| 42 | function | `_normalise_text` |
| 59 | function | `_normalise_path` |
| 70 | function | `_normalise_line` |
| 84 | function | `_proposal_source_file` |
| 91 | function | `_proposal_line` |
| 98 | function | `_proposal_type` |
| 119 | function | `_proposal_cwe` |
| 130 | function | `_proposal_endpoint` |
| 137 | function | `_proposal_parameter` |
| 145 | function | `_proposal_method` |
| 153 | function | `_extract_chunk_ids` |
| 180 | function | `_same_static_location` |
| 213 | function | `_same_runtime_location` |
| 251 | function | `_same_vulnerability` |
| 280 | function | `_are_duplicates` |
| 310 | function | `_merge_proposals` |
| 391 | class | `ProposalAggregator` |
| 406 | method | `ProposalAggregator.aggregate` |
| 483 | function | `aggregate_analysis_result` |

## `app/analysis/proposers/adapters.py`

| Line | Kind | Definition |
|---:|---|---|
| 8 | function | `adapt_static_context` |
| 30 | function | `adapt_dynamic_context` |
| 58 | function | `adapt_static_contexts` |
| 74 | function | `adapt_dynamic_contexts` |

## `app/analysis/proposers/base.py`

| Line | Kind | Definition |
|---:|---|---|
| 7 | class | `LLMProposer` |
| 12 | method | `LLMProposer.propose` |
| 23 | class | `StaticProposer` |
| 26 | method | `StaticProposer.propose` |

## `app/analysis/proposers/budget.py`

| Line | Kind | Definition |
|---:|---|---|
| 13 | class | `BudgetResult` |
| 28 | method | `BudgetResult.to_dict` |
| 42 | class | `LLMExecutionBudget` |
| 62 | method | `LLMExecutionBudget.apply` |
| 135 | method | `LLMExecutionBudget._chunk_char_count` |
| 153 | method | `LLMExecutionBudget._resolve_positive_int` |

## `app/analysis/proposers/context.py`

| Line | Kind | Definition |
|---:|---|---|
| 8 | class | `AnalysisContext` |
| 64 | method | `AnalysisContext.char_count` |
| 69 | method | `AnalysisContext.to_dict` |

## `app/analysis/proposers/factory.py`

| Line | Kind | Definition |
|---:|---|---|
| 18 | class | `NoOpStaticProposer` |
| 22 | method | `NoOpStaticProposer.propose` |
| 31 | function | `get_configured_llm_provider` |
| 39 | function | `create_static_proposer` |

## `app/analysis/proposers/gemini.py`

| Line | Kind | Definition |
|---:|---|---|
| 98 | class | `GeminiStaticProposer` |
| 154 | method | `GeminiStaticProposer.propose` |
| 201 | method | `GeminiStaticProposer.propose_contexts` |
| 247 | method | `GeminiStaticProposer._analyse_context` |
| 272 | method | `GeminiStaticProposer._analyse_chunk` |
| 308 | method | `GeminiStaticProposer._generate_with_retry` |
| 343 | method | `GeminiStaticProposer._generate_context_with_retry` |
| 367 | method | `GeminiStaticProposer._extract_status_code` |
| 380 | method | `GeminiStaticProposer._is_retryable_exception` |
| 388 | method | `GeminiStaticProposer._extract_payload` |
| 431 | method | `GeminiStaticProposer._is_valid_chunk` |
| 456 | method | `GeminiStaticProposer._build_prompt` |
| 504 | method | `GeminiStaticProposer._build_context_prompt` |
| 529 | method | `GeminiStaticProposer._normalise_context_proposal` |
| 598 | method | `GeminiStaticProposer._normalise_proposal` |
| 740 | method | `GeminiStaticProposer._validate_line_number` |
| 772 | method | `GeminiStaticProposer._optional_string` |
| 786 | method | `GeminiStaticProposer._normalise_severity` |

## `app/analysis/proposers/lmstudio.py`

| Line | Kind | Definition |
|---:|---|---|
| 25 | class | `LMStudioStaticProposer` |
| 85 | method | `LMStudioStaticProposer._json_instructions` |
| 111 | method | `LMStudioStaticProposer.propose` |
| 135 | method | `LMStudioStaticProposer.propose_contexts` |
| 314 | method | `LMStudioStaticProposer._chat_completion_with_retry` |
| 365 | method | `LMStudioStaticProposer._generate_with_retry` |
| 392 | method | `LMStudioStaticProposer._generate_context_with_retry` |
| 400 | method | `LMStudioStaticProposer._extract_payload` |

## `app/analysis/proposers/openai.py`

| Line | Kind | Definition |
|---:|---|---|
| 127 | class | `OpenAIStaticProposer` |
| 190 | method | `OpenAIStaticProposer._empty_execution_report` |
| 201 | method | `OpenAIStaticProposer.propose` |
| 271 | method | `OpenAIStaticProposer.propose_contexts` |
| 352 | method | `OpenAIStaticProposer._analyse_context` |
| 403 | method | `OpenAIStaticProposer._analyse_chunk` |
| 454 | method | `OpenAIStaticProposer._generate_with_retry` |
| 504 | method | `OpenAIStaticProposer._generate_context_with_retry` |
| 555 | method | `OpenAIStaticProposer._extract_status_code` |
| 595 | method | `OpenAIStaticProposer._is_retryable_exception` |
| 616 | method | `OpenAIStaticProposer._extract_payload` |
| 662 | method | `OpenAIStaticProposer._is_valid_chunk` |
| 701 | method | `OpenAIStaticProposer._build_prompt` |
| 762 | method | `OpenAIStaticProposer._build_context_prompt` |
| 851 | method | `OpenAIStaticProposer._normalise_context_proposal` |
| 1058 | method | `OpenAIStaticProposer._normalise_proposal` |
| 1238 | method | `OpenAIStaticProposer._validate_line_number` |
| 1287 | method | `OpenAIStaticProposer._optional_string` |
| 1304 | method | `OpenAIStaticProposer._normalise_severity` |

## `app/analysis/providers/mock_provider.py`

| Line | Kind | Definition |
|---:|---|---|
| 132 | function | `run_mock_static_analysis` |

## `app/analysis/providers/static_source_provider.py`

| Line | Kind | Definition |
|---:|---|---|
| 12 | function | `run_static_source_analysis` |

## `app/analysis/static_pipeline.py`

| Line | Kind | Definition |
|---:|---|---|
| 19 | function | `run_static_proposal_pipeline` |

## `app/analysis/static_source_candidates.py`

| Line | Kind | Definition |
|---:|---|---|
| 14 | function | `_attribute_path` |
| 23 | function | `_literal` |
| 29 | function | `_inputs` |
| 57 | function | `_names` |
| 61 | function | `_dynamic_expression` |
| 70 | function | `_sql_in_expression` |
| 78 | function | `_route` |
| 96 | function | `_candidate` |
| 114 | function | `_sql_candidates` |
| 168 | function | `_template_safe_filters` |
| 183 | function | `_xss_candidates` |
| 257 | function | `collect_static_source_candidates` |

## `app/dynamic_analysis/authentication.py`

| Line | Kind | Definition |
|---:|---|---|
| 21 | class | `DynamicAuthenticationError` |
| 26 | class | `AuthenticationResult` |
| 34 | method | `AuthenticationResult.to_dict` |
| 43 | function | `normalise_authentication_mode` |
| 61 | function | `create_analysis_session` |
| 257 | function | `_find_login_form` |
| 283 | function | `_build_login_payload` |
| 394 | function | `_choose_username_field` |
| 435 | function | `_form_control_value` |
| 520 | function | `_normalise_url_for_comparison` |

## `app/dynamic_analysis/context_builder.py`

| Line | Kind | Definition |
|---:|---|---|
| 21 | class | `DynamicContext` |
| 40 | method | `DynamicContext.to_dict` |
| 45 | class | `DynamicContextBuildResult` |
| 69 | method | `DynamicContextBuildResult.to_dict` |
| 102 | class | `DynamicContextBuilder` |
| 123 | method | `DynamicContextBuilder.build` |
| 248 | method | `DynamicContextBuilder._build_candidate_contexts` |
| 330 | method | `DynamicContextBuilder._prioritise_contexts` |
| 367 | method | `DynamicContextBuilder._context_from_form` |
| 414 | method | `DynamicContextBuilder._context_from_endpoint` |
| 462 | function | `_find_page_for_url` |
| 478 | function | `_page_observation` |
| 498 | function | `_render_context_text` |
| 656 | function | `_digest_json` |
| 665 | function | `_context_manifest_entry` |

## `app/dynamic_analysis/discovery.py`

| Line | Kind | Definition |
|---:|---|---|
| 28 | class | `DiscoveredParameter` |
| 36 | method | `DiscoveredParameter.to_dict` |
| 46 | class | `DiscoveredForm` |
| 54 | method | `DiscoveredForm.to_dict` |
| 67 | class | `DiscoveredEndpoint` |
| 74 | method | `DiscoveredEndpoint.to_dict` |
| 86 | class | `DiscoveredPage` |
| 101 | method | `DiscoveredPage.to_dict` |
| 121 | class | `DiscoveryResult` |
| 132 | method | `DiscoveryResult.parameters` |
| 159 | method | `DiscoveryResult.to_dict` |
| 199 | class | `DynamicDiscovery` |
| 241 | method | `DynamicDiscovery.discover` |
| 536 | function | `_parse_form` |
| 639 | function | `_extract_form_control_value` |
| 701 | function | `_extract_query_parameters` |
| 739 | function | `_resolve_http_url` |
| 789 | function | `_normalise_discovery_url` |
| 815 | function | `_build_response_excerpt` |
| 856 | function | `_is_html_response` |
| 867 | function | `_append_endpoint` |

## `app/dynamic_analysis/evidence/models.py`

| Line | Kind | Definition |
|---:|---|---|
| 9 | class | `VerificationDecision` |
| 17 | function | `_utc_now_iso` |
| 22 | class | `RuntimeObservation` |
| 50 | method | `RuntimeObservation.to_dict` |
| 55 | class | `EvidenceBundle` |
| 98 | method | `EvidenceBundle.to_dict` |
| 119 | class | `VerificationResult` |
| 139 | method | `VerificationResult.to_dict` |

## `app/dynamic_analysis/evidence/response_signals.py`

| Line | Kind | Definition |
|---:|---|---|
| 10 | class | `ResponseSignals` |
| 18 | class | `ResponseSignalExtractor` |
| 95 | method | `ResponseSignalExtractor.extract` |

## `app/dynamic_analysis/pipeline.py`

| Line | Kind | Definition |
|---:|---|---|
| 15 | class | `DynamicPipelineResult` |
| 25 | method | `DynamicPipelineResult.to_dict` |
| 29 | class | `DynamicAnalysisPipeline` |
| 58 | method | `DynamicAnalysisPipeline.run` |
| 152 | method | `DynamicAnalysisPipeline._propose` |
| 187 | method | `DynamicAnalysisPipeline._proposal_execution_report` |
| 228 | method | `DynamicAnalysisPipeline._proposal_status` |
| 245 | method | `DynamicAnalysisPipeline._target_to_dict` |
| 259 | method | `DynamicAnalysisPipeline._provider_name` |
| 281 | function | `run_dynamic_analysis` |

## `app/dynamic_analysis/pipelinebk.py`

| Line | Kind | Definition |
|---:|---|---|
| 14 | class | `DynamicPipelineResult` |
| 22 | method | `DynamicPipelineResult.to_dict` |
| 26 | class | `DynamicAnalysisPipeline` |
| 53 | method | `DynamicAnalysisPipeline.run` |
| 97 | method | `DynamicAnalysisPipeline._propose` |
| 132 | method | `DynamicAnalysisPipeline._target_to_dict` |
| 146 | method | `DynamicAnalysisPipeline._provider_name` |
| 168 | function | `run_dynamic_analysis` |

## `app/dynamic_analysis/planning/baseline_resolver.py`

| Line | Kind | Definition |
|---:|---|---|
| 13 | class | `BaselineResolution` |
| 23 | class | `BaselineResolutionPolicy` |
| 41 | class | `BaselineResolver` |
| 50 | method | `BaselineResolver.resolve` |
| 123 | method | `BaselineResolver._repeat` |
| 141 | method | `BaselineResolver._request` |
| 177 | method | `BaselineResolver._resolution` |
| 197 | method | `BaselineResolver._is_numeric` |

## `app/dynamic_analysis/planning/candidate_builder.py`

| Line | Kind | Definition |
|---:|---|---|
| 22 | class | `ProbeCandidateBuilder` |
| 24 | method | `ProbeCandidateBuilder.build` |
| 87 | method | `ProbeCandidateBuilder._canonical_endpoint` |
| 92 | method | `ProbeCandidateBuilder._query_values` |
| 100 | method | `ProbeCandidateBuilder._observed_value` |
| 115 | method | `ProbeCandidateBuilder._form_fixed_parameters` |
| 139 | method | `ProbeCandidateBuilder._make_candidate` |
| 184 | method | `ProbeCandidateBuilder._append_or_enrich` |

## `app/dynamic_analysis/planning/injection_input_factory.py`

| Line | Kind | Definition |
|---:|---|---|
| 13 | class | `InjectionProbeInputFactory` |
| 25 | method | `InjectionProbeInputFactory.build` |
| 46 | method | `InjectionProbeInputFactory.build_with_resolved_baseline` |
| 88 | method | `InjectionProbeInputFactory._merge_fixed_parameters` |
| 98 | method | `InjectionProbeInputFactory._input` |

## `app/dynamic_analysis/planning/injection_observation_policy.py`

| Line | Kind | Definition |
|---:|---|---|
| 9 | class | `InjectionObservationPlan` |
| 17 | method | `InjectionObservationPlan.test_values` |
| 22 | class | `InjectionObservationPolicy` |
| 64 | method | `InjectionObservationPolicy.plan` |
| 105 | method | `InjectionObservationPolicy._without_baseline` |
| 112 | method | `InjectionObservationPolicy._is_numeric` |

## `app/dynamic_analysis/planning/models.py`

| Line | Kind | Definition |
|---:|---|---|
| 10 | class | `ProbeCandidate` |
| 38 | method | `ProbeCandidate.to_dict` |

## `app/dynamic_analysis/probes/base.py`

| Line | Kind | Definition |
|---:|---|---|
| 10 | class | `DynamicProbe` |
| 17 | method | `DynamicProbe.supports` |
| 21 | method | `DynamicProbe.collect` |

## `app/dynamic_analysis/probes/injection/probe.py`

| Line | Kind | Definition |
|---:|---|---|
| 24 | class | `InjectionProbeInput` |
| 54 | class | `InjectionDifferentialProbe` |
| 84 | method | `InjectionDifferentialProbe.supports` |
| 90 | method | `InjectionDifferentialProbe.collect` |
| 151 | method | `InjectionDifferentialProbe._observe` |

## `app/dynamic_analysis/probes/registry.py`

| Line | Kind | Definition |
|---:|---|---|
| 9 | class | `ProbeRegistry` |
| 17 | method | `ProbeRegistry.register` |
| 33 | method | `ProbeRegistry.get` |
| 39 | method | `ProbeRegistry.applicable` |
| 46 | method | `ProbeRegistry.all` |

## `app/dynamic_analysis/target.py`

| Line | Kind | Definition |
|---:|---|---|
| 13 | class | `InvalidDynamicTarget` |
| 17 | class | `DynamicTarget` |
| 27 | method | `DynamicTarget.is_same_origin` |
| 73 | function | `build_dynamic_target` |
| 169 | function | `_effective_port` |
| 186 | function | `_format_host_for_url` |

## `app/dynamic_analysis/verification_readiness.py`

| Line | Kind | Definition |
|---:|---|---|
| 17 | class | `CandidatePreflight` |
| 23 | method | `CandidatePreflight.ready` |
| 27 | function | `_parameters` |
| 49 | function | `candidates_from_saved_discovery` |
| 86 | function | `preflight_saved_candidate` |

## `app/dynamic_analysis/verification_router.py`

| Line | Kind | Definition |
|---:|---|---|
| 10 | class | `VerificationReadiness` |
| 17 | class | `VerificationMode` |
| 24 | class | `VerificationCapability` |
| 50 | class | `VerificationRoute` |
| 64 | method | `VerificationRoute.can_verify` |
| 70 | method | `VerificationRoute.to_dict` |
| 150 | class | `VerificationRouter` |
| 170 | method | `VerificationRouter.register` |
| 197 | method | `VerificationRouter.route` |
| 371 | method | `VerificationRouter.all` |
| 391 | method | `VerificationRouter._has_context_value` |
| 409 | function | `route_finding_for_verification` |

## `app/dynamic_analysis/verification_service.py`

| Line | Kind | Definition |
|---:|---|---|
| 35 | class | `DynamicVerificationError` |
| 39 | class | `UnsupportedFindingError` |
| 43 | class | `CandidateNotFoundError` |
| 47 | class | `AmbiguousCandidateError` |
| 52 | class | `DynamicVerificationServiceResult` |
| 61 | method | `DynamicVerificationServiceResult.to_dict` |
| 71 | class | `DynamicVerificationService` |
| 116 | method | `DynamicVerificationService.verify` |
| 166 | method | `DynamicVerificationService._validate_finding` |
| 216 | method | `DynamicVerificationService._resolve_candidate` |
| 259 | method | `DynamicVerificationService._canonical_endpoint` |
| 279 | function | `verify_dynamic_finding` |

## `app/dynamic_analysis/verifiers/base.py`

| Line | Kind | Definition |
|---:|---|---|
| 13 | class | `EvidenceVerifier` |
| 19 | method | `EvidenceVerifier.supports` |
| 23 | method | `EvidenceVerifier.verify` |

## `app/dynamic_analysis/verifiers/injection/verifier.py`

| Line | Kind | Definition |
|---:|---|---|
| 11 | class | `InjectionDifferentialVerifier` |
| 15 | method | `InjectionDifferentialVerifier.supports` |
| 28 | method | `InjectionDifferentialVerifier.verify` |

## `app/dynamic_analysis/verifiers/registry.py`

| Line | Kind | Definition |
|---:|---|---|
| 9 | class | `VerifierRegistry` |
| 17 | method | `VerifierRegistry.register` |
| 31 | method | `VerifierRegistry.get` |
| 39 | method | `VerifierRegistry.applicable` |
| 49 | method | `VerifierRegistry.all` |

## `app/evidence_gate.py`

| Line | Kind | Definition |
|---:|---|---|
| 6 | function | `evaluate_evidence` |

## `app/http_probe.py`

| Line | Kind | Definition |
|---:|---|---|
| 9 | function | `main` |

## `app/models/finding.py`

| Line | Kind | Definition |
|---:|---|---|
| 10 | class | `ScanType` |
| 18 | class | `FindingType` |
| 40 | class | `FindingStatus` |
| 50 | class | `Finding` |
| 88 | method | `Finding.to_dict` |
| 100 | method | `Finding.from_dict` |

## `app/runtime_evidence_collector.py`

| Line | Kind | Definition |
|---:|---|---|
| 37 | function | `login_to_dvwa` |
| 81 | function | `count_dvwa_records` |
| 86 | function | `detect_database_error` |
| 109 | function | `build_request_record` |
| 144 | function | `execute_test` |
| 171 | function | `collect_sql_injection_evidence` |
| 333 | function | `save_evidence` |

## `app/static_analysis/archive.py`

| Line | Kind | Definition |
|---:|---|---|
| 15 | class | `ArchiveValidationError` |
| 20 | class | `ExtractionResult` |
| 28 | class | `SafeZipExtractor` |
| 44 | method | `SafeZipExtractor.extract` |
| 146 | method | `SafeZipExtractor._validate_member` |
| 184 | method | `SafeZipExtractor._validate_compression_ratio` |
| 207 | method | `SafeZipExtractor._safe_member_path` |

## `app/static_analysis/collector.py`

| Line | Kind | Definition |
|---:|---|---|
| 75 | class | `SourceFile` |
| 86 | method | `SourceFile.to_dict` |
| 91 | class | `CollectionResult` |
| 98 | method | `CollectionResult.file_count` |
| 102 | method | `CollectionResult.total_lines` |
| 106 | method | `CollectionResult.languages` |
| 109 | method | `CollectionResult.to_dict` |
| 120 | class | `StaticSourceCollector` |
| 143 | method | `StaticSourceCollector.collect` |
| 251 | method | `StaticSourceCollector._is_ignored_path` |
| 261 | method | `StaticSourceCollector._looks_binary` |
| 272 | method | `StaticSourceCollector._skip_record` |

## `app/static_analysis/context_builder.py`

| Line | Kind | Definition |
|---:|---|---|
| 20 | class | `ContextChunk` |
| 31 | method | `ContextChunk.to_dict` |
| 36 | class | `ContextBuildResult` |
| 53 | method | `ContextBuildResult.chunk_count` |
| 56 | method | `ContextBuildResult.to_dict` |
| 79 | class | `StaticContextBuilder` |
| 115 | method | `StaticContextBuilder.build` |
| 226 | method | `StaticContextBuilder._chunk_source_file` |
| 290 | method | `StaticContextBuilder._find_chunk_end` |

## `app/static_verification_service.py`

| Line | Kind | Definition |
|---:|---|---|
| 12 | class | `StaticVerificationError` |
| 17 | class | `StaticVerificationResult` |
| 23 | class | `StaticVerificationService` |
| 33 | method | `StaticVerificationService.verify` |
| 178 | method | `StaticVerificationService._verify_xss_source` |
| 235 | method | `StaticVerificationService._apply_source_scope` |
| 267 | method | `StaticVerificationService._normalise_chunks` |
| 314 | method | `StaticVerificationService._select_relevant_chunks` |
| 365 | method | `StaticVerificationService._build_local_windows` |
| 418 | method | `StaticVerificationService._fallback_windows` |
| 433 | method | `StaticVerificationService._parameter_present` |
| 440 | method | `StaticVerificationService._parameterised_execution` |
| 460 | method | `StaticVerificationService._unsafe_sql_composition` |
| 508 | method | `StaticVerificationService._line_is_relevant` |
| 537 | method | `StaticVerificationService._observation` |

## `app/web/scan_history_store.py`

| Line | Kind | Definition |
|---:|---|---|
| 14 | function | `display_awst_timestamp` |
| 27 | function | `archive_saved_scan` |

## `app/web/server.py`

| Line | Kind | Definition |
|---:|---|---|
| 19 | function | `_load_local_env` |
| 140 | function | `_finding_type_label` |
| 193 | function | `get_finding` |
| 207 | function | `verification_status_for` |
| 225 | function | `evidence_gate_result_for` |
| 236 | function | `build_evidence_tests` |
| 383 | function | `build_evidence_summary` |
| 412 | function | `build_web_evidence` |
| 428 | function | `save_web_evidence` |
| 467 | function | `_resolve_runtime_finding_endpoint` |
| 476 | function | `_saved_runtime_preflight` |
| 499 | function | `_runtime_readiness` |
| 520 | function | `build_view_model` |
| 755 | function | `register_analysis_result` |
| 783 | function | `prepare_dynamic_analysis_result` |
| 860 | function | `home` |
| 874 | function | `_job_update` |
| 881 | function | `_job_snapshot` |
| 897 | class | `_ProgressTrackingProposer` |
| 911 | method | `_ProgressTrackingProposer.last_execution_report` |
| 914 | method | `_ProgressTrackingProposer._begin` |
| 931 | method | `_ProgressTrackingProposer._finish` |
| 942 | method | `_ProgressTrackingProposer.live_progress` |
| 964 | method | `_ProgressTrackingProposer.propose` |
| 971 | method | `_ProgressTrackingProposer.propose_contexts` |
| 980 | function | `_run_static_job` |
| 1032 | class | `_ProgressDiscovery` |
| 1040 | method | `_ProgressDiscovery.discover` |
| 1056 | class | `_ProgressContextBuilder` |
| 1064 | method | `_ProgressContextBuilder.build` |
| 1079 | function | `_run_dynamic_job` |
| 1139 | function | `analysis_job_status` |
| 1147 | function | `start_static_analysis_job` |
| 1175 | function | `start_dynamic_analysis_job` |
| 1209 | function | `start_static_analysis` |
| 1314 | function | `start_dynamic_analysis` |
| 1554 | function | `analysis_results` |
| 1576 | function | `findings_list` |
| 1596 | function | `finding_detail` |
| 1618 | function | `verify_finding` |
| 1850 | function | `update_review` |
| 1938 | function | `_safe_analysis_id` |
| 1945 | function | `_scan_snapshot_path` |
| 1949 | function | `_save_scan_snapshot` |
| 2005 | function | `_load_scan_snapshot` |
| 2018 | function | `_scan_history_cards` |
| 2056 | function | `_restore_scan_snapshot` |
| 2107 | function | `scan_history` |
| 2118 | function | `open_scan_history` |
| 2127 | function | `open_scan_history_report` |
| 2137 | function | `archive_scan_history` |
| 2182 | function | `_report_findings_for_analysis` |
| 2191 | function | `_report_summary` |
| 2215 | function | `_build_analysis_report` |
| 2231 | function | `_saved_analysis_path` |
| 2235 | function | `_load_saved_analysis` |
| 2245 | function | `_saved_analysis_cards` |
| 2272 | function | `_report_csv_text` |
| 2293 | function | `analysis_report` |
| 2312 | function | `save_analysis` |
| 2329 | function | `reports_list` |
| 2338 | function | `saved_report` |
| 2351 | function | `export_report` |
