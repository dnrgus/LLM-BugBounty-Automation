"""SOURCE MODE: static ingestion and analysis of a source tree.

Per the v3.0 design doc's own scoping (section 8, "초기 범위"): this is a
pattern-based extractor for routes/inputs/sinks/secrets/LLM integration,
not a full interprocedural taint engine. It produces AttackSurfaceItem
candidates; actual exploitability is confirmed by LIVE verification
(HYBRID MODE) or a dedicated Pack, not by this module.
"""
