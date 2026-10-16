package main

import (
	"net/http"
	"time"
)

// Prices are USD per 1M tokens from the OpenAI API pricing page.
// Short applies at or under 272K input tokens. Long applies above that.
// Context window is 1.05M tokens.
type modelMeta struct {
	Input       float64
	CachedInput float64
	CacheWrite  float64
	Output      float64
	LongInput   float64
	LongCached  float64
	LongWrite   float64
	LongOutput  float64
	Context     int
	MaxOutput   int
	// Reasoning lists supported reasoning.effort values. Empty means thinking is not advertised.
	Reasoning []string
}

var catalog = map[string]modelMeta{
	"gpt-6-astra":   {10, 1, 12.5, 50, 20, 2, 25, 75, 1_050_000, 128_000, nil},
	"gpt-6.1-sol":   {2, 0.10, 2.5, 10, 4, 0.20, 5, 15, 1_050_000, 128_000, []string{"low", "medium", "high", "xhigh", "max"}},
	"gpt-6-sol":     {2, 0.20, 2.5, 10, 4, 0.40, 5, 15, 1_050_000, 128_000, []string{"none", "low", "medium", "high", "xhigh", "max"}},
	"gpt-6-luna":    {0.10, 0.01, 0.125, 0.50, 0.20, 0.02, 0.25, 0.75, 1_050_000, 128_000, []string{"none", "low", "medium", "high", "xhigh", "max"}},
	"gpt-5.6-sol":   {4, 0.40, 5, 20, 8, 0.80, 10, 30, 1_050_000, 128_000, nil},
	"gpt-5.6-terra": {2, 0.20, 2.5, 12, 4, 0.40, 5, 18, 1_050_000, 128_000, nil},
	"gpt-5.6-luna":  {0.20, 0.02, 0.25, 1.20, 0.40, 0.04, 0.50, 1.80, 1_050_000, 128_000, []string{"none", "low", "medium", "high", "xhigh", "max"}},
}

func (s *server) listModels(w http.ResponseWriter, r *http.Request) {
	if !s.clientOK(w, r) {
		return
	}
	ups, err := s.loadUpstreams()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load models"})
		return
	}
	data := make([]any, 0)
	seen := map[string]bool{}
	for _, u := range ups {
		for _, id := range u.Models {
			if seen[id] {
				continue
			}
			seen[id] = true
			data = append(data, modelObject(id))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func (s *server) getModel(w http.ResponseWriter, r *http.Request) {
	if !s.clientOK(w, r) {
		return
	}
	id := r.PathValue("id")
	ups, err := s.loadUpstreams()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load models"})
		return
	}
	for _, u := range ups {
		for _, m := range u.Models {
			if m == id {
				writeJSON(w, http.StatusOK, modelObject(id))
				return
			}
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
}

func (s *server) clientOK(w http.ResponseWriter, r *http.Request) bool {
	raw := clientKey(r)
	if raw == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing api key"})
		return false
	}
	ok, err := s.keyExists(raw)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key lookup failed"})
		return false
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return false
	}
	return true
}

func modelObject(id string) map[string]any {
	meta, known := catalog[id]
	if !known {
		meta = modelMeta{Context: 1_050_000, MaxOutput: 128_000}
	}
	obj := map[string]any{
		"id":                id,
		"object":            "model",
		"created":           time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Unix(),
		"owned_by":          "openai",
		"context_window":    meta.Context,
		"max_output_tokens": meta.MaxOutput,
		"input_modalities":  []string{"text", "image", "video"},
		"output_modalities": []string{"text"},
		"thinking":          len(meta.Reasoning) > 0,
		"pricing": map[string]any{
			"currency":                       "USD",
			"unit":                           "per_1m_tokens",
			"short_context_max_input_tokens": 272_000,
			"short": map[string]float64{
				"input": meta.Input, "cached_input": meta.CachedInput,
				"cache_write": meta.CacheWrite, "output": meta.Output,
			},
			"long": map[string]float64{
				"input": meta.LongInput, "cached_input": meta.LongCached,
				"cache_write": meta.LongWrite, "output": meta.LongOutput,
			},
		},
	}
	if len(meta.Reasoning) > 0 {
		obj["reasoning"] = map[string]any{
			"supported":        true,
			"default_effort":   "medium",
			"supported_effort": meta.Reasoning,
		}
	}
	return obj
}
