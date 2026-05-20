---
pipeline_tag: text-generation
license: apache-2.0
language:
  - en
tags:
  - llama-3
  - gguf
  - quantization
  - ollama
  - cybersecurity
  - web-pentesting
  - autonomous-agent
  - sql-injection
  - penetration-testing
base_model: meta-llama/Meta-Llama-3-8B-Instruct
---

# SENTINEL — Llama-3-8B (Quantized GGUF)

This directory contains the **fully merged and quantized** version of the SENTINEL autonomous web-exploitation agent. 

this folder contains a standalone, compressed model ready for immediate local inference using tools like [Ollama](https://ollama.com/) or [llama.cpp](https://github.com/ggerganov/llama.cpp).

## Quantization Details (`model-q5_k_m.gguf`)

The base Llama-3-8B-Instruct model and the SENTINEL SFT+GRPO fine-tuned adapter have been merged into a single file and compressed using **GGUF Quantization**.

- **Format:** GGUF
- **Quantization Method:** `Q5_K_M` (5-bit quantization with medium k-quants)
- **Size:** ~5.7 GB
- **Why Q5_K_M?** This specific quantization level strikes the ideal balance between performance and quality. It drastically reduces the memory footprint (allowing it to run comfortably on an RTX 3050 4GB or standard laptop RAM) while maintaining near-perfect accuracy compared to the uncompressed 16-bit model.

## Included Files

* **`model-q5_k_m.gguf`**: The standalone quantized model weights.
* **`Modelfile`**: The configuration file for creating an Ollama endpoint. It is highly optimized for performance and low VRAM:
  * Uses the Llama-3 `<|start_header_id|>` ChatML format.
  * `num_ctx 2048`: Reduced context window from 4096 to save ~400MB of VRAM on lower-end GPUs.
  * `temperature 0.0`: Forces the model to be completely deterministic, preventing hallucinated reasoning during pentesting.
  * `num_predict 256`: Caps generation at 256 tokens since SENTINEL's expected JSON outputs are small (~150 tokens).
* **`smoke_test.ps1`**: A PowerShell script to quickly verify that the model is generating valid JSON responses in the correct SENTINEL schema.

## How to Run with Ollama

You can instantly deploy this model locally using the included Modelfile.

1. Open a terminal in this directory.
2. Build the model in Ollama:
   ```bash
   ollama create sentinel -f Modelfile
   ```
3. Run the model:
   ```bash
   ollama run sentinel
   ```

*(For use with the SENTINEL pentesting agent pipeline, simply ensure Ollama is serving the model in the background: `ollama serve`)*
