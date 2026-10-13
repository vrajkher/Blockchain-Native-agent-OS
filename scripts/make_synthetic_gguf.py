#!/usr/bin/env python3
"""Generate a SYNTHETIC GGUF model with random weights for benchmarking.

The model has exactly the tensor shapes of Qwen2.5-0.5B-Instruct (494M
params) and is quantized to Q4_K_M by llama.cpp itself, so its RAM
footprint and CPU latency match the real model closely. Its weights are
random: OUTPUT TEXT IS MEANINGLESS. Use it only to measure memory/latency
when real weights cannot be downloaded.

Requires (dev only): pip install gguf numpy llama-cpp-python

    python scripts/make_synthetic_gguf.py --out models/synthetic-qwen2.5-0.5b-q4_k_m.gguf
"""

from __future__ import annotations

import argparse
import ctypes
import os
import tempfile

import numpy as np

SHAPES = {  # Qwen2.5-0.5B
    "tiny": dict(vocab=151936, hidden=64, inter=128, layers=2, heads=4, kv_heads=2),
    "qwen2.5-0.5b": dict(vocab=151936, hidden=896, inter=4864, layers=24, heads=14, kv_heads=2),
}

CHATML = ("{% for message in messages %}{{'<|im_start|>' + message['role'] + '\\n' + "
          "message['content'] + '<|im_end|>' + '\\n'}}{% endfor %}"
          "{% if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{% endif %}")


def bytes_to_unicode() -> list[str]:
    bs = list(range(ord("!"), ord("~") + 1)) + list(range(ord("¡"), ord("¬") + 1)) + \
        list(range(ord("®"), ord("ÿ") + 1))
    cs = bs[:]
    n = 0
    for b in range(256):
        if b not in bs:
            bs.append(b)
            cs.append(256 + n)
            n += 1
    table = dict(zip(bs, cs))
    return [chr(table[b]) for b in range(256)]


def build_vocab(vocab_size: int):
    tokens = bytes_to_unicode()
    letters = "abcdefghijklmnopqrstuvwxyz"
    merges = []
    for a in letters + "Ġ":
        for b in letters:
            merges.append(f"{a} {b}")
            tokens.append(a + b)
    specials = {151643: "<|endoftext|>", 151644: "<|im_start|>", 151645: "<|im_end|>"}
    types = [1] * len(tokens)
    while len(tokens) < vocab_size:
        i = len(tokens)
        if i in specials:
            tokens.append(specials[i])
            types.append(3)  # CONTROL
        else:
            tokens.append(f"<|unused{i}|>")
            types.append(5)  # UNUSED
    return tokens, types, merges


def write_f16(path: str, shape: dict, seed: int) -> None:
    import gguf

    rng = np.random.default_rng(seed)
    h, inter, L = shape["hidden"], shape["inter"], shape["layers"]
    heads, kvh = shape["heads"], shape["kv_heads"]
    head_dim = h // heads
    kv = kvh * head_dim

    def w(*dims):
        return (rng.standard_normal(dims, dtype=np.float32) * 0.02).astype(np.float16)

    wr = gguf.GGUFWriter(path, "qwen2")
    wr.add_name("synthetic-random-qwen2.5-0.5b-shape")
    wr.add_context_length(32768)
    wr.add_embedding_length(h)
    wr.add_feed_forward_length(inter)
    wr.add_block_count(L)
    wr.add_head_count(heads)
    wr.add_head_count_kv(kvh)
    wr.add_rope_freq_base(1_000_000.0)
    wr.add_layer_norm_rms_eps(1e-6)
    wr.add_file_type(gguf.LlamaFileType.MOSTLY_F16)
    tokens, types, merges = build_vocab(shape["vocab"])
    wr.add_tokenizer_model("gpt2")
    wr.add_tokenizer_pre("qwen2")
    wr.add_token_list(tokens)
    wr.add_token_types(types)
    wr.add_token_merges(merges)
    wr.add_eos_token_id(151645)
    wr.add_bos_token_id(151643)
    wr.add_pad_token_id(151643)
    wr.add_add_bos_token(False)
    wr.add_chat_template(CHATML)

    wr.add_tensor("token_embd.weight", w(shape["vocab"], h))
    wr.add_tensor("output_norm.weight", np.ones(h, dtype=np.float32))
    for i in range(L):
        p = f"blk.{i}."
        wr.add_tensor(p + "attn_norm.weight", np.ones(h, dtype=np.float32))
        wr.add_tensor(p + "attn_q.weight", w(h, h))
        wr.add_tensor(p + "attn_q.bias", np.zeros(h, dtype=np.float32))
        wr.add_tensor(p + "attn_k.weight", w(kv, h))
        wr.add_tensor(p + "attn_k.bias", np.zeros(kv, dtype=np.float32))
        wr.add_tensor(p + "attn_v.weight", w(kv, h))
        wr.add_tensor(p + "attn_v.bias", np.zeros(kv, dtype=np.float32))
        wr.add_tensor(p + "attn_output.weight", w(h, h))
        wr.add_tensor(p + "ffn_norm.weight", np.ones(h, dtype=np.float32))
        wr.add_tensor(p + "ffn_gate.weight", w(inter, h))
        wr.add_tensor(p + "ffn_up.weight", w(inter, h))
        wr.add_tensor(p + "ffn_down.weight", w(h, inter))
    wr.write_header_to_file()
    wr.write_kv_data_to_file()
    wr.write_tensors_to_file()
    wr.close()


def quantize(src: str, dst: str) -> None:
    import llama_cpp

    params = llama_cpp.llama_model_quantize_default_params()
    params.ftype = llama_cpp.LLAMA_FTYPE_MOSTLY_Q4_K_M
    params.nthread = os.cpu_count() or 1
    rc = llama_cpp.llama_model_quantize(src.encode(), dst.encode(), ctypes.byref(params))
    if rc != 0:
        raise SystemExit(f"quantization failed: {rc}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--shape", choices=sorted(SHAPES), default="qwen2.5-0.5b")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with tempfile.TemporaryDirectory(dir=os.path.dirname(os.path.abspath(args.out))) as tmp:
        f16 = os.path.join(tmp, "model-f16.gguf")
        write_f16(f16, SHAPES[args.shape], args.seed)
        quantize(f16, args.out)
    print(f"wrote {args.out} ({os.path.getsize(args.out) / 2**20:.1f} MiB) -- SYNTHETIC RANDOM WEIGHTS")


if __name__ == "__main__":
    main()
