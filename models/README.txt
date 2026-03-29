FastText classifier model for Yashigani gateway (Phase 12).

Place the trained binary here as: fasttext_classifier.bin

Generate training data and train:
  python scripts/generate_training_data.py > /tmp/train.txt
  fasttext supervised -input /tmp/train.txt -output models/fasttext_classifier \
      -epoch 25 -lr 0.5 -wordNgrams 2 -dim 100

The gateway image COPYs the entire models/ directory at build time.
If the file is absent the gateway degrades gracefully — all payloads
route to the LLM second-pass inspection (no security gap, ~5ms slower).

Model size: ~100 MB (quantized) — included in gateway image.
Do not commit trained model files to source control.
