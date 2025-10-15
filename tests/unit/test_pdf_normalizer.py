#!/usr/bin/env python3
import sys
from pathlib import Path
import json

# 1. Fix imports from anywhere
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# 2. Import classes
from agents.collector.datasets.file_loader import FileDatasetLoader
from agents.collector.normalizers.pdf_normalizer import PDFDatasetNormalizer

def test_pdf_normalizer():
    # 3. Point to your data directory
    loader = FileDatasetLoader("data/datasets")
    pdf_files = loader.list_files("*.pdf")
    print(f"Found {len(pdf_files)} PDF files")

    # 4. Load raw events
    raw_events = loader.load_pdf_events()
    print(f"Loaded {len(raw_events)} raw events")
    print("Sample raw event keys:", list(raw_events[0].keys()))

    # 5. Normalize
    normalizer = PDFDatasetNormalizer()
    normalized = [normalizer.normalize_event(evt) for evt in raw_events]
    print(f"Normalized {len(normalized)} events")

    # 6. Inspect one
    sample = normalized[0]
    print("\nSample normalized event JSON:")
    print(json.dumps(sample, indent=2))

if __name__ == "__main__":
    test_pdf_normalizer()
