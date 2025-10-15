# agents/collector/datasets/file_loader.py
import glob
from pathlib import Path
from typing import List, Dict, Any
from PyPDF2 import PdfReader
from agents.base.exceptions import CollectorException

class FileDatasetLoader:
    """
    Loader for offline CTI datasets (PDF, JSON, CSV).
    """

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)

    def list_files(self, pattern: str = "*.pdf") -> List[Path]:
        return list(self.data_dir.glob(pattern))

    def load_pdf_events(self) -> List[Dict[str, Any]]:
        """
        Extract text from each PDF and wrap into raw_event format.
        """
        raw_events = []
        for pdf_path in self.list_files("*.pdf"):
            try:
                reader = PdfReader(str(pdf_path))
                text = "\n".join(page.extract_text() or "" for page in reader.pages)
                raw_events.append({
                    "source": pdf_path.stem,
                    "content": text,
                    "metadata": {"filename": pdf_path.name}
                })
            except Exception as e:
                raise CollectorException(f"Failed to read {pdf_path}: {e}")
        return raw_events
