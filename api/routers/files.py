from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List, Dict, Any
import shutil
import os
from pathlib import Path
import uuid
from datetime import datetime
import PyPDF2
import logging

router = APIRouter()
logger = logging.getLogger("api.files")

UPLOAD_DIR = Path("data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def extract_text_from_pdf(file_path: Path) -> str:
    try:
        text = ""
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() + "\n"
        return text
    except Exception as e:
        logger.error(f"Failed to extract text from PDF: {e}")
        return ""

def parse_file(file_path: Path) -> str:
    """Read and extract text content from a file."""
    try:
        content = ""
        ext = file_path.suffix.lower()
        
        if ext == ".pdf":
            content = extract_text_from_pdf(file_path)
        elif ext in [".txt", ".md", ".json", ".log"]:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Fallback to mostly latin-1 for random log files
                 with open(file_path, "r", encoding="latin-1") as f:
                    content = f.read()
        return content
    except Exception as e:
        logger.error(f"Failed to parse file {file_path}: {e}")
        return ""

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a CTI report file (PDF, TXT, MD) and extract its content.
    """
    try:
        file_id = str(uuid.uuid4())
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{file.filename}"
        file_path = UPLOAD_DIR / safe_filename
        
        # Save file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Extract content
        content = parse_file(file_path)
        
        return {
            "id": file_id, # return ID as string
            "filename": file.filename,
            "filename": file.filename,
            "saved_name": safe_filename,
            "path": str(file_path),
            "content": content,
            "size": file_path.stat().st_size
        }
        
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/")
async def list_files():
    """List all uploaded files"""
    files = []
    for f in UPLOAD_DIR.glob("*"):
        if f.is_file():
            files.append({
                "filename": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })
    return sorted(files, key=lambda x: x["modified"], reverse=True)

@router.get("/download/{filename}")
async def download_file(filename: str):
    """Download or stream a file"""
    from fastapi.responses import FileResponse
    file_path = UPLOAD_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
        
    return FileResponse(
        path=file_path, 
        filename=filename,
        media_type="application/pdf" if filename.lower().endswith(".pdf") else "text/plain",
        content_disposition_type="inline"
    )

@router.get("/content/{filename}")
async def get_file_content(filename: str):
    """Get the text content of a file"""
    try:
        file_path = UPLOAD_DIR / filename
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
            
        content = parse_file(file_path)
        return {"filename": filename, "content": content}
    except Exception as e:
        logger.error(f"Failed to get file content: {e}")
        raise HTTPException(status_code=500, detail=str(e))
