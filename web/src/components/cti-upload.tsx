"use client"

import { useState } from "react"
import { Upload, FileText, CheckCircle, AlertCircle, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { api } from "@/lib/api"
import { useToast } from "@/components/ui/toast-notification"

interface CTIUploadProps {
    onParse: (content: string) => void
}

export function CTIUpload({ onParse }: CTIUploadProps) {
    const { showToast } = useToast()
    const [dragging, setDragging] = useState(false)
    const [file, setFile] = useState<File | null>(null)
    const [uploading, setUploading] = useState(false)
    const [parsed, setParsed] = useState(false)

    const handleDragOver = (e: React.DragEvent) => {
        e.preventDefault()
        setDragging(true)
    }

    const handleDragLeave = () => {
        setDragging(false)
    }

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault()
        setDragging(false)
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0])
            setParsed(false)
        }
    }

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0])
            setParsed(false)
        }
    }

    const handleParse = async () => {
        if (!file) return

        setUploading(true)
        try {
            const formData = new FormData()
            formData.append("file", file)

            const response = await api.uploadFile(file)
            onParse(response.content)
            setParsed(true)
            showToast("CTI Report parsed successfully", "success")
        } catch (error) {
            console.error("Upload failed", error)
            showToast("Failed to parse file", "error")
        } finally {
            setUploading(false)
        }
    }

    return (
        <Card className="h-full">
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5 text-blue-500" />
                    CTI Data Source
                </CardTitle>
                <CardDescription>Upload a threat report (PDF/TXT) to analyze.</CardDescription>
            </CardHeader>
            <CardContent>
                <div
                    className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors ${dragging ? "border-blue-500 bg-blue-500/10" : "border-neutral-800 hover:border-neutral-700"
                        }`}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                >
                    <input
                        type="file"
                        id="cti-upload"
                        className="hidden"
                        accept=".txt,.pdf,.md"
                        onChange={handleFileChange}
                    />

                    {!file ? (
                        <label htmlFor="cti-upload" className="cursor-pointer flex flex-col items-center gap-2">
                            <Upload className="h-8 w-8 text-neutral-500" />
                            <span className="text-sm text-neutral-400">Drag file or click to browse</span>
                            <span className="text-xs text-neutral-600">Supports PDF, TXT, MD</span>
                        </label>
                    ) : (
                        <div className="flex flex-col items-center gap-2">
                            <FileText className="h-8 w-8 text-blue-500" />
                            <span className="text-sm font-medium text-neutral-200">{file.name}</span>
                            <Button
                                size="sm"
                                variant="secondary"
                                className="mt-2 w-full"
                                onClick={handleParse}
                                disabled={uploading || parsed}
                            >
                                {uploading ? (
                                    <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Parsing...</>
                                ) : parsed ? (
                                    <><CheckCircle className="mr-2 h-4 w-4 text-emerald-500" /> Ready</>
                                ) : (
                                    "Parse Content"
                                )}
                            </Button>
                        </div>
                    )}
                </div>
            </CardContent>
        </Card>
    )
}
