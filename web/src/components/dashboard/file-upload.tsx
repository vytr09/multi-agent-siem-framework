"use client"

import { useCallback, useState } from "react"
import { useDropzone } from "react-dropzone"
import { Upload, FileText, CheckCircle, AlertCircle, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

interface FileUploadProps {
    onUploadComplete?: () => void
}

export function FileUpload({ onUploadComplete }: FileUploadProps) {
    const [isUploading, setIsUploading] = useState(false)
    const [uploadStatus, setUploadStatus] = useState<"idle" | "success" | "error">("idle")
    const [errorMessage, setErrorMessage] = useState("")

    const onDrop = useCallback(async (acceptedFiles: File[]) => {
        if (acceptedFiles.length === 0) return

        setIsUploading(true)
        setUploadStatus("idle")
        setErrorMessage("")

        const file = acceptedFiles[0]
        const formData = new FormData()
        formData.append("file", file)

        try {
            const response = await fetch("http://localhost:8000/files/upload", {
                method: "POST",
                body: formData,
            })

            if (!response.ok) {
                throw new Error("Upload failed")
            }

            setUploadStatus("success")
            if (onUploadComplete) onUploadComplete()
        } catch (error) {
            console.error(error)
            setUploadStatus("error")
            setErrorMessage("Failed to upload file")
        } finally {
            setIsUploading(false)
        }
    }, [onUploadComplete])

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop,
        accept: {
            'application/pdf': ['.pdf'],
            'text/plain': ['.txt', '.md', '.log', '.json']
        },
        maxFiles: 1
    })

    return (
        <div className="w-full">
            <div
                {...getRootProps()}
                className={cn(
                    "relative border-2 border-dashed rounded-xl p-10 transition-all duration-200 ease-in-out cursor-pointer text-center",
                    isDragActive
                        ? "border-primary bg-primary/5"
                        : "border-border hover:border-primary/50 hover:bg-muted/50",
                    uploadStatus === "error" && "border-destructive/50 bg-destructive/5",
                    uploadStatus === "success" && "border-green-500/50 bg-green-500/5"
                )}
            >
                <input {...getInputProps()} />

                <div className="flex flex-col items-center justify-center space-y-4">
                    <div className={cn(
                        "p-4 rounded-full bg-muted transition-colors",
                        isDragActive && "bg-primary/20 text-primary",
                        uploadStatus === "success" && "bg-green-100 text-green-600 dark:bg-green-900/30",
                        uploadStatus === "error" && "bg-red-100 text-red-600 dark:bg-red-900/30"
                    )}>
                        {isUploading ? (
                            <Loader2 className="w-8 h-8 animate-spin" />
                        ) : uploadStatus === "success" ? (
                            <CheckCircle className="w-8 h-8" />
                        ) : uploadStatus === "error" ? (
                            <AlertCircle className="w-8 h-8" />
                        ) : (
                            <Upload className="w-8 h-8 text-muted-foreground" />
                        )}
                    </div>

                    <div className="space-y-1">
                        <h3 className="text-lg font-semibold tracking-tight">
                            {isUploading ? "Uploading..." : "Upload CTI Report"}
                        </h3>
                        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
                            Drag & drop your PDF or Text report here, or click to browse.
                        </p>
                    </div>

                    {errorMessage && (
                        <p className="text-sm text-destructive font-medium">{errorMessage}</p>
                    )}

                    {!isUploading && (
                        <Button variant="secondary" size="sm" className="mt-2">
                            Select File
                        </Button>
                    )}
                </div>
            </div>
        </div>
    )
}
