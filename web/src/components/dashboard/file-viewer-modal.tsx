"use client"

import { useEffect, useState } from "react"
import { X, Loader2, FileText, Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { api, API_BASE_URL } from "@/lib/api"

interface FileViewerModalProps {
    isOpen: boolean
    onClose: () => void
    filename: string | null
}

export function FileViewerModal({ isOpen, onClose, filename }: FileViewerModalProps) {
    const [content, setContent] = useState<string>("")
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)

    const isPdf = filename?.toLowerCase().endsWith('.pdf')

    useEffect(() => {
        if (isOpen && filename) {
            if (!isPdf) {
                loadFileContent(filename)
            }
        } else {
            setContent("")
            setError(null)
        }
    }, [isOpen, filename, isPdf])

    const loadFileContent = async (fname: string) => {
        try {
            setLoading(true)
            setError(null)
            const data = await api.getFileContent(fname)
            setContent(data.content)
        } catch (err) {
            console.error(err)
            setError("Failed to load file content.")
        } finally {
            setLoading(false)
        }
    }

    if (!isOpen) return null

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="relative w-full max-w-4xl max-h-[90vh] h-[800px] bg-background rounded-lg shadow-lg border border-border flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                    <div className="flex items-center gap-2">
                        <FileText className="h-5 w-5 text-primary" />
                        <h2 className="text-lg font-semibold truncate max-w-md">
                            {filename?.replace(/^\d{8}_\d{6}_/, '') || "File Viewer"}
                        </h2>
                    </div>
                    <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8 hover:bg-muted">
                        <X className="h-4 w-4" />
                    </Button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-hidden p-0 bg-muted/30 relative">
                    {isPdf ? (
                        <iframe
                            src={`${API_BASE_URL}/uploads/${filename}`}
                            className="w-full h-full border-none"
                            title="PDF Viewer"
                        />
                    ) : (
                        <div className="h-full overflow-auto">
                            {loading ? (
                                <div className="flex flex-col items-center justify-center h-full">
                                    <Loader2 className="h-8 w-8 animate-spin text-primary mb-2" />
                                    <p className="text-muted-foreground">Loading text content...</p>
                                </div>
                            ) : error ? (
                                <div className="flex flex-col items-center justify-center h-full text-destructive">
                                    <p>{error}</p>
                                    <Button variant="outline" size="sm" onClick={() => filename && loadFileContent(filename)} className="mt-4">
                                        Retry
                                    </Button>
                                </div>
                            ) : (
                                <div className="p-6">
                                    <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-foreground bg-card p-4 rounded-md border border-border shadow-sm">
                                        {content}
                                    </pre>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="px-6 py-3 border-t border-border flex justify-end gap-2 bg-background rounded-b-lg">
                    <Button variant="outline" onClick={onClose}>Close</Button>
                </div>
            </div>
        </div>
    )
}
