"use client"

import { useEffect, useState, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Terminal, RefreshCw, Download, Trash2 } from "lucide-react"
import { api } from "@/lib/api"

export default function LogsPage() {
    const [logs, setLogs] = useState<string[]>([])
    const [loading, setLoading] = useState(true)
    const scrollRef = useRef<HTMLDivElement>(null)

    const fetchLogs = async () => {
        setLoading(true)
        try {
            const data = await api.getLogs(500) // Get last 500 lines
            setLogs(data.logs || [])
        } catch (error) {
            console.error("Failed to fetch logs:", error)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchLogs()
        const interval = setInterval(fetchLogs, 5000)
        return () => clearInterval(interval)
    }, [])

    // Auto-scroll to bottom when logs update
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight
        }
    }, [logs])

    const handleDownload = () => {
        const blob = new Blob([logs.join('\n')], { type: "text/plain" })
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `system_logs_${new Date().toISOString().split('T')[0]}.txt`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    return (
        <div className="h-[calc(100vh-6rem)] flex flex-col space-y-6">
            <div className="flex items-center justify-between flex-shrink-0">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-neutral-100">System Logs</h1>
                    <p className="text-neutral-400 mt-1">Real-time system events and debugging information.</p>
                </div>
                <div className="flex gap-3">
                    <Button variant="outline" onClick={fetchLogs}>
                        <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                        Refresh
                    </Button>
                    <Button variant="outline" onClick={handleDownload}>
                        <Download className="h-4 w-4 mr-2" />
                        Download
                    </Button>
                    <Button variant="ghost" size="icon">
                        <Trash2 className="h-4 w-4 text-neutral-500 hover:text-red-500" />
                    </Button>
                </div>
            </div>

            <Card className="flex-1 overflow-hidden flex flex-col border-neutral-800 bg-neutral-950">
                <CardHeader className="border-b border-neutral-800 py-3 bg-neutral-900">
                    <div className="flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-neutral-500" />
                        <span className="text-xs font-mono text-neutral-400">logs/system.log</span>
                    </div>
                </CardHeader>
                <CardContent className="flex-1 p-0 overflow-hidden relative">
                    <div
                        ref={scrollRef}
                        className="absolute inset-0 overflow-y-auto p-4 space-y-1 font-mono text-xs"
                    >
                        {logs.length === 0 && (
                            <div className="text-neutral-600 italic">No logs available...</div>
                        )}
                        {logs.map((log, i) => (
                            <div key={i} className="text-neutral-300 hover:bg-neutral-900 px-2 py-0.5 rounded">
                                <span className="text-neutral-600 mr-2">{i + 1}</span>
                                {log}
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}
