"use client"

import { useEffect, useRef, useState } from "react"
import { Terminal, Pause, Play, Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"

interface LogViewerProps {
    className?: string
}

export function LogViewer({ className }: LogViewerProps) {
    const [logs, setLogs] = useState<string[]>([])
    const [isConnected, setIsConnected] = useState(false)
    const [isPaused, setIsPaused] = useState(false)
    const [autoScroll, setAutoScroll] = useState(true)
    const scrollRef = useRef<HTMLDivElement>(null)
    const wsRef = useRef<WebSocket | null>(null)

    useEffect(() => {
        // Connect to WebSocket
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//localhost:8000/logs/ws`

        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        ws.onopen = () => {
            setIsConnected(true)
            console.log("Connected to Log Stream")
        }

        ws.onmessage = (event) => {
            if (isPaused) return
            setLogs((prev) => {
                const newLogs = [...prev, event.data]
                return newLogs.slice(-500) // Keep last 500 lines
            })
        }

        ws.onclose = () => {
            setIsConnected(false)
            console.log("Disconnected from Log Stream")
        }

        return () => {
            ws.close()
        }
    }, [isPaused])

    useEffect(() => {
        if (autoScroll && scrollRef.current) {
            const scrollElement = scrollRef.current.querySelector('[data-radix-scroll-area-viewport]');
            if (scrollElement) {
                scrollElement.scrollTop = scrollElement.scrollHeight;
            }
        }
    }, [logs, autoScroll])

    return (
        <div className={cn("flex flex-col h-[400px] border border-border rounded-lg bg-black text-green-500 font-mono text-xs shadow-inner", className)}>
            <div className="flex items-center justify-between px-4 py-2 bg-neutral-900 border-b border-neutral-800 rounded-t-lg">
                <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    <span className="font-semibold">System Logs</span>
                    <span className={`inline-block w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                </div>
                <div className="flex items-center gap-2">
                    <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 text-neutral-400 hover:text-white"
                        onClick={() => {
                            setIsPaused(!isPaused)
                            if (!isPaused) setAutoScroll(false)
                        }}
                    >
                        {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6 text-neutral-400 hover:text-white" onClick={() => setLogs([])}>
                        <span className="sr-only">Clear</span>
                        <span className="text-[10px] uppercase font-bold border rounded px-1">Cls</span>
                    </Button>
                </div>
            </div >

            <ScrollArea className="flex-1 p-4" ref={scrollRef}>
                <div className="space-y-1">
                    {logs.length === 0 && (
                        <div className="text-neutral-600 italic text-center mt-20">Waiting for logs...</div>
                    )}
                    {logs.map((log, i) => (
                        <div key={i} className="break-words whitespace-pre-wrap leading-tight">
                            <span className="opacity-50 mr-2">[{new Date().toLocaleTimeString()}]</span>
                            {log}
                        </div>
                    ))}
                </div>
            </ScrollArea>
        </div >
    )
}
