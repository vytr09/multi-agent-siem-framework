"use client"

import { useEffect, useRef, useState } from "react"
import { Terminal, Pause, Play, Filter, RefreshCw, TrendingUp, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface LogViewerProps {
    className?: string
}

// Keywords to highlight for feedback loop
const FEEDBACK_KEYWORDS = [
    'Iteration', 'iteration',
    'quality_score', 'Score', 'score',
    'feedback', 'Feedback', 'FEEDBACK',
    'Refining', 'refining',
    'Success criteria',
    'Detected', 'detected',
    'improvement', 'Improvement'
]

const AGENT_KEYWORDS = [
    'Extractor', 'EXTRACTOR',
    'RuleGen', 'RULEGEN',
    'AttackGen', 'ATTACKGEN',
    'Evaluator', 'EVALUATOR',
    'SIEM', 'Splunk', 'verification'
]

const ERROR_KEYWORDS = ['ERROR', 'Error', 'error', 'FAILED', 'Failed', 'failed']
const WARNING_KEYWORDS = ['WARNING', 'Warning', 'warning', 'WARN']

function getLogStyle(log: string): { className: string; icon?: React.ReactNode; badge?: string } {
    // Check for feedback-related logs first
    if (FEEDBACK_KEYWORDS.some(kw => log.includes(kw))) {
        return {
            className: 'text-purple-400 bg-purple-500/10',
            badge: 'Feedback',
            icon: <RefreshCw className="w-3 h-3 text-purple-400" />
        }
    }

    // Check for errors
    if (ERROR_KEYWORDS.some(kw => log.includes(kw))) {
        return {
            className: 'text-red-400 bg-red-500/10',
            icon: <AlertTriangle className="w-3 h-3 text-red-400" />
        }
    }

    // Check for warnings
    if (WARNING_KEYWORDS.some(kw => log.includes(kw))) {
        return {
            className: 'text-yellow-400 bg-yellow-500/10',
            icon: <AlertTriangle className="w-3 h-3 text-yellow-400" />
        }
    }

    // Check for agent-related logs
    if (AGENT_KEYWORDS.some(kw => log.includes(kw))) {
        return {
            className: 'text-cyan-400 bg-cyan-500/5'
        }
    }

    // Score mentions
    if (log.includes('%') || log.match(/\d+\.\d{2,}/)) {
        return {
            className: 'text-green-400',
            icon: <TrendingUp className="w-3 h-3 text-green-400" />
        }
    }

    return { className: 'text-green-500' }
}

export function LogViewer({ className }: LogViewerProps) {
    const [logs, setLogs] = useState<string[]>([])
    const [isConnected, setIsConnected] = useState(false)
    const [isPaused, setIsPaused] = useState(false)
    const [autoScroll, setAutoScroll] = useState(true)
    const [filterFeedback, setFilterFeedback] = useState(false)
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

    // Filter logs if feedback filter is active
    const displayedLogs = filterFeedback
        ? logs.filter(log => FEEDBACK_KEYWORDS.some(kw => log.includes(kw)))
        : logs

    const feedbackCount = logs.filter(log => FEEDBACK_KEYWORDS.some(kw => log.includes(kw))).length

    return (
        <div className={cn("flex flex-col h-[400px] border border-border rounded-lg bg-black text-green-500 font-mono text-xs shadow-inner", className)}>
            <div className="flex items-center justify-between px-4 py-2 bg-neutral-900 border-b border-neutral-800 rounded-t-lg">
                <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    <span className="font-semibold">System Logs</span>
                    <span className={`inline-block w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                    {feedbackCount > 0 && (
                        <Badge variant="secondary" className="bg-purple-500/20 text-purple-400 text-[10px] px-1.5">
                            {feedbackCount} Feedback
                        </Badge>
                    )}
                </div>
                <div className="flex items-center gap-2">
                    {/* Filter Feedback Toggle */}
                    <Button
                        variant={filterFeedback ? "default" : "ghost"}
                        size="icon"
                        className={cn(
                            "h-6 w-6",
                            filterFeedback
                                ? "bg-purple-500/30 text-purple-300 hover:bg-purple-500/40"
                                : "text-neutral-400 hover:text-white"
                        )}
                        onClick={() => setFilterFeedback(!filterFeedback)}
                        title="Filter Feedback Logs"
                    >
                        <Filter className="w-4 h-4" />
                    </Button>
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
                    {displayedLogs.length === 0 && (
                        <div className="text-neutral-600 italic text-center mt-20">
                            {filterFeedback ? 'No feedback logs yet...' : 'Waiting for logs...'}
                        </div>
                    )}
                    {displayedLogs.map((log, i) => {
                        const style = getLogStyle(log)
                        return (
                            <div
                                key={i}
                                className={cn(
                                    "break-words whitespace-pre-wrap leading-tight px-1 py-0.5 rounded",
                                    style.className
                                )}
                            >
                                <span className="opacity-50 mr-2">[{new Date().toLocaleTimeString()}]</span>
                                {style.icon && <span className="inline-block mr-1 align-middle">{style.icon}</span>}
                                {log}
                                {style.badge && (
                                    <Badge variant="outline" className="ml-2 text-[8px] py-0 px-1 text-purple-400 border-purple-500/30">
                                        {style.badge}
                                    </Badge>
                                )}
                            </div>
                        )
                    })}
                </div>
            </ScrollArea>
        </div >
    )
}
