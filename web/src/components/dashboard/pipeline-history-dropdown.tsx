"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
    History,
    ChevronDown,
    Calendar,
    FileText,
    Target,
    Shield,
    CheckCircle2,
    Trash2,
    Eye
} from "lucide-react"
import { api } from "@/lib/api"
import { formatDistanceToNow } from "date-fns"

interface HistoryRun {
    id: string
    filename: string
    timestamp: string
    report_source: string
    ttps_count: number
    rules_count: number
    final_score: number
    iterations: number
    verified_count: number
}

interface PipelineHistoryDropdownProps {
    onSelectRun: (result: any) => void
}

export function PipelineHistoryDropdown({ onSelectRun }: PipelineHistoryDropdownProps) {
    const [isOpen, setIsOpen] = useState(false)
    const [runs, setRuns] = useState<HistoryRun[]>([])
    const [loading, setLoading] = useState(false)
    const [total, setTotal] = useState(0)

    const loadHistory = async () => {
        setLoading(true)
        try {
            const data = await api.getPipelineHistory(10)
            setRuns(data.runs || [])
            setTotal(data.total || 0)
        } catch (e) {
            console.error("Failed to load history:", e)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        if (isOpen) {
            loadHistory()
        }
    }, [isOpen])

    const handleSelectRun = async (runId: string) => {
        try {
            const result = await api.getPipelineRun(runId)
            onSelectRun(result)
            setIsOpen(false)
        } catch (e) {
            console.error("Failed to load run:", e)
        }
    }

    const handleDeleteRun = async (runId: string, e: React.MouseEvent) => {
        e.stopPropagation()
        if (!confirm("Delete this run from history?")) return
        try {
            await api.deletePipelineRun(runId)
            loadHistory()
        } catch (e) {
            console.error("Failed to delete run:", e)
        }
    }

    const parseTimestamp = (ts: string) => {
        try {
            // Format: 20260115_195012
            const year = ts.slice(0, 4)
            const month = ts.slice(4, 6)
            const day = ts.slice(6, 8)
            const hour = ts.slice(9, 11)
            const min = ts.slice(11, 13)
            const date = new Date(`${year}-${month}-${day}T${hour}:${min}:00`)
            return formatDistanceToNow(date, { addSuffix: true })
        } catch {
            return ts
        }
    }

    return (
        <div className="relative">
            <Button
                variant="outline"
                onClick={() => setIsOpen(!isOpen)}
                className="gap-2"
            >
                <History className="h-4 w-4" />
                History
                {total > 0 && (
                    <Badge variant="secondary" className="ml-1">{total}</Badge>
                )}
                <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
            </Button>

            {isOpen && (
                <div className="absolute top-full mt-2 right-0 w-[400px] max-h-[500px] overflow-auto bg-popover border rounded-lg shadow-xl z-50">
                    <div className="p-3 border-b bg-muted/50">
                        <h4 className="font-semibold text-sm flex items-center gap-2">
                            <History className="h-4 w-4" />
                            Pipeline Run History
                        </h4>
                        <p className="text-xs text-muted-foreground">{total} runs saved</p>
                    </div>

                    {loading ? (
                        <div className="p-4 text-center text-muted-foreground">Loading...</div>
                    ) : runs.length === 0 ? (
                        <div className="p-4 text-center text-muted-foreground">
                            No history yet. Run a pipeline to see results here.
                        </div>
                    ) : (
                        <div className="divide-y">
                            {runs.map((run) => (
                                <div
                                    key={run.id}
                                    className="p-3 hover:bg-muted/50 cursor-pointer transition-colors group"
                                    onClick={() => handleSelectRun(run.id)}
                                >
                                    <div className="flex items-start justify-between gap-2">
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2 mb-1">
                                                <FileText className="h-4 w-4 text-primary flex-shrink-0" />
                                                <span className="font-medium text-sm truncate">
                                                    {run.report_source || run.filename}
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-1 text-xs text-muted-foreground mb-2">
                                                <Calendar className="h-3 w-3" />
                                                {parseTimestamp(run.timestamp)}
                                            </div>
                                            <div className="flex items-center gap-3 text-xs">
                                                <span className="flex items-center gap-1">
                                                    <Target className="h-3 w-3 text-blue-500" />
                                                    {run.ttps_count} TTPs
                                                </span>
                                                <span className="flex items-center gap-1">
                                                    <Shield className="h-3 w-3 text-purple-500" />
                                                    {run.rules_count} Rules
                                                </span>
                                                <span className="flex items-center gap-1">
                                                    <CheckCircle2 className="h-3 w-3 text-green-500" />
                                                    {run.verified_count} Verified
                                                </span>
                                            </div>
                                        </div>
                                        <div className="flex flex-col items-end gap-2">
                                            <Badge variant={run.final_score >= 0.7 ? "default" : "secondary"}>
                                                {Math.round(run.final_score * 100)}%
                                            </Badge>
                                            <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                                <Button
                                                    size="icon"
                                                    variant="ghost"
                                                    className="h-6 w-6"
                                                    onClick={(e) => { e.stopPropagation(); handleSelectRun(run.id) }}
                                                >
                                                    <Eye className="h-3 w-3" />
                                                </Button>
                                                <Button
                                                    size="icon"
                                                    variant="ghost"
                                                    className="h-6 w-6 text-red-500 hover:text-red-600"
                                                    onClick={(e) => handleDeleteRun(run.id, e)}
                                                >
                                                    <Trash2 className="h-3 w-3" />
                                                </Button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}
