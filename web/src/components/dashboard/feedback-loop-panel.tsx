import { RefreshCw, CheckCircle, AlertTriangle, ArrowRight, TrendingUp, Wrench, Bug, Sparkles, StopCircle, Shield, ChevronDown, ChevronUp, Eye, EyeOff, XCircle, CheckCircle2, AlertCircle, ArrowDown, History as HistoryIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useState } from "react"
import yaml from "js-yaml"

interface RuleData {
    id: string
    title: string
    description: string
    level: string
    technique_name: string
    logsource?: {
        category?: string
        product?: string
        service?: string
    }
    detection?: Record<string, unknown>
    tags?: string[]
    falsepositives?: string[]
    siem_verification?: {
        detected: boolean
        events_found: number
        message: string
        status?: string
    }
}

interface RuleHistoryItem {
    id?: string
    title: string
    description?: string
    level?: string
    technique_name?: string
    logsource?: {
        category?: string
        product?: string
        service?: string
    }
    detection?: Record<string, unknown>
    tags?: string[]
    siem_verification?: {
        detected: boolean
        events_found: number
        message: string
    }
    _iteration: number
    _score: number
    _is_initial: boolean
    _critique?: string
}

// Helper to convert rule object to YAML string
const ruleToYaml = (rule: any) => {
    try {
        // Strip internal fields starting with _
        const cleanRule = { ...rule }
        Object.keys(cleanRule).forEach(key => {
            if (key.startsWith('_') || key === 'siem_verification') delete cleanRule[key]
        })
        return yaml.dump(cleanRule)
    } catch (e) {
        return JSON.stringify(rule, null, 2)
    }
}

interface FeedbackLoopPanelProps {
    iterations: number
    initialScore?: number
    finalScore: number
    maxIterations?: number
    detected?: boolean
    rules?: RuleData[]
    ruleHistory?: RuleHistoryItem[]
}

// Simple Diff Component
function SimpleDiffView({ oldText, newText }: { oldText: string, newText: string }) {
    const oldLines = oldText.split('\n')
    const newLines = newText.split('\n')

    // Very basic diff logic
    return (
        <div className="bg-zinc-950 p-3 rounded-md overflow-auto max-h-[400px] text-xs font-mono border border-zinc-800">
            <div className="flex gap-4 mb-2 border-b border-zinc-800 pb-2">
                <div className="flex-1 text-red-400 font-semibold text-center">Previous</div>
                <div className="flex-1 text-green-400 font-semibold text-center">Current</div>
            </div>

            <div className="space-y-0.5">
                <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1">
                        {oldLines.map((line, i) => (
                            <div key={i} className={cn("px-1", !newLines.includes(line) ? "bg-red-900/30 text-red-300" : "text-zinc-500")}>
                                {line || ' '}
                            </div>
                        ))}
                    </div>
                    <div className="space-y-1">
                        {newLines.map((line, i) => (
                            <div key={i} className={cn("px-1", !oldLines.includes(line) ? "bg-green-900/30 text-green-300" : "text-zinc-300")}>
                                {line || ' '}
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}

export function FeedbackLoopPanel({
    iterations,
    initialScore,
    finalScore,
    maxIterations = 3,
    detected = false,
    rules = [],
    ruleHistory = []
}: FeedbackLoopPanelProps) {
    const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set())

    // Group rule history by TTP
    const historyByTtp = ruleHistory.reduce((acc, item) => {
        const key = item.technique_name || item.title || 'unknown'
        if (!acc[key]) acc[key] = []
        acc[key].push(item)
        return acc
    }, {} as Record<string, RuleHistoryItem[]>)

    // Sort versions inside each TTP by iteration
    Object.keys(historyByTtp).forEach(key => {
        historyByTtp[key].sort((a, b) => a._iteration - b._iteration)
    })

    // Calculate metrics
    const initialVersions = ruleHistory.filter(r => r._iteration === 0 || r._is_initial)
    const actualBaseline = initialVersions.length > 0
        ? initialVersions.reduce((sum, r) => sum + (r._score || 0), 0) / initialVersions.length
        : initialScore || 0.5

    // Calculate final score
    const bestScores: number[] = []
    Object.values(historyByTtp).forEach(versions => {
        let bestScore = 0
        for (const v of versions) {
            if (v.siem_verification?.detected) {
                bestScore = v._score || 0
                break
            }
            if ((v._score || 0) > bestScore) bestScore = v._score || 0
        }
        bestScores.push(bestScore)
    })
    const actualFinalScore = bestScores.length > 0
        ? bestScores.reduce((sum, s) => sum + s, 0) / bestScores.length
        : finalScore

    const improvement = actualFinalScore - actualBaseline
    const improvementPercent = actualBaseline > 0
        ? ((improvement / actualBaseline) * 100).toFixed(1)
        : "N/A"

    const totalRules = rules.length
    const verifiedRules = rules.filter(r => r.siem_verification?.detected).length
    const totalEvents = rules.reduce((sum, r) => sum + (r.siem_verification?.events_found || 0), 0)
    const hasHistory = ruleHistory.length > 0

    const toggleItem = (id: string, event?: React.MouseEvent) => {
        if (event) event.stopPropagation()
        const newExpanded = new Set(expandedItems)
        if (newExpanded.has(id)) newExpanded.delete(id)
        else newExpanded.add(id)
        setExpandedItems(newExpanded)
    }

    // Generate Stop Info
    const getStopReason = () => {
        if (detected || verifiedRules > 0) {
            return {
                reason: "SIEM Verification Passed",
                description: `Dừng ở iteration ${iterations} - ${verifiedRules}/${totalRules} rules verified (${totalEvents} events)`,
                type: "success" as const
            }
        }
        if (iterations >= maxIterations) {
            return {
                reason: "Max Iterations Reached",
                description: `Đã chạy hết ${maxIterations} vòng lặp`,
                type: "warning" as const
            }
        }
        return {
            reason: "Processing",
            description: `Đang chạy iteration ${iterations}...`,
            type: "info" as const
        }
    }
    const stopInfo = getStopReason()

    return (
        <div className="space-y-6">
            {/* HEADER METRICS */}
            <div className="grid grid-cols-4 gap-4">
                <div className="p-4 rounded-lg bg-card border flex flex-col items-center justify-center text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Baseline</p>
                    <p className="text-2xl font-bold text-red-500">{Math.round(actualBaseline * 100)}%</p>
                    <span className="text-[10px] text-muted-foreground">Iteration 0</span>
                </div>
                <div className="p-4 rounded-lg bg-card border flex flex-col items-center justify-center text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Improvement</p>
                    <div className="flex items-center gap-1">
                        <TrendingUp className={cn("w-4 h-4", improvement >= 0 ? "text-green-500" : "text-red-500")} />
                        <p className={cn("text-2xl font-bold", improvement >= 0 ? "text-green-500" : "text-red-500")}>
                            {improvement >= 0 ? "+" : ""}{Math.round(improvement * 100)}%
                        </p>
                    </div>
                    <span className="text-[10px] text-muted-foreground">{improvementPercent}% relative</span>
                </div>
                <div className="p-4 rounded-lg bg-card border flex flex-col items-center justify-center text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Final Score</p>
                    <p className="text-2xl font-bold text-green-500">{Math.round(actualFinalScore * 100)}%</p>
                    <span className="text-[10px] text-muted-foreground">After Feedback</span>
                </div>
                <div className="p-4 rounded-lg bg-card border flex flex-col items-center justify-center text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Iterations</p>
                    <p className="text-2xl font-bold">{iterations}</p>
                    <Badge variant={stopInfo.type === 'success' ? 'default' : 'outline'} className="text-[10px]">
                        {stopInfo.reason}
                    </Badge>
                </div>
            </div>

            {/* RULE EVOLUTION TIMELINE */}
            {hasHistory ? (
                <div className="space-y-4">
                    <h4 className="font-semibold flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-primary" />
                        Feedback Loop Timeline (Detailed)
                    </h4>

                    {Object.entries(historyByTtp).map(([ttpName, versions]) => {
                        const itemId = `history-${ttpName}`
                        const isExpanded = expandedItems.has(itemId)
                        const bestVersion = versions[versions.length - 1] // Simple last for header
                        const initialVersion = versions[0]

                        return (
                            <div key={ttpName} className="border rounded-lg bg-card overflow-hidden">
                                {/* Header Toggle */}
                                <div
                                    className="p-4 flex items-center justify-between cursor-pointer hover:bg-muted/50 transition-colors"
                                    onClick={(e) => toggleItem(itemId, e)}
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 rounded bg-primary/10 text-primary">
                                            <Shield className="w-5 h-5" />
                                        </div>
                                        <div>
                                            <p className="font-medium text-sm">{ttpName}</p>
                                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                                <span>{versions.length} versions</span>
                                                <span>•</span>
                                                <span className={cn(initialVersion._score < bestVersion._score ? "text-green-500" : "")}>
                                                    Score: {Math.round(initialVersion._score * 100)}% → {Math.round(bestVersion._score * 100)}%
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        {bestVersion.siem_verification?.detected && (
                                            <Badge className="bg-green-500 text-white hover:bg-green-600 border-none">
                                                <CheckCircle2 className="w-3 h-3 mr-1" />
                                                Verified
                                            </Badge>
                                        )}
                                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                                    </div>
                                </div>

                                {/* Timeline Content */}
                                {isExpanded && (
                                    <div className="p-6 pt-0 bg-muted/5 border-t">
                                        <div className="relative pl-6 pt-6 space-y-8">
                                            {/* Vertical Line */}
                                            <div className="absolute left-[27px] top-6 bottom-6 w-0.5 bg-border" />

                                            {versions.map((version, idx) => {
                                                const prevVersion = idx > 0 ? versions[idx - 1] : null
                                                const showDiff = prevVersion !== null
                                                const critique = version._critique || (idx > 0 ? "Refined based on feedback" : null)

                                                return (
                                                    <div key={idx} className="relative z-10">
                                                        {/* Critique Connector */}
                                                        {showDiff && critique && (
                                                            <div className="ml-8 mb-4 p-3 rounded bg-orange-500/10 border border-orange-500/20 text-xs text-orange-600">
                                                                <div className="flex items-start gap-2">
                                                                    <div className="mt-0.5"><Wrench className="w-3 h-3" /></div>
                                                                    <div>
                                                                        <span className="font-semibold">Feedback:</span> {critique}
                                                                    </div>
                                                                </div>
                                                                <div className="absolute -left-[29px] top-4 w-3 h-3 rounded-full bg-orange-500 border-2 border-background" />
                                                            </div>
                                                        )}

                                                        {/* Version Node */}
                                                        <div className="flex items-start gap-4">
                                                            <div className={cn(
                                                                "flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center border-4 border-background font-bold text-xs ring-1 ring-border shadow-sm",
                                                                version.siem_verification?.detected ? "bg-green-500 text-white" : "bg-card"
                                                            )}>
                                                                V{version._iteration}
                                                            </div>

                                                            <div className="flex-1 space-y-2">
                                                                <div className="flex items-center justify-between">
                                                                    <div className="flex items-center gap-2">
                                                                        <Badge variant="outline">Score: {Math.round(version._score * 100)}%</Badge>
                                                                        {version._is_initial && <Badge variant="secondary">Initial Draft</Badge>}
                                                                    </div>
                                                                    {showDiff && (
                                                                        <Button
                                                                            variant="ghost"
                                                                            size="sm"
                                                                            className="h-6 text-xs gap-1"
                                                                            onClick={(e) => toggleItem(`diff-${ttpName}-${idx}`, e)}
                                                                        >
                                                                            {expandedItems.has(`diff-${ttpName}-${idx}`) ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                                                                            {expandedItems.has(`diff-${ttpName}-${idx}`) ? "Hide Changes" : "View Changes"}
                                                                        </Button>
                                                                    )}
                                                                </div>

                                                                {/* Diff or Code View */}
                                                                {showDiff && expandedItems.has(`diff-${ttpName}-${idx}`) ? (
                                                                    <SimpleDiffView
                                                                        oldText={prevVersion ? ruleToYaml(prevVersion) : ''}
                                                                        newText={ruleToYaml(version)}
                                                                    />
                                                                ) : (
                                                                    <div className="bg-zinc-950 p-3 rounded-md border border-zinc-800">
                                                                        <pre className="text-xs font-mono text-zinc-400 whitespace-pre-wrap max-h-[200px] overflow-auto">
                                                                            {ruleToYaml(version)}
                                                                        </pre>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )
                                            })}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )
                    })}
                </div>
            ) : (
                <div className="p-12 text-center border-2 border-dashed rounded-lg bg-muted/10">
                    <HistoryIcon className="w-10 h-10 text-muted-foreground mx-auto mb-3 opacity-50" />
                    <h3 className="text-lg font-medium">Chưa có lịch sử chạy</h3>
                    <p className="text-sm text-muted-foreground max-w-sm mx-auto mt-1">
                        Hãy chạy pipeline để xem quá trình Feedback Loop tự động cải thiện luật như thế nào.
                    </p>
                </div>
            )}
        </div>
    )
}

export function FeedbackLoopBadge({ iterations, improvement }: { iterations: number; improvement: number }) {
    return (
        <div className="flex items-center gap-2">
            <RefreshCw className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">{iterations} iteration{iterations !== 1 ? 's' : ''}</span>
            {improvement > 0 && <Badge className="bg-green-500/20 text-green-600 text-xs">+{Math.round(improvement * 100)}%</Badge>}
        </div>
    )
}
