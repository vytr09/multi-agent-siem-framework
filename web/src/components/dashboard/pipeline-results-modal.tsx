"use client"

import { useState } from "react"
import { X, FileText, Shield, Zap, BarChart3, CheckCircle, XCircle, Info, AlertTriangle, RefreshCw, ChevronDown, ChevronUp, Code } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"
import { FeedbackLoopPanel } from "./feedback-loop-panel"
import { DemoMetricsHeader } from "./demo-metrics-header"
import yaml from "js-yaml"

interface PipelineResult {
    status: string
    extraction?: {
        extraction_results?: Array<{
            extracted_ttps: Array<{
                ttp_id: string
                technique_name: string
                attack_id: string
                tactic: string
                confidence_score: number
                extraction_method: string
                indicators?: string[]
                tools?: string[]
                reasoning?: string
                quote?: string
            }>
        }>
    }
    rules?: {
        rules?: Array<{
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
        }>
    }
    attacks?: Array<{
        id: string
        technique_name: string
        platform: string
        command: string
        safety_level: string
        description: string
    }>
    siem_metrics?: {
        true_positives: number
        false_positives: number
        false_negatives: number
        precision: number
        detection_rate: number
        f1_score: number
    }
    evaluation?: {
        summary?: {
            average_quality_score: number
        }
    }
    iterations?: number
    final_score?: number
    rule_history?: Array<any>
}

interface PipelineResultsModalProps {
    isOpen: boolean
    onClose: () => void
    result: PipelineResult | null
}

const tabs = [
    { id: "overview", label: "Overview", icon: BarChart3 },
    { id: "ttps", label: "TTPs", icon: FileText },
    { id: "rules", label: "Rules", icon: Shield },
    { id: "attacks", label: "Attacks", icon: Zap },
    { id: "feedback", label: "Feedback Loop", icon: RefreshCw },
]

// Helper to convert rule object to YAML string
const ruleToYaml = (rule: any) => {
    try {
        // Strip internal fields starting with _ or extra UI fields
        const cleanRule = { ...rule }
        // Remove verification result from the YAML view as it's not part of Sigma
        const keysToRemove = ['id', 'technique_name', 'siem_verification', '_score', '_iteration', '_is_initial']

        Object.keys(cleanRule).forEach(key => {
            if (key.startsWith('_') || keysToRemove.includes(key)) delete cleanRule[key]
        })
        return yaml.dump(cleanRule)
    } catch (e) {
        return JSON.stringify(rule, null, 2)
    }
}

// Sub-component for individual Rule Item
function RuleItem({ rule }: { rule: any }) {
    const [isExpanded, setIsExpanded] = useState(false)

    return (
        <div className="rounded-lg border bg-card overflow-hidden">
            <div className="p-4 flex items-start justify-between">
                <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                        <h3 className="font-medium text-foreground">{rule.title}</h3>
                        <div className="flex items-center gap-2">
                            {rule.siem_verification?.detected ? (
                                <Badge className="bg-green-500 hover:bg-green-600 text-white gap-1">
                                    <CheckCircle className="h-3 w-3" />
                                    Verified ({rule.siem_verification.events_found})
                                </Badge>
                            ) : (
                                <Badge variant="outline" className="text-muted-foreground gap-1">
                                    <XCircle className="h-3 w-3" />
                                    Not Detected
                                </Badge>
                            )}
                        </div>
                    </div>

                    <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{rule.description}</p>
                    <div className="flex items-center gap-2 mt-2">
                        <Badge variant="outline">{rule.level}</Badge>
                        <span className="text-xs text-muted-foreground">{rule.technique_name}</span>
                        <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-xs ml-auto gap-1 text-primary hover:text-primary/80"
                            onClick={() => setIsExpanded(!isExpanded)}
                        >
                            <Code className="h-3 w-3" />
                            {isExpanded ? "Hide Source" : "View YAML"}
                            {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                        </Button>
                    </div>
                </div>
            </div>

            {isExpanded && (
                <div className="bg-zinc-950 p-4 border-t border-border animate-in slide-in-from-top-2">
                    <pre className="text-xs font-mono text-zinc-300 whitespace-pre-wrap overflow-x-auto">
                        {ruleToYaml(rule)}
                    </pre>
                </div>
            )}
        </div>
    )
}

export function PipelineResultsModal({ isOpen, onClose, result }: PipelineResultsModalProps) {
    const [activeTab, setActiveTab] = useState("overview")

    if (!isOpen || !result) return null

    const ttps = result.extraction?.extraction_results?.[0]?.extracted_ttps || []
    const rules = result.rules?.rules || []
    const attacks = result.attacks || []
    const metrics = result.siem_metrics

    const getConfidenceColor = (score: number) => {
        if (score >= 0.8) return "text-green-500"
        if (score >= 0.6) return "text-yellow-500"
        return "text-red-500"
    }

    const getSafetyColor = (level: string) => {
        switch (level) {
            case "low": return "bg-green-500/20 text-green-600"
            case "medium": return "bg-yellow-500/20 text-yellow-600"
            case "high": return "bg-red-500/20 text-red-600"
            default: return "bg-muted text-muted-foreground"
        }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="relative w-full max-w-5xl max-h-[90vh] bg-background rounded-lg shadow-lg border border-border flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                    <div className="flex items-center gap-2">
                        <BarChart3 className="h-5 w-5 text-primary" />
                        <h2 className="text-lg font-semibold">Pipeline Analysis Results</h2>
                        {result.final_score && (
                            <Badge className="ml-2">{Math.round(result.final_score * 100)}% Quality</Badge>
                        )}
                    </div>
                    <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8">
                        <X className="h-4 w-4" />
                    </Button>
                </div>

                {/* Tabs */}
                <div className="flex border-b border-border px-6">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={cn(
                                "flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors",
                                activeTab === tab.id
                                    ? "border-primary text-primary"
                                    : "border-transparent text-muted-foreground hover:text-foreground"
                            )}
                        >
                            <tab.icon className="h-4 w-4" />
                            {tab.label}
                            {tab.id === "ttps" && <Badge variant="secondary" className="ml-1">{ttps.length}</Badge>}
                            {tab.id === "rules" && <Badge variant="secondary" className="ml-1">{rules.length}</Badge>}
                            {tab.id === "attacks" && <Badge variant="secondary" className="ml-1">{attacks.length}</Badge>}
                        </button>
                    ))}
                </div>

                {/* Content */}
                <ScrollArea className="flex-1 p-6">
                    {/* NEW: Overview Tab with DemoMetricsHeader */}
                    {activeTab === "overview" && (
                        <div className="space-y-6">
                            <DemoMetricsHeader
                                ttpsCount={ttps.length}
                                rulesCount={rules.length}
                                attacksCount={attacks.length}
                                detectionRate={metrics?.detection_rate || 0}
                                precision={metrics?.precision || 0}
                                f1Score={metrics?.f1_score || 0}
                                qualityScore={result.final_score || 0}
                                iterations={result.iterations || 1}
                            />

                            {/* Quick Stats */}
                            <div className="grid grid-cols-2 gap-4">
                                <div className="p-4 rounded-lg border bg-card">
                                    <h4 className="font-medium mb-2">Pipeline Status</h4>
                                    <div className="flex items-center gap-2">
                                        <CheckCircle className="h-5 w-5 text-green-500" />
                                        <span className="text-sm text-muted-foreground">
                                            Completed in {result.iterations || 1} iteration(s)
                                        </span>
                                    </div>
                                </div>
                                <div className="p-4 rounded-lg border bg-card">
                                    <h4 className="font-medium mb-2">Final Quality</h4>
                                    <div className="flex items-center gap-4">
                                        <span className="text-3xl font-bold text-primary">
                                            {Math.round((result.final_score || 0) * 100)}%
                                        </span>
                                        <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-primary"
                                                style={{ width: `${(result.final_score || 0) * 100}%` }}
                                            />
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === "ttps" && (
                        <div className="space-y-3">
                            {ttps.length === 0 ? (
                                <p className="text-muted-foreground text-center py-8">No TTPs extracted.</p>
                            ) : (
                                ttps.map((ttp, index) => (
                                    <div key={ttp.ttp_id || index} className="p-4 rounded-lg border bg-card">
                                        <div className="flex items-start justify-between">
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <span className="font-mono text-sm font-bold text-primary">{ttp.attack_id}</span>
                                                    <span className="font-medium">{ttp.technique_name}</span>
                                                </div>
                                                <p className="text-sm text-muted-foreground mt-1">Tactic: {ttp.tactic}</p>

                                                {/* EVIDENCE/INDICATORS */}
                                                {(ttp.indicators && ttp.indicators.length > 0 || ttp.tools && ttp.tools.length > 0) && (
                                                    <div className="mt-3 flex flex-wrap gap-2">
                                                        {ttp.indicators?.map((ind: string, i: number) => (
                                                            <Badge key={`ind-${i}`} variant="secondary" className="text-[10px] bg-blue-500/10 text-blue-600 hover:bg-blue-500/20 border-blue-200/20">
                                                                Ind: {ind}
                                                            </Badge>
                                                        ))}
                                                        {ttp.tools?.map((tool: string, i: number) => (
                                                            <Badge key={`tool-${i}`} variant="secondary" className="text-[10px] bg-orange-500/10 text-orange-600 hover:bg-orange-500/20 border-orange-200/20">
                                                                Tool: {tool}
                                                            </Badge>
                                                        ))}
                                                    </div>
                                                )}

                                                {/* NEW: Reason & Quote (for improved evidence) */}
                                                {(ttp.reasoning || ttp.quote) && (
                                                    <div className="mt-4 pt-3 border-t border-border/50">
                                                        {ttp.quote && (
                                                            <div className="mb-2">
                                                                <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1 mb-1">
                                                                    <Info className="h-3 w-3" /> Source Evidence
                                                                </span>
                                                                <blockquote className="text-xs italic text-muted-foreground border-l-2 border-primary/50 pl-3 py-1 bg-muted/30 rounded-r">
                                                                    "{ttp.quote}"
                                                                </blockquote>
                                                            </div>
                                                        )}
                                                        {ttp.reasoning && (
                                                            <div>
                                                                <span className="text-xs font-semibold text-muted-foreground">Reasoning: </span>
                                                                <span className="text-xs text-muted-foreground">{ttp.reasoning}</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}

                                                <Badge variant="outline" className="mt-2 text-xs">{ttp.extraction_method}</Badge>                                            </div>
                                            <div className="text-right">
                                                <p className={cn("text-2xl font-bold", getConfidenceColor(ttp.confidence_score))}>
                                                    {Math.round(ttp.confidence_score * 100)}%
                                                </p>
                                                <p className="text-xs text-muted-foreground">Confidence</p>
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}

                    {activeTab === "rules" && (
                        <div className="space-y-3">
                            {rules.length === 0 ? (
                                <p className="text-muted-foreground text-center py-8">No rules generated.</p>
                            ) : (
                                rules.map((rule, index) => (
                                    <RuleItem key={rule.id || index} rule={rule} />
                                ))
                            )}
                        </div>
                    )}

                    {activeTab === "attacks" && (
                        <div className="space-y-3">
                            {attacks.length === 0 ? (
                                <p className="text-muted-foreground text-center py-8">No attacks generated.</p>
                            ) : (
                                attacks.map((attack, index) => (
                                    <div key={attack.id || index} className="p-4 rounded-lg border bg-card">
                                        <div className="flex items-start justify-between mb-2">
                                            <div>
                                                <h3 className="font-medium text-foreground">{attack.technique_name}</h3>
                                                <p className="text-sm text-muted-foreground">{attack.description}</p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <Badge variant="outline">{attack.platform}</Badge>
                                                <Badge className={getSafetyColor(attack.safety_level)}>{attack.safety_level}</Badge>
                                            </div>
                                        </div>
                                        <pre className="mt-2 p-3 rounded-md bg-muted font-mono text-xs overflow-x-auto">
                                            {attack.command}
                                        </pre>
                                    </div>
                                ))
                            )}
                        </div>
                    )}

                    {activeTab === "feedback" && (
                        <FeedbackLoopPanel
                            iterations={result.iterations || 1}
                            finalScore={result.final_score || 0}
                            maxIterations={3}
                            detected={(metrics?.detection_rate ?? 0) > 0}
                            rules={rules}
                            ruleHistory={result.rule_history}
                        />
                    )}
                </ScrollArea>

                {/* Footer */}
                <div className="px-6 py-3 border-t border-border flex justify-end">
                    <Button variant="outline" onClick={onClose}>Close</Button>
                </div>
            </div>
        </div>
    )
}
