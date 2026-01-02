"use client"

import { useState } from "react"
import { X, FileText, Shield, Zap, BarChart3, CheckCircle, XCircle, Info, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"

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
            siem_verification?: {
                detected: boolean
                events_found: number
                message: string
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
}

interface PipelineResultsModalProps {
    isOpen: boolean
    onClose: () => void
    result: PipelineResult | null
}

const tabs = [
    { id: "ttps", label: "TTPs", icon: FileText },
    { id: "rules", label: "Rules", icon: Shield },
    { id: "attacks", label: "Attacks", icon: Zap },
    { id: "metrics", label: "Metrics", icon: BarChart3 },
]

export function PipelineResultsModal({ isOpen, onClose, result }: PipelineResultsModalProps) {
    const [activeTab, setActiveTab] = useState("ttps")

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
                                                <Badge variant="outline" className="mt-2 text-xs">{ttp.extraction_method}</Badge>
                                            </div>
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
                                    <div key={rule.id || index} className="p-4 rounded-lg border bg-card">
                                        <div className="flex items-start justify-between">
                                            <div className="flex-1">
                                                <h3 className="font-medium text-foreground">{rule.title}</h3>
                                                <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{rule.description}</p>
                                                <div className="flex items-center gap-2 mt-2">
                                                    <Badge variant="outline">{rule.level}</Badge>
                                                    <span className="text-xs text-muted-foreground">{rule.technique_name}</span>
                                                </div>
                                            </div>
                                            <div className="ml-4">
                                                {rule.siem_verification?.detected ? (
                                                    <div className="flex items-center gap-2 text-green-500">
                                                        <CheckCircle className="h-5 w-5" />
                                                        <div className="text-right">
                                                            <p className="text-sm font-medium">Verified</p>
                                                            <p className="text-xs text-muted-foreground">{rule.siem_verification.events_found} events</p>
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div className="flex items-center gap-2 text-muted-foreground">
                                                        <XCircle className="h-5 w-5" />
                                                        <p className="text-sm">Not Verified</p>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
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

                    {activeTab === "metrics" && (
                        <div className="space-y-6">
                            {/* Quality Score */}
                            <div className="p-6 rounded-lg border bg-card">
                                <h3 className="font-medium mb-4">Overall Quality</h3>
                                <div className="flex items-center gap-4">
                                    <div className="text-4xl font-bold text-primary">
                                        {Math.round((result.final_score || 0) * 100)}%
                                    </div>
                                    <div className="flex-1 h-4 bg-muted rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-primary transition-all"
                                            style={{ width: `${(result.final_score || 0) * 100}%` }}
                                        />
                                    </div>
                                </div>
                                {result.iterations && (
                                    <p className="text-sm text-muted-foreground mt-2">
                                        Completed in {result.iterations} iteration(s)
                                    </p>
                                )}
                            </div>

                            {/* SIEM Metrics */}
                            {metrics && (
                                <div className="p-6 rounded-lg border bg-card">
                                    <h3 className="font-medium mb-4">SIEM Detection Metrics</h3>
                                    <div className="grid grid-cols-3 gap-4">
                                        <div className="p-4 rounded-md bg-green-500/10 text-center">
                                            <p className="text-2xl font-bold text-green-500">{metrics.true_positives}</p>
                                            <p className="text-xs text-muted-foreground">True Positives</p>
                                        </div>
                                        <div className="p-4 rounded-md bg-yellow-500/10 text-center">
                                            <p className="text-2xl font-bold text-yellow-500">{metrics.false_positives}</p>
                                            <p className="text-xs text-muted-foreground">False Positives</p>
                                        </div>
                                        <div className="p-4 rounded-md bg-red-500/10 text-center">
                                            <p className="text-2xl font-bold text-red-500">{metrics.false_negatives}</p>
                                            <p className="text-xs text-muted-foreground">False Negatives</p>
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-3 gap-4 mt-4">
                                        <div className="text-center">
                                            <p className="text-lg font-bold">{Math.round(metrics.precision * 100)}%</p>
                                            <p className="text-xs text-muted-foreground">Precision</p>
                                        </div>
                                        <div className="text-center">
                                            <p className="text-lg font-bold">{Math.round(metrics.detection_rate * 100)}%</p>
                                            <p className="text-xs text-muted-foreground">Detection Rate</p>
                                        </div>
                                        <div className="text-center">
                                            <p className="text-lg font-bold">{Math.round(metrics.f1_score * 100)}%</p>
                                            <p className="text-xs text-muted-foreground">F1 Score</p>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
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
