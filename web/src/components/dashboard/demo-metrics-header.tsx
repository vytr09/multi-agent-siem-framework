"use client"

import { Activity, Shield, Zap, Target, CheckCircle, RefreshCw, TrendingUp } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface DemoMetricsHeaderProps {
    ttpsCount: number
    rulesCount: number
    attacksCount: number
    detectionRate: number
    precision: number
    f1Score: number
    qualityScore: number
    iterations: number
}

/**
 * DemoMetricsHeader - Top-level summary component for RQ4 demo
 * Shows key pipeline metrics at a glance
 */
export function DemoMetricsHeader({
    ttpsCount,
    rulesCount,
    attacksCount,
    detectionRate,
    precision,
    f1Score,
    qualityScore,
    iterations
}: DemoMetricsHeaderProps) {
    return (
        <div className="bg-gradient-to-r from-primary/10 via-primary/5 to-transparent rounded-lg p-4 border border-primary/20">
            {/* Top Row: Pipeline Summary */}
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                    <Activity className="h-5 w-5 text-primary" />
                    <span className="font-semibold text-foreground">Pipeline Results Summary</span>
                </div>
                <Badge
                    variant="secondary"
                    className={cn(
                        "text-xs",
                        qualityScore >= 0.7 ? "bg-green-500/20 text-green-600" : "bg-yellow-500/20 text-yellow-600"
                    )}
                >
                    {Math.round(qualityScore * 100)}% Quality Score
                </Badge>
            </div>

            {/* Main Metrics Grid */}
            <div className="grid grid-cols-4 gap-4">
                {/* TTPs */}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border">
                    <div className="p-2 rounded-full bg-blue-500/10 text-blue-500">
                        <Target className="h-4 w-4" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{ttpsCount}</p>
                        <p className="text-xs text-muted-foreground">TTPs Extracted</p>
                    </div>
                </div>

                {/* Rules */}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border">
                    <div className="p-2 rounded-full bg-purple-500/10 text-purple-500">
                        <Shield className="h-4 w-4" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{rulesCount}</p>
                        <p className="text-xs text-muted-foreground">Sigma Rules</p>
                    </div>
                </div>

                {/* Attacks */}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border">
                    <div className="p-2 rounded-full bg-orange-500/10 text-orange-500">
                        <Zap className="h-4 w-4" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{attacksCount}</p>
                        <p className="text-xs text-muted-foreground">Attack Commands</p>
                    </div>
                </div>

                {/* Iterations */}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border">
                    <div className="p-2 rounded-full bg-primary/10 text-primary">
                        <RefreshCw className="h-4 w-4" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{iterations}</p>
                        <p className="text-xs text-muted-foreground">Iterations</p>
                    </div>
                </div>
            </div>

            {/* Bottom Row: Detection Metrics (RQ4 focus) */}
            <div className="mt-4 pt-4 border-t border-border/50">
                <div className="flex items-center gap-2 mb-3">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm font-medium text-muted-foreground">SIEM Detection Metrics (RQ4)</span>
                </div>
                <div className="grid grid-cols-3 gap-4">
                    <MetricBar
                        label="Precision"
                        value={precision}
                        color="green"
                        highlight={precision >= 0.9}
                    />
                    <MetricBar
                        label="Recall (Detection Rate)"
                        value={detectionRate}
                        color="blue"
                    />
                    <MetricBar
                        label="F1-Score"
                        value={f1Score}
                        color="purple"
                    />
                </div>
            </div>
        </div>
    )
}

interface MetricBarProps {
    label: string
    value: number
    color: "green" | "blue" | "purple" | "orange"
    highlight?: boolean
}

function MetricBar({ label, value, color, highlight }: MetricBarProps) {
    const colorClasses = {
        green: "bg-green-500",
        blue: "bg-blue-500",
        purple: "bg-purple-500",
        orange: "bg-orange-500"
    }

    const textClasses = {
        green: "text-green-500",
        blue: "text-blue-500",
        purple: "text-purple-500",
        orange: "text-orange-500"
    }

    return (
        <div className={cn(
            "p-3 rounded-lg bg-background/50",
            highlight && "ring-2 ring-green-500/30"
        )}>
            <div className="flex justify-between items-center mb-2">
                <span className="text-xs text-muted-foreground">{label}</span>
                <span className={cn("text-lg font-bold", textClasses[color])}>
                    {Math.round(value * 100)}%
                </span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                    className={cn("h-full rounded-full transition-all duration-500", colorClasses[color])}
                    style={{ width: `${value * 100}%` }}
                />
            </div>
            {highlight && (
                <div className="flex items-center gap-1 mt-1">
                    <TrendingUp className="h-3 w-3 text-green-500" />
                    <span className="text-xs text-green-500">Excellent</span>
                </div>
            )}
        </div>
    )
}

/**
 * Compact version for pipeline summary card
 */
export function PipelineMetricsBadges({
    precision,
    recall,
    f1
}: {
    precision: number
    recall: number
    f1: number
}) {
    return (
        <div className="flex items-center gap-2 flex-wrap">
            <Badge className="bg-green-500/20 text-green-600 border-green-500/30">
                P: {Math.round(precision * 100)}%
            </Badge>
            <Badge className="bg-blue-500/20 text-blue-600 border-blue-500/30">
                R: {Math.round(recall * 100)}%
            </Badge>
            <Badge className="bg-purple-500/20 text-purple-600 border-purple-500/30">
                F1: {Math.round(f1 * 100)}%
            </Badge>
        </div>
    )
}
