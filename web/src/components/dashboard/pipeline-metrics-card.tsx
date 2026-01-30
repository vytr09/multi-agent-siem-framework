"use client"

import { FileText, Shield, Zap, Target, CheckCircle, XCircle, TrendingUp, RefreshCw } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface PipelineMetricsCardProps {
    ttpsCount: number
    rulesCount: number
    attacksCount: number
    detectionRate: number
    precision: number
    f1Score: number
    iterations: number
    verifiedCount?: number
    className?: string
}

export function PipelineMetricsCard({
    ttpsCount,
    rulesCount,
    attacksCount,
    detectionRate,
    precision,
    f1Score,
    iterations,
    verifiedCount,
    className
}: PipelineMetricsCardProps) {
    const metrics = [
        {
            label: "TTPs Extracted",
            value: ttpsCount,
            icon: FileText,
            color: "text-blue-500",
            bgColor: "bg-blue-500/10"
        },
        {
            label: "Rules Generated",
            value: rulesCount,
            icon: Shield,
            color: "text-primary",
            bgColor: "bg-primary/10"
        },
        {
            label: "Attack Commands",
            value: attacksCount,
            icon: Zap,
            color: "text-orange-500",
            bgColor: "bg-orange-500/10"
        },
        {
            label: "Detection Rate",
            value: `${Math.round(detectionRate * 100)}%`,
            icon: Target,
            color: detectionRate >= 0.8 ? "text-green-500" : detectionRate >= 0.5 ? "text-yellow-500" : "text-red-500",
            bgColor: detectionRate >= 0.8 ? "bg-green-500/10" : detectionRate >= 0.5 ? "bg-yellow-500/10" : "bg-red-500/10"
        }
    ]

    return (
        <div className={cn("p-6 rounded-lg border bg-card", className)}>
            <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-foreground flex items-center gap-2">
                    <TrendingUp className="h-5 w-5 text-primary" />
                    Pipeline Summary
                </h3>
                <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs">
                        <RefreshCw className="h-3 w-3 mr-1" />
                        {iterations} iteration{iterations !== 1 ? 's' : ''}
                    </Badge>
                    {verifiedCount !== undefined && (
                        <Badge className="bg-green-500/20 text-green-600 text-xs">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            {verifiedCount} Verified
                        </Badge>
                    )}
                </div>
            </div>

            {/* Main Metrics Grid */}
            <div className="grid grid-cols-4 gap-4">
                {metrics.map((metric) => (
                    <div
                        key={metric.label}
                        className={cn(
                            "p-4 rounded-lg text-center transition-all hover:scale-105",
                            metric.bgColor
                        )}
                    >
                        <metric.icon className={cn("h-6 w-6 mx-auto mb-2", metric.color)} />
                        <p className={cn("text-2xl font-bold", metric.color)}>
                            {metric.value}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                            {metric.label}
                        </p>
                    </div>
                ))}
            </div>

            {/* Secondary Metrics Row */}
            <div className="mt-4 pt-4 border-t border-border grid grid-cols-3 gap-4 text-center">
                <div>
                    <p className="text-lg font-semibold text-foreground">
                        {(precision * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-muted-foreground">Precision</p>
                </div>
                <div>
                    <p className="text-lg font-semibold text-foreground">
                        {(detectionRate * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-muted-foreground">Recall</p>
                </div>
                <div>
                    <p className="text-lg font-semibold text-foreground">
                        {(f1Score * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-muted-foreground">F1 Score</p>
                </div>
            </div>
        </div>
    )
}

// Compact version for sidebar or small spaces
export function PipelineMetricsCompact({
    ttpsCount,
    rulesCount,
    detectionRate,
    className
}: {
    ttpsCount: number
    rulesCount: number
    detectionRate: number
    className?: string
}) {
    return (
        <div className={cn("flex items-center gap-4 p-3 rounded-lg bg-muted/50", className)}>
            <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-blue-500" />
                <span className="text-sm font-medium">{ttpsCount} TTPs</span>
            </div>
            <div className="w-px h-4 bg-border" />
            <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">{rulesCount} Rules</span>
            </div>
            <div className="w-px h-4 bg-border" />
            <div className="flex items-center gap-2">
                {detectionRate >= 0.8 ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                ) : (
                    <XCircle className="h-4 w-4 text-yellow-500" />
                )}
                <span className={cn(
                    "text-sm font-medium",
                    detectionRate >= 0.8 ? "text-green-500" : "text-yellow-500"
                )}>
                    {Math.round(detectionRate * 100)}% Detection
                </span>
            </div>
        </div>
    )
}
