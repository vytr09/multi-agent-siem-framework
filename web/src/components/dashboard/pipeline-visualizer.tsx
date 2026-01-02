"use client"

import { CheckCircle, Circle, Loader2, ArrowRight } from "lucide-react"
import { cn } from "@/lib/utils"

export type PipelineStage = "idle" | "running" | "completed" | "error"

interface PipelineVisualizerProps {
    currentStage: number
    stages?: { id: string; label: string; status: PipelineStage }[]
}

const DEFAULT_STAGES = [
    { id: "ingest", label: "Ingest CTI", status: "idle" as PipelineStage },
    { id: "extract", label: "Extract TTPs", status: "idle" as PipelineStage },
    { id: "rulegen", label: "Generate Rules", status: "idle" as PipelineStage },
    { id: "verify", label: "Verify & Attack", status: "idle" as PipelineStage },
]

export function PipelineVisualizer({ currentStage = 0, stages = DEFAULT_STAGES }: PipelineVisualizerProps) {
    return (
        <div className="w-full py-8">
            <div className="relative flex items-center justify-between w-full max-w-4xl mx-auto">
                {/* Progress Bar Background */}
                <div className="absolute top-1/2 left-0 w-full h-1 bg-muted -z-10 -translate-y-1/2 rounded-full" />

                {/* Active Progress Bar */}
                <div
                    className="absolute top-1/2 left-0 h-1 bg-primary -z-10 -translate-y-1/2 rounded-full transition-all duration-500 ease-in-out"
                    style={{ width: `${(currentStage / (stages.length - 1)) * 100}%` }}
                />

                {stages.map((stage, index) => {
                    let status = stage.status as PipelineStage;
                    // Auto-calculate status based on index if not explicitly running/error
                    if (status === 'idle') {
                        if (index < currentStage) status = 'completed';
                        if (index === currentStage) status = 'running';
                    }

                    return (
                        <div key={stage.id} className="flex flex-col items-center gap-3 px-2">
                            <div className={cn(
                                "flex items-center justify-center w-10 h-10 rounded-full border-2 transition-all duration-300 z-10 bg-background",
                                status === "completed" && "bg-primary border-primary text-primary-foreground",
                                status === "running" && "border-primary text-primary animate-pulse",
                                status === "idle" && "border-muted-foreground/30 text-muted-foreground",
                                status === "error" && "border-destructive bg-destructive text-destructive-foreground"
                            )}>
                                {status === "completed" ? (
                                    <CheckCircle className="w-6 h-6" />
                                ) : status === "running" ? (
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                ) : (
                                    <Circle className="w-5 h-5" />
                                )}
                            </div>
                            <span className={cn(
                                "text-xs font-medium uppercase tracking-wide transition-colors",
                                status === "idle" ? "text-muted-foreground" : "text-foreground"
                            )}>
                                {stage.label}
                            </span>
                        </div>
                    )
                })}
            </div>
        </div>
    )
}
