"use client"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { CheckCircle, FileText, Shield, Zap, BarChart3, Eye } from "lucide-react"

interface PipelineResult {
    status: string
    extraction?: {
        extraction_summary?: {
            total_ttps_extracted: number
        }
    }
    rules?: {
        rules?: any[]
    }
    attacks?: any[]
    siem_verification?: any[]
    final_score?: number
    final_report?: {
        total_ttps: number
        optimized_ttps: number
        generated_rules: number
        generated_attacks: number
    }
}

interface PipelineSummaryProps {
    result: PipelineResult | null
    onViewDetails: () => void
}

export function PipelineSummary({ result, onViewDetails }: PipelineSummaryProps) {
    if (!result || result.status !== "success") return null

    const ttpsCount = result.final_report?.total_ttps || 0
    const rulesCount = result.final_report?.generated_rules || 0
    const attacksCount = result.final_report?.generated_attacks || 0
    const score = result.final_score || 0
    const verified = result.siem_verification?.some((v: any) => v.detected) || false

    return (
        <div className="mt-4 p-4 rounded-lg border border-primary/30 bg-primary/5 space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-primary">
                    <CheckCircle className="h-5 w-5" />
                    <span className="font-semibold">Analysis Complete</span>
                </div>
                <Button size="sm" variant="secondary" onClick={onViewDetails}>
                    <Eye className="h-4 w-4 mr-2" />
                    View Full Report
                </Button>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-4 gap-4">
                <div className="flex items-center gap-3 p-3 rounded-md bg-background border">
                    <div className="p-2 rounded-md bg-blue-500/10">
                        <FileText className="h-4 w-4 text-blue-500" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{ttpsCount}</p>
                        <p className="text-xs text-muted-foreground">TTPs Extracted</p>
                    </div>
                </div>

                <div className="flex items-center gap-3 p-3 rounded-md bg-background border">
                    <div className="p-2 rounded-md bg-green-500/10">
                        <Shield className="h-4 w-4 text-green-500" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{rulesCount}</p>
                        <p className="text-xs text-muted-foreground">Rules Generated</p>
                    </div>
                </div>

                <div className="flex items-center gap-3 p-3 rounded-md bg-background border">
                    <div className="p-2 rounded-md bg-orange-500/10">
                        <Zap className="h-4 w-4 text-orange-500" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{attacksCount}</p>
                        <p className="text-xs text-muted-foreground">Attacks Created</p>
                    </div>
                </div>

                <div className="flex items-center gap-3 p-3 rounded-md bg-background border">
                    <div className="p-2 rounded-md bg-purple-500/10">
                        <BarChart3 className="h-4 w-4 text-purple-500" />
                    </div>
                    <div>
                        <p className="text-2xl font-bold text-foreground">{Math.round(score * 100)}%</p>
                        <p className="text-xs text-muted-foreground">Quality Score</p>
                    </div>
                </div>
            </div>

            {/* Verification Badge */}
            <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">SIEM Verification:</span>
                {verified ? (
                    <Badge className="bg-green-500/20 text-green-600 border-green-500/30">✓ Detected</Badge>
                ) : (
                    <Badge variant="secondary">Not Verified</Badge>
                )}
            </div>
        </div>
    )
}
