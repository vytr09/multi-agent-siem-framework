import React from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { CheckCircle, ArrowRight, Activity, Shield, Zap, Target, FileText, Server } from "lucide-react";
import { cn } from "@/lib/utils";
import { AgentStatus } from "@/lib/api";

interface PipelineStepProps {
    icon: React.ElementType;
    title: string;
    status: 'idle' | 'running' | 'completed' | 'error';
    description?: string;
}

const PipelineStep = ({ icon: Icon, title, status, description }: PipelineStepProps) => {
    const statusColors = {
        idle: "border-border text-muted-foreground bg-muted",
        running: "border-primary/50 text-primary bg-primary/10 animate-pulse shadow-[0_0_15px_rgba(37,99,235,0.2)]",
        completed: "border-emerald-500/50 text-emerald-500 bg-emerald-500/10",
        error: "border-destructive/50 text-destructive bg-destructive/10",
    };

    return (
        <div className={cn("flex flex-col items-center p-4 rounded-lg border min-w-[140px] text-center transition-all duration-300 relative z-10", statusColors[status])}>
            <div className={cn("p-3 rounded-full mb-3 bg-card border transition-colors duration-300",
                status === 'running' ? 'border-primary/50 text-primary' :
                    status === 'completed' ? 'border-emerald-500/50 text-emerald-500' :
                        'border-border text-muted-foreground'
            )}>
                <Icon className="h-6 w-6" />
            </div>
            <h3 className="font-semibold text-sm mb-1 text-foreground">{title}</h3>
            {description && <p className="text-xs text-muted-foreground">{description}</p>}

            {status === 'running' && (
                <div className="absolute -top-1 -right-1">
                    <span className="relative flex h-3 w-3">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-3 w-3 bg-primary"></span>
                    </span>
                </div>
            )}
        </div>
    );
};

const Arrow = ({ active }: { active: boolean }) => (
    <div className="hidden md:flex flex-1 items-center justify-center -mx-4 z-0">
        <div className={cn("h-[2px] w-full relative transition-colors duration-500", active ? "bg-primary/50" : "bg-border")}>
            {active && (
                <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 bg-primary rounded-full animate-ping" />
            )}
        </div>
        <ArrowRight className={cn("ml-[-10px] h-4 w-4 relative z-10", active ? "text-primary" : "text-border")} />
    </div>
);

export function PipelineVisualization({ agentStatus }: { agentStatus?: AgentStatus | null }) {

    // Map agent status to step status
    const getStepStatus = (agentKey: keyof AgentStatus | 'cti' | 'verify'): 'idle' | 'running' | 'completed' | 'error' => {
        if (!agentStatus) return 'idle';

        // Mock CTI logic: If extractor is running, CTI is done.
        if (agentKey === 'cti') {
            return (agentStatus.extractor === 'running' || agentStatus.rulegen === 'running') ? 'completed' : 'idle';
        }

        // Mock Verification Logic
        if (agentKey === 'verify') {
            return (agentStatus.attackgen === 'completed') ? 'running' : 'idle';
        }

        const status = agentStatus[agentKey as keyof AgentStatus];
        if (status === 'running') return 'running';
        if (status === 'error') return 'error';
        // If the NEXT agent is running, this one is likely completed
        if (agentKey === 'extractor' && (agentStatus.rulegen === 'running' || agentStatus.attackgen === 'running')) return 'completed';
        if (agentKey === 'rulegen' && (agentStatus.attackgen === 'running')) return 'completed';

        return status === 'running' ? 'running' : 'idle';
    };

    return (
        <Card className="col-span-full border-border bg-card/30 backdrop-blur">
            <CardHeader>
                <CardTitle>Pipeline Architecture View</CardTitle>
                <CardDescription>Live Multi-Agent Orchestration Flow</CardDescription>
            </CardHeader>
            <CardContent>
                <div className="flex flex-col md:flex-row items-stretch justify-between gap-4 py-6 overflow-x-auto">

                    {/* Step 1: CTI Report */}
                    <PipelineStep
                        icon={FileText}
                        title="CTI Ingestion"
                        status={getStepStatus('cti') === 'idle' ? 'completed' : getStepStatus('cti')}
                        description="Parsed & Vectorized"
                    />

                    <Arrow active={agentStatus?.extractor === 'running'} />

                    {/* Step 2: Extraction */}
                    <PipelineStep
                        icon={Activity}
                        title="Extractor Agent"
                        status={getStepStatus('extractor')}
                        description="Gemini Pro"
                    />

                    <Arrow active={agentStatus?.rulegen === 'running'} />

                    {/* Step 3: Rule Gen */}
                    <PipelineStep
                        icon={Shield}
                        title="RuleGen Agent"
                        status={getStepStatus('rulegen')}
                        description="Cerebras Llama-3"
                    />

                    <Arrow active={agentStatus?.attackgen === 'running'} />

                    {/* Step 4: Attack Gen */}
                    <PipelineStep
                        icon={Zap}
                        title="AttackGen Agent"
                        status={getStepStatus('attackgen')}
                        description="LangChain"
                    />

                    <Arrow active={agentStatus?.attackgen === 'running'} />

                    {/* Step 5: Verification */}
                    <PipelineStep
                        icon={Server}
                        title="Verification"
                        status={getStepStatus('verify')}
                        description="SIEM + SSH"
                    />

                    <Arrow active={agentStatus?.evaluator === 'running'} />

                    {/* Step 6: Evaluation */}
                    <PipelineStep
                        icon={Target}
                        title="Evaluator Agent"
                        status={getStepStatus('evaluator')}
                        description="Quality Score"
                    />

                </div>
            </CardContent>
        </Card>
    );
}
