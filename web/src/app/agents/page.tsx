"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Activity, Shield, Zap, Target, Play, StopCircle, RefreshCw, Power } from "lucide-react"
import { api, API_BASE_URL, type AgentStatus, type AgentDetail } from "@/lib/api"
import { useToast } from "@/components/ui/toast-notification"


export default function AgentsPage() {
    const [agentData, setAgentData] = useState<{ status: AgentStatus, details: Record<string, AgentDetail> } | null>(null)
    const [loading, setLoading] = useState(true)
    const { showToast } = useToast()

    const fetchData = async () => {
        try {
            const data = await api.getAgents()
            setAgentData(data)
        } catch (error) {
            console.error("Failed to fetch data:", error)
            showToast("Failed to fetch agent data", "error")
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 5000)
        return () => clearInterval(interval)
    }, [])

    const getStatusVariant = (status: string) => {
        switch (status) {
            case "running": return "success"
            case "stopped": return "secondary"
            case "error": return "destructive"
            default: return "outline"
        }
    }

    const handleStart = async (agentKey: string) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let payload: any = {};

        // Define specific test payloads for each agent
        if (agentKey === 'extractor') {
            payload = {
                reports: [{
                    id: "test-report-" + Date.now(),
                    content: "Test report: The attacker used PowerShell to execute malicious commands.",
                    source: "Manual Test",
                    timestamp: new Date().toISOString()
                }]
            };
        } else if (agentKey === 'rulegen') {
            payload = {
                ttps: [{
                    technique_id: "T1059.001",
                    technique_name: "PowerShell",
                    tactic: "execution",
                    description: "PowerShell usage for execution"
                }]
            };
        } else if (agentKey === 'attackgen') {
            payload = {
                ttps: [{
                    technique_id: "T1059.001",
                    technique_name: "PowerShell",
                    platform: "windows"
                }]
            };
        } else if (agentKey === 'evaluator') {
            // Evaluator needs rules to evaluate
            payload = {
                rules: [{
                    title: "Test Rule",
                    id: "test-rule-1",
                    detection: { selection: { Image: "powershell.exe" } }
                }]
            };
        }

        try {
            // Run specific agent
            await api.runAgent(agentKey, payload);
            fetchData();
            showToast(`Started ${agentKey} successfully!`, "success");
        } catch (error) {
            console.error(`Failed to start ${agentKey}:`, error);
            showToast(`Failed to start ${agentKey}. Check console.`, "error");
        }
    }

    const handleStop = async (agentKey?: string) => {
        try {
            if (agentKey) {
                await fetch(`${API_BASE_URL}/agents/${agentKey}/stop`, { method: "POST" })
                showToast(`Stopped ${agentKey} successfully`, "success")
            } else {
                await fetch(`${API_BASE_URL}/agents/stop`, { method: "POST" })
                showToast("All agents stopped successfully", "info")
            }
            fetchData()
        } catch (error) {
            console.error("Failed to stop agents:", error)
            showToast("Failed to stop agents", "error")
        }
    }

    // Icon mapping helper
    const getIcon = (key: string) => {
        switch (key) {
            case 'extractor': return Activity;
            case 'rulegen': return Shield;
            case 'attackgen': return Zap;
            case 'evaluator': return Target;
            default: return Activity;
        }
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-foreground">Agents</h1>
                    <p className="text-muted-foreground mt-1">Manage and monitor individual AI agents.</p>
                </div>
                <div className="flex gap-3">
                    <Button variant="outline" onClick={fetchData}>
                        <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                        Refresh
                    </Button>
                    <Button variant="destructive" className="gap-2" onClick={() => handleStop()}>
                        <Power className="h-4 w-4" />
                        Stop All
                    </Button>
                </div>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                {agentData && Object.entries(agentData.details).map(([key, detail]) => {
                    const Icon = getIcon(key);
                    return (
                        <Card key={key} className="relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-6">
                                <Badge variant={getStatusVariant(agentData.status?.[key as keyof AgentStatus] || 'stopped')}>
                                    {agentData.status?.[key as keyof AgentStatus] || 'Unknown'}
                                </Badge>
                            </div>
                            <CardHeader>
                                <div className="flex items-center gap-4">
                                    <div className="p-3 rounded-lg bg-muted border border-border">
                                        <Icon className="h-6 w-6 text-primary" />
                                    </div>
                                    <div>
                                        <CardTitle>{detail.name}</CardTitle>
                                        <CardDescription className="mt-1">{detail.description}</CardDescription>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-4">
                                    <div>
                                        <h4 className="text-sm font-medium text-muted-foreground mb-2">Model Configuration</h4>
                                        <div className="bg-muted rounded-md p-3 border border-border">
                                            <code className="text-xs text-primary">{detail.model}</code>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-medium text-muted-foreground mb-2">Capabilities</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {detail.capabilities.map((cap) => (
                                                <Badge key={cap} variant="outline" className="bg-muted">
                                                    {cap}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                    <div className="pt-4 flex gap-3">
                                        <Button className="w-full" variant="secondary" onClick={() => handleStart(key)}>
                                            <Play className="h-4 w-4 mr-2" />
                                            Start Agent
                                        </Button>
                                        <Button className="w-full" variant="outline" onClick={() => handleStop(key)}>
                                            <StopCircle className="h-4 w-4 mr-2" />
                                            Stop
                                        </Button>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )
                })}
                {!agentData && !loading && (
                    <div className="col-span-2 text-center text-muted-foreground py-12">
                        Failed to load agent configuration.
                    </div>
                )}
            </div>

        </div>
    )
}
