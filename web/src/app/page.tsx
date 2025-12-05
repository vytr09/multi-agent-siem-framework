"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Activity, Shield, Zap, Target, Play, AlertTriangle, CheckCircle, RefreshCw } from "lucide-react"
import { api, type AgentStatus, type SystemMetrics } from "@/lib/api"
import { useToast } from "@/components/ui/toast-notification"

export default function Dashboard() {
  const { showToast } = useToast()
  const [agents, setAgents] = useState<AgentStatus | null>(null)
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const [activity, setActivity] = useState<any[]>([])
  const [latestAttack, setLatestAttack] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetchData = async () => {
    try {
      const [agentData, metricsData, activityData, attackData] = await Promise.all([
        api.getAgents(),
        api.getMetrics(),
        api.getActivity(),
        api.getLatestAttack()
      ])
      setAgents(agentData.status)
      setMetrics(metricsData)
      setActivity(Array.isArray(activityData) ? activityData : [])
      setLatestAttack(attackData)
      setLastUpdated(new Date())
    } catch (error) {
      console.error("Failed to fetch data:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleRunPipeline = async () => {
    try {
      showToast("Starting pipeline simulation...", "info")
      // Sample CTI report for demonstration
      const sampleReport = {
        id: "demo_report_" + Date.now(),
        content: "The attacker used PowerShell to execute a base64 encoded command. The command was 'powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAIgBIADQAcwBJAEE'. This indicates a potential fileless malware attack using T1059.001.",
        source: "Dashboard Simulation"
      }

      // Trigger pipeline with sample data
      await api.startPipeline({ cti_reports: [sampleReport] })

      showToast("Pipeline started successfully", "success")

      // Force refresh after a short delay
      setTimeout(fetchData, 2000)
    } catch (error) {
      console.error("Failed to run pipeline:", error)
      showToast("Failed to start pipeline", "error")
    }
  }

  useEffect(() => {
    setLastUpdated(new Date()) // Set initial time on client
    fetchData()
    const interval = setInterval(fetchData, 5000) // Poll every 5 seconds
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

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold font-heading text-neutral-100">Mission Control</h1>
          <p className="text-neutral-400 mt-1">
            Real-time overview of SIEM agents and threat detection.
            <span className="text-xs ml-2 opacity-50">Updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Syncing...'}</span>
          </p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" onClick={fetchData}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button className="gap-2" onClick={handleRunPipeline}>
            <Play className="h-4 w-4" />
            Run Pipeline
          </Button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Active Agents</CardTitle>
            <Activity className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">
              {agents ? Object.values(agents).filter(s => s === 'running').length : 0}/4
            </div>
            <p className="text-xs text-neutral-500 mt-1">All systems operational</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Rules Generated</CardTitle>
            <Shield className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{metrics?.rules_generated || 0}</div>
            <p className="text-xs text-neutral-500 mt-1">Total rules in database</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Detection Rate</CardTitle>
            <Target className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{metrics?.detection_rate || 0}%</div>
            <p className="text-xs text-neutral-500 mt-1">Based on feedback loops</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Attacks Launched</CardTitle>
            <Zap className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{metrics?.attacks_launched || 0}</div>
            <p className="text-xs text-neutral-500 mt-1">Total simulations run</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-7">

        {/* Latest Threat Detection */}
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Latest Threat Detection</CardTitle>
            <CardDescription>Most recent attack simulation result.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] w-full rounded-lg bg-neutral-900 border border-neutral-800 flex flex-col items-center justify-center relative overflow-hidden p-6">
              <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-20"></div>

              {latestAttack && latestAttack.technique !== "None" ? (
                <div className="z-10 text-center space-y-6">
                  <div className="flex justify-center">
                    <div className={`h-24 w-24 rounded-full flex items-center justify-center border-4 ${latestAttack.status === 'Detected' ? 'border-emerald-500/50 bg-emerald-500/10' : 'border-red-500/50 bg-red-500/10'}`}>
                      {latestAttack.status === 'Detected' ? (
                        <Shield className="h-10 w-10 text-emerald-500" />
                      ) : (
                        <AlertTriangle className="h-10 w-10 text-red-500" />
                      )}
                    </div>
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-neutral-100">{latestAttack.technique}</h3>
                    <p className="text-sm text-neutral-400 mt-1 max-w-[250px] mx-auto truncate" title={latestAttack.details}>
                      {latestAttack.details}
                    </p>
                    <p className={`text-lg font-medium mt-2 ${latestAttack.status === 'Detected' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {latestAttack.status.toUpperCase()}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="text-neutral-500 flex flex-col items-center z-10">
                  <Activity className="h-12 w-12 mb-4 animate-pulse text-yellow-500/50" />
                  <span>Waiting for active pipeline...</span>
                  <Button variant="link" className="mt-2 text-yellow-500" onClick={handleRunPipeline}>
                    Start Simulation
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Agent Status */}
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Agent Status</CardTitle>
            <CardDescription>Health and activity monitoring.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { name: "Extractor Agent", key: "extractor", type: "NLP + Gemini", icon: Activity },
                { name: "RuleGen Agent", key: "rulegen", type: "Cerebras Llama-3", icon: Shield },
                { name: "AttackGen Agent", key: "attackgen", type: "LangChain", icon: Zap },
                { name: "Evaluator Agent", key: "evaluator", type: "Gemini Judge", icon: Target },
              ].map((agent, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-neutral-900 border border-neutral-800">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-md bg-neutral-800">
                      <agent.icon className="h-4 w-4 text-neutral-400" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-neutral-200">{agent.name}</p>
                      <p className="text-xs text-neutral-500">{agent.type}</p>
                    </div>
                  </div>
                  <Badge variant={getStatusVariant(agents?.[agent.key as keyof AgentStatus] || 'stopped')}>
                    {agents?.[agent.key as keyof AgentStatus] || 'Unknown'}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
          <CardDescription>Latest system events and logs.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {activity.length === 0 && (
              <p className="text-sm text-neutral-500 italic">No recent activity logged.</p>
            )}
            {Array.isArray(activity) && activity.map((log, i) => (
              <div key={i} className="flex items-start gap-4 pb-4 border-b border-neutral-800 last:border-0 last:pb-0">
                <span className="text-xs font-mono text-neutral-500 mt-1">{log.time}</span>
                <div>
                  <p className="text-sm text-neutral-300">{log.event}</p>
                </div>
                <div className="ml-auto">
                  {log.type === "error" && <AlertTriangle className="h-4 w-4 text-red-500" />}
                  {log.type === "success" && <CheckCircle className="h-4 w-4 text-emerald-500" />}
                  {log.type === "warning" && <AlertTriangle className="h-4 w-4 text-amber-500" />}
                  {log.type === "info" && <Activity className="h-4 w-4 text-blue-500" />}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
