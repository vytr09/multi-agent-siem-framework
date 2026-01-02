/* eslint-disable @typescript-eslint/no-explicit-any */
"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Save, Settings, Bell, Lock, Database, Server, RotateCw } from "lucide-react"
import { api } from "@/lib/api"
import { useToast } from "@/components/ui/toast-notification"

interface AgentLLMConfig {
    provider?: string
    model?: string
    base_url?: string
    api_key?: string
}

interface Config {
    agents?: {
        collector?: {
            interval?: number
        }
        extractor?: {
            llm?: AgentLLMConfig
            confidence_scoring?: {
                min_threshold?: number
                high_confidence_threshold?: number
            }
        }
        rulegen?: {
            llm?: AgentLLMConfig
        }
        evaluator?: {
            benchmark?: {
                llm_judge?: AgentLLMConfig
            }
            metrics?: {
                retention_days?: number
            }
        }
        attackgen?: {
            llm?: AgentLLMConfig
        }
    }
    feedback?: {
        enabled?: boolean
        max_iterations?: number
        minimum_score?: number
        improvement_threshold?: number
    }
}



interface Provider {
    name: string
    type: string
    model: string
    priority: number
    api_key_env: string
}

interface Env {
    [key: string]: string | undefined
}

export default function SettingsPage() {
    const [config, setConfig] = useState<Config | null>(null)
    const [env, setEnv] = useState<Env | null>(null)
    const [loading, setLoading] = useState(true)
    const [saving, setSaving] = useState(false)
    const [activeTab, setActiveTab] = useState("general")
    const [providers, setProviders] = useState<Provider[]>([])
    const { showToast } = useToast()

    useEffect(() => {
        fetchSettings()
        fetchProviders()
    }, [])

    const fetchProviders = async () => {
        try {
            const data = await api.getProviders()
            if (data && data.providers) {
                setProviders(data.providers)
            }
        } catch (error) {
            console.error("Failed to fetch providers:", error)
        }
    }

    const handleSetActiveProvider = async (name: string) => {
        try {
            await api.setActiveProvider(name)
            showToast(`Set ${name} as active provider`, "success")
            fetchProviders() // Refresh list
        } catch (error) {
            console.error(error)
            showToast("Failed to set active provider", "error")
        }
    }

    const handleReloadAgents = async () => {
        try {
            await api.reloadAgents()
            showToast("Agents reloaded successfully", "success")
        } catch (error) {
            console.error(error)
            showToast("Failed to reload agents", "error")
        }
    }

    const fetchSettings = async () => {
        try {
            const data = await api.getSettings()
            setConfig(data.config)
            setEnv(data.env)
        } catch (error) {
            console.error("Failed to fetch settings:", error)
            showToast("Failed to fetch settings", "error")
        } finally {
            setLoading(false)
        }
    }

    const handleSave = async () => {
        setSaving(true)
        try {
            await api.updateSettings({ config, env })
            showToast("Settings saved successfully!", "success")
        } catch (error) {
            console.error("Failed to save settings:", error)
            showToast("Failed to save settings.", "error")
        } finally {
            setSaving(false)
        }
    }

    const updateConfig = (path: string[], value: string | number | boolean) => {
        setConfig((prev) => {
            if (!prev) return null
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const newConfig = { ...prev } as any
            let current = newConfig
            for (let i = 0; i < path.length - 1; i++) {
                if (!current[path[i]]) current[path[i]] = {}
                current = current[path[i]]
            }
            current[path[path.length - 1]] = value
            return newConfig
        })
    }

    const updateEnv = (key: string, value: string) => {
        setEnv((prev) => ({
            ...prev,
            [key]: value
        }))
    }

    if (loading) {
        return <div className="text-muted-foreground">Loading settings...</div>
    }

    const tabs = [
        { id: "general", label: "General", icon: Settings },
        { id: "integrations", label: "Integrations", icon: Database },
        { id: "models", label: "AI Models", icon: Lock },
        { id: "providers", label: "Provider Manager", icon: Server },
        { id: "system", label: "System", icon: Bell },
    ]

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-foreground">Settings</h1>
                    <p className="text-muted-foreground mt-1">Configure system parameters and preferences.</p>
                </div>
                <Button className="gap-2" onClick={handleSave} disabled={saving}>
                    <Save className="h-4 w-4" />
                    {saving ? "Saving..." : "Save Changes"}
                </Button>
            </div>

            <div className="flex flex-col md:flex-row gap-8">
                {/* Sidebar Navigation */}
                <aside className="w-full md:w-64 shrink-0">
                    <nav className="flex flex-col space-y-1">
                        {tabs.map((tab) => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === tab.id
                                    ? "bg-primary/10 text-primary border-r-2 border-primary"
                                    : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                                    }`}
                            >
                                <tab.icon className="h-4 w-4" />
                                {tab.label}
                            </button>
                        ))}
                    </nav>
                </aside>

                {/* Main Content Area */}
                <div className="flex-1 space-y-6">
                    {activeTab === "general" && (
                        <Card>
                            <CardHeader>
                                <CardTitle>General Configuration</CardTitle>
                                <CardDescription>Basic system settings and display options.</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-foreground">Collector Interval (seconds)</label>
                                    <input
                                        type="number"
                                        value={config?.agents?.collector?.interval || 300}
                                        onChange={(e) => updateConfig(['agents', 'collector', 'interval'], parseInt(e.target.value))}
                                        className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-foreground">Environment</label>
                                    <div className="flex gap-2">
                                        <Badge variant="default">Production</Badge>
                                        <Badge variant="outline">Staging</Badge>
                                        <Badge variant="outline">Development</Badge>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {activeTab === "integrations" && (
                        <div className="space-y-6">
                            {/* API Keys */}
                            <Card>
                                <CardHeader>
                                    <CardTitle>API Configuration</CardTitle>
                                    <CardDescription>Manage API keys for external services.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">OpenAI API Key</label>
                                        <input
                                            type="password"
                                            value={env?.OPENAI_API_KEY || ""}
                                            onChange={(e) => updateEnv('OPENAI_API_KEY', e.target.value)}
                                            placeholder="sk-..."
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">Gemini API Key</label>
                                        <input
                                            type="password"
                                            value={env?.GEMINI_API_KEY || ""}
                                            onChange={(e) => updateEnv('GEMINI_API_KEY', e.target.value)}
                                            placeholder="AIza..."
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">Cerebras API Key</label>
                                        <input
                                            type="password"
                                            value={env?.CEREBRAS_API_KEY || ""}
                                            onChange={(e) => updateEnv('CEREBRAS_API_KEY', e.target.value)}
                                            placeholder="csk-..."
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                </CardContent>
                            </Card>

                            {/* Splunk Configuration */}
                            <Card>
                                <CardHeader>
                                    <CardTitle>Splunk Configuration</CardTitle>
                                    <CardDescription>Connection details for Splunk SIEM.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Host</label>
                                            <input
                                                type="text"
                                                value={env?.SPLUNK_HOST || ""}
                                                onChange={(e) => updateEnv('SPLUNK_HOST', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Port</label>
                                            <input
                                                type="text"
                                                value={env?.SPLUNK_PORT || "8089"}
                                                onChange={(e) => updateEnv('SPLUNK_PORT', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Username</label>
                                            <input
                                                type="text"
                                                value={env?.SPLUNK_USER || ""}
                                                onChange={(e) => updateEnv('SPLUNK_USER', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Password</label>
                                            <input
                                                type="password"
                                                value={env?.SPLUNK_PASSWORD || ""}
                                                onChange={(e) => updateEnv('SPLUNK_PASSWORD', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <input
                                            type="checkbox"
                                            id="splunk-ssl"
                                            checked={env?.SPLUNK_VERIFY_SSL === 'true'}
                                            onChange={(e) => updateEnv('SPLUNK_VERIFY_SSL', e.target.checked ? 'true' : 'false')}
                                            className="rounded border-input bg-background text-primary focus:ring-primary"
                                        />
                                        <label htmlFor="splunk-ssl" className="text-sm font-medium text-foreground">Verify SSL</label>
                                    </div>
                                </CardContent>
                            </Card>

                            {/* SSH Configuration */}
                            <Card>
                                <CardHeader>
                                    <CardTitle>SSH Configuration</CardTitle>
                                    <CardDescription>Remote access for command execution.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Host</label>
                                            <input
                                                type="text"
                                                value={env?.SSH_HOST || ""}
                                                onChange={(e) => updateEnv('SSH_HOST', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Port</label>
                                            <input
                                                type="text"
                                                value={env?.SSH_PORT || "22"}
                                                onChange={(e) => updateEnv('SSH_PORT', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Username</label>
                                            <input
                                                type="text"
                                                value={env?.SSH_USER || ""}
                                                onChange={(e) => updateEnv('SSH_USER', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Password</label>
                                            <input
                                                type="password"
                                                value={env?.SSH_PASSWORD || ""}
                                                onChange={(e) => updateEnv('SSH_PASSWORD', e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">Key Path (Optional)</label>
                                        <input
                                            type="text"
                                            value={env?.SSH_KEY_PATH || ""}
                                            onChange={(e) => updateEnv('SSH_KEY_PATH', e.target.value)}
                                            placeholder="/path/to/private/key"
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                </CardContent>
                            </Card>
                        </div>
                    )}

                    {activeTab === "models" && (
                        <Card>
                            <CardHeader>
                                <CardTitle>LLM Configuration</CardTitle>
                                <CardDescription>Manage AI model settings for each agent.</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                {/* Extractor Agent */}
                                <div className="space-y-3 border-b border-neutral-800 pb-4">
                                    <h3 className="text-sm font-semibold text-foreground">Extractor Agent</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Provider</label>
                                            <select
                                                value={config?.agents?.extractor?.llm?.provider || "gemini"}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.extractor?.llm?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.extractor?.llm?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.extractor?.llm?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* RuleGen Agent */}
                                <div className="space-y-3 border-b border-neutral-800 pb-4">
                                    <h3 className="text-sm font-semibold text-foreground">RuleGen Agent</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Provider</label>
                                            <select
                                                value={config?.agents?.rulegen?.llm?.provider || "openai"}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.rulegen?.llm?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.rulegen?.llm?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.rulegen?.llm?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Evaluator Agent */}
                                <div className="space-y-3 border-b border-neutral-800 pb-4">
                                    <h3 className="text-sm font-semibold text-foreground">Evaluator Agent (LLM Judge)</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Provider</label>
                                            <select
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.provider || "gemini"}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* AttackGen Agent */}
                                <div className="space-y-3">
                                    <h3 className="text-sm font-semibold text-foreground">AttackGen Agent</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Provider</label>
                                            <select
                                                value={config?.agents?.attackgen?.llm?.provider || "openai"}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.attackgen?.llm?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.attackgen?.llm?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-muted-foreground">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.attackgen?.llm?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                        </div>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {activeTab === "system" && (
                        <div className="space-y-6">
                            {/* Thresholds */}
                            <Card>
                                <CardHeader>
                                    <CardTitle>Detection Thresholds</CardTitle>
                                    <CardDescription>Adjust sensitivity of detection agents.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">Confidence Threshold (0.0 - 1.0)</label>
                                        <input
                                            type="number"
                                            step="0.1"
                                            min="0"
                                            max="1"
                                            value={config?.agents?.extractor?.confidence_scoring?.min_threshold || 0.5}
                                            onChange={(e) => updateConfig(['agents', 'extractor', 'confidence_scoring', 'min_threshold'], parseFloat(e.target.value))}
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">High Confidence Threshold</label>
                                        <input
                                            type="number"
                                            step="0.1"
                                            min="0"
                                            max="1"
                                            value={config?.agents?.extractor?.confidence_scoring?.high_confidence_threshold || 0.8}
                                            onChange={(e) => updateConfig(['agents', 'extractor', 'confidence_scoring', 'high_confidence_threshold'], parseFloat(e.target.value))}
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                </CardContent>
                            </Card>

                            {/* Feedback Loop Configuration */}
                            <Card>
                                <CardHeader>
                                    <CardTitle>Feedback Loop Configuration</CardTitle>
                                    <CardDescription>Configure the iterative refinement process for rule generation.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="flex items-center gap-2 pb-2">
                                        <input
                                            type="checkbox"
                                            id="feedback-enabled"
                                            checked={config?.feedback?.enabled ?? true}
                                            onChange={(e) => updateConfig(['feedback', 'enabled'], e.target.checked)}
                                            className="rounded border-input bg-background text-primary focus:ring-primary"
                                        />
                                        <label htmlFor="feedback-enabled" className="text-sm font-medium text-foreground">Enable Feedback Loop</label>
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Max Iterations</label>
                                            <input
                                                type="number"
                                                min="1"
                                                max="10"
                                                value={config?.feedback?.max_iterations || 3}
                                                onChange={(e) => updateConfig(['feedback', 'max_iterations'], parseInt(e.target.value))}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                            <p className="text-xs text-muted-foreground">Maximum number of refinement attempts per TTP.</p>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-foreground">Minimum Quality Score</label>
                                            <input
                                                type="number"
                                                step="0.05"
                                                min="0.1"
                                                max="1.0"
                                                value={config?.feedback?.minimum_score || 0.7}
                                                onChange={(e) => updateConfig(['feedback', 'minimum_score'], parseFloat(e.target.value))}
                                                className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                            />
                                            <p className="text-xs text-muted-foreground">Target score to stop refinement (0.0 - 1.0).</p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>

                            {/* Data Retention */}
                            <Card>
                                <CardHeader>
                                    <CardTitle>Data Retention</CardTitle>
                                    <CardDescription>Configure log and report storage policies.</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-foreground">Log Retention (Days)</label>
                                        <input
                                            type="number"
                                            value={config?.agents?.evaluator?.metrics?.retention_days || 30}
                                            onChange={(e) => updateConfig(['agents', 'evaluator', 'metrics', 'retention_days'], parseInt(e.target.value))}
                                            className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
                                        />
                                    </div>
                                    <div className="pt-2">
                                        <Button variant="destructive" size="sm" className="w-full">
                                            Clear All Cached Data
                                        </Button>
                                    </div>
                                </CardContent>
                            </Card>
                        </div>
                    )}

                    {activeTab === "providers" && (
                        <Card>
                            <CardHeader>
                                <div className="flex justify-between items-center">
                                    <div>
                                        <CardTitle>LLM Provider Manager</CardTitle>
                                        <CardDescription>Manage and rotate active LLM providers.</CardDescription>
                                    </div>
                                    <Button variant="outline" size="sm" onClick={handleReloadAgents}>
                                        <RotateCw className="h-4 w-4 mr-2" />
                                        Reload Agents
                                    </Button>
                                </div>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <div className="grid gap-4">
                                    {providers.map((provider, index) => (
                                        <div
                                            key={`${provider.name}-${provider.model}-${index}`}
                                            className={`flex items-center justify-between p-4 rounded-lg border ${provider.priority === 1 ? 'border-primary/50 bg-primary/5' : 'border-border'}`}
                                        >
                                            <div className="flex items-center gap-4">
                                                <div className={`w-2 h-2 rounded-full ${provider.priority === 1 ? 'bg-primary' : 'bg-muted-foreground/30'}`} />
                                                <div>
                                                    <div className="flex items-center gap-2">
                                                        <h3 className="font-medium">{provider.name}</h3>
                                                        <Badge variant="outline" className="text-xs">{provider.type}</Badge>
                                                        {provider.priority === 1 && <Badge>Active</Badge>}
                                                    </div>
                                                    <p className="text-sm text-muted-foreground mt-1">
                                                        Model: {provider.model} • Priority: {provider.priority}
                                                    </p>
                                                </div>
                                            </div>

                                            {provider.priority !== 1 && (
                                                <Button size="sm" variant="secondary" onClick={() => handleSetActiveProvider(provider.name)}>
                                                    Set Active
                                                </Button>
                                            )}
                                        </div>
                                    ))}
                                </div>
                                <div className="p-4 rounded-lg bg-primary/10 border border-primary/20">
                                    <p className="text-sm text-muted-foreground">
                                        <strong>Note:</strong> Provider rotation happens automatically if the active provider fails.
                                        Clicking "Set Active" forces a specific provider to Priority 1.
                                        You must click "Reload Agents" for changes to take effect on running agents.
                                    </p>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </div>
            </div>
        </div>
    )
}
