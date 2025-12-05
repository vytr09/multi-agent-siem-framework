/* eslint-disable @typescript-eslint/no-explicit-any */
"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Save, Settings, Bell, Lock, Database } from "lucide-react"
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
    const { showToast } = useToast()

    useEffect(() => {
        fetchSettings()
    }, [])

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
        return <div className="text-neutral-400">Loading settings...</div>
    }

    const tabs = [
        { id: "general", label: "General", icon: Settings },
        { id: "integrations", label: "Integrations", icon: Database },
        { id: "models", label: "AI Models", icon: Lock },
        { id: "system", label: "System", icon: Bell },
    ]

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-neutral-100">Settings</h1>
                    <p className="text-neutral-400 mt-1">Configure system parameters and preferences.</p>
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
                                    ? "bg-neutral-800 text-yellow-500"
                                    : "text-neutral-400 hover:bg-neutral-800/50 hover:text-neutral-200"
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
                                    <label className="text-sm font-medium text-neutral-300">Collector Interval (seconds)</label>
                                    <input
                                        type="number"
                                        value={config?.agents?.collector?.interval || 300}
                                        onChange={(e) => updateConfig(['agents', 'collector', 'interval'], parseInt(e.target.value))}
                                        className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-neutral-300">Environment</label>
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
                                        <label className="text-sm font-medium text-neutral-300">OpenAI API Key</label>
                                        <input
                                            type="password"
                                            value={env?.OPENAI_API_KEY || ""}
                                            onChange={(e) => updateEnv('OPENAI_API_KEY', e.target.value)}
                                            placeholder="sk-..."
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-neutral-300">Gemini API Key</label>
                                        <input
                                            type="password"
                                            value={env?.GEMINI_API_KEY || ""}
                                            onChange={(e) => updateEnv('GEMINI_API_KEY', e.target.value)}
                                            placeholder="AIza..."
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-neutral-300">Cerebras API Key</label>
                                        <input
                                            type="password"
                                            value={env?.CEREBRAS_API_KEY || ""}
                                            onChange={(e) => updateEnv('CEREBRAS_API_KEY', e.target.value)}
                                            placeholder="csk-..."
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
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
                                            <label className="text-sm font-medium text-neutral-300">Host</label>
                                            <input
                                                type="text"
                                                value={env?.SPLUNK_HOST || ""}
                                                onChange={(e) => updateEnv('SPLUNK_HOST', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-neutral-300">Port</label>
                                            <input
                                                type="text"
                                                value={env?.SPLUNK_PORT || "8089"}
                                                onChange={(e) => updateEnv('SPLUNK_PORT', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-neutral-300">Username</label>
                                            <input
                                                type="text"
                                                value={env?.SPLUNK_USER || ""}
                                                onChange={(e) => updateEnv('SPLUNK_USER', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-neutral-300">Password</label>
                                            <input
                                                type="password"
                                                value={env?.SPLUNK_PASSWORD || ""}
                                                onChange={(e) => updateEnv('SPLUNK_PASSWORD', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <input
                                            type="checkbox"
                                            id="splunk-ssl"
                                            checked={env?.SPLUNK_VERIFY_SSL === 'true'}
                                            onChange={(e) => updateEnv('SPLUNK_VERIFY_SSL', e.target.checked ? 'true' : 'false')}
                                            className="rounded border-neutral-700 bg-neutral-900 text-yellow-500 focus:ring-yellow-500"
                                        />
                                        <label htmlFor="splunk-ssl" className="text-sm font-medium text-neutral-300">Verify SSL</label>
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
                                            <label className="text-sm font-medium text-neutral-300">Host</label>
                                            <input
                                                type="text"
                                                value={env?.SSH_HOST || ""}
                                                onChange={(e) => updateEnv('SSH_HOST', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-neutral-300">Port</label>
                                            <input
                                                type="text"
                                                value={env?.SSH_PORT || "22"}
                                                onChange={(e) => updateEnv('SSH_PORT', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-neutral-300">Username</label>
                                            <input
                                                type="text"
                                                value={env?.SSH_USER || ""}
                                                onChange={(e) => updateEnv('SSH_USER', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-neutral-300">Password</label>
                                            <input
                                                type="password"
                                                value={env?.SSH_PASSWORD || ""}
                                                onChange={(e) => updateEnv('SSH_PASSWORD', e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-neutral-300">Key Path (Optional)</label>
                                        <input
                                            type="text"
                                            value={env?.SSH_KEY_PATH || ""}
                                            onChange={(e) => updateEnv('SSH_KEY_PATH', e.target.value)}
                                            placeholder="/path/to/private/key"
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
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
                                    <h3 className="text-sm font-semibold text-neutral-200">Extractor Agent</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Provider</label>
                                            <select
                                                value={config?.agents?.extractor?.llm?.provider || "gemini"}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.extractor?.llm?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.extractor?.llm?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.extractor?.llm?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'extractor', 'llm', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* RuleGen Agent */}
                                <div className="space-y-3 border-b border-neutral-800 pb-4">
                                    <h3 className="text-sm font-semibold text-neutral-200">RuleGen Agent</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Provider</label>
                                            <select
                                                value={config?.agents?.rulegen?.llm?.provider || "openai"}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.rulegen?.llm?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.rulegen?.llm?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.rulegen?.llm?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'rulegen', 'llm', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Evaluator Agent */}
                                <div className="space-y-3 border-b border-neutral-800 pb-4">
                                    <h3 className="text-sm font-semibold text-neutral-200">Evaluator Agent (LLM Judge)</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Provider</label>
                                            <select
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.provider || "gemini"}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.evaluator?.benchmark?.llm_judge?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'evaluator', 'benchmark', 'llm_judge', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* AttackGen Agent */}
                                <div className="space-y-3">
                                    <h3 className="text-sm font-semibold text-neutral-200">AttackGen Agent</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Provider</label>
                                            <select
                                                value={config?.agents?.attackgen?.llm?.provider || "openai"}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'provider'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            >
                                                <option value="gemini">Gemini</option>
                                                <option value="openai">OpenAI / Compatible</option>
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Model Name</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.attackgen?.llm?.model || ""}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'model'], e.target.value)}
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">Base URL (Optional)</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.attackgen?.llm?.base_url || ""}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'base_url'], e.target.value)}
                                                placeholder="https://api.example.com/v1"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-medium text-neutral-400">API Key Ref</label>
                                            <input
                                                type="text"
                                                value={config?.agents?.attackgen?.llm?.api_key || ""}
                                                onChange={(e) => updateConfig(['agents', 'attackgen', 'llm', 'api_key'], e.target.value)}
                                                placeholder="${ENV_VAR_NAME}"
                                                className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
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
                                        <label className="text-sm font-medium text-neutral-300">Confidence Threshold (0.0 - 1.0)</label>
                                        <input
                                            type="number"
                                            step="0.1"
                                            min="0"
                                            max="1"
                                            value={config?.agents?.extractor?.confidence_scoring?.min_threshold || 0.5}
                                            onChange={(e) => updateConfig(['agents', 'extractor', 'confidence_scoring', 'min_threshold'], parseFloat(e.target.value))}
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-neutral-300">High Confidence Threshold</label>
                                        <input
                                            type="number"
                                            step="0.1"
                                            min="0"
                                            max="1"
                                            value={config?.agents?.extractor?.confidence_scoring?.high_confidence_threshold || 0.8}
                                            onChange={(e) => updateConfig(['agents', 'extractor', 'confidence_scoring', 'high_confidence_threshold'], parseFloat(e.target.value))}
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
                                        />
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
                                        <label className="text-sm font-medium text-neutral-300">Log Retention (Days)</label>
                                        <input
                                            type="number"
                                            value={config?.agents?.evaluator?.metrics?.retention_days || 30}
                                            onChange={(e) => updateConfig(['agents', 'evaluator', 'metrics', 'retention_days'], parseInt(e.target.value))}
                                            className="w-full h-10 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500"
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
                </div>
            </div>
        </div>
    )
}
