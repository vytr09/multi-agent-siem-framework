"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Shield, FileText, RefreshCw, Download, Copy, Search, Filter } from "lucide-react"
import { api } from "@/lib/api"
import yaml from "js-yaml"

interface Rule {
    title: string;
    id: string;
    description: string;
    level: string;
    tags: string[];
    [key: string]: any;
}

export default function RulesPage() {
    const [rules, setRules] = useState<Rule[]>([])
    const [filteredRules, setFilteredRules] = useState<Rule[]>([])
    const [loading, setLoading] = useState(true)
    const [searchQuery, setSearchQuery] = useState("")
    const [severityFilter, setSeverityFilter] = useState<string>("all")

    const fetchRules = async () => {
        setLoading(true)
        try {
            const data = await api.getRules()
            // API now returns a flat list of rules
            const ruleList = Array.isArray(data) ? data : []
            setRules(ruleList)
            setFilteredRules(ruleList)
        } catch (error) {
            console.error("Failed to fetch rules:", error)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchRules()
    }, [])

    useEffect(() => {
        let result = rules

        if (searchQuery) {
            const query = searchQuery.toLowerCase()
            result = result.filter(r =>
                r.title?.toLowerCase().includes(query) ||
                r.id?.toLowerCase().includes(query) ||
                r.description?.toLowerCase().includes(query)
            )
        }

        if (severityFilter !== "all") {
            result = result.filter(r => r.level === severityFilter)
        }

        setFilteredRules(result)
    }, [searchQuery, severityFilter, rules])

    const handleExport = () => {
        const blob = new Blob([JSON.stringify(rules, null, 2)], { type: "application/json" })
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `sigma_rules_${new Date().toISOString().split('T')[0]}.json`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text)
    }

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-neutral-100">Detection Rules</h1>
                    <p className="text-neutral-400 mt-1">Generated Sigma rules for threat detection.</p>
                </div>
                <div className="flex gap-3">
                    <Button variant="outline" onClick={fetchRules}>
                        <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                        Refresh
                    </Button>
                    <Button variant="outline" onClick={handleExport}>
                        <Download className="h-4 w-4 mr-2" />
                        Export All
                    </Button>
                </div>
            </div>

            {/* Search and Filter Bar */}
            <div className="flex flex-col md:flex-row gap-4 bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-500" />
                    <input
                        type="text"
                        placeholder="Search rules by title, ID, or description..."
                        className="w-full bg-neutral-950 border border-neutral-800 rounded-md pl-9 pr-4 py-2 text-sm text-neutral-100 focus:outline-none focus:border-yellow-500/50 transition-colors"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
                <div className="relative w-full md:w-48">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-500" />
                    <select
                        className="w-full bg-neutral-950 border border-neutral-800 rounded-md pl-9 pr-4 py-2 text-sm text-neutral-100 focus:outline-none focus:border-yellow-500/50 transition-colors appearance-none"
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                    >
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
            </div>

            <div className="grid gap-6">
                {filteredRules.length === 0 && !loading && (
                    <Card className="border-dashed border-neutral-700 bg-transparent">
                        <CardContent className="flex flex-col items-center justify-center py-12">
                            <Shield className="h-12 w-12 text-neutral-600 mb-4" />
                            <p className="text-neutral-400">No rules found matching your criteria.</p>
                            {rules.length === 0 && (
                                <Button variant="link" className="mt-2 text-yellow-500">Run the pipeline to generate rules</Button>
                            )}
                        </CardContent>
                    </Card>
                )}

                {filteredRules.map((rule, index) => {
                    const yamlContent = yaml.dump(rule, { indent: 2, lineWidth: -1 })
                    return (
                        <Card key={index} className="group transition-all hover:border-yellow-500/50">
                            <CardHeader>
                                <div className="flex items-start justify-between">
                                    <div className="flex gap-4">
                                        <div className="p-2 rounded-md bg-neutral-800 h-fit">
                                            <FileText className="h-5 w-5 text-emerald-500" />
                                        </div>
                                        <div>
                                            <CardTitle className="text-lg">{rule.title || "Untitled Rule"}</CardTitle>
                                            <CardDescription className="mt-1 font-mono text-xs text-neutral-500">
                                                ID: {rule.id || "N/A"}
                                            </CardDescription>
                                        </div>
                                    </div>
                                    <Badge variant={rule.level === "critical" ? "destructive" : "default"}>
                                        {rule.level || "medium"}
                                    </Badge>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-4">
                                    <p className="text-sm text-neutral-300">{rule.description}</p>

                                    <div className="relative group/code">
                                        <div className="absolute right-2 top-2 opacity-0 group-hover/code:opacity-100 transition-opacity">
                                            <Button size="icon" variant="ghost" className="h-6 w-6 bg-neutral-800 hover:bg-neutral-700" onClick={() => copyToClipboard(yamlContent)}>
                                                <Copy className="h-3 w-3" />
                                            </Button>
                                        </div>
                                        <pre className="p-4 rounded-lg bg-neutral-950 border border-neutral-800 overflow-x-auto max-h-96">
                                            <code className="text-xs font-mono text-neutral-300 whitespace-pre">
                                                {yamlContent}
                                            </code>
                                        </pre>
                                    </div>

                                    <div className="flex flex-wrap gap-2">
                                        {rule.tags?.map((tag: string) => {
                                            const isAttack = tag.startsWith("attack.")
                                            return (
                                                <Badge
                                                    key={tag}
                                                    variant="outline"
                                                    className={`text-xs ${isAttack ? 'border-red-500/30 text-red-400 bg-red-500/5' : ''}`}
                                                >
                                                    {tag}
                                                </Badge>
                                            )
                                        })}
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )
                })}
            </div>
        </div>
    )
}
