"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Shield, FileText, RefreshCw, Download, Copy, Search, Filter } from "lucide-react"
import { api } from "@/lib/api"
import yaml from "js-yaml"
import { RuleEditor } from "@/components/dashboard/rule-editor"

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
                    <h1 className="text-3xl font-bold font-heading text-foreground">Detection Rules</h1>
                    <p className="text-muted-foreground mt-1">Generated Sigma rules for threat detection.</p>
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
            <div className="flex flex-col md:flex-row gap-4 bg-muted/50 p-4 rounded-lg border border-border">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <input
                        type="text"
                        placeholder="Search rules by title, ID, or description..."
                        className="w-full bg-background border border-input rounded-md pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:border-ring transition-colors"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
                <div className="relative w-full md:w-48">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <select
                        className="w-full bg-background border border-input rounded-md pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:border-ring transition-colors appearance-none"
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
                    <Card className="border-dashed border-border bg-transparent">
                        <CardContent className="flex flex-col items-center justify-center py-12">
                            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                            <p className="text-muted-foreground">No rules found matching your criteria.</p>
                            {rules.length === 0 && (
                                <Button variant="link" className="mt-2 text-primary">Run the pipeline to generate rules</Button>
                            )}
                        </CardContent>
                    </Card>
                )}

                {filteredRules.map((rule, index) => (
                    <div key={index} className="h-full">
                        <RuleEditor rule={rule} />
                    </div>
                ))}
            </div>
        </div>
    )
}
