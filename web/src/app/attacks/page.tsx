"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Shield, Terminal, RefreshCw, Copy, Search, Filter, Play } from "lucide-react"
import { api } from "@/lib/api"

interface AttackCommand {
    id: string;
    technique_id: string;
    technique_name: string;
    tactic: string;
    platform: string;
    command: string;
    description: string;
    requires_admin: boolean;
    safety_level: string;
    confidence_score: number;
    [key: string]: any;
}

export default function AttacksPage() {
    const [attacks, setAttacks] = useState<AttackCommand[]>([])
    const [filteredAttacks, setFilteredAttacks] = useState<AttackCommand[]>([])
    const [loading, setLoading] = useState(true)
    const [searchQuery, setSearchQuery] = useState("")
    const [platformFilter, setPlatformFilter] = useState<string>("all")

    const fetchAttacks = async () => {
        setLoading(true)
        try {
            const data = await api.getAttacks()
            const attackList = Array.isArray(data) ? data : []
            setAttacks(attackList)
            setFilteredAttacks(attackList)
        } catch (error) {
            console.error("Failed to fetch attacks:", error)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchAttacks()
    }, [])

    useEffect(() => {
        let result = attacks

        if (searchQuery) {
            const query = searchQuery.toLowerCase()
            result = result.filter(a =>
                a.technique_name?.toLowerCase().includes(query) ||
                a.technique_id?.toLowerCase().includes(query) ||
                a.description?.toLowerCase().includes(query) ||
                a.command?.toLowerCase().includes(query)
            )
        }

        if (platformFilter !== "all") {
            result = result.filter(a => a.platform === platformFilter)
        }

        setFilteredAttacks(result)
    }, [searchQuery, platformFilter, attacks])

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text)
    }

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-foreground">Generated Attacks</h1>
                    <p className="text-muted-foreground mt-1">Simulated attack commands for validation.</p>
                </div>
                <div className="flex gap-3">
                    <Button variant="outline" onClick={fetchAttacks}>
                        <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                        Refresh
                    </Button>
                </div>
            </div>

            {/* Search and Filter Bar */}
            <div className="flex flex-col md:flex-row gap-4 bg-card p-4 rounded-lg border border-border">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <input
                        type="text"
                        placeholder="Search attacks by technique, ID, or command..."
                        className="w-full bg-background border border-input rounded-md pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring transition-colors"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
                <div className="relative w-full md:w-48">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <select
                        className="w-full bg-background border border-input rounded-md pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:border-ring transition-colors appearance-none"
                        value={platformFilter}
                        onChange={(e) => setPlatformFilter(e.target.value)}
                    >
                        <option value="all">All Platforms</option>
                        <option value="windows">Windows</option>
                        <option value="linux">Linux</option>
                        <option value="macos">macOS</option>
                    </select>
                </div>
            </div>

            <div className="grid gap-6">
                {filteredAttacks.length === 0 && !loading && (
                    <Card className="border-dashed border-border bg-transparent">
                        <CardContent className="flex flex-col items-center justify-center py-12">
                            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                            <p className="text-muted-foreground">No attacks found matching your criteria.</p>
                        </CardContent>
                    </Card>
                )}

                {filteredAttacks.map((attack, index) => (
                    <Card key={index} className="group transition-all hover:border-red-500/50">
                        <CardHeader>
                            <div className="flex items-start justify-between">
                                <div className="flex gap-4">
                                    <div className="p-2 rounded-md bg-muted h-fit">
                                        <Terminal className="h-5 w-5 text-destructive" />
                                    </div>
                                    <div>
                                        <CardTitle className="text-lg">{attack.technique_name || "Unknown Technique"}</CardTitle>
                                        <CardDescription className="mt-1 font-mono text-xs text-muted-foreground">
                                            {attack.technique_id} • {attack.tactic}
                                        </CardDescription>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <Badge variant="outline">{attack.platform}</Badge>
                                    <Badge variant={attack.safety_level === "high" ? "destructive" : "secondary"}>
                                        Safety: {attack.safety_level}
                                    </Badge>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-4">
                                <p className="text-sm text-muted-foreground">{attack.description}</p>

                                <div className="relative group/code">
                                    <div className="absolute right-2 top-2 opacity-0 group-hover/code:opacity-100 transition-opacity flex gap-2">
                                        <Button size="icon" variant="ghost" className="h-6 w-6 bg-muted hover:bg-muted/80" onClick={() => copyToClipboard(attack.command)}>
                                            <Copy className="h-3 w-3 text-muted-foreground" />
                                        </Button>
                                    </div>
                                    <pre className="p-4 rounded-lg bg-muted/30 border border-border overflow-x-auto">
                                        <code className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">
                                            {attack.command}
                                        </code>
                                    </pre>
                                </div>

                                <div className="flex items-center justify-between text-xs text-muted-foreground">
                                    <span>Confidence: {(attack.confidence_score * 100).toFixed(0)}%</span>
                                    <span>{new Date(attack.generated_at).toLocaleString()}</span>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>
        </div>
    )
}
