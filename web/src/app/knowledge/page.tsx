"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/card"
import { Input } from "../../components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Search, Database, FileText, Shield, Globe, Loader2 } from "lucide-react"
import { api } from "@/lib/api"
import { useToast } from "@/components/ui/toast-notification"
import { ScrollArea } from "@/components/ui/scroll-area"

export default function KnowledgePage() {
    const { showToast } = useToast()
    const [stats, setStats] = useState<any>(null)
    const [searchQuery, setSearchQuery] = useState("")
    const [searchResults, setSearchResults] = useState<any[]>([])
    const [loading, setLoading] = useState(false)
    const [searching, setSearching] = useState(false)

    useEffect(() => {
        loadStats()
    }, [])

    const loadStats = async () => {
        setLoading(true)
        try {
            const data = await api.getKnowledgeStats()
            setStats(data)
        } catch (error) {
            console.error("Failed to load knowledge stats:", error)
        } finally {
            setLoading(false)
        }
    }

    // Debounced search effect
    useEffect(() => {
        const timer = setTimeout(() => {
            if (searchQuery.trim().length >= 2) {
                executeSearch(searchQuery)
            } else {
                setSearchResults([])
            }
        }, 500)

        return () => clearTimeout(timer)
    }, [searchQuery])

    const executeSearch = async (query: string) => {
        setSearching(true)
        try {
            const data = await api.searchKnowledge(query)
            setSearchResults(data.results || [])
        } catch (error) {
            console.error("Search failed:", error)
            showToast("Search failed", "error")
        } finally {
            setSearching(false)
        }
    }

    const handleSearch = (e: React.FormEvent) => {
        e.preventDefault()
        // Immediate search on submit
        if (searchQuery.trim()) {
            executeSearch(searchQuery)
        }
    }

    return (
        <div className="space-y-6 max-w-7xl mx-auto h-[calc(100vh-100px)] flex flex-col">
            <div className="flex-none">
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h1 className="text-3xl font-bold font-heading text-foreground">Knowledge Base</h1>
                        <p className="text-muted-foreground mt-1">
                            Search indexed TTPs, Rules, and MITRE ATT&CK context.
                            {stats && !stats.enabled && <span className="text-yellow-500 ml-2">(Vector DB Disabled)</span>}
                        </p>
                    </div>
                </div>

                {/* Stats Cards */}
                <div className="grid gap-4 md:grid-cols-4 mb-8">
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium text-muted-foreground">Sigma Rules</CardTitle>
                            <Shield className="h-4 w-4 text-emerald-500" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">
                                {loading ? <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /> : (stats?.stats?.sigma_rules || 0)}
                            </div>
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium text-muted-foreground">Known TTPs</CardTitle>
                            <Database className="h-4 w-4 text-blue-500" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">
                                {loading ? <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /> : (stats?.stats?.historical_ttps || 0)}
                            </div>
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium text-muted-foreground">Processed Reports</CardTitle>
                            <FileText className="h-4 w-4 text-purple-500" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">
                                {loading ? <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /> : (stats?.stats?.investigations || 0)}
                            </div>
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium text-muted-foreground">MITRE Techniques</CardTitle>
                            <Globe className="h-4 w-4 text-red-500" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">
                                {loading ? <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /> : (stats?.stats?.mitre_attack || 0)}
                            </div>
                        </CardContent>
                    </Card>
                </div>

                {/* Search Bar */}
                <Card className="mb-6">
                    <CardContent className="pt-6">
                        <form onSubmit={handleSearch} className="flex gap-4">
                            <div className="relative flex-1">
                                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                <Input
                                    placeholder="Search for techniques, rules, or threat actors (e.g. 'PowerShell', 'APT29')..."
                                    className="pl-10 h-10"
                                    value={searchQuery}
                                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                                />
                            </div>
                            <Button type="submit" disabled={searching}>
                                {searching ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
                                Search
                            </Button>
                        </form>
                    </CardContent>
                </Card>
            </div>

            {/* Results Area */}
            <div className="flex-1 min-h-0">
                <ScrollArea className="h-full pr-4">
                    <div className="space-y-4 pb-10">
                        {searchResults.length === 0 && !searching && searchQuery && (
                            <div className="text-center py-12 text-muted-foreground">
                                No results found in the Knowledge Base.
                            </div>
                        )}

                        {searchResults.map((result, i) => (
                            <Card key={i} className="bg-card/50 border-border/50 hover:border-border transition-colors">
                                <CardHeader className="pb-2">
                                    <div className="flex items-start justify-between">
                                        <div className="space-y-1">
                                            <div className="flex items-center gap-2">
                                                <Badge variant={result.type === 'rule' ? 'default' : 'secondary'} className="uppercase text-[10px]">
                                                    {result.type === 'mitre_context' ? 'MITRE' : result.type}
                                                </Badge>
                                                <CardTitle className="text-lg text-primary">{result.title}</CardTitle>
                                            </div>
                                        </div>
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    <div className="text-sm text-foreground/80 whitespace-pre-wrap font-mono bg-muted/30 p-4 rounded-md">
                                        {result.content}
                                    </div>
                                    {result.type === 'rule' && (
                                        <div className="mt-4 flex gap-2">
                                            {result.metadata?.tags?.map((tag: string) => (
                                                <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
                                            ))}
                                        </div>
                                    )}
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                </ScrollArea>
            </div>
        </div>
    )
}
