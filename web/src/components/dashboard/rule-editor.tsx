"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Edit2, Check, X, Download, Copy, AlertTriangle } from "lucide-react"
import yaml from "js-yaml"

interface RuleEditorProps {
    rule: any
    onSave?: (updatedRule: any) => void
    onClose?: () => void
}

export function RuleEditor({ rule, onSave, onClose }: RuleEditorProps) {
    const [isEditing, setIsEditing] = useState(false)
    const [content, setContent] = useState(yaml.dump(rule, { indent: 2, lineWidth: -1 }))
    const [error, setError] = useState<string | null>(null)

    const handleSave = () => {
        try {
            const parsed = yaml.load(content)
            if (onSave) onSave(parsed)
            setIsEditing(false)
            setError(null)
        } catch (e: any) {
            setError("Invalid YAML syntax: " + e.message)
        }
    }

    return (
        <Card className="h-full flex flex-col border-primary/20 shadow-lg">
            <CardHeader className="border-b border-border bg-muted/20">
                <div className="flex items-start justify-between">
                    <div>
                        <div className="flex items-center gap-2">
                            <CardTitle className="text-xl font-heading">{rule.title || "Untitled Rule"}</CardTitle>
                            <Badge variant={rule.status === 'stable' ? 'success' : 'secondary'}>{rule.status || 'experimental'}</Badge>
                        </div>
                        <CardDescription className="mt-1 font-mono text-xs">{rule.id}</CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                        {isEditing ? (
                            <>
                                <Button size="sm" variant="ghost" onClick={() => setIsEditing(false)}>
                                    <X className="w-4 h-4 mr-2" /> Cancel
                                </Button>
                                <Button size="sm" onClick={handleSave}>
                                    <Check className="w-4 h-4 mr-2" /> Save Changes
                                </Button>
                            </>
                        ) : (
                            <Button size="sm" variant="outline" onClick={() => setIsEditing(true)}>
                                <Edit2 className="w-4 h-4 mr-2" /> Edit Rule
                            </Button>
                        )}
                    </div>
                </div>
            </CardHeader>
            <CardContent className="flex-1 p-0 relative min-h-[400px]">
                {/* Editor Area */}
                <div className="absolute inset-0 flex flex-col">
                    {isEditing ? (
                        <textarea
                            className="flex-1 w-full h-full p-6 bg-background font-mono text-sm resize-none focus:outline-none"
                            value={content}
                            onChange={(e) => setContent(e.target.value)}
                            spellCheck={false}
                        />
                    ) : (
                        <div className="flex-1 w-full h-full p-6 bg-muted/10 font-mono text-sm overflow-auto whitespace-pre-wrap">
                            {content}
                        </div>
                    )}

                    {error && (
                        <div className="absolute bottom-4 left-4 right-4 p-3 bg-destructive/10 border border-destructive/50 text-destructive text-sm rounded-md flex items-center gap-2 animate-in slide-in-from-bottom-2">
                            <AlertTriangle className="w-4 h-4" />
                            {error}
                        </div>
                    )}
                </div>
            </CardContent>
            <CardFooter className="border-t border-border bg-muted/20 py-3 flex justify-between items-center text-xs text-muted-foreground">
                <div className="flex gap-4">
                    <span>Author: {rule.author || "Unknown"}</span>
                    <span>Date: {rule.date || "N/A"}</span>
                </div>
                <div>
                    {rule.logsource && `${rule.logsource.product} / ${rule.logsource.category}`}
                </div>
            </CardFooter>
        </Card>
    )
}
