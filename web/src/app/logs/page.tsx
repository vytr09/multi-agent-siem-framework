"use client"

import { LogViewer } from "@/components/dashboard/log-viewer"
import { Button } from "@/components/ui/button"
import { Download, Trash2, RefreshCw } from "lucide-react"

export default function LogsPage() {
    return (
        <div className="h-[calc(100vh-6rem)] flex flex-col space-y-6">
            <div className="flex items-center justify-between flex-shrink-0">
                <div>
                    <h1 className="text-3xl font-bold font-heading text-foreground">System Logs</h1>
                    <p className="text-muted-foreground mt-1">Real-time system events and debugging information.</p>
                </div>
                {/* 
                   LogViewer handles its own controls, but if we wanted global page controls we could add them here.
                   For now, we'll let LogViewer handle the view.
                */}
            </div>

            <div className="flex-1 overflow-hidden border rounded-lg bg-card shadow-sm">
                <LogViewer className="h-full border-0 shadow-none" />
            </div>
        </div>
    )
}
