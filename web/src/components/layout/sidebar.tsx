"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { LayoutDashboard, Bot, Shield, Settings, Activity, Terminal, Zap, Network } from "lucide-react"
import { cn } from "@/lib/utils"

const navigation = [
    { name: "Workbench", href: "/", icon: LayoutDashboard },
    { name: "Knowledge", href: "/knowledge", icon: Network },
    { name: "Agents", href: "/agents", icon: Bot },
    { name: "Rules", href: "/rules", icon: Shield },
    { name: "Attacks", href: "/attacks", icon: Zap },
    { name: "Logs", href: "/logs", icon: Terminal },
    { name: "Settings", href: "/settings", icon: Settings },
]

export function Sidebar() {
    const pathname = usePathname()

    return (
        <div className="flex h-screen w-64 flex-col border-r border-border bg-card">
            <div className="flex h-16 items-center border-b border-border px-6">
                <Activity className="mr-2 h-6 w-6 text-primary" />
                <span className="text-lg font-bold font-heading tracking-tight text-foreground">
                    SIEM Agent
                </span>
            </div>
            <div className="flex-1 overflow-y-auto py-4">
                <nav className="space-y-1 px-3">
                    {navigation.map((item) => {
                        const isActive = pathname === item.href
                        return (
                            <Link
                                key={item.name}
                                href={item.href}
                                className={cn(
                                    "group flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-colors duration-200",
                                    isActive
                                        ? "bg-primary/10 text-primary"
                                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                                )}
                            >
                                <item.icon
                                    className={cn(
                                        "mr-3 h-5 w-5 flex-shrink-0",
                                        isActive
                                            ? "text-primary"
                                            : "text-muted-foreground group-hover:text-foreground"
                                    )}
                                />
                                {item.name}
                            </Link>
                        )
                    })}
                </nav>
            </div>
            <div className="border-t border-neutral-700 p-4">
                <div className="flex items-center">
                    <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold text-xs">
                        AD
                    </div>
                    <div className="ml-3">
                        <p className="text-sm font-medium text-foreground">Admin User</p>
                        <p className="text-xs text-muted-foreground">admin@siem.local</p>
                    </div>
                </div>
            </div>
        </div>
    )
}
