"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { LayoutDashboard, Bot, Shield, Settings, Activity, Terminal, Zap } from "lucide-react"
import { cn } from "@/lib/utils"

const navigation = [
    { name: "Dashboard", href: "/", icon: LayoutDashboard },
    { name: "Agents", href: "/agents", icon: Bot },
    { name: "Rules", href: "/rules", icon: Shield },
    { name: "Attacks", href: "/attacks", icon: Zap },
    { name: "Logs", href: "/logs", icon: Terminal },
    { name: "Settings", href: "/settings", icon: Settings },
]

export function Sidebar() {
    const pathname = usePathname()

    return (
        <div className="flex h-screen w-64 flex-col border-r border-neutral-700 bg-neutral-900">
            <div className="flex h-16 items-center border-b border-neutral-700 px-6">
                <Activity className="mr-2 h-6 w-6 text-yellow-500" />
                <span className="text-lg font-bold font-heading tracking-tight text-neutral-100">
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
                                        ? "bg-yellow-500/10 text-yellow-500"
                                        : "text-neutral-400 hover:bg-neutral-800 hover:text-neutral-100"
                                )}
                            >
                                <item.icon
                                    className={cn(
                                        "mr-3 h-5 w-5 flex-shrink-0",
                                        isActive
                                            ? "text-yellow-500"
                                            : "text-neutral-500 group-hover:text-neutral-300"
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
                    <div className="h-8 w-8 rounded-full bg-yellow-500/20 flex items-center justify-center text-yellow-500 font-bold text-xs">
                        AD
                    </div>
                    <div className="ml-3">
                        <p className="text-sm font-medium text-neutral-200">Admin User</p>
                        <p className="text-xs text-neutral-500">admin@siem.local</p>
                    </div>
                </div>
            </div>
        </div>
    )
}
