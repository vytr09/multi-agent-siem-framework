import { Bell, Search } from "lucide-react"
import { Button } from "@/components/ui/button"

export function Header() {
    return (
        <header className="flex h-16 items-center justify-between border-b border-neutral-700 bg-neutral-900 px-6">
            <div className="flex items-center">
                <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-neutral-500" />
                    <input
                        type="text"
                        placeholder="Search events, rules..."
                        className="h-9 w-64 rounded-md border border-neutral-700 bg-neutral-800 pl-9 pr-4 text-sm text-neutral-200 placeholder:text-neutral-500 focus:border-yellow-500 focus:outline-none focus:ring-1 focus:ring-yellow-500"
                    />
                </div>
            </div>
            <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
                    <span className="text-xs font-medium text-neutral-400">System Online</span>
                </div>
                <Button variant="ghost" size="icon" className="relative">
                    <Bell className="h-5 w-5" />
                    <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-yellow-500"></span>
                </Button>
            </div>
        </header>
    )
}
