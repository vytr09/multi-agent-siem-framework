"use client"

import { Bell, Check, Trash2, Info, AlertTriangle, CheckCircle, XCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useNotifications, NotificationType } from "@/contexts/notification-context"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"
import { formatDistanceToNow } from "date-fns"

export function NotificationPopover() {
    const { notifications, unreadCount, markAsRead, markAllAsRead, clearNotification } = useNotifications()

    const getIcon = (type: NotificationType) => {
        switch (type) {
            case "success": return <CheckCircle className="h-4 w-4 text-green-500" />
            case "warning": return <AlertTriangle className="h-4 w-4 text-yellow-500" />
            case "error": return <XCircle className="h-4 w-4 text-red-500" />
            default: return <Info className="h-4 w-4 text-blue-500" />
        }
    }

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="relative">
                    <Bell className="h-5 w-5 text-muted-foreground" />
                    {unreadCount > 0 && (
                        <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-red-500 animate-pulse border border-background"></span>
                    )}
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
                <div className="flex items-center justify-between px-2 py-1.5">
                    <DropdownMenuLabel className="font-normal text-sm">Notifications</DropdownMenuLabel>
                    {notifications.length > 0 && (
                        <Button variant="ghost" size="sm" onClick={markAllAsRead} className="h-auto px-2 py-1 text-xs">
                            Mark all read
                        </Button>
                    )}
                </div>
                <DropdownMenuSeparator />

                {notifications.length === 0 ? (
                    <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                        No notifications
                    </div>
                ) : (
                    <ScrollArea className="h-[300px]">
                        <div className="flex flex-col gap-1 p-1">
                            {notifications.map((notification) => (
                                <div
                                    key={notification.id}
                                    className={cn(
                                        "relative flex gap-3 rounded-md p-3 text-sm transition-colors hover:bg-muted",
                                        !notification.read && "bg-muted/50"
                                    )}
                                    onClick={() => markAsRead(notification.id)}
                                >
                                    <div className="mt-0.5 shrink-0">{getIcon(notification.type)}</div>
                                    <div className="flex-1 space-y-1">
                                        <p className={cn("font-medium leading-none", !notification.read && "text-foreground")}>
                                            {notification.title}
                                        </p>
                                        <p className="text-xs text-muted-foreground line-clamp-2">
                                            {notification.message}
                                        </p>
                                        <p className="text-[10px] text-muted-foreground">
                                            {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
                                        </p>
                                    </div>
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-6 w-6 shrink-0 opacity-0 group-hover:opacity-100"
                                        onClick={(e) => {
                                            e.stopPropagation()
                                            clearNotification(notification.id)
                                        }}
                                    >
                                        <Trash2 className="h-3 w-3" />
                                    </Button>
                                </div>
                            ))}
                        </div>
                    </ScrollArea>
                )}
            </DropdownMenuContent>
        </DropdownMenu>
    )
}
