"use client"

import React, { createContext, useContext, useState, useCallback, ReactNode } from "react"
import { v4 as uuidv4 } from 'uuid'

export type NotificationType = "info" | "success" | "warning" | "error"

export interface Notification {
    id: string
    title: string
    message: string
    type: NotificationType
    timestamp: Date
    read: boolean
}

interface NotificationContextType {
    notifications: Notification[]
    unreadCount: number
    addNotification: (title: string, message: string, type?: NotificationType) => void
    markAsRead: (id: string) => void
    markAllAsRead: () => void
    clearNotification: (id: string) => void
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined)

export function NotificationProvider({ children }: { children: ReactNode }) {
    const [notifications, setNotifications] = useState<Notification[]>([])

    const addNotification = useCallback((title: string, message: string, type: NotificationType = "info") => {
        const newNotification: Notification = {
            id: uuidv4(),
            title,
            message,
            type,
            timestamp: new Date(),
            read: false,
        }
        setNotifications((prev) => [newNotification, ...prev])
    }, [])

    const markAsRead = useCallback((id: string) => {
        setNotifications((prev) =>
            prev.map((n) => (n.id === id ? { ...n, read: true } : n))
        )
    }, [])

    const markAllAsRead = useCallback(() => {
        setNotifications((prev) => prev.map((n) => ({ ...n, read: true })))
    }, [])

    const clearNotification = useCallback((id: string) => {
        setNotifications((prev) => prev.filter((n) => n.id !== id))
    }, [])

    const unreadCount = notifications.filter((n) => !n.read).length

    return (
        <NotificationContext.Provider
            value={{
                notifications,
                unreadCount,
                addNotification,
                markAsRead,
                markAllAsRead,
                clearNotification,
            }}
        >
            {children}
        </NotificationContext.Provider>
    )
}

export function useNotifications() {
    const context = useContext(NotificationContext)
    if (context === undefined) {
        throw new Error("useNotifications must be used within a NotificationProvider")
    }
    return context
}
