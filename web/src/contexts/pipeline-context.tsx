"use client"

import { createContext, useContext, useState, ReactNode, useCallback } from "react"

interface PipelineStatus {
    stage: string
    status: string
    message: string
    progress?: number
}

interface PipelineContextType {
    // Pipeline execution state
    pipelineState: number // 0=Idle, 1=Ingest, 2=Extract, 3=RuleGen, 4=Completed
    selectedCaseId: string | null
    pipelineResult: any
    pipelineStatus: PipelineStatus | null
    isRunning: boolean

    // Actions
    setPipelineState: (state: number) => void
    setSelectedCaseId: (id: string | null) => void
    setPipelineResult: (result: any) => void
    setPipelineStatus: (status: PipelineStatus | null) => void
    resetPipeline: () => void
}

const PipelineContext = createContext<PipelineContextType | undefined>(undefined)

export function PipelineProvider({ children }: { children: ReactNode }) {
    const [pipelineState, setPipelineState] = useState(0)
    const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)
    const [pipelineResult, setPipelineResult] = useState<any>(null)
    const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus | null>(null)

    const isRunning = pipelineState > 0 && pipelineState < 4

    const resetPipeline = useCallback(() => {
        setPipelineState(0)
        setSelectedCaseId(null)
        setPipelineResult(null)
        setPipelineStatus(null)
    }, [])

    return (
        <PipelineContext.Provider value={{
            pipelineState,
            selectedCaseId,
            pipelineResult,
            pipelineStatus,
            isRunning,
            setPipelineState,
            setSelectedCaseId,
            setPipelineResult,
            setPipelineStatus,
            resetPipeline
        }}>
            {children}
        </PipelineContext.Provider>
    )
}

export function usePipeline() {
    const context = useContext(PipelineContext)
    if (context === undefined) {
        throw new Error("usePipeline must be used within a PipelineProvider")
    }
    return context
}
